"""Apache santé & saturation : sonde (parsing, zéro impact), évaluation, corrélation, historique."""
import datetime
import json
import re
import sqlite3
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock

import apache_health
import apache_probe

BASE = Path(__file__).resolve().parent
TIMED = r'%h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i" %D'


def access_line(ip, seconds, path, status=200, ua='Mozilla/5.0', at=None):
    at = at or datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=30)
    return (f'{ip} - - [{at.strftime("%d/%b/%Y:%H:%M:%S %z")}] "GET {path}?q=secret HTTP/1.1" {status} 512 '
            f'"-" "{ua}" {int(seconds * 1e6)}')


class ProbeParsingTests(unittest.TestCase):
    def setUp(self):
        # La sonde démarre normalement à chaque SSH ; son import ne doit pas épuiser le budget du test.
        started = apache_probe.time.monotonic()
        budget = mock.patch.multiple(apache_probe, STARTED=started, DEADLINE=started + 40)
        budget.start()
        self.addCleanup(budget.stop)

    def test_logformat_to_regex(self):
        regex = apache_probe.format_regex(TIMED)
        match = regex.match(access_line('198.51.100.7', 12.5, '/societe-abc-def-123'))
        self.assertEqual(match['ip'], '198.51.100.7')
        self.assertEqual(match['status'], '200')
        self.assertEqual(match['bytes'], '512')
        self.assertEqual(int(match['us']), 12500000)
        self.assertEqual(match['ua'], 'Mozilla/5.0')
        self.assertIsNone(apache_probe.format_regex('%h %l %u %t "%r" %>s %O'), 'sans %D : pas d’analyse')

    def test_logformat_scoped_to_its_virtualhost(self):
        files = {
            '/etc/apache2/apache2.conf': 'LogFormat "%h %l %u %t \\"%r\\" %>s %O" combined\n',
            '/etc/apache2/sites-enabled/a.conf': '<VirtualHost *:80>\nServerName www.a.test\n'
                                                 'LogFormat "%h %l %u %t \\"%r\\" %>s %b %D" combined\n'
                                                 'CustomLog ${APACHE_LOG_DIR}/a-access_log combined\n'
                                                 'ProxyPass / http://192.0.2.13:8080/\n</VirtualHost>\n',
            '/etc/apache2/sites-enabled/b.conf': '<VirtualHost *:80>\nServerName b.test\n'
                                                 'CustomLog ${APACHE_LOG_DIR}/b-access_log combined\n</VirtualHost>\n',
        }
        with mock.patch.object(apache_probe.glob, 'glob', side_effect=lambda p: sorted(f for f in files if 'sites-enabled' in f) if 'sites-enabled' in p else []), \
                mock.patch.object(apache_probe, 'read_config', side_effect=lambda p: files[p]):
            config = apache_probe.vhosts()
        self.assertIn('%D', config['logs']['/var/log/apache2/a-access_log'][0])
        self.assertNotIn('%D', config['logs']['/var/log/apache2/b-access_log'][0])
        self.assertEqual(config['backends']['http://192.0.2.13:8080']['vhosts'], ['www.a.test'])

    def test_uri_normalization_drops_parameters(self):
        self.assertEqual(apache_probe.normalize_uri('GET /societe-maroc-telecom-12345?token=x HTTP/1.1'), '/societe-*')
        self.assertEqual(apache_probe.normalize_uri('GET /api/v1/items/42 HTTP/1.1'), '/api/v1/items/{n}')

    def test_bot_categories(self):
        self.assertEqual(apache_probe.bot_category('Mozilla/5.0 (compatible; bingbot/2.0)'), 'bingbot')
        self.assertEqual(apache_probe.bot_category('meta-externalagent/1.1'), 'meta-externalagent')
        self.assertEqual(apache_probe.bot_category('sqlmap/1.7'), 'scanners')
        self.assertIsNone(apache_probe.bot_category('Mozilla/5.0 (Windows NT 10.0)'))

    def test_access_log_aggregates_and_concurrency(self):
        lines = [access_line('198.51.100.7', 12, '/societe-a-b-1') for _ in range(3)] + \
                [access_line('198.51.100.8', 0.2, '/', ua='bingbot/2.0', status=403) for _ in range(7)]
        config = {'logs': {'/var/log/apache2/demoapp-access_log': (TIMED, 'timed')}}
        now = datetime.datetime.now().timestamp()
        with mock.patch.object(apache_probe.glob, 'glob', side_effect=lambda p: ['/var/log/apache2/demoapp-access_log'] if 'access' in p else []), \
                mock.patch.object(apache_probe.os, 'stat', return_value=mock.Mock(st_mtime=now, st_size=4096)), \
                mock.patch.object(apache_probe, 'read_tail', return_value=(lines, False)):
            data = apache_probe.access_logs(config)
        self.assertEqual((data['total'], data['slow10'], data['slow1']), (10, 3, 3))
        self.assertEqual(data['sample_response_bytes']['198.51.100.7'], 1536)
        self.assertEqual(data['max'], 12.0)
        self.assertEqual(data['top_ips'][0]['ip'], '198.51.100.7')
        self.assertEqual(data['top_ips'][0]['slow10'], 3)
        self.assertEqual(data['top_uris'][0]['uri'], '/societe-*')
        self.assertEqual(data['bots']['s403'], 7)
        self.assertEqual(dict(data['bots']['blocked_categories']), {'bingbot': 7})
        self.assertGreaterEqual(data['concurrency']['peak_10m'], 3)
        self.assertNotIn('secret', json.dumps(data), 'paramètres d’URL jamais remontés')

    def test_log_without_duration_is_excluded_not_invented(self):
        config = {'logs': {'/var/log/apache2/access.log': ('%h %l %u %t "%r" %>s %O', 'combined')}}
        now = datetime.datetime.now().timestamp()
        with mock.patch.object(apache_probe.glob, 'glob', side_effect=lambda p: ['/var/log/apache2/access.log']), \
                mock.patch.object(apache_probe.os, 'stat', return_value=mock.Mock(st_mtime=now, st_size=10)):
            with self.assertRaisesRegex(RuntimeError, '%D'):
                apache_probe.access_logs(config)

    def test_backend_states(self):
        entry = {'scheme': 'http', 'host': '192.0.2.20', 'port': 8080, 'vhosts': ['www.example.test']}
        with mock.patch.object(apache_probe.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', ('192.0.2.20', 8080))]), \
                mock.patch.object(apache_probe.socket, 'create_connection', side_effect=ConnectionRefusedError):
            self.assertEqual(apache_probe.probe_backend(entry)['state'], 'TCP DOWN')
        response = mock.Mock(status=404)
        conn = mock.Mock(getresponse=mock.Mock(return_value=response))
        with mock.patch.object(apache_probe.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', ('192.0.2.20', 8080))]), \
                mock.patch.object(apache_probe.socket, 'create_connection'), \
                mock.patch.object(apache_probe.http.client, 'HTTPConnection', return_value=conn):
            result = apache_probe.probe_backend(entry)
        self.assertEqual(result['state'], 'HTTP RESPONDING', '404 sur / : le backend répond')
        method, path = conn.request.call_args[0][:2]
        self.assertEqual((method, path), ('HEAD', '/'))
        self.assertEqual(conn.request.call_args[1]['headers']['Host'], 'www.example.test')

    def test_saturation_log_window(self):
        now = datetime.datetime.now()
        stamp = lambda d: (now - d).strftime('[%a %b %d %H:%M:%S.000001 %Y]')
        lines = [stamp(datetime.timedelta(hours=2)) + ' [mpm_event:error] AH00484: server reached MaxRequestWorkers setting',
                 stamp(datetime.timedelta(minutes=5)) + ' [mpm_event:error] AH03490: scoreboard is full, not at MaxRequestWorkers']
        with mock.patch.object(apache_probe, 'read_tail', return_value=(lines, False)):
            data = apache_probe.saturation_events()
        self.assertEqual(data['counts'], {'AH00484': 0, 'AH10159': 0, 'AH03490': 1}, 'seules les 30 dernières minutes comptent')
        self.assertIsNotNone(data['last']['AH03490'])


class ZeroImpactTests(unittest.TestCase):
    def test_probe_has_no_mutating_command(self):
        source = (BASE / 'apache_probe.py').read_text(encoding='utf-8')
        code = re.sub(r'"""[\s\S]*?"""', '', source)  # docstrings exclues
        for forbidden in (r"'systemctl'", r"'kill'", r"'pkill'", r"'iptables'", r"'nft'", r"'fail2ban-client'",
                          r"'reload'", r"'restart'", r"'apachectl'", r"'apache2ctl'", r"'rm'", r"'tee'", r"'sed'",
                          r"open\([^)]*['\"][wa]", r"'POST'", r"'PUT'", r"'DELETE'"):
            self.assertIsNone(re.search(forbidden, code), forbidden)
        commands = set(re.findall(r"run\(\['([\w-]+)'", code))
        self.assertLessEqual(commands, {'sudo'})
        # sudo uniquement pour lire : head/tail bornés, directement ou via le script infraops-read.
        self.assertEqual(set(re.findall(r"'sudo', '-n', '([\w-]+)'", code)), set())
        self.assertEqual(set(re.findall(r"bounded_read\('(\w+)'", code)), {'tail', 'head'})
        self.assertIn("['sudo', '-n', READER, op, str(size), path]", code)
        self.assertIn("['sudo', '-n', op, '-c', str(size), '--', path]", code)
        self.assertEqual(apache_probe.READER, '/usr/local/sbin/infraops-read')

    def test_bounded_reader_used_when_installed(self):
        with mock.patch.object(apache_probe.os.path, 'isfile', return_value=True):
            self.assertEqual(apache_probe.bounded_read('tail', 4096, '/var/log/apache2/error.log'),
                             ['sudo', '-n', '/usr/local/sbin/infraops-read', 'tail', '4096', '/var/log/apache2/error.log'])
        with mock.patch.object(apache_probe.os.path, 'isfile', return_value=False):
            self.assertEqual(apache_probe.bounded_read('head', 10, '/etc/apache2/apache2.conf'),
                             ['sudo', '-n', 'head', '-c', '10', '--', '/etc/apache2/apache2.conf'])

    def test_sent_command_is_the_probe_and_fits_windows(self):
        import base64
        import shlex
        import zlib
        import ssh
        import waf_audit  # noqa: F401 (enregistre l'opération)
        command = ssh.OPERATIONS['waf_apache']
        self.assertLess(len(command), 30000, 'limite de 32 767 caractères de CreateProcess')
        blob = re.search(r"b64decode\('([^']+)'\)", shlex.split(command)[2])[1]
        self.assertEqual(zlib.decompress(base64.b64decode(blob)), (BASE / 'apache_probe.py').read_bytes())

    def test_timeouts_everywhere(self):
        source = (BASE / 'apache_probe.py').read_text(encoding='utf-8')
        self.assertIn('timeout=3', source)
        self.assertIn('timeout=2', source)
        self.assertIn('DEADLINE = STARTED + 40', source)


def apache(busy=None, max_workers=1000, saturation=None, access=None, backends=None):
    s = {'config': {'status': 'observed', 'data': {'effective_max_workers': max_workers}}}
    if busy is not None:
        s['status'] = {'status': 'observed', 'data': {'BusyWorkers': busy, 'IdleWorkers': 10}}
    if saturation:
        s['saturation'] = {'status': 'observed', 'data': {'counts': saturation, 'last': {k: '2026-09-29T10:00:00' for k in saturation}, 'window_seconds': 1800}}
    if access:
        s['access'] = {'status': 'observed', 'data': access}
    if backends:
        s['backends'] = {'status': 'observed', 'data': {'backends': backends}}
    return {'sections': s}


def sockets(cw):
    return {'sockets': {'status': 'observed', 'data': {'process_visible': True, 'by_process': [['apache2', cw]], 'close_wait_total': cw}}}


class EvaluationTests(unittest.TestCase):
    def test_worker_levels(self):
        for busy, level in ((10, 'ok'), (600, 'yellow'), (750, 'orange'), (900, 'red'), (1000, 'critical')):
            self.assertEqual(apache_health.evaluate(apache(busy), {})['workers']['level'], level, busy)
        self.assertEqual(apache_health.evaluate(apache(12, saturation={'AH00484': 1}), {})['workers']['level'], 'critical')

    def test_missing_data_is_na(self):
        result = apache_health.evaluate({'sections': {}}, {})
        self.assertEqual(result['workers']['level'], 'unknown')
        self.assertTrue(all(card['value'] == 'N/A' for card in result['cards']))
        self.assertIn('N/A', ' '.join(result['summary']))

    def test_slow_levels(self):
        base = {'total': 100, 'slow5': 0, 'slow10': 0}
        self.assertEqual(apache_health.evaluate(apache(access={**base, 'avg': 0.4}), {})['slow']['level'], 'ok')
        self.assertEqual(apache_health.evaluate(apache(access={**base, 'avg': 4}), {})['slow']['level'], 'orange')
        # Plus de 10 % de requêtes ≥ 10 s : rouge « Critique », pas « critical » (réservé à la saturation des workers).
        self.assertEqual(apache_health.evaluate(apache(access={**base, 'avg': 2, 'slow10': 11}), {})['slow']['level'], 'red')

    def cases(self, **kw):
        return {d['case'] for d in apache_health.evaluate(apache(**{k: v for k, v in kw.items() if k != 'cw'}), sockets(kw['cw']) if 'cw' in kw else {},
                                                          kw.get('previous'))['diagnostics']}

    def test_correlation_cases(self):
        slow = {'total': 100, 'avg': 8, 'slow5': 40, 'slow10': 20, 'rps': 5}
        self.assertIn(1, self.cases(busy=950, access=slow))
        self.assertIn(3, self.cases(busy=12, cw=250))
        self.assertNotIn(3, self.cases(busy=12, cw=183), '183 : dans la plage normale observée (p95 172, p99 216)')
        self.assertNotIn(4, self.cases(busy=12, cw=250))
        self.assertIn(4, self.cases(busy=800, cw=250, access=slow))
        self.assertIn(5, self.cases(busy=12, saturation={'AH03490': 2}))
        self.assertNotIn(5, self.cases(busy=12, saturation={'AH10159': 2}), 'AH10159 = proche, pas confirmé')
        fast = {'total': 6000, 'avg': 0.2, 'slow5': 0, 'slow10': 0, 'rps': 40}
        result = apache_health.evaluate(apache(950, access=fast), {}, {'rps_reference': 10})
        self.assertIn(2, {d['case'] for d in result['diagnostics']})
        self.assertNotIn(2, self.cases(busy=950, access=fast), 'sans référence historique : pas de conclusion')

    def test_summary_messages(self):
        healthy = apache_health.evaluate(apache(12, access={'total': 100, 'avg': 0.3, 'slow5': 0, 'slow10': 0},
                                                backends=[{'backend': '10.77.0.13:8080', 'state': 'HTTP RESPONDING'}]), sockets(183))
        text = ' '.join(healthy['summary'])
        self.assertIn('Apache healthy.', text)
        self.assertIn('12/1000 workers busy.', text)
        self.assertIn('183 persistent backend CLOSE_WAIT detected.', text)
        self.assertIn('Slow-request rate is currently normal.', text)
        crit = ' '.join(apache_health.evaluate(apache(1000, saturation={'AH00484': 3}, access={'total': 100, 'avg': 15, 'slow5': 60, 'slow10': 40,
                                                                                            'top_vhosts': [['demoapp', 80]]}), {})['summary'])
        self.assertIn('CRITICAL: Apache worker saturation detected.', crit)
        self.assertIn('MaxRequestWorkers reached.', crit)
        self.assertIn('demoapp traffic represents the majority', crit)
        self.assertNotIn('bloqu', crit)

    def test_history_record_and_delta(self):
        db_path = ':memory:'
        conn = sqlite3.connect(db_path)
        self.addCleanup(conn.close)

        @contextmanager
        def connect():
            with conn:
                yield conn

        first = {'apache': apache(12), 'sections': sockets(100)}
        apache_health.record(connect, 'waf', first)
        second = {'apache': apache(15), 'sections': sockets(183)}
        apache_health.record(connect, 'waf', second)
        self.assertEqual(second['apache_health']['close_wait']['delta'], 83)
        samples = apache_health.history(connect, 'waf')
        self.assertEqual([s['close_wait'] for s in samples[:2]], [183, 100])
        self.assertEqual(set(samples[0]), {'ts', 'busy', 'max_workers', 'utilization', 'close_wait', 'req_per_sec_status', 'rps',
                                           'requests_10m', 'slow5', 'slow10', 'avg', 'peak_concurrency', 'backend_max_ttfb_ms',
                                           'backends_down', 'top_ip', 'top_uri', 'ah00484', 'ah03490', 'level', 'down_since'})


class RemoteReaderScriptTests(unittest.TestCase):
    def test_liens_durs_refuses_avant_lecture(self):
        # Audit SSH-11 : un lien dur dans /var/log/apache2 contournait realpath.
        script = (Path(__file__).parent / 'deploy/remote/infraops-read.sh').read_text(encoding='utf-8')
        check = script.index('stat -c %h')
        self.assertLess(check, script.index('exec head'))
        self.assertLess(script.index('realpath -e'), check)
        self.assertNotIn(chr(13), script, 'fins de ligne LF (exécuté sous Linux)')


if __name__ == '__main__':
    unittest.main()
