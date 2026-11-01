"""Exactitude de la page WAF / HA : sorties brutes → sonde → évaluation.

Les fixtures de test_fixtures/waf reprennent le format exact des commandes lues sur le WAF ;
chaque valeur attendue est comptée à la main dans test_fixtures/waf/README.md. Aucun appel
réseau ni commande réelle : subprocess.run et glob sont simulés.
"""
import contextlib
import io
import json
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import apache_health
import waf_findings
import waf_probe

FIXTURES = Path(__file__).parent / 'test_fixtures' / 'waf'
ACCESS = ['/var/log/apache2/shop.example.test-access_log', '/var/log/apache2/old.example.test-access_log']
ERROR = '/var/log/apache2/error.log'


def raw(name):
    return (FIXTURES / name).read_text(encoding='utf-8')


def fake_run(ss_all=None):
    def run(args, **kwargs):
        out, code = '', 0
        if args[:3] == ['sudo', '-n', 'fail2ban-client'] and args[3] == 'status':
            out = raw('fail2ban_status.txt')
        elif args[-2:] == ['banip', '--with-time']:
            out = raw('fail2ban_banip_with_time.txt')
        elif args == ['ss', '-Htan']:
            out = ss_all if ss_all is not None else raw('ss_all.txt')
        elif args == ['ss', '-Htln']:
            out = raw('ss_listen.txt')
        elif args[:3] == ['sudo', '-n', 'ss']:
            out = raw('ss_close_wait_processes.txt')
        elif args[:3] == ['sudo', '-n', 'tail']:
            name = args[-1].rsplit('/', 1)[-1]
            out = raw('error.log' if name == 'error.log' else name)
        else:
            code = 1  # autres sections hors du périmètre de ces fixtures : « unknown », jamais inventées
        return SimpleNamespace(returncode=code, stdout=out, stderr='')
    return run


def fake_glob(pattern):
    if pattern.endswith('*-access_log'):
        return ACCESS
    if pattern == ERROR:
        return [ERROR]
    return []


def probe(**kw):
    buffer = io.StringIO()
    with mock.patch.object(waf_probe.subprocess, 'run', side_effect=fake_run(**kw)), \
            mock.patch.object(waf_probe.glob, 'glob', side_effect=fake_glob), \
            mock.patch.object(waf_probe.os.path, 'isfile', return_value=False), contextlib.redirect_stdout(buffer):
        waf_probe.main()
    return json.loads(buffer.getvalue())['sections']


class GoldenProbeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = probe()

    def test_fail2ban(self):
        d = self.s['fail2ban']['data']
        self.assertEqual((d['currently_banned'], d['total_banned'], d['currently_failed'], d['total_failed']), (5, 412, 3, 1287))
        self.assertEqual(len(d['banned_ips']), 5)
        self.assertIn('2001:db8::7', d['banned_ips'])
        bans = self.s['bantimes']['data']['bans']
        self.assertEqual(len(bans), 3)
        self.assertEqual(bans['198.51.100.4']['duration_seconds'], 604800)

    def test_sockets(self):
        d = self.s['sockets']['data']
        self.assertEqual(d['total'], 20)
        self.assertEqual(d['states'], {'LISTEN': 3, 'ESTAB': 6, 'TIME-WAIT': 5, 'CLOSE-WAIT': 4, 'FIN-WAIT-2': 1, 'LAST-ACK': 1})
        self.assertEqual((d['close_wait_total'], d['close_wait_outbound'], d['close_wait_inbound']), (4, 3, 1))
        self.assertEqual((d['fin_unread'], d['recv_q_nonzero'], d['recv_q_bytes']), (2, 1, 516))
        self.assertEqual(d['by_upstream'], [['192.0.2.20:8080', 2], ['192.0.2.21:8069', 1]])
        self.assertEqual(d['by_pid'][0], ['apache2:2101', 2])
        self.assertFalse(d['truncated'])

    def test_http_sample(self):
        t = self.s['traffic']['data']
        self.assertEqual((t['requests'], t['unparsed_lines']), (9, 1))
        self.assertEqual(t['http_codes'], {'200': 5, '403': 1, '500': 1, '502': 1, '503': 1})
        self.assertEqual(t['errors_5xx_pct'], 33.33)
        self.assertEqual(sum(n for _, n in t['top_ips']), 8, 'ligne vhost_combined : code compté, IP non')
        self.assertEqual(t['top_urls'][0], ['/catalogue', 3])
        self.assertEqual(t['window_seconds'], [60, 21600])
        self.assertEqual(t['banned_requests'], {'198.51.100.4': 1, '192.0.2.66': 1})
        self.assertNotIn('SECRET', json.dumps(self.s))

    def test_modsecurity(self):
        m = self.s['modsecurity']['data']
        self.assertEqual(m['alert_lines'], 4, 'notices de démarrage exclues')
        self.assertEqual(dict(m['rules']), {'920350': 2, '949110': 1, '930130': 1})
        self.assertEqual(m['anomaly_max'], 10)
        self.assertEqual({e['client'] for e in m['events']}, {'198.51.100.4', '2001:db8::50', '2001:db8::51', '127.0.0.1'})
        self.assertEqual(sum(e['action'] == 'deny_reported' for e in m['events']), 1)
        self.assertEqual(m['banned_alerts'], {'198.51.100.4': {'lines': 1, 'rules': [['949110', 1]]}})

    def test_ss_under_load_is_measured_not_dropped(self):
        # 13 000 sockets ≈ 0,9 Mo : l'ancien plafond de 800 Ko faisait échouer toute la section.
        line = 'TIME-WAIT  0      0         192.0.2.10:443         198.51.100.7:{}\n'
        many = raw('ss_all.txt') + ''.join(line.format(20000 + i) for i in range(13000))
        self.assertGreater(len(many), 800000)
        d = probe(ss_all=many)['sockets']
        self.assertEqual(d['status'], 'observed')
        self.assertEqual(d['data']['states']['TIME-WAIT'], 13005)
        self.assertFalse(d['data']['truncated'])


class VhostErrorLogTests(unittest.TestCase):
    """Constat E11 : les refus ModSecurity d'un site sont écrits dans le journal d'erreurs du vhost.
    Fixtures *.tpl : « {-5m} » devient l'horodatage Apache d'il y a 5 minutes (fenêtre de 30 min)."""
    MAIN = '/var/log/apache2/error.log'
    SHOP = '/var/log/apache2/shop.example.test-error_log'
    API = '/var/log/apache2/api.example.test-error_log'
    QUIET = '/var/log/apache2/quiet.example.test-error_log'

    def lines(self, name):
        now = datetime.now()
        stamp = lambda m: (now - timedelta(minutes=int(m[1]))).strftime('[%a %b %d %H:%M:%S.000001 %Y]')
        import re
        return [re.sub(r'\{-(\d+)m\}', stamp, line) for line in raw(name).splitlines()]

    def run_probe(self, unreadable=(), truncated=(), total=None):
        import apache_probe
        files = {self.MAIN: 'apache_error.log.tpl', self.SHOP: 'shop.example.test-error_log.tpl', self.API: 'api.example.test-error_log.tpl'}
        reads = []

        def read_tail(path, max_bytes):
            reads.append(path)
            if path in unreadable:
                raise RuntimeError('Commande refusée ou indisponible (code 1)')
            return self.lines(files[path]), path in truncated

        def mtime(path):  # journal calme : non modifié depuis 2 h, donc ignoré sans lecture
            return datetime.now().timestamp() - (7200 if path == self.QUIET else 10)

        patches = [mock.patch.object(apache_probe, 'read_tail', side_effect=read_tail),
                   mock.patch.object(apache_probe.glob, 'glob', return_value=[self.API, self.QUIET, self.SHOP]),
                   mock.patch.object(apache_probe.os.path, 'getmtime', side_effect=mtime)]
        if total is not None:
            patches.append(mock.patch.object(apache_probe, 'VHOST_ERROR_TOTAL', total))
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            return apache_probe.saturation_events(), reads

    def test_vhost_refusals_are_counted_with_the_main_log(self):
        data, reads = self.run_probe()
        self.assertEqual(data['modsecurity_denied'], 4, 'error.log 1 + shop 2 + api 1')
        self.assertEqual(data['modsecurity_main_denied'], 1, 'ancien décompte : error.log seul')
        self.assertEqual(data['modsecurity_lines'], 5, 'notices de rechargement exclues')
        self.assertEqual(data['counts']['AH03490'], 1)
        v = data['modsecurity_vhosts']
        self.assertEqual(v['by_file'], [(self.SHOP, 2), (self.API, 1)])
        self.assertEqual((v['files_discovered'], v['files_read']), (3, 2))
        self.assertTrue(v['complete'])
        self.assertNotIn(self.QUIET, reads, 'journal non modifié dans la fenêtre : pas de lecture')
        self.assertIn('journaux d’erreurs des vhosts', data['scope'])

    def test_incomplete_coverage_is_reported_as_a_minimum(self):
        # api tronqué, première ligne lue il y a 2 min : le début de la fenêtre manque. shop illisible.
        data, _ = self.run_probe(unreadable=(self.SHOP,), truncated=(self.API,))
        v = data['modsecurity_vhosts']
        self.assertEqual(data['modsecurity_denied'], 2, 'error.log 1 + api 1 : minimum')
        self.assertEqual((v['unreadable'], v['partial'], v['complete']), ([self.SHOP], [self.API], False))
        health = apache_health.evaluate({'sections': {'saturation': {'status': 'observed', 'data': data}}}, {})
        note = next(c for c in health['cards'] if c['key'] == 'modsec')['note']
        self.assertIn('2 refus ModSecurity sur 30 min (error.log et journaux des vhosts, couverture partielle : minimum)', note)

    def test_truncated_log_that_covers_the_window_is_complete(self):
        # shop tronqué, mais sa première ligne lue (il y a 45 min) précède la fenêtre : rien ne manque.
        data, _ = self.run_probe(truncated=(self.SHOP,))
        self.assertEqual((data['modsecurity_denied'], data['modsecurity_vhosts']['complete']), (4, True))

    def test_read_budget_leaves_files_unread_but_listed(self):
        data, reads = self.run_probe(total=1024 * 1024)
        v = data['modsecurity_vhosts']
        self.assertEqual((v['files_read'], v['not_read'], v['complete']), (1, [self.SHOP], False))
        self.assertNotIn(self.SHOP, reads)


class FindingIdentityTests(unittest.TestCase):
    def certs(self, *paths):
        cert = {'not_before': '2026-01-01T00:00:00+00:00', 'not_after': '2026-10-25T00:00:00+00:00', 'status': 'observed'}
        return {'sections': {'certificates': {'status': 'observed', 'data': {'certificates': [{**cert, 'path': p} for p in paths]}}}}

    def ids(self, waf):
        now = datetime(2026, 10, 27, tzinfo=timezone.utc)
        return {f['evidence'].split(' — ')[0]: f['id'] for f in waf_findings.analyze(waf, '192.0.2.10', now)[1] if f['id'].startswith('waf:tls:')}

    def test_certificate_id_does_not_move_when_a_certificate_is_added(self):
        before = self.ids(self.certs('/etc/ssl/a.crt', '/etc/ssl/pay.crt'))
        after = self.ids(self.certs('/etc/ssl/0-new.crt', '/etc/ssl/a.crt', '/etc/ssl/pay.crt'))
        self.assertEqual(before['/etc/ssl/pay.crt'], after['/etc/ssl/pay.crt'])
        self.assertNotIn('/etc/ssl', ''.join(after.values()), 'identifiant sans chemin en clair')


class SampleSizeTests(unittest.TestCase):
    def finding(self, requests, pct):
        waf = {'sections': {'traffic': {'status': 'observed', 'data': {'errors_5xx_pct': pct, 'requests': requests}}}}
        return next(f for f in waf_findings.analyze(waf, '192.0.2.10')[1] if f['id'] == 'waf:http5xx')

    def test_small_sample_is_inconclusive(self):
        self.assertEqual(self.finding(2, 50.0)['severity'], 'unknown')
        self.assertEqual(self.finding(500, 6.0)['severity'], 'warning')


class BanPlanTests(unittest.TestCase):
    def test_refuses_loopback_and_the_waf_itself(self):
        for ip in ('127.0.0.1', '::1', '192.0.2.10', '0.0.0.0'):
            with self.assertRaises(ValueError, msg=ip):
                waf_findings.command_plan(ip, 'ban', '192.0.2.10')
        self.assertIn('Adresse privée', waf_findings.command_plan('10.0.0.5', 'ban', '192.0.2.10')['note'])
        self.assertEqual(waf_findings.command_plan('127.0.0.1', 'inspect', '192.0.2.10')['action'], 'inspect')


RESPONDING = [{'backend': '192.0.2.20:8080', 'state': 'HTTP RESPONDING'}]


def apache(busy=24, max_workers=1000, access=None, backends=RESPONDING):
    """Collecte Apache complète par défaut (error.log lu, backends testés) ; access=None : journaux sans %D."""
    sections = {'status': {'status': 'observed', 'data': {'BusyWorkers': busy}},
                'config': {'status': 'observed', 'data': {'effective_max_workers': max_workers}},
                'saturation': {'status': 'observed', 'data': {'counts': {'AH00484': 0, 'AH10159': 0, 'AH03490': 0}, 'last': {}}},
                'backends': {'status': 'observed', 'data': {'backends': backends}}}
    if access is not None:
        sections['access'] = {'status': 'observed', 'data': access}
    return {'sections': sections}


def sockets(cw):
    return {'sockets': {'status': 'observed', 'data': {'process_visible': True, 'by_process': [['apache2', cw]], 'close_wait_total': cw}}}


NORMAL = {'total': 5000, 'avg': 0.09, 'slow5': 2, 'slow10': 2}


class HealthFromRealProfileTests(unittest.TestCase):
    """Profils relevés sur prdlabwaf03 du 20 au 27 octobre (docs/WAF-SEUILS.md)."""

    def test_normal_close_wait_is_not_an_alert(self):
        # p95 hors épisode : 172 CLOSE_WAIT, 24 workers sur 1000.
        result = apache_health.evaluate(apache(access=NORMAL), sockets(172))
        self.assertEqual(result['close_wait']['level'], 'ok')
        self.assertEqual(result['overall'], 'ok')

    def test_slow_episode_is_critical_but_not_saturation(self):
        # 25/10 01:56 : 198/1000 workers, 857 requêtes ≥ 10 s sur 2401, aucun AH00484.
        episode = {'total': 2401, 'avg': 21.035, 'slow5': 900, 'slow10': 857}
        result = apache_health.evaluate(apache(198, access=episode), sockets(242))
        self.assertEqual(result['overall'], 'red')
        self.assertNotEqual(result['workers']['level'], 'critical')
        self.assertNotIn('APACHE SATURATION', [f['title'] for f in result['findings']])
        self.assertIn('waf:apache:slow', [f['id'] for f in result['findings']])
        self.assertEqual(result['close_wait']['level'], 'yellow', '242 : médiane des épisodes lents')

    def test_chronic_backend_stops_driving_the_overall_state(self):
        down = [{'backend': '10.77.0.33:8069', 'state': 'NETWORK DOWN'}, {'backend': '192.0.2.20:8080', 'state': 'HTTP RESPONDING'}]
        now = datetime(2026, 10, 27, 8, tzinfo=timezone.utc)
        first = apache_health.evaluate(apache(access=NORMAL, backends=down), sockets(50), {}, now)
        self.assertEqual(first['overall'], 'orange', 'panne récente : Risque')
        later = apache_health.evaluate(apache(access=NORMAL, backends=down), sockets(50), first['sample'], now + timedelta(hours=25))
        self.assertEqual(later['backends']['chronic'], 1)
        self.assertEqual(later['overall'], 'yellow', 'chronique : Vigilance, toujours signalé')
        self.assertIn('chronic', ' '.join(later['summary']))

    def test_nothing_measured_is_never_ok(self):
        healthy_backends = [{'backend': '192.0.2.20:8080', 'state': 'HTTP RESPONDING'}]
        result = apache_health.evaluate({'sections': {'backends': {'status': 'observed', 'data': {'backends': healthy_backends}}}}, {})
        self.assertEqual(result['overall'], 'unknown')
        partial = apache_health.evaluate(apache(), sockets(10))  # journaux sans %D : latences non mesurées
        self.assertEqual(partial['overall'], 'unknown')

    def test_each_missing_or_failed_section_prevents_ok(self):
        """Matrice de dégradation côté évaluation : une section Apache absente ou en erreur, ou les
        sockets du WAF absents, interdisent l'état global « ok » ; la raison reste exposée."""
        healthy = apache(access=NORMAL)
        self.assertEqual(apache_health.evaluate(healthy, sockets(50))['overall'], 'ok')
        for name in ('status', 'config', 'saturation', 'backends', 'access'):
            for state in ('absent', 'error'):
                sections = dict(healthy['sections'])
                if state == 'absent':
                    del sections[name]
                else:
                    sections[name] = {'status': 'unknown', 'error': 'Commande refusée ou indisponible (code 1)'}
                result = apache_health.evaluate({'sections': sections}, sockets(50))
                self.assertNotEqual(result['overall'], 'ok', (name, state))
                self.assertIn(name, result['errors'], (name, state))
        self.assertNotEqual(apache_health.evaluate(healthy, {})['overall'], 'ok', 'sockets non collectés')

    def test_waf_section_failure_becomes_an_incomplete_finding(self):
        for name in ('services', 'fail2ban', 'traffic', 'modsecurity', 'sockets', 'certificates', 'conntrack', 'iptables'):
            waf = {'sections': {name: {'status': 'unknown', 'error': 'Commande refusée ou indisponible (code 1)'}}}
            ids = {f['id']: f['severity'] for f in waf_findings.analyze(waf, '192.0.2.10')[1]}
            self.assertEqual(ids.get('waf:coverage:' + name), 'unknown', name)

    def test_403_card_is_information_not_a_modsecurity_verdict(self):
        card = next(c for c in apache_health.evaluate(apache(access={**NORMAL, 'bots': {'s403': 386}}), sockets(5))['cards'] if c['key'] == 'modsec')
        self.assertEqual((card['title'], card['value'], card['level']), ('HTTP 403 · 10 MIN', '386', 'info'))


if __name__ == '__main__':
    unittest.main()
