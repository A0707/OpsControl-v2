"""Analyse CLOSE_WAIT de la sonde WAF : parsing ss, sens, processus, seuils."""
import contextlib
import io
import json
import subprocess
import unittest
from unittest import mock

import waf_findings
import waf_probe

SS_ALL = """ESTAB 0 0 192.0.2.5:443 198.51.100.7:51000
ESTAB 0 0 192.0.2.5:443 198.51.100.8:51001
CLOSE-WAIT 1 0 192.0.2.5:40000 192.0.2.20:8080
CLOSE-WAIT 0 0 192.0.2.5:40001 192.0.2.20:8080
CLOSE-WAIT 0 0 [::ffff:192.0.2.5]:443 [::ffff:198.51.100.9]:52000
TIME-WAIT 0 0 192.0.2.5:40002 192.0.2.21:8080
LISTEN 0 511 *:443 *:*
"""
SS_LISTEN = "LISTEN 0 511 *:443 *:*\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n"
# Filtre d'état : ss omet la colonne State.
SS_CW = """1 0 192.0.2.5:40000 192.0.2.20:8080 users:(("apache2",pid=101,fd=12))
0 0 192.0.2.5:40001 192.0.2.20:8080 users:(("apache2",pid=102,fd=13))
0 0 [::ffff:192.0.2.5]:443 [::ffff:198.51.100.9]:52000 users:(("apache2",pid=103,fd=9))
"""


def fake_run(sudo_ss_allowed=True):
    def run(args, **kwargs):
        out, code = '', 1
        if args == ['ss', '-Htan']:
            out, code = SS_ALL, 0
        elif args == ['ss', '-Htln']:
            out, code = SS_LISTEN, 0
        elif args[:3] == ['sudo', '-n', 'ss']:
            out, code = (SS_CW, 0) if sudo_ss_allowed else ('', 1)
        elif args == ['ss', '-Htan', 'state', 'close-wait']:
            out, code = '\n'.join(l.split(' users:')[0] for l in SS_CW.splitlines()), 0
        elif args[:2] == ['ps', '-C']:
            out, code = '101\n102\n103\n104\n', 0
        return subprocess.CompletedProcess(args, code, out, '')
    return run


def probe(**kw):
    buffer = io.StringIO()
    with mock.patch.object(waf_probe.subprocess, 'run', side_effect=fake_run(**kw)), \
            mock.patch.object(waf_probe.glob, 'glob', return_value=[]), contextlib.redirect_stdout(buffer):
        waf_probe.main()
    return json.loads(buffer.getvalue())['sections']['sockets']


class CloseWaitProbeTests(unittest.TestCase):
    def test_states_direction_and_processes(self):
        section = probe()
        self.assertEqual(section['status'], 'observed')
        d = section['data']
        self.assertEqual(d['states'], {'ESTAB': 2, 'CLOSE-WAIT': 3, 'TIME-WAIT': 1, 'LISTEN': 1})
        self.assertEqual((d['close_wait_total'], d['close_wait_outbound'], d['close_wait_inbound']), (3, 2, 1))
        self.assertEqual(d['by_upstream'], [['192.0.2.20:8080', 2]])
        self.assertEqual(d['by_local_port'], [[443, 1]])
        self.assertEqual(d['by_client'], [['198.51.100.9', 1]])
        self.assertEqual(d['by_process'], [['apache2', 3]])
        # Recv-Q = 1 : seul le FIN est en attente, pas des données applicatives.
        self.assertEqual((d['fin_unread'], d['recv_q_nonzero'], d['recv_q_bytes']), (1, 0, 0))
        self.assertEqual(d['by_pid'][0], ['apache2:101', 1])
        self.assertEqual(d['samples'][0]['recv_q'], 1)
        self.assertEqual(d['apache_processes'], 4)
        self.assertTrue(d['process_visible'])

    def test_without_sudo_processes_are_not_invented(self):
        d = probe(sudo_ss_allowed=False)['data']
        self.assertFalse(d['process_visible'])
        self.assertEqual(d['by_process'], [])
        self.assertEqual(d['close_wait_total'], 3)
        self.assertIsNone(d['samples'][0]['process'])


class CloseWaitFindingTests(unittest.TestCase):
    """Seuils 200/300/1000 (calibrés, docs/WAF-SEUILS.md) ; au-delà de 200, gravité modulée par les workers."""

    def finding(self, apache_cw, busy=None, max_workers=1000):
        waf = {'sections': {'certificates': {'status': 'observed', 'data': {'certificates': []}},
                            'sockets': {'status': 'observed', 'data': {
                                'close_wait_total': apache_cw, 'process_visible': True,
                                'by_process': [['apache2', apache_cw]]}}}}
        if busy is not None:
            waf['apache'] = {'sections': {
                'status': {'status': 'observed', 'data': {'BusyWorkers': busy}},
                'config': {'status': 'observed', 'data': {'effective_max_workers': max_workers}}}}
        _, findings = waf_findings.analyze(waf, '192.0.2.5')
        return next((f for f in findings if f['id'] == 'waf:apache:close_wait'), None)

    def test_thresholds_and_correlation(self):
        self.assertIsNone(self.finding(200, busy=10), 'plage normale observée sur prdlabwaf03')
        self.assertEqual(self.finding(201, busy=10)['severity'], 'warning')
        self.assertEqual(self.finding(250, busy=800)['severity'], 'critical')
        self.assertEqual(self.finding(250)['severity'], 'warning', 'sans server-status : pas de critique')
        text = json.dumps(self.finding(250, busy=800), ensure_ascii=False)
        self.assertNotIn('workers Apache bloqués', text)
        self.assertIn('persistantes', text)
        self.assertFalse(self.finding(250, busy=800)['executable'])


if __name__ == '__main__':
    unittest.main()
