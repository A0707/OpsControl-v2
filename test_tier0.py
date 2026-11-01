from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import asyncio
import contextlib
import json
import os
import sqlite3
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI, HTTPException

import tier0

HOSTS = [{'key': 'job06', 'name': 'prdlabjob06', 'fqdn': 'prdlabjob06.host.example.test', 'ip': '10.77.0.167',
          'role': 'BATCH', 'criticality': 'critical', 'port': 22},
         {'key': 'web', 'name': 'web', 'ip': '10.0.0.9', 'criticality': 'standard'}]


# Jeton de test conforme à tier0.MIN_TOKEN_LENGTH (32 caractères minimum).
JETON = 'jeton-de-test-webhook-zabbix-0123456789'


class FakeRequest:
    def __init__(self, body, token=None, content_length=None):
        self._body = json.dumps(body).encode() if not isinstance(body, bytes) else body
        self.headers = {'authorization': 'Bearer ' + token} if token else {}
        if content_length is not None:
            self.headers['content-length'] = str(content_length)

    async def body(self):
        return self._body

    async def stream(self):
        for i in range(0, len(self._body), 4096):
            yield self._body[i:i + 4096]


def make_context(test_case, problems=()):
    db = sqlite3.connect(':memory:', check_same_thread=False)
    test_case.addCleanup(db.close)
    db.execute('CREATE TABLE batch_states(key TEXT, ip TEXT, payload TEXT)')
    db.execute('INSERT INTO batch_states VALUES(?,?,?)', ('job06', '10.77.0.167', json.dumps(
        {'status': 'observed', 'collected_at': '2026-09-25T12:00:00+00:00',
         'jobs': [{'state': 'scheduled'}, {'state': 'failed'}]})))

    @contextlib.contextmanager
    def connect():
        yield db

    zabbix = {'key': 'z', 'name': 'ZABBIX', 'provider': 'Zabbix',
              'last_result': {'status': 'observed', 'collected_at': '2026-09-26T08:00:00+00:00',
                              'inventory': {'problems': list(problems)}}}
    collected = []
    ctx = SimpleNamespace(HOSTS=HOSTS, cfg=SimpleNamespace(port=22), connect=connect,
                          rows=lambda: [{'key': 'job06', 'collected_at': '2026-09-20T01:24:53+00:00', 'cpu': 12.0,
                                         'ram': 40.0, 'disk_max': 83, 'status': 'warning', 'stale': True}],
                          api_connections=lambda: [zabbix], collect_api_connection=collected.append)
    ctx.collected = collected
    return ctx


def install(ctx):
    app = FastAPI()
    tier0.install(app, ctx)
    routes = {(r.path, tuple(sorted(r.methods))): r.endpoint for r in all_routes(app) if hasattr(r, 'methods')}
    return routes[('/api/webhooks/zabbix', ('POST',))], routes[('/api/tier0', ('GET',))]


class PingParserTests(unittest.TestCase):
    """OC-AUDIT-006 : sous Windows, « hôte inaccessible » d'une passerelle sort avec le code 0."""
    REPLIES = ('Réponse de 10.0.0.9 : octets=32 temps<1ms TTL=64',
               'Reply from 10.0.0.9: bytes=32 time=1ms TTL=128',
               '64 bytes from 10.0.0.9: icmp_seq=1 ttl=63 time=0.4 ms')
    FAILURES = ('Réponse de 10.0.0.1 : Impossible de joindre l’hôte de destination.',
                'Reply from 10.0.0.1: Destination host unreachable.',
                'Délai d’attente de la demande dépassé.', 'Request timed out.', '')

    def run_ping(self, returncode, stdout):
        import subprocess
        import network_audit
        done = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr='')
        with patch('network_audit.shutil.which', return_value='ping'), \
                patch('network_audit.subprocess.run', return_value=done) as run:
            result = network_audit.ping('10.0.0.9')
        run.assert_called_once()
        return result

    def test_only_a_ttl_line_with_code_zero_is_a_reply(self):
        for text in self.REPLIES:
            self.assertTrue(self.run_ping(0, text), text)
        for text in self.FAILURES:
            self.assertFalse(self.run_ping(0, text), text)
        self.assertFalse(self.run_ping(1, self.REPLIES[0]))

    def test_discovery_uses_the_same_rule(self):
        import subprocess
        import network_discovery as nd
        done = subprocess.CompletedProcess([], 0, stdout=self.FAILURES[1], stderr='')
        with patch('network_discovery.ping_executable', return_value='ping'), \
                patch('network_discovery.subprocess.run', return_value=done):
            self.assertEqual(nd.ping_ttl('10.0.0.9'), (False, None))

    def test_unreachable_target_with_old_tcp_success_is_not_up(self):
        # Ping « faux succès » neutralisé : sans écho ni TCP, l'hôte n'est plus déclaré up.
        state = {}
        for _ in range(tier0.DOWN_AFTER):
            state = tier0.evaluate(state, self.run_ping(0, self.FAILURES[1]), False, '2026-10-21T10:00:00+00:00')
        self.assertEqual(state['status'], 'down')


class EvaluateTests(unittest.TestCase):
    def test_single_loss_is_degraded_two_total_losses_is_down(self):
        s = tier0.evaluate({}, True, True, 't0')
        self.assertEqual(s['status'], 'up')
        s = tier0.evaluate(s, False, False, 't1')
        self.assertEqual(s['status'], 'degraded')  # une seule perte : pas de faux « hors service »
        s = tier0.evaluate(s, False, False, 't2')
        self.assertEqual((s['status'], s['down_since']), ('down', 't1'))  # depuis la PREMIÈRE perte
        s = tier0.evaluate(s, False, False, 't3')
        self.assertEqual(s['down_since'], 't1')
        s = tier0.evaluate(s, True, True, 't4')
        self.assertEqual((s['status'], s['down_since'], s['changed_at']), ('up', None, 't4'))

    def test_one_probe_failing_is_degraded_not_down(self):
        s = {}
        for t in ('a', 'b', 'c'):
            s = tier0.evaluate(s, False, True, t)  # ICMP filtré mais SSH répond
        self.assertEqual(s['status'], 'degraded')

    def test_unknown_probe_is_never_up(self):
        self.assertNotEqual(tier0.evaluate({}, None, None, 'a')['status'], 'up')


class WebhookTests(unittest.TestCase):
    def run_hook(self, hook, body, token, content_length=None):
        return asyncio.run(hook(FakeRequest(body, token, content_length)))

    def test_closed_without_server_token(self):
        hook, _ = install(make_context(self))
        with patch.dict(os.environ, {tier0.TOKEN_ENV: ''}):
            with self.assertRaises(HTTPException) as e:
                self.run_hook(hook, {'eventid': '1'}, 'x')
        self.assertEqual(e.exception.status_code, 503)

    def test_wrong_token_refused(self):
        hook, _ = install(make_context(self))
        with patch.dict(os.environ, {tier0.TOKEN_ENV: JETON}):
            with self.assertRaises(HTTPException) as e:
                self.run_hook(hook, {'eventid': '1'}, 'mauvais')
        self.assertEqual(e.exception.status_code, 401)

    def test_problem_then_resolved_and_collect_triggered(self):
        ctx = make_context(self)
        hook, view = install(ctx)
        with patch.dict(os.environ, {tier0.TOKEN_ENV: JETON}), \
                patch.object(tier0, '_start') as thread:
            self.run_hook(hook, {'eventid': '42', 'status': 'PROBLEM', 'host': 'prdlabjob06.host.example.test',
                                 'trigger': 'Batch NUIT en échec', 'severity': 'High'}, JETON)
            self.assertTrue(thread.called)  # collecte Zabbix immédiate demandée
            self.assertEqual([e['trigger'] for e in ctx.tier0_snapshot()['push_problems']], ['Batch NUIT en échec'])
            h = view()['hosts'][0]
            self.assertEqual(h['push'][0]['eventid'], '42')
            self.run_hook(hook, {'eventid': '42', 'status': 'RESOLVED'}, JETON)
        self.assertEqual(ctx.tier0_snapshot()['push_problems'], [])
        self.assertEqual(ctx.tier0_snapshot()['webhook']['count'], 2)

    def test_oversized_and_invalid_bodies(self):
        hook, _ = install(make_context(self))
        with patch.dict(os.environ, {tier0.TOKEN_ENV: JETON}):
            with self.assertRaises(HTTPException) as e:
                self.run_hook(hook, b'x' * (tier0.WEBHOOK_MAX_BYTES + 1), JETON)
            self.assertEqual(e.exception.status_code, 413)
            # Taille annoncée trop grande : refus avant toute lecture du corps.
            with self.assertRaises(HTTPException) as e:
                self.run_hook(hook, b'{}', JETON, content_length=tier0.WEBHOOK_MAX_BYTES + 1)
            self.assertEqual(e.exception.status_code, 413)
            with self.assertRaises(HTTPException) as e:
                self.run_hook(hook, b'[1,2]', JETON)
            self.assertEqual(e.exception.status_code, 422)

    def test_jeton_serveur_trop_court_ferme_le_webhook(self):
        hook, _ = install(make_context(self))
        court = 'x' * (tier0.MIN_TOKEN_LENGTH - 1)
        with patch.dict(os.environ, {tier0.TOKEN_ENV: court}):
            with self.assertRaises(HTTPException) as e:
                self.run_hook(hook, {'eventid': '1'}, court)
        self.assertEqual(e.exception.status_code, 503)


class ViewTests(unittest.TestCase):
    def test_only_critical_hosts_with_zabbix_batch_and_dated_audit(self):
        problems = [{'description': 'Free disk space is less than 20% on volume /', 'severity': 'warning',
                     'severity_label': 'Avertissement', 'hosts': ['prdlabjob06.host.example.test']},
                    {'description': 'Autre', 'severity': 'critical', 'hosts': ['web']}]
        _, view = install(make_context(self, problems))
        data = view()
        self.assertEqual([h['key'] for h in data['hosts']], ['job06'])
        h = data['hosts'][0]
        self.assertEqual(len(h['zabbix']['problems']), 1)
        self.assertEqual((h['batch']['declared'], h['batch']['failed'], h['batch']['results_measured']), (2, 1, False))
        self.assertEqual(h['audit']['collected_at'], '2026-09-20T01:24:53+00:00')
        self.assertEqual(data['sources'][0]['provider'], 'Zabbix')

    def test_probe_updates_state_and_revision(self):
        ctx = make_context(self)
        install(ctx)
        # La référence répond : c'est bien le serveur qui est tombé, pas le chemin de mesure.
        with patch('network_audit.ping', side_effect=lambda ip, t: ip == tier0.REFERENCE_DEFAULT), \
                patch('ssh.tcp_reachable', return_value=(False, None)), \
                patch.object(tier0, '_start') as thread:
            for n in range(2):
                ctx.tier0_tick(now=100 + n * 10)
                target, args, _ = next(c.args for c in reversed(thread.call_args_list) if c.args[2] == 'tier0-probe')
                target(*args)
        snap = ctx.tier0_snapshot()
        self.assertEqual([(s['key'], s['status']) for s in snap['hosts']], [('job06', 'down')])
        self.assertGreaterEqual(snap['revision'], 2)

    def test_tcp_only_when_icmp_fails_or_for_confirmation(self):
        # Chaque connexion TCP laisse une ligne dans les journaux sshd : on ne
        # la fait que si elle apporte une information.
        ctx = make_context(self)
        install(ctx)

        def sonder(ping_ok, n):
            with patch('network_audit.ping', side_effect=lambda ip, t: True if ip == tier0.REFERENCE_DEFAULT else ping_ok), \
                    patch('ssh.tcp_reachable', return_value=(True, 30)) as tcp, \
                    patch.object(tier0, '_start') as thread:
                ctx.tier0_tick(now=1000 + n * 10)
                target, args, _ = next(c.args for c in reversed(thread.call_args_list) if c.args[2] == 'tier0-probe')
                target(*args)
            return tcp.call_count

        self.assertEqual(sonder(True, 0), 1)   # première sonde : TCP de référence
        self.assertEqual(sonder(True, 1), 0)   # ICMP répond, TCP récent : pas de connexion
        self.assertEqual(sonder(False, 2), 1)  # ICMP muet : TCP pour trancher
        self.assertEqual(ctx.tier0_snapshot()['hosts'][0]['status'], 'degraded')

    def test_failed_tcp_is_retested_not_cached(self):
        # Constaté au redémarrage : un échec TCP ponctuel, réutilisé 5 min,
        # affichait les 3 serveurs critiques « dégradés » à tort.
        ctx = make_context(self)
        install(ctx)
        reponses = iter([(False, None), (True, 40)])

        def sonder(n):
            with patch('network_audit.ping', return_value=True), \
                    patch('ssh.tcp_reachable', side_effect=lambda *a: next(reponses)) as tcp, \
                    patch.object(tier0, '_start') as thread:
                ctx.tier0_tick(now=2000 + n * 10)
                target, args, _ = next(c.args for c in reversed(thread.call_args_list) if c.args[2] == 'tier0-probe')
                target(*args)
            return tcp.call_count

        self.assertEqual(sonder(0), 1)
        self.assertEqual(ctx.tier0_snapshot()['hosts'][0]['status'], 'degraded')
        self.assertEqual(sonder(1), 1)  # échec précédent : retesté immédiatement
        self.assertEqual(ctx.tier0_snapshot()['hosts'][0]['status'], 'up')


class ObserverTests(unittest.TestCase):
    """Constaté le 26/09 : les 3 serveurs critiques « tombaient » ensemble chaque
    minute, quand la collecte réseau des 87 serveurs saturait le poste de mesure."""

    def test_disturbed_path_counts_nothing_and_says_so(self):
        s = tier0.evaluate({}, True, True, 't0')
        for t in ('t1', 't2', 't3'):
            s = tier0.evaluate(s, False, False, t, observateur_ok=False)
        self.assertEqual((s['status'], s['perturbed'], s.get('failures', 0)), ('unknown', True, 0))
        s = tier0.evaluate(s, True, True, 't4')
        self.assertEqual((s['status'], s['perturbed']), ('up', False))

    def test_real_outage_still_detected_when_reference_answers(self):
        s = {}
        for t in ('t1', 't2'):
            s = tier0.evaluate(s, False, False, t, observateur_ok=True)
        self.assertEqual(s['status'], 'down')

    def test_established_outage_not_erased_by_disturbance(self):
        s = {}
        for t in ('t1', 't2'):
            s = tier0.evaluate(s, False, False, t)
        s = tier0.evaluate(s, False, False, 't3', observateur_ok=False)
        self.assertEqual((s['status'], s['down_since']), ('down', 't1'))

    def test_probe_checks_reference_only_when_needed_and_alerts(self):
        import alert_center
        from types import SimpleNamespace
        ctx = make_context(self)
        install(ctx)
        vus = []

        def ping(ip, t):
            vus.append(ip)
            return False
        with patch('network_audit.ping', side_effect=ping), patch('ssh.tcp_reachable', return_value=(False, None)),                 patch.object(tier0, '_start') as thread:
            ctx.tier0_tick(now=0)
            target, args, _ = next(c.args for c in thread.call_args_list if c.args[2] == 'tier0-probe')
            target(*args)
        self.assertIn(tier0.REFERENCE_DEFAULT, vus)
        snap = ctx.tier0_snapshot()
        self.assertEqual((snap['observer']['ok'], snap['hosts'][0]['status']), (False, 'unknown'))
        vue = SimpleNamespace(rows=lambda: [], api_connections=lambda: [], tier0_snapshot=ctx.tier0_snapshot)
        ids = [a['id'] for a in alert_center.build(vue)['alerts']]
        self.assertIn('Sonde directe:observer:warning', ids)
        self.assertFalse(any(i.startswith('Sonde directe:down') for i in ids))
        vus.clear()
        with patch('network_audit.ping', side_effect=ping), patch.object(tier0, '_start'):
            pass
        with patch('network_audit.ping', side_effect=lambda ip, t: vus.append(ip) or True),                 patch('ssh.tcp_reachable', return_value=(True, 5)), patch.object(tier0, '_start') as thread:
            ctx.tier0_tick(now=10)
            target, args, _ = next(c.args for c in thread.call_args_list if c.args[2] == 'tier0-probe')
            target(*args)
        self.assertNotIn(tier0.REFERENCE_DEFAULT, vus)  # tout répond : pas de sonde de référence


if __name__ == '__main__':
    unittest.main()
