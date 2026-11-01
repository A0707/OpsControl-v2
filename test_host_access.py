"""Accès SSH depuis l'interface (host_access.py) : empreintes, test de connexion, modification groupée."""
from routers import all_routes  # routes des APIRouter inclus
import contextlib
import json
import os
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI, HTTPException
from pydantic import ValidationError

import host_access
import ssh
from ssh import SSHConfig

HOSTS = [{'key': 'waf04', 'name': 'WAF04', 'ip': '10.77.0.151', 'role': 'WAF', 'environment': 'PROD'},
         {'key': 'db01', 'name': 'db01', 'ip': '10.77.0.20', 'role': 'DB', 'environment': 'PROD', 'user': 'audituser', 'port': 22},
         {'key': 'off', 'name': 'off', 'ip': '10.77.0.99', 'role': 'X', 'environment': 'REC'}]


def make_key(folder, name):
    path = Path(folder) / name
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)], check=True, capture_output=True)
    return (path.with_suffix('.pub')).read_text(encoding='utf-8').split()[:2]


class Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        # Les empreintes personnelles ne doivent pas influencer un test isolé.
        personal_home = patch.object(Path, 'home', return_value=self.base)
        personal_home.start()
        self.addCleanup(personal_home.stop)
        (self.base / 'data').mkdir()
        (self.base / 'hosts.yaml').write_text(json.dumps({'ssh': {'users': ['audituser']}, 'hosts': HOSTS}), encoding='utf-8')
        env = patch.dict(os.environ, {'COCKPIT_SSH_DIR': str(self.base / 'data')})
        env.start()
        self.addCleanup(env.stop)
        db = sqlite3.connect(self.base / 'state.db', check_same_thread=False)
        db.execute('CREATE TABLE network(key TEXT, ip TEXT, payload TEXT)')
        self.addCleanup(db.close)

        @contextlib.contextmanager
        def connect():
            with db:
                yield db
        self.db = db
        self.rows = [dict(h) for h in HOSTS]
        self.context = SimpleNamespace(BASE=self.base, HOSTS=[dict(h) for h in HOSTS], rows=lambda: self.rows,
                                       cfg=SSHConfig(user='audituser', key_path='', users=('audituser',), ports=(22,)),
                                       connect=connect, lock=threading.Lock(), net_lock=threading.Lock(),
                                       job={'running': False}, net_job={'running': False})
        app = FastAPI()
        self.app = app
        host_access.install(app, self.context)
        self.routes = {(r.path, next(iter(r.methods))): r.endpoint for r in all_routes(app) if r.path.startswith('/api/')}

    def call(self, path, method, *args):
        return self.routes[path, method](*args)


class ProblemsTests(Harness):
    def test_lecture_repetee_sans_relancer_ssh_keygen(self):
        # Audit SEC-07 : lecture viewer ; le magasin inchangé ne relance aucun ssh-keygen.
        store = self.base / 'data' / 'known_hosts'
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text('', encoding='utf-8')
        with patch.object(host_access, '_keygen', return_value=subprocess.CompletedProcess([], 1, '', '')) as keygen:
            first = self.call('/api/ssh/host-keys', 'GET')
            calls = keygen.call_count
            second = self.call('/api/ssh/host-keys', 'GET')
        self.assertGreater(calls, 0)
        self.assertEqual(keygen.call_count, calls)
        self.assertEqual(first, second)

    def test_absente_changee_et_reussite_ignoree(self):
        self.rows[0]['attempts'] = [{'ok': False, 'error_kind': 'host_key', 'error': 'Clé SSH absente des magasins InfraOps.'}]
        self.rows[1]['last_attempt'] = {'attempts': [{'ok': False, 'error_kind': 'host_key',
                                                      'error': 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED'}]}
        self.rows[2]['attempts'] = [{'ok': False, 'error_kind': 'host_key', 'error': 'x'}, {'ok': True}]
        found = self.call('/api/ssh/host-keys', 'GET')['hosts']
        self.assertEqual([(h['key'], h['state']) for h in found], [('db01', 'changed'), ('waf04', 'absent')])


class FingerprintTests(Harness):
    def scan(self, line):
        def capture(ip, candidate, timeout):
            return f'{ip} {line}\n' if ip == '10.77.0.151' else ''
        with patch('register_host_key.capture_key', side_effect=capture), patch.object(ssh, 'audit'):
            return self.call('/api/ssh/host-keys/scan', 'POST', host_access.Scan(keys=['waf04', 'off']))

    def test_lecture_puis_confirmation(self):
        kind, blob = make_key(self.tmp.name, 'k1')
        scan = self.scan(f'{kind} {blob}')
        hosts = {h['key']: h for h in scan['hosts']}
        self.assertEqual(hosts['off']['status'], 'unreachable')
        self.assertEqual(hosts['waf04']['status'], 'captured')
        self.assertTrue(hosts['waf04']['fingerprints'][0]['sha256'].startswith('SHA256:'))
        store = self.base / 'data' / 'known_hosts'
        self.assertFalse(store.exists(), 'rien n’est écrit à la lecture')
        with self.assertRaises(HTTPException) as e:
            self.call('/api/ssh/host-keys/accept', 'POST', host_access.Accept(scan_id=scan['scan_id'], keys=['waf04'], confirm='oui ?'))
        self.assertEqual(e.exception.status_code, 422)
        result = self.call('/api/ssh/host-keys/accept', 'POST', host_access.Accept(scan_id=scan['scan_id'], keys=['waf04'], confirm='OUI'))
        self.assertEqual(result['written'], [{'key': 'waf04', 'ip': '10.77.0.151', 'port': 22, 'replaced': False}])
        self.assertIn(blob, store.read_text(encoding='utf-8'))
        with self.assertRaises(HTTPException) as e:   # lecture consommée : pas de réutilisation
            self.call('/api/ssh/host-keys/accept', 'POST', host_access.Accept(scan_id=scan['scan_id'], keys=['waf04'], confirm='OUI'))
        self.assertEqual(e.exception.status_code, 410)

    def test_cle_changee_remplace_l_ancienne(self):
        old_kind, old = make_key(self.tmp.name, 'old')
        store = self.base / 'data' / 'known_hosts'
        store.write_text(f'10.77.0.151 {old_kind} {old}\n', encoding='utf-8')
        kind, new = make_key(self.tmp.name, 'new')
        scan = self.scan(f'{kind} {new}')
        self.assertTrue({h['key']: h for h in scan['hosts']}['waf04']['replaces_existing'])
        # Audit SSH-03 : « OUI » ne suffit pas pour remplacer une clé déjà enregistrée.
        with self.assertRaises(HTTPException) as e:
            self.call('/api/ssh/host-keys/accept', 'POST', host_access.Accept(scan_id=scan['scan_id'], keys=['waf04'], confirm='OUI'))
        self.assertEqual(e.exception.status_code, 422)
        self.assertIn('REMPLACER', e.exception.detail)
        self.assertIn(old, store.read_text(encoding='utf-8'), 'rien n’est modifié sans la confirmation renforcée')
        result = self.call('/api/ssh/host-keys/accept', 'POST',
                           host_access.Accept(scan_id=scan['scan_id'], keys=['waf04'], confirm='REMPLACER'))
        self.assertTrue(result['written'][0]['replaced'])
        text = store.read_text(encoding='utf-8')
        self.assertIn(new, text)
        self.assertNotIn(old, text, 'l’ancienne clé est retirée, sinon OpenSSH refuserait encore')

    def test_remplacer_exige_selon_le_port_reellement_capture(self):
        # Audit SSH-03 (suite) : serveur sans port propre, joint sur 2222 via ssh.ports.
        from dataclasses import replace
        old_kind, old = make_key(self.tmp.name, 'old2222')
        store = self.base / 'data' / 'known_hosts'
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(f'[10.77.0.151]:2222 {old_kind} {old}\n', encoding='utf-8')
        kind, new = make_key(self.tmp.name, 'new2222')
        self.context.cfg = replace(self.context.cfg, ports=(22, 2222))

        def capture(ip, candidate, timeout):
            return f'[{ip}]:2222 {kind} {new}\n' if candidate.port == 2222 and ip == '10.77.0.151' else ''
        with patch('register_host_key.capture_key', side_effect=capture), patch.object(ssh, 'audit'):
            scan = self.call('/api/ssh/host-keys/scan', 'POST', host_access.Scan(keys=['waf04']))
        self.assertTrue(scan['hosts'][0]['replaces_existing'])
        with self.assertRaises(HTTPException) as e:
            self.call('/api/ssh/host-keys/accept', 'POST', host_access.Accept(scan_id=scan['scan_id'], keys=['waf04'], confirm='OUI'))
        self.assertEqual(e.exception.status_code, 422)
        result = self.call('/api/ssh/host-keys/accept', 'POST',
                           host_access.Accept(scan_id=scan['scan_id'], keys=['waf04'], confirm='REMPLACER'))
        self.assertEqual((result['written'][0]['port'], result['written'][0]['replaced']), (2222, True))
        self.assertNotIn(old, store.read_text(encoding='utf-8'), 'ancienne clé du port 2222 retirée')

    def test_remplacement_annonce_sur_port_non_standard(self):
        # Audit SSH-03 : l'écran de lecture interrogeait le magasin sur le port 22 seulement.
        old_kind, old = make_key(self.tmp.name, 'old3300')
        store = self.base / 'data' / 'known_hosts'
        store.parent.mkdir(parents=True, exist_ok=True)
        store.write_text(f'[10.77.0.151]:3300 {old_kind} {old}\n', encoding='utf-8')
        waf = next(h for h in self.context.HOSTS if h['key'] == 'waf04')
        waf['port'] = 3300
        try:
            kind, new = make_key(self.tmp.name, 'new3300')
            scan = self.scan(f'{kind} {new}')
            self.assertTrue({h['key']: h for h in scan['hosts']}['waf04']['replaces_existing'])
        finally:
            waf.pop('port')

    def test_capture_sans_authentification_et_arbre_arrete_au_delai(self):
        # Audit SSH-02/07 : aucune tentative d'authentification vers un hôte non vérifié ;
        # au délai, tout l'arbre de processus (ProxyJump compris) est arrêté.
        import register_host_key
        cfg = SSHConfig(user='audit', key_path='', users=('audit',), ports=(22,))

        class Proc:
            def __init__(self):
                self.calls = 0

            def wait(self, timeout=None):
                self.calls += 1
                if self.calls == 1:
                    raise subprocess.TimeoutExpired('ssh', timeout)
                return 0
        proc = Proc()
        with patch('shutil.which', return_value='ssh'), \
                patch.object(ssh, 'persistent_config', return_value=Path('cfg')), \
                patch('subprocess.Popen', return_value=proc) as popen, \
                patch.object(ssh, 'stop_native') as stop:
            register_host_key.capture_key('10.77.0.151', cfg, 5)
        argv = popen.call_args.args[0]
        joined = ' '.join(argv)
        for option in ('PreferredAuthentications=none', 'PubkeyAuthentication=no', 'StrictHostKeyChecking=accept-new'):
            self.assertIn(option, joined)
        self.assertNotIn('StrictHostKeyChecking=yes', argv)
        stop.assert_called_once_with(proc)

    def test_options_ssh_sans_relais_d_agent_ni_x11(self):
        cfg = SSHConfig(user='audit', key_path='', users=('audit',), ports=(22,))
        with patch('shutil.which', return_value='ssh'), patch.object(ssh, 'persistent_config', return_value=Path('cfg')):
            argv = ssh.native_args('10.77.0.151', cfg)
        for option in ('-a', '-x', 'ForwardAgent=no', 'ForwardX11=no', 'StrictHostKeyChecking=yes'):
            self.assertIn(option, argv)

    def test_cle_envoyee_par_le_navigateur_impossible(self):
        with self.assertRaises(ValidationError):
            host_access.Accept(scan_id='0' * 32, keys=['waf04'], confirm='OUI', lines=['10.77.0.151 ssh-ed25519 AAAA'])


class ConnectionTestTests(Harness):
    def test_parametres_saisis_sans_enregistrement(self):
        original = (self.base / 'hosts.yaml').read_bytes()
        inventory = json.dumps(self.context.HOSTS)
        # IPv4 privée hors inventaire, port SSH déjà utilisé par un serveur du parc (3300 ci-dessous).
        self.context.HOSTS.append({'key': 'bastion', 'name': 'bastion', 'ip': '10.9.9.9', 'port': 3300})
        request = host_access.TestParams(ip='10.20.30.40', user='audit_demo', port=3300)
        result = ssh.RunResult(True, 0, 'up 3 days', '', 5)
        with patch.object(ssh, 'run_operation', return_value=result) as run, \
                patch.object(host_access, 'known_entry', return_value=False) as known:
            answer = self.call('/api/hosts/test-params', 'POST', request)
        self.context.HOSTS.pop()
        self.assertTrue(answer['ok'])
        self.assertFalse(answer['saved'])
        self.assertEqual(run.call_count, 1)
        ip, operation, candidate, _ = run.call_args.args
        self.assertEqual((ip, operation, candidate.user, candidate.port),
                         ('10.20.30.40', 'uptime', 'audit_demo', 3300))
        self.assertEqual(candidate.target, '')
        self.assertTrue(candidate.strict_host_key)
        self.assertTrue(all(c.args[2] == 3300 for c in known.call_args_list))
        self.assertEqual((self.base / 'hosts.yaml').read_bytes(), original)
        self.assertEqual(json.dumps(self.context.HOSTS), inventory)
        self.assertEqual(self.db.execute('SELECT count(*) FROM network').fetchone()[0], 0)

    def test_parametres_vides_utilisent_le_compte_global(self):
        with patch.object(ssh, 'run_operation', return_value=ssh.RunResult(False,255,'','Denied',1,'auth')) as run:
            answer = self.call('/api/hosts/test-params', 'POST',
                               host_access.TestParams(ip='10.77.0.151', user='', port=22))
        self.assertEqual(run.call_args.args[2].user, self.context.cfg.user)
        self.assertEqual(answer['cause'], 'auth')
        self.assertEqual(run.call_count, 1)

    def test_cible_hors_parc_refusee_avant_ssh(self):
        # Audit SEC-03 / GIT-01 : pas d'oracle de balayage IP/port pour un opérateur.
        refused = [('8.8.8.8', 22), ('127.0.0.1', 22), ('0.0.0.0', 22), ('169.254.1.1', 22),
                   ('198.18.0.1', 22), ('100.64.0.1', 22), ('2001:db8::1', 22), ('::1', 22),
                   ('10.20.30.40', 443), ('10.77.0.151', 3389)]
        with patch.object(ssh, 'run_operation') as run:
            for ip, port in refused:
                with self.subTest(ip=ip, port=port), self.assertRaises(HTTPException) as raised:
                    self.call('/api/hosts/test-params', 'POST', host_access.TestParams(ip=ip, user='', port=port))
                self.assertEqual(raised.exception.status_code, 422)
        run.assert_not_called()

    def test_ip_de_l_inventaire_acceptee_meme_hors_rfc1918(self):
        self.context.HOSTS.append({'key': 'ext', 'name': 'ext', 'ip': '192.0.2.10'})
        try:
            with patch.object(ssh, 'run_operation', return_value=ssh.RunResult(True, 0, 'up', '', 1)) as run:
                self.call('/api/hosts/test-params', 'POST', host_access.TestParams(ip='192.0.2.10', user='', port=22))
            self.assertEqual(run.call_count, 1)
        finally:
            self.context.HOSTS.pop()

    def test_viewer_refuse_sur_l_application_reelle(self):
        # Audit GIT-02 : refus HTTP du rôle viewer avec la vraie politique d'accès.
        import access_policy
        from test_access_policy import call, proxy, SECRET
        guarded = FastAPI()
        access_policy.install(guarded)
        host_access.install(guarded, self.context)
        with patch.dict(os.environ, {'INFRAOPS_TRUSTED_PROXY_SECRET': SECRET, 'INFRAOPS_OPERATORS': '',
                                     'INFRAOPS_ADMINS': '', 'INFRAOPS_DEFAULT_ROLE': 'viewer'}), \
                patch.object(ssh, 'run_operation') as run:
            status, _, _ = call(guarded, 'POST', '/api/hosts/test-params',
                                {'X-Cockpit-Request': '1', 'Content-Type': 'application/json', **proxy('lecteur@ex.test')},
                                body=json.dumps({'ip': '10.77.0.151', 'port': 22}).encode())
        self.assertEqual(status, 403)
        run.assert_not_called()

    def test_parametres_invalides_refuses_avant_ssh(self):
        bad = [{'ip':'pas-une-ip'}, {'ip':'192.0.2.1;id'}, {'user':'-oProxyCommand=id'},
               {'user':'a'*65}, {'port':0}, {'port':65536}, {'command':'id'},
               {'key_path':'/secret'}, {'ip':'a'*46}]
        with patch.object(ssh, 'run_operation') as run:
            for values in bad:
                with self.subTest(values=values), self.assertRaises(ValidationError):
                    host_access.TestParams(**({'ip':'192.0.2.1','user':'demo','port':22} | values))
        run.assert_not_called()

    def test_route_parametres_classee_operateur_collect_one(self):
        import access_policy
        self.assertEqual(access_policy.classify('POST','/api/hosts/test-params'), ('operator','collect_one'))

    def test_http_invalide_ne_lance_pas_ssh(self):
        from test_access_policy import call
        with patch.object(ssh, 'run_operation') as run:
            for body in ({'ip':'invalid','port':22}, {'ip':'192.0.2.1','user':'-oX','port':22},
                         {'ip':'192.0.2.1','port':65536}, {'ip':'192.0.2.1','port':22,'command':'id'}):
                status, _, _ = call(self.app, 'POST', '/api/hosts/test-params', body=json.dumps(body).encode())
                self.assertEqual(status, 422)
        run.assert_not_called()

    def test_diagnostic_par_cause(self):
        self.db.execute('INSERT INTO network VALUES(?,?,?)', ('waf04', '10.77.0.151', json.dumps(
            {'collected_at': '2026-10-06T01:25:50+00:00', 'ping': True, 'ports': [{'port': 22, 'ok': True}]})))
        failure = ssh.RunResult(False, 255, '', 'No ED25519 host key is known for 10.77.0.151 and you have requested strict checking.', 1900, 'host_key')
        with patch.object(ssh, 'run_operation', return_value=failure) as run:
            result = self.call('/api/hosts/{key}/test', 'POST', 'waf04')
        self.assertFalse(result['ok'])
        self.assertEqual(result['cause'], 'host_key')
        self.assertTrue(result['steps'][0]['ok'], 'réseau joignable')
        self.assertFalse(result['steps'][1]['ok'], 'empreinte inconnue')
        self.assertEqual(run.call_args.args[1], 'uptime', 'opération de lecture de la liste fermée')

    def test_succes(self):
        with patch.object(ssh, 'run_operation', return_value=ssh.RunResult(True, 0, ' 01:00 up 3 days', '', 400)):
            result = self.call('/api/hosts/{key}/test', 'POST', 'db01')
        self.assertTrue(result['ok'])
        self.assertIn('audituser@10.77.0.20:22', result['summary'])


class BulkTests(Harness):
    def saved(self):
        return {h['key']: h for h in json.loads((self.base / 'hosts.yaml').read_text(encoding='utf-8'))['hosts']}

    def test_modification_groupee(self):
        r = self.call('/api/manage/hosts/bulk', 'POST', host_access.Bulk(keys=['waf04', 'off'], role='WAF ModSecurity', environment='PREPROD'))
        self.assertEqual(r['changes'], {'role': 'WAF ModSecurity', 'environment': 'PREPROD'})
        saved = self.saved()
        self.assertEqual((saved['waf04']['role'], saved['off']['environment']), ('WAF ModSecurity', 'PREPROD'))
        self.assertEqual(saved['db01']['role'], 'DB', 'serveur non sélectionné inchangé')
        self.assertEqual(self.context.HOSTS[0]['role'], 'WAF ModSecurity', 'inventaire en mémoire à jour')

    def test_acces_et_role_acceptes_pendant_une_collecte(self):
        # Le lot en cours garde sa copie figée (jobs.launch) : plus de refus 409 (audit A1).
        self.context.job['running'] = True
        self.call('/api/manage/hosts/bulk', 'POST', host_access.Bulk(keys=['waf04'], port=2222))
        self.assertEqual(self.saved()['waf04']['port'], 2222)
        self.call('/api/manage/hosts/bulk', 'POST', host_access.Bulk(keys=['waf04'], criticality='critical'))
        self.assertEqual(self.saved()['waf04']['criticality'], 'critical')

    def test_validations(self):
        for bad in ({'port': 0}, {'user': '-oProxyCommand=x'}, {'role': ''}):
            with self.assertRaises(ValidationError):
                host_access.Bulk(keys=['waf04'], **bad)
        with self.assertRaises(HTTPException) as e:
            self.call('/api/manage/hosts/bulk', 'POST', host_access.Bulk(keys=['inconnu'], role='X'))
        self.assertEqual(e.exception.status_code, 404)
        with self.assertRaises(HTTPException):
            self.call('/api/manage/hosts/bulk', 'POST', host_access.Bulk(keys=['waf04']))


if __name__ == '__main__':
    unittest.main()


class SshHygieneTests(unittest.TestCase):
    """Audit SSH-06/08/09."""

    def test_environnement_sans_secrets(self):
        with patch.dict(os.environ, {'INFRAOPS_ZABBIX_AUTH': 'x', 'INFRAOPS_TRUSTED_PROXY_SECRET': 'y',
                                     'SSH_AUTH_SOCK': '/tmp/agent', 'INFRAOPS_WEBHOOK_TOKEN': 'z'}):
            env = ssh.ssh_environment()
        self.assertNotIn('INFRAOPS_ZABBIX_AUTH', env)
        self.assertNotIn('INFRAOPS_TRUSTED_PROXY_SECRET', env)
        self.assertNotIn('INFRAOPS_WEBHOOK_TOKEN', env)
        self.assertEqual(env['SSH_AUTH_SOCK'], '/tmp/agent')
        self.assertIn('PATH', {k.upper() for k in env})

    def test_plafond_global_de_sessions(self):
        active = peak = 0
        gate = threading.Lock()

        def fake(*args):
            nonlocal active, peak
            with gate:
                active += 1
                peak = max(peak, active)
            import time
            time.sleep(0.05)
            with gate:
                active -= 1
            return ssh.RunResult(True, 0, '', '', 1)
        with patch.object(ssh, 'SESSIONS', threading.BoundedSemaphore(2)), patch.object(ssh, '_run_operation', fake):
            workers = [threading.Thread(target=ssh.run_operation, args=('10.0.0.1', 'uptime', None)) for _ in range(6)]
            for w in workers:
                w.start()
            for w in workers:
                w.join(5)
        self.assertEqual(peak, 2)

    def test_meme_magasin_d_empreintes_partout(self):
        import network_audit
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {'COCKPIT_SSH_DIR': folder}):
            self.assertEqual(network_audit.known_hosts_files()[0], Path(folder) / 'known_hosts')
            self.assertEqual(host_access.known_hosts_path('ignoré'), Path(folder) / 'known_hosts')
