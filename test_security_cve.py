"""Sécurité & CVE : versions, relevé SSH, détection sans faux positif, workflow, GLPI, veille.

Aucun appel réseau : SSH, Wazuh et sources publiques sont simulés."""
import contextlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI, HTTPException
from starlette.datastructures import Headers

import access_policy
import itsm
import security_alerts
import security_cve as sc
import security_feeds as feeds
import security_remediation
import ssh
from routers import all_routes
from security_versions import debian_compare, is_older, rpm_compare

OUTPUT = """##OS
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
ID=debian
VERSION_ID="12"
VERSION_CODENAME=bookworm
##KERNEL
6.1.0-18-amd64
REBOOT_REQUIRED
##PKG
dpkg|openssl|3.0.11-1~deb12u2|openssl|3.0.11-1~deb12u2|amd64
dpkg|libssl3|3.0.11-1~deb12u2|openssl|3.0.11-1~deb12u2|amd64
dpkg|apache2|2.4.62-1~deb12u2|apache2|2.4.62-1~deb12u2|amd64
dpkg|sudo|1.9.13p3-1+deb12u1|sudo|1.9.13p3-1+deb12u1|amd64
dpkg|bad;rm|1|x|1|amd64
##UPGRADABLE
libssl3/stable-security 3.0.15-1~deb12u1 amd64 [upgradable from: 3.0.11-1~deb12u2]
##CHANGELOG
sudo|CVE-2026-2222
##BIN
php|PHP 8.2.7 (cli)
openssl|OpenSSL 3.0.11 19 Sep 2023
##DOCKER
RC|0
app|php:8.1-apache|Up 3 days
##IMAGES
php|8.1-apache|abc123|2025-01-01
debian|latest|def456|2025-01-01
##END
"""
DSA = """[21 Oct 2026] DSA-5800-1 openssl - security update
\t{CVE-2026-1111 CVE-2026-1112}
\t[bookworm] - openssl 3.0.15-1~deb12u1
\t[bullseye] - openssl 1.1.1w-0+deb11u2
[20 Oct 2026] DSA-5799-1 apache2 - security update
\t{CVE-2026-3333}
\t[bookworm] - apache2 2.4.62-1~deb12u2
[19 Oct 2026] DSA-5798-1 sudo - security update
\t{CVE-2026-2222}
\t[bookworm] - sudo 1.9.13p3-1+deb12u2
[18 Oct 2026] DSA-5797-1 zlib - security update
\t{CVE-2026-4444}
\t[bookworm] - zlib <not-affected> (vulnerable code not present)
"""


class VersionTests(unittest.TestCase):
    def test_repeated_versions_share_the_same_comparison_without_hiding_invalid_input(self):
        import security_versions as versions
        versions._older_cached.cache_clear()
        try:
            with mock.patch.object(versions, 'compare', wraps=versions.compare) as compare:
                for _ in range(100):
                    self.assertTrue(versions.is_older('dpkg', '1.0', '2.0'))
                self.assertEqual(compare.call_count, 1)
            self.assertIsNone(versions.is_older('dpkg', '', '2.0'))
            self.assertIsNone(versions.is_older('dpkg', None, '2.0'))
        finally:
            versions._older_cached.cache_clear()

    def test_debian_ordering_matches_dpkg(self):
        for older, newer in (('1.0~rc1', '1.0'), ('1.0', '1.0-1'), ('3.0.11-1~deb12u2', '3.0.15-1~deb12u1'),
                             ('3.0.15-1~deb12u1', '3.0.15-1'), ('2.0', '1:0.9'), ('2.4.62-1~deb12u1', '2.4.62-1~deb12u2'),
                             ('1.9.13p3-1+deb12u1', '1.9.13p3-1+deb12u2'), ('1.2.3', '1.2.10')):
            self.assertEqual(debian_compare(older, newer), -1, (older, newer))
            self.assertEqual(debian_compare(newer, older), 1)
        self.assertEqual(debian_compare('1.0-1', '1.0-1'), 0)
        self.assertEqual(debian_compare('0:1.0', '1.0'), 0)

    def test_rpm_ordering(self):
        self.assertEqual(rpm_compare('1:3.0.7-24.el9', '1:3.0.7-27.el9'), -1)
        self.assertEqual(rpm_compare('2.4.57-5.el9', '2.4.57-5.el9'), 0)
        self.assertEqual(rpm_compare('1.0~beta', '1.0'), -1)
        self.assertEqual(rpm_compare('1:1.0', '2.0'), 1)

    def test_unreadable_version_is_never_guessed(self):
        self.assertIsNone(is_older('dpkg', '', '1.0'))
        self.assertIsNone(is_older('dpkg', '1.0 ; rm', '1.0'))


class InventoryTests(unittest.TestCase):
    def test_operation_is_fixed_and_read_only(self):
        command = ssh.OPERATIONS['security_packages']
        self.assertIs(command, sc.COMMAND)
        text = command.replace('2>/dev/null', '').replace('2>&1', '').replace('>/dev/null', '')
        for forbidden in ('apt-get install', 'apt-get upgrade', 'apt update', 'dnf upgrade', 'rm ', 'systemctl', '>'):
            self.assertNotIn(forbidden, text, forbidden)
        # « sudo » n'apparaît que comme NOM de paquet (changelog relu), jamais comme commande.
        self.assertNotRegex(command, r'(^|[;&|(]\s*)sudo\b')

    def test_parse(self):
        inv = sc.parse_inventory(OUTPUT)
        self.assertTrue(inv['complete'])
        self.assertEqual(inv['os']['codename'], 'bookworm')
        self.assertTrue(inv['reboot_required'])
        self.assertEqual([p['name'] for p in inv['packages']], ['openssl', 'libssl3', 'apache2', 'sudo'])  # « bad;rm » refusé
        self.assertEqual(inv['upgradable'][0]['candidate'], '3.0.15-1~deb12u1')
        self.assertEqual(inv['changelog'], {'sudo': ['CVE-2026-2222']})
        self.assertEqual(inv['docker']['containers'][0]['image'], 'php:8.1-apache')
        self.assertEqual(len(inv['docker']['images']), 2)

    def test_truncated_output_is_incomplete(self):
        self.assertFalse(sc.parse_inventory(OUTPUT.split('##BIN')[0])['complete'])

    def test_components_and_images(self):
        inv = sc.parse_inventory(OUTPUT)
        names = {c['component']: c for c in sc.components(inv)}
        self.assertEqual(names['OpenSSL']['versions'], ['3.0.11-1~deb12u2'])
        self.assertEqual(names['OpenSSL']['binary'], 'OpenSSL 3.0.11 19 Sep 2023')
        found = sc.image_findings(inv['docker']['images'], today=date(2026, 10, 21))
        self.assertEqual([f['level'] for f in found], ['warning', 'unknown'])
        self.assertEqual(sc.image_findings([{'repository': 'php', 'tag': '8.10'}], today=date(2026, 10, 21)), [])
        self.assertTrue(sc.os_support({'id': 'debian', 'version_id': '11'}, date(2026, 10, 21))['expired'])
        self.assertFalse(sc.os_support({'id': 'debian', 'version_id': '12'}, date(2026, 10, 21))['expired'])
        self.assertIsNone(sc.os_support({'id': 'gentoo', 'version_id': '1'}))


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = self.temp.name + '/test.sqlite3'
        self.hosts = [{'key': 'web01', 'name': 'web01', 'ip': '192.0.2.10', 'environment': 'Production', 'services': ['apache2'],
                       'vmid': 101, 'node': 'pve1'},
                      {'key': 'db01', 'name': 'db01', 'ip': '192.0.2.11', 'environment': 'Recette', 'services': []}]
        self.settings = {}
        self.context = SimpleNamespace(connect=self.connect, rows=lambda: self.hosts, HOSTS=self.hosts, WORKERS=2,
                                       read_setting=self.settings.get, write_setting=self.write_setting,
                                       api_connections=lambda: [], cfg=None)
        with self.connect() as db:
            sc.migrate(db)
            itsm.migrate(db)
        self.env = mock.patch.dict(os.environ, {'INFRAOPS_LOCAL_ROLE': 'admin', 'INFRAOPS_REQUIRE_PROXY': '0',
                                                'INFRAOPS_TRUSTED_PROXY_SECRET': ''})
        self.env.start()
        self.addCleanup(self.env.stop)

    def write_setting(self, name, value):
        self.settings[name] = str(value)
        return True

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()

    def store_inventory(self, key='web01', output=OUTPUT):
        inv = sc.parse_inventory(output)
        with self.connect() as db:
            db.execute('INSERT OR REPLACE INTO sec_inventory(host_key, host_ip, collected_at, complete, payload) VALUES(?,?,?,?,?)',
                       (key, '192.0.2.10', sc.iso(), int(inv['complete']), json.dumps(inv)))

    def store_fixes(self, text=DSA):
        with self.connect() as db:
            for f in feeds.parse_debian_list(text):
                db.execute('INSERT OR REPLACE INTO sec_fixes VALUES(?,?,?,?,?,?,?,?)',
                           ('DSA', f['advisory'], f['release'], f['package'], f['fixed'], json.dumps(f['cves']), f['date'], f['title']))

    def vulns(self):
        with self.connect() as db:
            return {r[0]: r for r in db.execute('SELECT cve, status, confidence, installed, fixed, sources, package FROM sec_vulns')}


class DetectionTests(Base):
    def test_only_published_fix_of_same_release_opens_a_vulnerability(self):
        self.store_inventory()
        self.store_fixes()
        totals = sc.analyze(self.context)
        found = self.vulns()
        # openssl : 3.0.11-1~deb12u2 < 3.0.15-1~deb12u1 (bookworm) ; deux CVE, une entrée chacune.
        self.assertEqual(sorted(found), ['CVE-2026-1111', 'CVE-2026-1112', 'CVE-2026-2222'])
        self.assertEqual(found['CVE-2026-1111'][2], 'confirmé')
        self.assertEqual(found['CVE-2026-1111'][6], 'openssl')
        # apache2 déjà à la version corrigée (rétroportage) : rien ; zlib <not-affected> : rien.
        self.assertNotIn('CVE-2026-3333', found)
        # CVE citée dans le changelog du paquet installé : « à vérifier », jamais « confirmé ».
        self.assertEqual(found['CVE-2026-2222'][2], 'à vérifier')
        self.assertEqual(totals['new'], 3)

    def test_package_built_for_another_release_is_to_verify(self):
        # Audit UI du 31/10 (fiche 13.2) : prdlabbak02, annoncé trixie/sid, porte des paquets +deb12.
        self.assertIn('Debian 12 (bookworm)', sc.release_mismatch('3.0.11-1~deb12u2', 'trixie', {'id': 'debian', 'version_id': '13'}))
        self.assertIsNone(sc.release_mismatch('3.0.11-1~deb12u2', 'bookworm', {'id': 'debian', 'version_id': '12'}))
        self.assertIsNone(sc.release_mismatch('2.4.62-1', 'bookworm', {'id': 'debian', 'version_id': '12'}))
        self.assertIn('testing/sid', sc.release_mismatch('2.4.62-1', 'trixie', {'id': 'debian', 'version_id': '', 'pretty': 'Debian GNU/Linux trixie/sid'}))
        self.store_inventory(output=OUTPUT.replace('VERSION_ID="12"', 'VERSION_ID="13"').replace('VERSION_CODENAME=bookworm', 'VERSION_CODENAME=trixie'))
        self.store_fixes()
        with self.connect() as db:
            # Correctifs bookworm présentés comme ceux de trixie : seule la release annoncée diffère.
            db.execute("DELETE FROM sec_fixes WHERE release != 'bookworm'")
            db.execute("UPDATE sec_fixes SET release='trixie'")
        sc.analyze(self.context)
        found = self.vulns()
        self.assertTrue(found)
        self.assertTrue(all(v[2] == 'à vérifier' for v in found.values()))

    def test_binaries_of_same_source_are_deduplicated(self):
        self.store_inventory()
        self.store_fixes()
        sc.analyze(self.context)
        with self.connect() as db:
            evidence = json.loads(db.execute("SELECT evidence FROM sec_vulns WHERE cve='CVE-2026-1111'").fetchone()[0])
            count = db.execute("SELECT count(*) FROM sec_vulns WHERE cve='CVE-2026-1111'").fetchone()[0]
        self.assertEqual(count, 1)
        self.assertEqual(evidence['binaries'], ['libssl3', 'openssl'])
        self.assertIn('Correctif disponible', evidence['repository'])

    def test_no_inventory_means_no_conclusion(self):
        self.store_fixes()
        sc.analyze(self.context)
        self.assertEqual(self.vulns(), {})

    def test_resolution_requires_every_source_to_have_measured(self):
        self.store_inventory()
        self.store_fixes()
        sc.analyze(self.context)
        # Wazuh signale aussi la CVE : sources debian + wazuh.
        with self.connect() as db:
            db.execute('INSERT INTO sec_wazuh VALUES(?,?,?,?,?,?)', ('web01', 'wz', '001', sc.iso(), 1, json.dumps(
                [{'cve': 'CVE-2026-1111', 'package': 'libssl3', 'version': '3.0.11-1~deb12u2', 'fixed': None, 'cvss': 9.8,
                  'severity': 'critical', 'reference': None, 'detected_at': None}])))
        sc.analyze(self.context)
        self.assertEqual(json.loads(self.vulns()['CVE-2026-1111'][5]), ['debian', 'wazuh'])
        # Mise à jour constatée par SSH, mais Wazuh plus mesuré (donnée ancienne) : état inchangé.
        self.store_inventory(output=OUTPUT.replace('3.0.11-1~deb12u2', '3.0.15-1~deb12u1'))
        with self.connect() as db:
            db.execute("UPDATE sec_wazuh SET at='2020-01-01T00:00:00+00:00', items='[]'")
        sc.analyze(self.context)
        self.assertEqual(self.vulns()['CVE-2026-1111'][1], 'open')
        # CVE-2026-1112, vue par Debian seule (qui a mesuré) : corrigée dès ce passage.
        self.assertEqual(self.vulns()['CVE-2026-1112'][1], 'resolved')
        # Wazuh relu et complet sans la CVE : correction constatée.
        with self.connect() as db:
            db.execute('UPDATE sec_wazuh SET at=?', (sc.iso(),))
        totals = sc.analyze(self.context)
        self.assertEqual(self.vulns()['CVE-2026-1111'][1], 'resolved')
        self.assertEqual(totals['resolved'], 1)
        # Retour arrière du paquet : la vulnérabilité réapparaît (même entrée, rouverte).
        self.store_inventory()
        totals = sc.analyze(self.context)
        self.assertEqual(self.vulns()['CVE-2026-1111'][1], 'open')
        self.assertGreaterEqual(totals['reopened'], 1)

    def test_notifications_are_targeted(self):
        self.store_inventory()
        self.store_fixes()
        with self.connect() as db:
            db.execute("INSERT INTO sec_cve(cve, kev) VALUES('CVE-2026-1111', 1)")
            db.execute("INSERT INTO sec_cve(cve, kev) VALUES('CVE-2099-0001', 1)")   # KEV hors parc : rien
        # Horloge figée deux jours après les avis du jeu DSA : la fenêtre « nouveau correctif »
        # (7 jours) ne doit pas dépendre de la date d'exécution du test.
        moment = datetime(2026, 10, 23, 12, tzinfo=timezone.utc)
        with mock.patch.object(security_alerts, 'now', return_value=moment):
            sc.analyze(self.context)
        with self.connect() as db:
            refs = [r[0] for r in db.execute('SELECT ref FROM sec_notifications')]
        # KEV sur le parc : notifiée ; KEV hors parc : rien. Les avis Debian de moins de 7 jours
        # qui corrigent une CVE applicable produisent « nouveau correctif ».
        self.assertIn('kev:CVE-2026-1111', refs)
        self.assertFalse([r for r in refs if 'CVE-2099-0001' in r])
        self.assertIn('fix:DSA-5800-1:bookworm', refs)
        self.assertNotIn('fix:DSA-5799-1:bookworm', refs)   # apache2 déjà corrigé : non applicable

    def test_wazuh_items_normalised(self):
        legacy = sc._wazuh_items([{'cve': 'CVE-2026-10001', 'name': 'curl', 'version': '7.88.1-10', 'cvss3_score': 7.5, 'severity': 'High',
                                   'condition': 'Package less than 7.88.1-10+deb12u5', 'status': 'VALID'},
                                  {'cve': 'CVE-2026-10002', 'name': 'curl', 'status': 'SOLVED'}, {'cve': 'x', 'name': 'curl'}])
        self.assertEqual([(i['cve'], i['fixed'], i['cvss']) for i in legacy], [('CVE-2026-10001', '7.88.1-10+deb12u5', 7.5)])
        indexer = sc._wazuh_items([{'_source': {'vulnerability': {'id': 'CVE-2026-10003', 'severity': 'Critical', 'score': {'base': 9.1}},
                                                'package': {'name': 'bash', 'version': '5.2.15-2'}}}])
        self.assertEqual(indexer[0]['package'], 'bash')


class RemediationTests(Base):
    def test_plan_from_verified_data(self):
        self.store_inventory()
        self.store_fixes()
        sc.analyze(self.context)
        with self.connect() as db:
            item = sc.vulns(db, self.hosts, "v.cve='CVE-2026-1111'")[0]
            inventory = sc._load_inventory(db, 'web01')
        plan = security_remediation.plan(item, self.hosts[0], inventory, {'kev': True})
        self.assertIn('sudo apt-get install --only-upgrade libssl3 openssl', plan['update'])
        self.assertTrue(any('qm snapshot 101' in line for line in plan['backup']))
        self.assertTrue(any('libssl3=3.0.11-1~deb12u2' in line for line in plan['rollback']))
        self.assertTrue(any('ge 3.0.15-1~deb12u1' in line for line in plan['verify']))
        self.assertIn('EXPLOITÉE ACTIVEMENT', plan['text'])
        self.assertIn('n’exécute aucune', plan['text'])

    def test_unsafe_values_never_reach_a_command(self):
        vuln = {'cve': 'CVE-2026-1111', 'package': 'openssl;reboot', 'installed': '1.0$(id)', 'fixed': '2.0',
                'evidence': {'manager': 'dpkg', 'binaries': ['openssl;reboot']}, 'sources': ['debian']}
        plan = security_remediation.plan(vuln, {'key': 'x'}, {}, None)
        self.assertEqual(plan['update'], [])
        self.assertNotIn('reboot', ' '.join(plan['precheck'] + plan['update'] + plan['rollback']))
        self.assertIsNone(plan['installed'])
        self.assertTrue(plan['warnings'])


class RouteTests(Base):
    def setUp(self):
        super().setUp()
        app = FastAPI()
        sc.install(app, self.context)
        self.get = {r.path: r.endpoint for r in all_routes(app) if 'GET' in r.methods}
        self.post = {r.path: r.endpoint for r in all_routes(app) if 'POST' in r.methods}
        self.request = SimpleNamespace(headers=Headers({}))
        self.store_inventory()
        self.store_fixes()
        sc.analyze(self.context)
        with self.connect() as db:
            self.vid = db.execute("SELECT id FROM sec_vulns WHERE cve='CVE-2026-1111'").fetchone()[0]

    def act(self, action, note='', owner=''):
        return self.post['/api/security/vulns/action'](sc.VulnAction(id=self.vid, action=action, note=note, owner=owner, by='operator'),
                                                        self.request)

    def test_workflow_and_history(self):
        with self.assertRaises(HTTPException) as exc:
            self.act('false_positive', note='court')
        self.assertEqual(exc.exception.status_code, 422)
        self.assertEqual(self.act('validate')['status'], 'validated')
        with self.assertRaises(HTTPException) as exc:
            self.act('validate')
        self.assertEqual(exc.exception.status_code, 409)
        self.assertEqual(self.act('assign', owner='jdoe')['owner'], 'jdoe')
        self.assertEqual(self.act('start', note='Fenêtre jeudi 22 h')['status'], 'in_progress')
        detail = self.get['/api/security/vulns/{ident}'](self.vid)
        self.assertEqual([e['action'] for e in detail['events']], ['start', 'assign', 'validate', 'detected'])
        self.assertEqual(detail['events'][0]['actor'], 'operator')
        history = self.get['/api/security/history'](days=30)
        self.assertTrue(any(e['action'] == 'validate' for e in history['events']))

    def test_views(self):
        # Un serveur retiré de l'inventaire ne compte plus comme intégré à Wazuh (audit UI du 31/10, 12.2).
        with self.connect() as db:
            for key in ('web01', 'retire'):
                db.execute('INSERT OR REPLACE INTO sec_wazuh VALUES(?,?,?,?,?,?)', (key, 'wz', '001', sc.iso(), 1, '[]'))
        summary = self.get['/api/security/summary']()
        self.assertEqual(summary['counts']['wazuh_hosts'], 1)
        self.assertEqual(summary['counts']['open'], 3)
        # Un seul serveur : autant de CVE uniques que de couples serveur/CVE (fiche 13.1).
        self.assertEqual(summary['counts']['unique_cves'], 3)
        self.assertEqual(summary['counts']['to_verify'], 1)
        host = self.get['/api/security/hosts/{key}']('web01')
        self.assertEqual(host['os']['codename'], 'bookworm')
        self.assertTrue(host['reboot_required'])
        plan = self.get['/api/security/vulns/{ident}/plan'](self.vid)
        self.assertEqual(plan['server']['vmid'], 101)
        csv_body = self.get['/api/security/report'](format='csv', status='active').body.decode('utf-8')
        self.assertIn('CVE-2026-1111', csv_body)
        self.assertTrue(csv_body.startswith('﻿Serveur;'))
        packages = self.get['/api/security/packages/{key}']('web01', q='ssl')
        self.assertEqual([p['name'] for p in packages['items']], ['openssl', 'libssl3'])
        self.assertIsNotNone(packages['items'][1]['upgradable'])

    def test_glpi_requires_validation_and_carries_plan(self):
        context = SimpleNamespace(**vars(self.context))
        context.security_vuln_snapshot = lambda ident: sc.vuln_snapshot(self.context, ident)
        app = FastAPI()
        itsm.install(app, context)
        take = {r.path: r.endpoint for r in all_routes(app)}['/api/itsm/take']
        body = itsm.Take(origin='vulnerability', origin_id=self.vid, host_key='web01', by='operator')
        with self.assertRaises(HTTPException) as exc:
            take(body, self.request)
        self.assertEqual(exc.exception.status_code, 409)
        self.act('validate')
        self.act('assign', owner='jdoe')
        case = take(body, self.request)
        self.assertEqual(case['origin'], 'vulnerability')
        self.assertEqual(case['owner'], 'jdoe')
        snapshot = case['snapshot']
        self.assertIn('CVE-2026-1111', snapshot['title'])
        self.assertIn('only-upgrade libssl3 openssl', snapshot['recommendation'])
        self.assertIn('3.0.15-1~deb12u1', snapshot['evidence'])
        self.assertEqual(snapshot['target'], 'web01')
        # Dédupliqué : une seconde demande renvoie le même dossier.
        self.assertEqual(take(body, self.request)['id'], case['id'])
        # État d'origine pour la résolution automatique GLPI.
        self.assertEqual(sc.vuln_states(self.context, [self.vid]), {self.vid: 'active'})
        with self.connect() as db:
            db.execute("UPDATE sec_vulns SET status='resolved' WHERE id=?", (self.vid,))
        context.security_vuln_states = lambda ids: sc.vuln_states(self.context, ids)
        with self.connect() as db:
            cases = [itsm.get(db, case['id'])]
        self.assertEqual(itsm.origin_states(context, cases), {case['id']: 'resolved'})

    def test_settings_and_scan_conflict(self):
        result = self.post['/api/security/settings'](sc.Settings(feeds_auto=True, scan_hours=24), self.request)
        self.assertEqual(result, {'feeds_auto': True, 'feeds_hours': 1, 'scan_hours': 24, 'wazuh_indexer': '',
                                  'mail_to': '', 'mail_level': 'critical', 'epss_threshold': 0.5})
        with self.assertRaises(HTTPException) as exc:
            self.post['/api/security/settings'](sc.Settings(wazuh_indexer='inconnu'), self.request)
        self.assertEqual(exc.exception.status_code, 422)
        with mock.patch('jobs.spawn') as spawn:
            self.post['/api/security/hosts/{key}/scan']('web01', sc.Scan(by='operator'), self.request)
            # Un relevé SSH en cours ne bloque plus la veille (constaté : 97 serveurs, veille
            # restée « jamais synchronisée ») ; un second relevé, lui, est refusé.
            state = self.post['/api/security/sync'](sc.Scan(by='operator'), self.request)
            with self.assertRaises(HTTPException) as exc:
                self.post['/api/security/scan'](sc.Scan(by='operator'), self.request)
            with self.assertRaises(HTTPException) as again:
                self.post['/api/security/sync'](sc.Scan(by='operator'), self.request)
        self.assertEqual((exc.exception.status_code, again.exception.status_code), (409, 409))
        self.assertEqual(spawn.call_count, 2)
        self.assertTrue(state['scan']['running'] and state['sync']['running'])

    def test_scheduler_retries_a_refused_sync(self):
        # Veille échue pendant qu'une synchronisation tourne déjà : pas de second lancement,
        # et l'échéance n'est consommée qu'une fois la veille réellement démarrée.
        with mock.patch('jobs.spawn') as spawn, mock.patch('time.time', return_value=10 ** 10):
            self.context.security_tick()
            self.context.security_tick()
        self.assertEqual([c.args[1][0] for c in spawn.call_args_list], ['sync'])
        app = FastAPI()
        context = SimpleNamespace(**{**vars(self.context), 'security_tick': None})
        sc.install(app, context)
        with mock.patch('jobs.spawn') as spawn, mock.patch('time.time', return_value=10 ** 10):
            routes = {r.path: r.endpoint for r in all_routes(app) if 'POST' in r.methods}
            routes['/api/security/scan'](sc.Scan(by='operator'), self.request)
            context.security_tick()
        self.assertEqual([c.args[1][0] for c in spawn.call_args_list], ['scan', 'sync'])

    def test_scan_stores_only_complete_inventory(self):
        result = ssh.RunResult(True, 0, OUTPUT.split('##BIN')[0], '', 10)
        cfg = ssh.SSHConfig(user='infraops', key_path='k')
        with mock.patch('ssh.run_operation', return_value=result) as run, mock.patch('config.candidates', return_value=[cfg]):
            outcome = sc._ssh_scan(self.context, self.hosts[0], 'operator')
        self.assertEqual(run.call_args[0][1], 'security_packages')
        self.assertEqual(outcome['status'], 'partial')


class AccessTests(unittest.TestCase):
    def test_routes_are_classified(self):
        self.assertEqual(access_policy.classify('POST', '/api/security/scan'), ('operator', 'collect_all'))
        self.assertEqual(access_policy.classify('POST', '/api/security/hosts/web01/scan'), ('operator', 'collect_one'))
        self.assertEqual(access_policy.classify('POST', '/api/security/vulns/action'), ('operator', 'mutation'))
        self.assertEqual(access_policy.classify('POST', '/api/security/settings'), ('admin', 'mutation'))
        self.assertEqual(access_policy.classify('GET', '/api/security/summary'), ('viewer', None))

    def test_models_forbid_extra_fields(self):
        with self.assertRaises(ValueError):
            sc.VulnAction(id='a' * 20, action='validate', command='rm -rf /')
        with self.assertRaises(ValueError):
            sc.VulnAction(id='zz', action='validate')


class FeedTests(unittest.TestCase):
    def test_xml_with_dtd_or_entities_is_refused(self):
        for body in (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><rss/>', b'<rss><!ENTITY x SYSTEM "file:///etc/passwd"></rss>'):
            with self.assertRaises(feeds.FeedError):
                feeds.parse_xml(body)

    def test_rss_and_atom(self):
        rss = b'''<rss><channel><item><title>Multiples vulnerabilites dans OpenSSL</title>
        <link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/</link><pubDate>Tue, 20 Oct 2026 10:00:00 +0000</pubDate>
        <description>CVE-2026-1111 et CVE-2026-1112</description><guid>CERTFR-2026-AVI-0001</guid></item></channel></rss>'''
        item = feeds.parse_feed(rss, 'certfr_avis')[0]
        self.assertEqual(item['cves'], ['CVE-2026-1111', 'CVE-2026-1112'])
        self.assertEqual(item['published'], '2026-10-20T10:00:00+00:00')
        atom = b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>PHP 8.3.14 Released</title><id>php-8.3.14</id>
        <link href="https://www.php.net/releases/8_3_14.php"/><updated>2026-10-19T00:00:00Z</updated><summary>security fixes</summary></entry></feed>'''
        self.assertEqual(feeds.parse_feed(atom, 'php')[0]['url'], 'https://www.php.net/releases/8_3_14.php')

    def test_kev_dsa_nvd(self):
        kev = feeds.parse_kev(json.dumps({'vulnerabilities': [{'cveID': 'CVE-2026-1111', 'vendorProject': 'OpenSSL', 'product': 'OpenSSL',
                                                                'dateAdded': '2026-10-20', 'dueDate': '2026-11-10', 'requiredAction': 'Patch'},
                                                               {'cveID': 'bad'}]}).encode())
        self.assertEqual(list(kev), ['CVE-2026-1111'])
        fixes = feeds.parse_debian_list(DSA)
        self.assertEqual([(f['advisory'], f['release'], f['fixed']) for f in fixes][:2],
                         [('DSA-5800-1', 'bookworm', '3.0.15-1~deb12u1'), ('DSA-5800-1', 'bullseye', '1.1.1w-0+deb11u2')])
        self.assertFalse(any(f['package'] == 'zlib' for f in fixes))
        nvd = feeds.parse_nvd(json.dumps({'vulnerabilities': [{'cve': {'id': 'CVE-2026-1111', 'published': '2026-10-01T00:00:00.000', 'metrics': {
            'cvssMetricV31': [{'type': 'Primary', 'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL', 'vectorString': 'CVSS:3.1/AV:N'}}]},
            'descriptions': [{'lang': 'en', 'value': 'Buffer overflow'}]}}]}).encode())
        self.assertEqual((nvd['cvss'], nvd['version'], nvd['description']), (9.8, '3.1', 'Buffer overflow'))
        self.assertEqual(feeds.severity_of(9.8), 'critical')

    def test_fetch_https_only_and_bounded(self):
        with self.assertRaises(feeds.FeedError):
            feeds.fetch('http://example.test/feed', 10)

        class Answer:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self, n):
                return b'x' * n
        opener = mock.Mock()
        opener.open.return_value = Answer()
        with mock.patch('urllib.request.build_opener', return_value=opener):
            with self.assertRaises(feeds.FeedError):
                feeds.fetch('https://example.test/feed', 10)

    def test_source_can_be_disabled_or_mirrored(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_SECURITY_FEED_PHP': 'off', 'INFRAOPS_SECURITY_FEED_KEV': 'https://miroir.test/kev.json'}):
            self.assertIsNone(feeds.source_url('php'))
            self.assertEqual(feeds.source_url('kev'), 'https://miroir.test/kev.json')


class SyncTests(Base):
    def test_sync_feeds_isolates_failures_and_enriches(self):
        self.store_inventory()
        bodies = {
            'kev': json.dumps({'vulnerabilities': [{'cveID': 'CVE-2026-1111', 'dateAdded': date.today().isoformat()}]}).encode(),
            'debian_dsa': DSA.encode(),
            'certfr_avis': b'<rss><channel><item><title>Avis OpenSSL CVE-2026-1111</title><link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0001/</link></item></channel></rss>',
        }
        calls = []

        def fetch(url, limit, headers=None):
            calls.append(url)
            for name, body in bodies.items():
                if url == feeds.SOURCES[name][0]:
                    return body
            if url.startswith(feeds.NVD_URL):
                return json.dumps({'vulnerabilities': [{'cve': {'id': url.rsplit('=', 1)[-1], 'metrics': {'cvssMetricV31': [{'cvssData': {'baseScore': 7.5}}]}}}]}).encode()
            raise feeds.FeedError('HTTP 503')
        # Analyse avant enrichissement : les CVE détectées sont enrichies par NVD.
        stop = mock.Mock()
        stop.is_set.return_value = False
        stop.wait.return_value = False
        report = sc.sync_feeds(self.context, stop, fetch)
        sc.analyze(self.context)
        report = sc.sync_feeds(self.context, stop, fetch)
        status = {r['source']: r['status'] for r in report}
        self.assertEqual(status['kev'], 'ok')
        # Source en erreur au premier passage : espacée au second (backoff), sans nouvel appel.
        self.assertEqual(status['php'], 'backoff')
        self.assertEqual(status['nvd'], 'ok')
        with self.connect() as db:
            kev, cvss = db.execute("SELECT kev, cvss FROM sec_cve WHERE cve='CVE-2026-1111'").fetchone()
            adv = db.execute("SELECT count(*) FROM sec_advisories WHERE source='certfr_avis'").fetchone()[0]
        self.assertEqual((kev, cvss), (1, 7.5))
        self.assertEqual(adv, 1)   # dédupliqué au second passage
        sc.analyze(self.context)
        with self.connect() as db:
            refs = sorted(r[0] for r in db.execute('SELECT ref FROM sec_notifications'))
        self.assertIn('kev:CVE-2026-1111', refs)
        self.assertTrue(any(r.startswith('adv:certfr_avis:') for r in refs))


if __name__ == '__main__':
    unittest.main()
