"""Veille sécurité en ligne : réponses RÉELLES des API officielles (test_fixtures/security).

Scénario principal, tiré de l'actualité enregistrée le 21/10/2026 : PHP publie deux
vulnérabilités critiques (CVE-2026-109618, CVE-2026-109619 ; avis GHSA de php/php-src,
NVD 9.8, relayées par WordPress et Fortinet PSIRT). Plusieurs VPS WordPress sont concernés
différemment selon la version réellement installée. Aucun appel réseau : les réponses
enregistrées sont servies par un faux `fetch`. Les inventaires des serveurs sont des
sorties SSH simulées (paquets et conteneurs fictifs), jamais des données CVE inventées.
"""
import contextlib
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi import FastAPI, HTTPException
from starlette.datastructures import Headers

import itsm
import security_alerts
import security_cve as sc
import security_feeds as feeds
import security_watch
from routers import all_routes

FIXTURES = Path(__file__).with_name('test_fixtures') / 'security'
NOW = datetime(2026, 10, 22, 8, 0, tzinfo=timezone.utc)
PHP_CVES = ('CVE-2026-109618', 'CVE-2026-109619')
EMPTY_NVD = json.dumps({'resultsPerPage': 0, 'startIndex': 0, 'totalResults': 0, 'vulnerabilities': []}).encode()


def ssh_output(os_lines, packages=(), containers=(), wordpress=(), swarm=None, services=()):
    """Sortie de l'opération security_packages pour un serveur fictif."""
    lines = ['##OS', *os_lines, '##KERNEL', '6.1.0-26-amd64', '##PKG']
    lines += [f'dpkg|{name}|{version}|{source}|{version}|amd64' for name, source, version in packages]
    lines += ['##UPGRADABLE', '##CHANGELOG', '##BIN', '##DOCKER']
    if containers or swarm:
        lines += ['RC|0'] + [f'{name}|{image}|Up 2 days' for name, image in containers] + ['##IMAGES']
        lines += ['##SWARM', swarm or '', '##SERVICES'] + [f'{n}|{i}|3/3' for n, i in services]
    else:
        lines += ['ABSENT']
    lines += ['##WP'] + [f"{path}/wp-includes/version.php|wp_version = '{version}'" for path, version in wordpress] + ['##END']
    return '\n'.join(lines) + '\n'


BOOKWORM = ['ID=debian', 'VERSION_ID="12"', 'VERSION_CODENAME=bookworm', 'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"']
TRIXIE = ['ID=debian', 'VERSION_ID="13"', 'VERSION_CODENAME=trixie', 'PRETTY_NAME="Debian GNU/Linux 13 (trixie)"']
BASE_PKG = [('openssl', 'openssl', '3.0.17-1~deb12u2'), ('bash', 'bash', '5.2.15-2+b7')]
HOSTS = {
    # VPS WordPress en conteneurs, PHP officiel 8.3.30 : confirmé par la version exacte de l'image.
    'wp-vps-01': ssh_output(BOOKWORM, BASE_PKG, [('wp1', 'wordpress:6.8.3-php8.3-apache'), ('php1', 'php:8.3.30-apache')]),
    # WordPress sur PHP 7.4 (branche sans correctif) : toute la branche est affectée.
    'wp-vps-02': ssh_output(BOOKWORM, BASE_PKG, [('wp2', 'wordpress:php7.4-apache')]),
    # PHP de Debian 12 (8.2.31), sans avis Debian publié : potentielle (rétroportage possible).
    # WordPress 7.1.1 installé hors conteneur : CVE-2026-87902 (avis WordPress) confirmée.
    'wp-vps-03': ssh_output(BOOKWORM, BASE_PKG + [('php8.2-fpm', 'php8.2', '8.2.31-1~deb12u1'),
                                                  ('libapache2-mod-php8.2', 'php8.2', '8.2.31-1~deb12u1')],
                            wordpress=[('/var/www/site', '7.1.1')]),
    # Debian 13 : DSA-6574-1 publiée (8.4.27-1~deb13u1), version installée antérieure : confirmée.
    'wp-vps-04': ssh_output(TRIXIE, [('php8.4-fpm', 'php8.4', '8.4.26-1~deb13u1')]),
    # PHP 8.3.36 (corrigé) : non applicable. Nœud Swarm manager avec un service WordPress.
    'wp-vps-05': ssh_output(BOOKWORM, BASE_PKG, [('php5', 'php:8.3.36-fpm')], swarm='active|true|28.3.3',
                            services=[('blog_wordpress', 'wordpress:6.8.3-php8.3-fpm')]),
    # PHP 8.2.10 : dans la plage de CVE-2024-4577, mais la configuration NVD exige Windows.
    'legacy-php': ssh_output(BOOKWORM, BASE_PKG, [('legacy', 'php:8.2.10-fpm')]),
}


def fixture(name):
    return (FIXTURES / name).read_bytes()


class Recorded:
    """Faux fetch : sert les réponses enregistrées, simule les erreurs réseau et le 304."""

    def __init__(self, nvd_available=True):
        self.calls, self.nvd_available, self.not_modified = [], nvd_available, set()
        self.routes = {feeds.SOURCES[k][0]: f for k, f in (
            ('kev', 'kev.json'), ('debian_dsa', 'debian_dsa.txt'), ('certfr_avis', 'certfr_avis.xml'),
            ('php_advisories', 'ghsa_php.json'), ('php', 'php.xml'), ('wordpress_advisories', 'ghsa_wordpress.json'),
            ('wordpress', 'wordpress.xml'), ('fortinet', 'fortinet.xml'), ('proxmox', 'proxmox.xml'))}

    def __call__(self, url, limit, headers=None):
        self.calls.append((url, dict(headers or {})))
        if url in self.not_modified:
            raise feeds.NotModified()
        if url == feeds.SOURCES['debian_dla'][0]:
            raise feeds.FeedError('Source injoignable : TimeoutError')
        if url == feeds.SOURCES['certfr_alertes'][0]:
            raise feeds.FeedError('HTTP 503 : limitation de débit de la source')
        if url in self.routes:
            body = feeds.Body(fixture(self.routes[url]))
            body.etag = '"enregistre-' + self.routes[url] + '"'
            return body
        if url.startswith(feeds.NVD_URL):
            name = 'nvd_' + url.rsplit('=', 1)[-1] + '.json'
            return fixture(name) if self.nvd_available and (FIXTURES / name).exists() else EMPTY_NVD
        if url.startswith(feeds.NVD_SEARCH) and 'cpe:2.3:a:php:php' in url:
            return fixture('nvd_php_window.json') if self.nvd_available else EMPTY_NVD
        if url.startswith(feeds.NVD_SEARCH):
            return EMPTY_NVD
        if url.startswith(feeds.EPSS_URL):
            wanted = set(url.split('=', 1)[1].split(','))
            rows = [r for f in ('epss_known.json', 'epss_new.json') for r in json.loads(fixture(f))['data'] if r['cve'] in wanted]
            return json.dumps({'status': 'OK', 'data': rows}).encode()
        if url == 'https://cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1314/json/':
            return fixture('certfr_CERTFR-2026-AVI-1314.json')
        raise feeds.FeedError('HTTP 404')


class WatchBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = self.temp.name + '/watch.sqlite3'
        self.hosts = [{'key': k, 'name': k, 'ip': f'192.0.2.{i + 10}', 'environment': 'Production', 'role': 'VPS WordPress',
                       'services': []} for i, k in enumerate(HOSTS)]
        self.hosts[0]['exposure'] = 'internet'
        self.settings = {}
        self.context = SimpleNamespace(connect=self.connect, rows=lambda: self.hosts, HOSTS=self.hosts, WORKERS=2,
                                       read_setting=self.settings.get, write_setting=self.write, api_connections=lambda: [])
        with self.connect() as db:
            sc.migrate(db)
            itsm.migrate(db)
            for key, output in HOSTS.items():
                inv = sc.parse_inventory(output)
                db.execute('INSERT INTO sec_inventory VALUES(?,?,?,?,?)', (key, '192.0.2.1', NOW.isoformat(), int(inv['complete']),
                                                                         json.dumps(inv)))
        for module in (security_alerts, security_watch):
            patch = mock.patch.object(module, 'now', return_value=NOW)
            patch.start()
            self.addCleanup(patch.stop)
        self.env = mock.patch.dict(os.environ, {'INFRAOPS_LOCAL_ROLE': 'admin', 'INFRAOPS_REQUIRE_PROXY': '0',
                                                'INFRAOPS_TRUSTED_PROXY_SECRET': '', 'NVD_API_KEY': '', 'GITHUB_TOKEN': ''})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.pacer = security_watch.Pacer(sleep=lambda seconds: None)

    def write(self, name, value):
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

    def sync(self, fetch=None, force=False):
        self.fetch = fetch or Recorded()
        report = sc.sync_feeds(self.context, None, self.fetch, force, self.pacer)
        return {r['source']: r for r in report}, sc.analyze(self.context)

    def matches(self, cve):
        with self.connect() as db:
            return {r[0]: (r[1], r[2], r[3]) for r in db.execute(
                'SELECT host_key, status, reason, fixed FROM sec_matches WHERE cve=? AND tech=? ORDER BY host_key, status', (cve, 'php'))}

    def statuses(self, cve):
        with self.connect() as db:
            out = {}
            for host, status in db.execute('SELECT host_key, status FROM sec_matches WHERE cve=? AND tech=?', (cve, 'php')):
                out.setdefault(host, set()).add(status)
            return out


class PhpCriticalScenarioTests(WatchBase):
    def test_php_critical_release_on_wordpress_vps(self):
        report, analysis = self.sync()
        self.assertEqual(report['php_advisories']['status'], 'ok')
        statuses = self.statuses('CVE-2026-109618')
        self.assertEqual(statuses['wp-vps-01'], {'confirmed', 'potential'})   # php:8.3.30 exact ; wordpress:…php8.3 (branche)
        self.assertEqual(statuses['wp-vps-02'], {'confirmed'})                # branche 7.4 entièrement affectée
        self.assertEqual(statuses['wp-vps-03'], {'potential'})                # PHP Debian : rétroportage possible
        self.assertEqual(statuses['wp-vps-04'], {'confirmed'})                # DSA-6574-1 publiée, non appliquée
        self.assertEqual(statuses['wp-vps-05'], {'not_applicable', 'potential'})  # php:8.3.36 corrigé ; Swarm php8.3
        self.assertEqual(statuses['legacy-php'], {'confirmed'})               # php:8.2.10 < 8.2.35
        with self.connect() as db:
            reasons = dict(db.execute("SELECT host_key, reason FROM sec_matches WHERE cve='CVE-2026-109618' AND host_key IN "
                                      "('wp-vps-03','wp-vps-04') AND tech='php'").fetchall())
            vulns = {r[0]: json.loads(r[1]) for r in db.execute("SELECT host_key, sources FROM sec_vulns WHERE cve='CVE-2026-109618'")}
        self.assertIn('rétroporté possible', reasons['wp-vps-03'])
        self.assertIn('DSA-6574-1', reasons['wp-vps-04'])
        # Confirmées : dans le workflow (remédiation, GLPI) ; potentielles : pas de vulnérabilité ouverte.
        self.assertEqual(sorted(vulns), ['legacy-php', 'wp-vps-01', 'wp-vps-02', 'wp-vps-04'])
        self.assertEqual(vulns['wp-vps-01'], ['upstream'])
        self.assertIn('debian', vulns['wp-vps-04'])

    def test_versions_vulnerable_and_fixed_from_vendor(self):
        self.sync()
        fixed = {host: f for host, (_, _, f) in self.matches('CVE-2026-109618').items()}
        self.assertEqual(fixed['wp-vps-04'], '8.4.27-1~deb13u1')
        with self.connect() as db:
            target = db.execute("SELECT fixed FROM sec_matches WHERE cve='CVE-2026-109618' AND instance LIKE '%php:8.3.30%'").fetchone()[0]
        self.assertEqual(target, '8.3.36')

    def test_alerts_for_critical_kev_exposed_fix_without_duplicates(self):
        _, analysis = self.sync()
        with self.connect() as db:
            refs = {r[0]: (r[1], json.loads(r[2])) for r in db.execute('SELECT ref, level, hosts FROM sec_notifications')}
        level, hosts = refs['crit:CVE-2026-109618']
        self.assertEqual(level, 'critical')
        # wp-vps-05 : php:8.3.36 corrigé, mais le service Swarm WordPress (php8.3, branche) reste potentiel.
        self.assertEqual(set(hosts), {'wp-vps-01', 'wp-vps-02', 'wp-vps-03', 'wp-vps-04', 'wp-vps-05', 'legacy-php'})
        self.assertEqual(refs['exposed:CVE-2026-109618'][1], ['wp-vps-01'])          # exposé à Internet (inventaire)
        self.assertIn('fix:DSA-6574-1:trixie', refs)                                 # nouveau correctif Debian
        self.assertIn('fix:GHSA-w8hw-w9fx-j79w', refs)                               # nouveau correctif PHP
        # EPSS : pas encore de score pour ces CVE (absence ≠ 0) ; CVE-2024-4577 (EPSS 99 %) non applicable.
        self.assertFalse([r for r in refs if r.startswith('epss:')])
        self.assertFalse([r for r in refs if 'CVE-2024-4577' in r])
        first = analysis['alerts']
        self.assertGreater(first, 0)
        # Second passage, rien de nouveau : aucune notification créée ni réactivée.
        _, again = self.sync()
        self.assertEqual(again['alerts'], 0)
        with self.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM sec_notifications').fetchone()[0], len(refs))
            self.assertEqual(db.execute("SELECT count(*) FROM sec_advisories WHERE source='php_advisories'").fetchone()[0], 5)

    def test_new_host_reactivates_notification(self):
        self.sync()
        with self.connect() as db:
            db.execute('UPDATE sec_notifications SET read_at=?, emailed_at=?', (NOW.isoformat(), NOW.isoformat()))
            inv = sc.parse_inventory(ssh_output(BOOKWORM, BASE_PKG, [('wp6', 'php:8.3.20-apache')]))
            db.execute('INSERT INTO sec_inventory VALUES(?,?,?,?,?)', ('wp-vps-06', '192.0.2.99', NOW.isoformat(), 1, json.dumps(inv)))
        self.hosts.append({'key': 'wp-vps-06', 'name': 'wp-vps-06', 'ip': '192.0.2.99', 'services': []})
        analysis = sc.analyze(self.context)
        with self.connect() as db:
            read_at, emailed, hosts = db.execute("SELECT read_at, emailed_at, hosts FROM sec_notifications "
                                                 "WHERE ref='crit:CVE-2026-109618'").fetchone()
        self.assertIsNone(read_at)
        self.assertIsNone(emailed)
        self.assertIn('wp-vps-06', json.loads(hosts))
        self.assertGreater(analysis['alerts'], 0)


class FalsePositiveTests(WatchBase):
    def test_windows_only_configuration_is_not_applicable_on_linux(self):
        self.sync()
        with self.connect() as db:
            db.execute("INSERT INTO sec_cve(cve) VALUES('CVE-2024-4577') ON CONFLICT DO NOTHING")
        # CVE-2024-4577 (KEV, EPSS 99 %) : enregistrement NVD réel, PHP 8.2.0–8.2.20 ET Windows.
        with self.connect() as db:
            security_watch.store_nvd(db, 'CVE-2024-4577', feeds.parse_nvd(fixture('nvd_CVE-2024-4577.json')))
        sc.analyze(self.context)
        with self.connect() as db:
            status, reason = db.execute("SELECT status, reason FROM sec_matches WHERE cve='CVE-2024-4577' AND host_key='legacy-php'").fetchone()
            vuln = db.execute("SELECT count(*) FROM sec_vulns WHERE cve='CVE-2024-4577'").fetchone()[0]
        self.assertEqual(status, 'not_applicable')
        self.assertIn('microsoft windows', reason)
        self.assertEqual(vuln, 0)

    def test_old_branch_outside_ranges(self):
        self.sync()
        with self.connect() as db:
            security_watch.store_nvd(db, 'CVE-2019-11043', feeds.parse_nvd(fixture('nvd_CVE-2019-11043.json')))
        sc.analyze(self.context)
        # PHP-FPM 7.1–7.3 (KEV) : PHP 7.4 et 8.x hors des plages.
        self.assertEqual({s for _, (s, _, _) in self.matches('CVE-2019-11043').items()}, {'not_applicable'})

    def test_no_published_range_means_no_conclusion(self):
        self.sync(Recorded(nvd_available=False))
        with self.connect() as db:
            orphan = db.execute("SELECT count(*) FROM sec_matches WHERE cve='CVE-2026-100200'").fetchone()[0]
        self.assertEqual(orphan, 0)   # CVE citée par le CERT-FR (Windows), aucune plage pour une techno du parc

    def test_wordpress_advisory_version(self):
        self.sync()
        with self.connect() as db:
            rows = dict(db.execute("SELECT host_key, status FROM sec_matches WHERE cve='CVE-2026-87902' AND tech='wordpress'").fetchall())
        self.assertEqual(rows['wp-vps-03'], 'confirmed')      # WordPress 7.1.1 (fichier de version) < 7.1.2
        # Avis réel rétroporté sur toutes les branches : 6.8.0–6.8.9 corrigée en 6.8.10.
        self.assertEqual(rows['wp-vps-01'], 'confirmed')


class CollectorTests(WatchBase):
    def test_network_errors_isolated_and_backoff(self):
        report, _ = self.sync()
        self.assertEqual(report['debian_dla']['status'], 'failed')
        self.assertEqual(report['certfr_alertes']['status'], 'failed')
        self.assertEqual(report['kev']['status'], 'ok')
        with self.connect() as db:
            dla = security_watch.state(db, 'debian_dla')
            limited = security_watch.state(db, 'certfr_alertes')
        self.assertEqual((dla['status'], dla['failures']), ('error', 1))
        # Limitation de débit : espacement plus long qu'une erreur réseau.
        self.assertGreater(limited['next_after'], dla['next_after'])
        report, _ = self.sync()
        self.assertEqual(report['debian_dla']['status'], 'backoff')
        self.assertFalse([u for u, _ in self.fetch.calls if u == feeds.SOURCES['debian_dla'][0]])
        report, _ = self.sync(force=True)   # action manuelle : retentée
        self.assertEqual(report['debian_dla']['status'], 'failed')

    def test_conditional_requests_and_not_modified(self):
        self.sync()
        fetch = Recorded()
        fetch.not_modified.add(feeds.SOURCES['kev'][0])
        report, _ = self.sync(fetch)
        self.assertEqual(report['kev']['status'], 'not_modified')
        sent = dict(fetch.calls)[feeds.SOURCES['kev'][0]]
        self.assertEqual(sent['If-None-Match'], '"enregistre-kev.json"')
        with self.connect() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM sec_cve WHERE kev=1').fetchone()[0], 5)   # conservé

    def test_api_keys_only_in_headers(self):
        with mock.patch.dict(os.environ, {'NVD_API_KEY': 'cle-nvd-de-test', 'GITHUB_TOKEN': 'jeton-github-de-test'}):  # pragma: allowlist secret -- valeurs factices de test
            self.sync()
        nvd = [h for u, h in self.fetch.calls if u.startswith(feeds.NVD_SEARCH)]
        github = [h for u, h in self.fetch.calls if u.startswith('https://api.github.com/')]
        self.assertTrue(nvd and all(h.get('apiKey') == 'cle-nvd-de-test' for h in nvd))
        self.assertTrue(github and all(h.get('Authorization') == 'Bearer jeton-github-de-test' for h in github))
        self.assertFalse([u for u, _ in self.fetch.calls if 'cle-nvd' in u or 'jeton-github' in u])
        with self.connect() as db:
            dump = '\n'.join(str(r) for t in ('sec_source_state', 'sec_syncs', 'sec_cve') for r in db.execute(f'SELECT * FROM {t}'))
        self.assertNotIn('cle-nvd-de-test', dump)

    def test_cve_update_is_tracked(self):
        # 13:34 UTC : l'avis PHP est publié, NVD ne connaît pas encore la CVE (réponse vide).
        self.sync(Recorded(nvd_available=False))
        self.assertEqual(self.statuses('CVE-2026-109618')['wp-vps-02'], {'confirmed'})   # plages de l'avis PHP
        # « < 8.4.27 » vaut pour la branche 8.4 seulement : PHP 8.3.36 (corrigé) n'est pas concerné.
        self.assertIn('not_applicable', self.statuses('CVE-2026-109618')['wp-vps-05'])
        # Plus tard : NVD publie l'enregistrement analysé (9.8, configurations).
        self.sync(Recorded(nvd_available=True), force=True)
        with self.connect() as db:
            changes = {r[0]: (r[1], r[2]) for r in db.execute("SELECT field, old, new FROM sec_cve_changes WHERE cve='CVE-2026-109618'")}
            cvss = db.execute("SELECT cvss FROM sec_cve WHERE cve='CVE-2026-109618'").fetchone()[0]
        self.assertEqual(changes['cvss'], (None, '9.8'))
        self.assertEqual(changes['nvd_status'], (None, 'Modified'))
        self.assertEqual(cvss, 9.8)

    def test_epss_scores_and_absence(self):
        self.sync()
        with self.connect() as db:
            security_watch.store_nvd(db, 'CVE-2024-4577', feeds.parse_nvd(fixture('nvd_CVE-2024-4577.json')))
            db.execute("INSERT INTO sec_advisories(source, id, title, cves, first_seen) VALUES('kev','X','t','[\"CVE-2024-4577\"]',?)",
                       (NOW.isoformat(),))
        self.sync(force=True)
        with self.connect() as db:
            rows = {r[0]: (r[1], r[2]) for r in db.execute("SELECT cve, epss, epss_at FROM sec_cve WHERE cve IN "
                                                           "('CVE-2024-4577','CVE-2026-109618')")}
        self.assertAlmostEqual(rows['CVE-2024-4577'][0], 0.99987)
        self.assertIsNone(rows['CVE-2026-109618'][0])      # interrogée, sans score : jamais 0
        self.assertIsNotNone(rows['CVE-2026-109618'][1])


class MailTests(WatchBase):
    def setUp(self):
        super().setUp()
        patch = mock.patch.dict(os.environ, {'INFRAOPS_SMTP_HOST': 'smtp.example.test', 'INFRAOPS_SMTP_FROM': 'opscontrol@example.test',
                                             'INFRAOPS_SMTP_USER': 'opscontrol', 'INFRAOPS_SMTP_PASSWORD': 'mot-de-passe-de-test',  # pragma: allowlist secret -- valeur factice de test
                                             'INFRAOPS_SECURITY_MAIL_TO': 'soc@example.test'})
        patch.start()
        self.addCleanup(patch.stop)
        self.sent = []
        outer = self

        class FakeSMTP:
            def __init__(self, host, port, timeout=None, context=None):
                self.host = host

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def starttls(self, context=None):
                outer.tls = context

            def login(self, user, password):
                outer.login = (user, password)

            def send_message(self, message):
                outer.sent.append(message)
        self.smtp = FakeSMTP

    def test_single_digest_then_no_repeat(self):
        self.sync()
        result = security_alerts.dispatch(self.context, self.smtp)
        self.assertEqual(result['status'], 'sent')
        self.assertEqual(len(self.sent), 1)
        message = self.sent[0]
        self.assertIn('critique', message['Subject'])
        body = message.get_content()
        self.assertIn('CVE-2026-109618', body)
        self.assertIn('wp-vps-01', body)
        self.assertNotIn('mot-de-passe-de-test', body)
        self.assertIsNotNone(self.tls)                       # STARTTLS avec contexte vérifié
        # Rien de nouveau : aucun second envoi, même sans limitation de fréquence.
        self.assertEqual(security_alerts.dispatch(self.context, self.smtp, force=True)['status'], 'nothing')
        self.assertEqual(len(self.sent), 1)

    def test_smtp_failure_keeps_notifications_pending(self):
        self.sync()

        class Broken(self.smtp):
            def send_message(self, message):
                raise OSError('connexion refusée')
        self.assertEqual(security_alerts.dispatch(self.context, Broken)['status'], 'failed')
        with self.connect() as db:
            pending = db.execute("SELECT count(*) FROM sec_notifications WHERE emailed_at IS NULL AND level='critical'").fetchone()[0]
        self.assertGreater(pending, 0)
        self.assertEqual(security_alerts.dispatch(self.context, self.smtp, force=True)['status'], 'sent')

    def test_not_configured(self):
        with mock.patch.dict(os.environ, {'INFRAOPS_SMTP_HOST': ''}):
            self.assertEqual(security_alerts.dispatch(self.context, self.smtp)['status'], 'not_configured')


class RouteTests(WatchBase):
    def setUp(self):
        super().setUp()
        app = FastAPI()
        sc.install(app, self.context)
        self.get = {r.path: r.endpoint for r in all_routes(app) if 'GET' in r.methods}
        self.post = {r.path: r.endpoint for r in all_routes(app) if 'POST' in r.methods}
        self.request = SimpleNamespace(headers=Headers({}))
        self.sync()

    def watch(self, **filters):
        args = {'tech': '', 'host': '', 'source': '', 'severity': '', 'status': '', 'days': 30, **filters}
        return self.get['/api/security/watch'](**args)

    def test_dashboard(self):
        data = self.watch()
        top = data['cves'][0]
        self.assertIn(top['cve'], PHP_CVES)
        self.assertEqual(top['priority']['rank'], 'P1')
        self.assertIn('exposée à Internet', top['priority']['why'])
        self.assertTrue(any('PHP' in r and '8.3.36' in r for r in top['ranges']))
        self.assertGreaterEqual(data['kpis']['confirmed'], 2)
        self.assertIn('php', {t['tech'] for t in data['techs']})
        statuses = {s['key']: s['status'] for s in data['sources']}
        self.assertEqual((statuses['kev'], statuses['debian_dla']), ('ok', 'error'))
        self.assertTrue(any(b['source'] == 'wordpress' and 'PHP' in b['title'] for b in data['bulletins']))
        self.assertTrue(any(a['kind'] == 'exposed' for a in data['alerts']))

    def test_filters(self):
        self.assertEqual({c['cve'] for c in self.watch(tech='wordpress')['cves']} & {'CVE-2026-87902'}, {'CVE-2026-87902'})
        only = self.watch(host='wp-vps-04')
        self.assertTrue(only['cves'] and all(m['host_key'] == 'wp-vps-04' for c in only['cves'] for m in c['hosts']))
        self.assertTrue(all(c['severity'] == 'critical' for c in self.watch(severity='critical')['cves']))
        self.assertTrue(all('php_advisories' in c['sources'] for c in self.watch(source='php_advisories')['cves']))

    def test_pages_compactes_et_preuves_a_la_demande(self):
        full = self.watch()
        pages = [self.watch(limit=1, offset=n, projection='list') for n in range(full['total'])]
        self.assertEqual([p['cves'][0]['cve'] for p in pages], [c['cve'] for c in full['cves']])
        self.assertTrue(all(p['cves'][0]['hosts'] == [] and p['cves'][0]['detail_available'] for p in pages))
        ident = pages[0]['cves'][0]['cve']
        detail = self.watch(cve=ident, limit=1)
        self.assertEqual(detail['total'], 1)
        self.assertEqual(detail['cves'][0]['hosts'], full['cves'][0]['hosts'])
        self.assertEqual(self.watch(cve='absent')['cves'], [])
        with self.assertRaises(HTTPException):
            self.watch(limit=0)

    def match(self, host, needle):
        data = self.watch(host=host)
        cve = next(c for c in data['cves'] if c['cve'] == 'CVE-2026-109618')
        return next(m for m in cve['hosts'] if needle in m['instance'])

    def test_plans_per_origin(self):
        image = self.get['/api/security/matches/plan'](id=self.match('wp-vps-01', 'php:8.3.30')['id'], cve='CVE-2026-109618')
        self.assertIn('docker compose pull php1 && docker compose up -d php1', image['update'])
        self.assertTrue(any('php:8.3.36-apache' in line for line in image['update'] + image['precheck']))
        self.assertTrue(any('avant-' in line for line in image['backup']))
        distro = self.get['/api/security/matches/plan'](id=self.match('wp-vps-03', 'php8.2')['id'], cve='CVE-2026-109618')
        self.assertTrue(any('apt-get install --only-upgrade libapache2-mod-php8.2 php8.2-fpm' in line for line in distro['update']))
        self.assertTrue(any('potentielle' in w for w in distro['warnings']))
        with self.connect() as db:
            mid = db.execute("SELECT id FROM sec_matches WHERE cve='CVE-2026-87902' AND host_key='wp-vps-03'").fetchone()[0]
        wordpress = self.get['/api/security/matches/plan'](id=mid, cve='CVE-2026-87902')
        self.assertIn('sudo -u www-data wp --path=/var/www/site core update --version=7.1.2', wordpress['update'])
        self.assertTrue(any('db export' in line for line in wordpress['backup']))
        self.assertTrue(any('--version=7.1.1 --force' in line for line in wordpress['rollback']))

    def test_potential_confirmed_after_verification_then_glpi(self):
        match = self.match('wp-vps-03', 'php8.2')
        body = sc.MatchDecision(id=match['id'], cve='CVE-2026-109618', decision='confirm', note='court', by='operator')
        with self.assertRaises(HTTPException) as exc:
            self.post['/api/security/matches/decide'](body, self.request)
        self.assertEqual(exc.exception.status_code, 422)
        body.note = 'Changelog Debian vérifié : correctif absent'
        updated = self.post['/api/security/matches/decide'](body, self.request)
        self.assertEqual(updated['status'], 'confirmed')
        self.assertIsNotNone(updated['vuln_id'])
        with self.connect() as db:
            status, sources = db.execute('SELECT status, sources FROM sec_vulns WHERE id=?', (updated['vuln_id'],)).fetchone()
        self.assertEqual((status, json.loads(sources)), ('validated', ['manual']))
        context = SimpleNamespace(**vars(self.context))
        app = FastAPI()
        itsm.install(app, context)
        take = {r.path: r.endpoint for r in all_routes(app)}['/api/itsm/take']
        case = take(itsm.Take(origin='vulnerability', origin_id=updated['vuln_id'], host_key='wp-vps-03', by='operator'), self.request)
        self.assertIn('CVE-2026-109618', case['snapshot']['title'])
        # Retrait de la décision : de nouveau potentielle, la vulnérabilité est constatée close.
        self.post['/api/security/matches/decide'](sc.MatchDecision(id=match['id'], cve='CVE-2026-109618', decision='reset', by='operator'),
                                                  self.request)
        with self.connect() as db:
            self.assertEqual(db.execute('SELECT status FROM sec_vulns WHERE id=?', (updated['vuln_id'],)).fetchone()[0], 'resolved')

    def test_confirmed_match_cannot_be_decided(self):
        match = self.match('wp-vps-02', 'wordpress:php7.4')
        with self.assertRaises(HTTPException) as exc:
            self.post['/api/security/matches/decide'](sc.MatchDecision(id=match['id'], cve='CVE-2026-109618', decision='not_applicable',
                                                                      note='Pas exposé selon moi', by='x'), self.request)
        self.assertEqual(exc.exception.status_code, 409)

    def test_center_alerts_and_settings(self):
        alerts = self.context.security_center_alerts()
        self.assertTrue(any(a['ref'] == 'crit:CVE-2026-109618' for a in alerts))
        settings = self.post['/api/security/settings'](sc.Settings(feeds_hours=3, mail_to='soc@example.test; rssi@example.test',
                                                                   mail_level='warning', epss_threshold=0.2), self.request)
        self.assertEqual((settings['feeds_hours'], settings['mail_to'], settings['epss_threshold']),
                         (3, 'soc@example.test, rssi@example.test', 0.2))
        with self.assertRaises(HTTPException):
            self.post['/api/security/settings'](sc.Settings(mail_to='pas-une-adresse'), self.request)



class RecommendationTests(RouteTests):
    def plan(self, key):
        return self.get['/api/security/hosts/{key}/recommendations'](key)

    def test_one_package_update_for_all_cves_of_a_server(self):
        plan = self.plan('wp-vps-04')
        packages = [r for r in plan['recommendations'] if r['kind'] == 'packages']
        self.assertEqual(len(packages), 1)
        rec = packages[0]
        self.assertEqual(rec['cves'], list(PHP_CVES))
        self.assertEqual(rec['apply'], ['sudo apt-get update', 'sudo apt-get install --only-upgrade php8.4-fpm'])
        self.assertTrue(any('ge 8.4.27-1~deb13u1' in line for line in rec['verify']))
        self.assertIn('sudo apt-get install --allow-downgrades php8.4-fpm=8.4.26-1~deb13u1', rec['rollback'])
        self.assertEqual(plan['recommendations'][0], rec)           # la plus urgente en tête
        self.assertIn('apt-get install --only-upgrade php8.4-fpm', plan['text'])

    def test_one_recommendation_per_container_with_target_tag(self):
        recs = {r['instance']: r for r in self.plan('wp-vps-01')['recommendations'] if r['kind'] == 'upstream'}
        php = recs['conteneur php1 (php:8.3.30-apache)']
        self.assertEqual(php['priority'], 'P1')                     # critique et serveur exposé
        self.assertTrue(set(PHP_CVES) <= set(php['cves']))
        self.assertTrue(any('php:8.3.36-apache' in line for line in php['apply']))
        self.assertTrue(any('wordpress:6.8.10-php8.3-apache' in line for line in recs['conteneur wp1 (wordpress:6.8.3-php8.3-apache)']['apply']))

    def test_vendor_severity_and_potential_cap(self):
        recs = self.plan('wp-vps-03')['recommendations']
        wordpress = next(r for r in recs if r['kind'] == 'upstream')
        self.assertEqual(wordpress['priority'], 'P2')               # avis WordPress « critical », sans CVSS
        self.assertIn('sudo -u www-data wp --path=/var/www/site core update --version=7.1.2', wordpress['apply'])
        verify = next(r for r in recs if r['kind'] == 'verify')
        self.assertIn(verify['priority'], ('P2', 'P3'))             # potentielle : jamais P1
        self.assertTrue(any('zgrep -c CVE-2026-109618 /usr/share/doc/libapache2-mod-php8.2/changelog.Debian.gz' in line
                            for line in verify['precheck']))

    def test_fleet_summary(self):
        data = self.get['/api/security/recommendations']()
        levels = {i['key']: i['level'] for i in data['items']}
        self.assertEqual(levels['wp-vps-01'], 'P1')
        self.assertEqual(data['items'][0]['level'], 'P1')
        self.assertGreaterEqual(data['counts']['P1'], 1)


class RiskRecommendationTests(unittest.TestCase):
    def test_risks_without_cve(self):
        import security_recommendations as reco
        inv = sc.parse_inventory(ssh_output(['ID=debian', 'VERSION_ID="11"', 'VERSION_CODENAME=bullseye', 'PRETTY_NAME="Debian 11"'], BASE_PKG,
                                            [('legacy', 'php:7.4-apache')]))
        inv.update(reboot_required=True, collected_at=NOW.isoformat(), upgradable=[{'name': 'curl', 'suite': 'bullseye-security',
                                                                                    'candidate': '7.74.0-1.3+deb11u14', 'current': None}])
        inv['docker']['findings'] = sc.image_findings(inv['docker']['images'] or [{'repository': 'php', 'tag': '7.4-apache'}], today=NOW.date())
        host = {'key': 'old01', 'name': 'old01', 'ip': '192.0.2.50', 'environment': 'Production',
                'findings': [{'id': 'service:auditd.service', 'title': 'Service auditd.service : failed', 'domain': 'Services', 'severity': 'critical',
                              'evidence': 'failed', 'check_command': 'systemctl status --no-pager -- auditd.service',
                              'solution_command': 'sudo systemctl start -- auditd.service', 'precaution': 'Vérifier la cause'}]}
        support = sc.os_support(inv['os'], NOW.date())
        plan = reco.build(host, inv, [], [], 'WAF', support, None, today=NOW.date(), at=NOW)
        kinds = {r['kind']: r for r in plan['recommendations']}
        self.assertEqual(kinds['os']['priority'], 'P1')              # hors support ET exposé
        self.assertIn('Debian 12 (bookworm)', ' '.join(kinds['os']['apply']))
        self.assertEqual(kinds['reboot']['kind'], 'reboot')
        self.assertEqual(kinds['pending']['priority'], 'P3')         # dépôt de sécurité
        self.assertIn('sudo systemctl start -- auditd.service', kinds['audit']['apply'])
        self.assertIn('Aucune détection Wazuh', ' '.join(kinds['coverage']['why']))
        self.assertEqual(plan['recommendations'][0]['kind'], 'os')
        self.assertEqual(plan['level'], 'P1')

    def test_never_scanned_server(self):
        import security_recommendations as reco
        plan = reco.build({'key': 'new01', 'name': 'new01'}, {}, [], [], None, None, None, today=NOW.date(), at=NOW)
        self.assertEqual([r['kind'] for r in plan['recommendations']], ['coverage'])
        self.assertEqual(plan['recommendations'][0]['priority'], 'P2')
        self.assertIn('Aucun relevé des paquets', plan['text'])


class SshOperationTests(unittest.TestCase):
    def test_new_sections_are_read_only_and_parsed(self):
        command = sc.COMMAND
        self.assertIn('wp-includes/version.php', command)
        self.assertNotIn('wp core', command)
        inv = sc.parse_inventory(HOSTS['wp-vps-05'])
        self.assertEqual(inv['docker']['swarm'], {'state': 'active', 'manager': True, 'server_version': '28.3.3'})
        self.assertEqual(inv['docker']['services'][0]['image'], 'wordpress:6.8.3-php8.3-fpm')
        self.assertEqual(sc.parse_inventory(HOSTS['wp-vps-03'])['wordpress'], [{'path': '/var/www/site', 'version': '7.1.1'}])
        refused = sc.parse_inventory(HOSTS['wp-vps-03'].replace("'7.1.1'", "'7.1.1; rm -rf /'"))
        self.assertEqual(refused['wordpress'], [])


if __name__ == '__main__':
    unittest.main()
