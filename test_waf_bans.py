"""IP bannies : collecte (waf_probe), analyse (waf_bans), commandes préparées (waf_findings)."""
import contextlib
import io
import json
import unittest
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import waf_bans
import waf_findings as wf
import waf_probe
import migrations
import retention
import ip_location

BANNED = '93.184.216.34 151.101.1.7 10.0.0.5 45.33.32.9 45.33.32.10 45.33.32.11'
WITH_TIME = ('93.184.216.34 \t2026-10-06 01:00:00 + 600 = 2026-10-06 01:10:00\n'
             '10.0.0.5 \t2026-10-05 22:00:00 + -1 = 9999-12-31 23:59:59\n')


def run_probe(with_time=WITH_TIME):
    def fake_glob(pattern):
        if pattern.endswith('access.log'):
            return ['/var/log/apache2/access.log']
        if pattern.endswith('error.log'):
            return ['/var/log/apache2/error.log']
        return []

    def fake_run(args, **kwargs):
        out = ''
        if 'systemctl' in args:
            out = 'LoadState=loaded\nActiveState=active\nSubState=running'
        elif 'status' in args:
            out = 'Currently banned: 6\nCurrently failed: 0\nTotal failed: 20\nTotal banned: 9\nBanned IP list: ' + BANNED
        elif '--with-time' in args:
            if with_time is None:
                return SimpleNamespace(returncode=1, stdout='', stderr='sudo: a password is required')
            out = with_time
        elif 'ignoreip' in args:
            out = '127.0.0.1/8 ::1 45.33.32.9'
        elif 'get' in args:
            out = '60'
        elif args[-1].endswith('access.log'):
            out = ('93.184.216.34 - - [13/Sep/2026:12:00:00 +0000] "GET /wp-login.php HTTP/1.1" 403 10\n' * 3 +
                   '93.184.216.200 - - [13/Sep/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 10\n')
        elif args[-1].endswith('error.log'):
            out = ('[Sun Sep 13 12:00:00 2026] [client 93.184.216.34] ModSecurity: Access denied [id "942100"] Total Score: 9\n'
                   '[Sun Sep 13 12:00:01 2026] [client 93.184.216.34] ModSecurity: Warning [id "920350"] Total Score: 3\n')
        return SimpleNamespace(returncode=0, stdout=out, stderr='')

    capture = io.StringIO()
    with patch.object(waf_probe.glob, 'glob', side_effect=fake_glob), \
            patch.object(waf_probe.subprocess, 'run', side_effect=fake_run), contextlib.redirect_stdout(capture):
        waf_probe.main()
    return json.loads(capture.getvalue())


class ProbeTests(unittest.TestCase):
    def test_dates_et_rapprochement_des_journaux(self):
        s = run_probe()['sections']
        bans = s['bantimes']['data']['bans']
        self.assertEqual(bans['93.184.216.34'], {'banned_at': '2026-10-06 01:00:00', 'duration_seconds': 600,
                                             'expires_at': '2026-10-06 01:10:00'})
        self.assertEqual(bans['10.0.0.5']['duration_seconds'], -1)
        self.assertEqual(s['traffic']['data']['banned_requests'], {'93.184.216.34': 3}, 'IP non bannie exclue')
        alerts = s['modsecurity']['data']['banned_alerts']['93.184.216.34']
        self.assertEqual(alerts['lines'], 2)
        self.assertEqual(sorted(r for r, _ in alerts['rules']), ['920350', '942100'])

    def test_dates_refusees_restent_inconnues(self):
        s = run_probe(with_time=None)['sections']
        self.assertEqual(s['bantimes']['status'], 'unknown')
        self.assertEqual(s['fail2ban']['status'], 'observed', 'le reste de la collecte continue')


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.waf = {'collected_at': '2026-10-06T01:05:00+00:00', 'sections': run_probe()['sections']}
        self.result = waf_bans.analyze(self.waf, '10.77.0.131', {'10.0.0.5': 'bastion'})
        self.rows = {r['ip']: r for r in self.result['rows']}

    def test_verdicts(self):
        self.assertEqual(self.rows['45.33.32.9']['verdict'], 'incoherent', 'bannie ET en liste blanche')
        self.assertEqual(self.rows['10.0.0.5']['verdict'], 'verify')
        self.assertIn('bastion', ' '.join(self.rows['10.0.0.5']['reasons']))
        self.assertEqual(self.rows['151.101.1.7']['verdict'], 'verify', 'aucune trace : motif à confirmer')
        self.assertEqual(self.rows['93.184.216.34']['verdict'], 'keep')
        self.assertEqual(self.rows['93.184.216.34']['modsec_lines'], 2)
        self.assertEqual(self.rows['93.184.216.34']['requests'], 3)
        self.assertEqual(self.rows['93.184.216.34']['banned_at'], '2026-10-06 01:00:00')

    def test_tri_campagne_et_synthese(self):
        self.assertEqual(self.result['rows'][0]['verdict'], 'incoherent', 'le plus grave en tête')
        self.assertEqual(self.result['summary']['campaigns'], [{'network': '45.33.32.0/24', 'bans': 3}])
        self.assertEqual(self.result['summary']['listed'], 6)
        self.assertTrue(self.result['coverage']['ban_times'])
        self.assertTrue(self.result['coverage']['activity_known'])

    def test_collecte_ancienne_ne_bascule_pas_le_verdict(self):
        old = json.loads(json.dumps(self.waf))
        old['sections']['traffic']['data'].pop('banned_requests')
        rows = {r['ip']: r for r in waf_bans.analyze(old, '10.77.0.131')['rows']}
        # OC-AUDIT-011 : absence de données ≠ preuve du motif, le ban est à vérifier, jamais « maintenir ».
        self.assertEqual(rows['151.101.1.7']['verdict'], 'verify')
        self.assertEqual(rows['93.184.216.34']['verdict'], 'verify', 'même une IP active : rien n’est rapproché')
        self.assertIn('Activité non rapprochée', ' '.join(rows['151.101.1.7']['reasons']))

    def test_ordinary_http_traffic_is_not_a_reason_to_keep(self):
        waf = json.loads(json.dumps(self.waf))
        waf['sections']['modsecurity']['data']['banned_alerts'] = {}
        row = {r['ip']: r for r in waf_bans.analyze(waf, '10.77.0.131')['rows']}['93.184.216.34']
        self.assertEqual((row['verdict'], row['requests'], row['modsec_lines']), ('verify', 3, 0))
        self.assertIn('sans alerte ModSecurity', ' '.join(row['reasons']))


class BanHistoryTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        migrations.apply(self.db)

    def collect(self, hour, banned, count=None, epoch=None, status='observed'):
        waf = {'collected_at':f'2026-10-06T{hour:02}:00:00+00:00','sections':{
            'fail2ban':{'status':status,'data':{'banned_ips':banned,
                'currently_banned':len(banned) if count is None else count}},
            'bantimes':{'data':{'bans':{'192.0.2.1':{'banned_at':epoch}}}}}}
        with self.db:
            waf_bans.observe(self.db, 'waf-demo', '192.0.2.254', waf)

    def row(self):
        return self.db.execute('SELECT first_seen,last_seen,current_since,rebans,active FROM waf_ban_history').fetchone()

    def test_continuous_ban_and_reappearance_are_idempotent(self):
        self.collect(1, ['192.0.2.1'])
        self.collect(2, ['192.0.2.1'])
        self.collect(2, ['192.0.2.1'])
        self.assertEqual(self.row()[3], 0)
        self.collect(3, [])
        self.assertEqual(self.row()[4], 0)
        self.collect(4, ['192.0.2.1'])
        first,last,since,rebans,_ = self.row()
        self.assertTrue(first.startswith('2026-10-06T01'))
        self.assertTrue(last.startswith('2026-10-06T04'))
        self.assertEqual(last, since)
        self.assertEqual(rebans, 1)

    def test_failed_partial_and_old_collections_do_not_create_rebans(self):
        self.collect(1, ['192.0.2.1'])
        self.collect(2, [], status='unknown')
        self.collect(3, [], count=10)
        self.collect(4, ['192.0.2.1'])
        self.collect(2, [])
        self.assertEqual(self.row()[3:], (0,1))

    def test_new_fail2ban_epoch_detects_reban_without_observed_gap(self):
        self.collect(1, ['192.0.2.1'], epoch='2026-10-06 00:30:00')
        self.collect(2, ['192.0.2.1'], epoch='2026-10-06 01:30:00')
        self.assertEqual(self.row()[3], 1)

    def test_reponse_malformee_ignoree_sans_exception(self):
        # Audit WAF-01 : un WAF compromis ou une sonde modifiée ne fait plus échouer la collecte.
        waf = {'collected_at': '2026-10-06T01:00:00+00:00', 'sections': {
            'fail2ban': {'status': 'observed', 'data': {'banned_ips': ['192.0.2.1', 'x', 5, None],
                                                       'currently_banned': 4}},
            'bantimes': {'data': {'bans': {'192.0.2.1': 5}}}}}
        with self.db:
            waf_bans.observe(self.db, 'waf-demo', '192.0.2.254', waf)
        self.assertEqual(self.db.execute('SELECT ip FROM waf_ban_history').fetchall(), [('192.0.2.1',)])
        waf['collected_at'] = '2026-10-06T02:00:00+00:00'
        waf['sections']['bantimes'] = {'data': {'bans': 'texte'}}
        with self.db:
            waf_bans.observe(self.db, 'waf-demo', '192.0.2.254', waf)
        result = waf_bans.analyze(waf, '192.0.2.254')
        self.assertEqual([r['ip'] for r in result['rows']], ['192.0.2.1'])

    def test_purge_after_thirty_days(self):
        self.collect(1, ['192.0.2.1'])
        counts = retention.sweep(self.db, [], now=datetime(2026,11,7,tzinfo=timezone.utc))
        self.assertEqual(counts['waf_ban_history'], 1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM waf_ban_sources').fetchone()[0], 0)


class CampaignAndLocationTests(unittest.TestCase):
    def test_known_bot_recommendation_comes_from_sample_only(self):
        waf = {'sections':{'traffic':{'data':{'banned_user_agents':{
            '93.184.216.34':[['Mozilla/5.0 bingbot/2.0',10]]}}}}}
        with patch('socket.create_connection', side_effect=AssertionError('Réseau interdit')):
            result = waf_bans.campaign_recommendations([('93.184.216.0/24',67)], waf)[0]
        self.assertEqual(result['bots'], ['bingbot'])
        self.assertIn('limitation de débit', result['text'])
        self.assertIn('429', result['rule'])
        self.assertFalse(result['executable'])
        waf['sections']['traffic']['data']['banned_user_agents']['93.184.216.34'] = [['sqlmap/1.0',1]]
        self.assertEqual(waf_bans.campaign_recommendations([('93.184.216.0/24',3)], waf)[0]['bots'], [])

    def test_local_csv_longest_prefix_and_no_external_query(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'geo-test.csv'
            path.write_text('network,country,city,asn,organization\n'
                            '93.184.0.0/16,Pays fictif,Ville générique,AS-test,Exemple\n'
                            '93.184.216.0/24,Pays fictif,Ville test,AS-test,Exemple\n',encoding='utf-8')
            with patch.dict('os.environ', {'INFRAOPS_GEOIP_CSV':str(path)}), patch('socket.create_connection', side_effect=AssertionError('Réseau interdit')):
                locate = ip_location.locator()
                self.assertEqual(locate('93.184.216.34')['city'], 'Ville test')
                self.assertEqual(locate('192.0.2.1')['status'], 'private')
                result = waf_bans.analyze({'sections':{'traffic':{'data':{'top_ips':[['93.184.216.34',100]]}}}}, '192.0.2.254', locate=locate)
                self.assertEqual(result['top_traffic'][0]['location']['city'], 'Ville test')

    def test_missing_database_does_not_invent_a_country(self):
        with patch.dict('os.environ', {'INFRAOPS_GEOIP_CSV':''}):
            locate = ip_location.locator()
            result = locate('93.184.216.34')
            self.assertEqual(locate('inconnue')['status'], 'unknown')
        self.assertEqual(result['status'], 'unconfigured')
        self.assertNotIn('country', result)


class CommandTests(unittest.TestCase):
    def test_verification_en_lecture_seule(self):
        plan = wf.command_plan('93.184.216.34', 'inspect', '10.77.0.131')
        text = '\n'.join(plan['commands'])
        self.assertIn('banip --with-time | grep -F -- 93.184.216.34', text)
        self.assertIn('fail2ban.log', text)
        for mutation in ('unbanip', ' banip 93', 'addignoreip', 'delignoreip', ' set apache'):
            self.assertNotIn(mutation, text)
        self.assertFalse(plan['executable'])

    def test_deban_avec_commande_inverse(self):
        plan = wf.command_plan('93.184.216.34', 'unban', '10.77.0.131')
        self.assertEqual(plan['commands'], ['sudo fail2ban-client set apache-modsecurity unbanip 93.184.216.34'])
        self.assertEqual(plan['undo'], 'sudo fail2ban-client set apache-modsecurity banip 93.184.216.34')
        self.assertIn('grep -F -- 93.184.216.34', plan['verify'][0])

    def test_injection_refusee(self):
        for bad in ('93.184.216.34; id', '$(id)', '93.184.216.34 | sh', 'fe80::1%eth0'):
            with self.assertRaises(ValueError):
                wf.command_plan(bad, 'inspect', '10.77.0.131')


class LowFindingsTests(unittest.TestCase):
    """Audit WAF-03/04/05/08/09."""

    def test_commande_nc_validee_et_quotee(self):
        import apache_health
        self.assertEqual(apache_health.nc_command('10.0.0.5:8080'), 'nc -vz -w 3 10.0.0.5 8080')
        self.assertEqual(apache_health.nc_command('[2001:db8::1]:80'), 'nc -vz -w 3 2001:db8::1 80')
        for bad in ('a;id:80', '$(id):80', 'x:99999', 'sans-port'):
            self.assertEqual(apache_health.nc_command(bad), '', bad)

    def test_cgnat_et_ipv4_encapsulee(self):
        from ipaddress import ip_address
        self.assertEqual(waf_bans._kind(ip_address('100.64.1.1'), '10.77.0.131'), 'privée')
        self.assertEqual(waf_bans._kind(ip_address('8.8.8.8'), '10.77.0.131'), 'publique')
        self.assertEqual(waf_bans._network('::ffff:203.0.113.9'), '203.0.113.0/24')

    def test_liste_blanche_dns_signalee(self):
        waf = {'collected_at': '2026-10-06T01:05:00+00:00', 'sections': {
            'fail2ban': {'status': 'observed', 'data': {'banned_ips': ['8.8.8.8'], 'currently_banned': 1}},
            'ignoreip': {'data': {'addresses': ['127.0.0.1/8'], 'unparsed': 2}}}}
        row = waf_bans.analyze(waf, '10.77.0.131')['rows'][0]
        self.assertIn('partiellement analysée : 2', ' '.join(row['reasons']))

    def test_geoip_ligne_fautive_ignoree_et_echec_memorise(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'geo.csv'
            path.write_text('network,country,city,asn,organization\n'
                            '93.184.216.5/24,Pays,Ville,AS,Org\nnimporte quoi,X,Y,Z,W\n', encoding='utf-8')
            with patch.dict('os.environ', {'INFRAOPS_GEOIP_CSV': str(path)}):
                self.assertEqual(ip_location.locator()('93.184.216.34')['city'], 'Ville')
            bad = Path(folder) / 'bad.csv'
            bad.write_text('pas_de_colonne_network\n1\n', encoding='utf-8')
            ip_location._load_once.cache_clear()
            with patch.dict('os.environ', {'INFRAOPS_GEOIP_CSV': str(bad)}), \
                    patch.object(ip_location, '_load', wraps=ip_location._load) as load:
                for _ in range(3):
                    self.assertEqual(ip_location.locator()('93.184.216.34')['status'], 'unavailable')
            self.assertEqual(load.call_count, 1, 'base invalide relue une seule fois')

if __name__ == '__main__':
    unittest.main()
