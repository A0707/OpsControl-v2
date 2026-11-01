import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

import alert_center
import alert_policy as policy
import shares_view
import storage_probe

NOW = datetime.now(timezone.utc).isoformat()
OLD = '2026-01-01T00:00:00+00:00'
GIB = policy.GIB


def host(key, ip, stale=False, shares=(), exports=None, findings=(), status='critical', at=NOW, fs=(), **extra):
    return {'key': key, 'name': key, 'ip': ip, 'stale': stale, 'status': status, 'collected_at': at,
            'issues': [], 'findings': list(findings),
            'storage': {'remote_shares': list(shares), 'exports': exports, 'filesystems': list(fs)}, **extra}


def volume(mount, use, total_gib=20, free_gib=None):
    total = total_gib * GIB
    free = free_gib * GIB if free_gib is not None else total * (100 - use) // 100
    return {'mount': mount, 'use_pct': use, 'total_kb': total, 'available_kb': free, 'used_kb': total - free}


def mount(source, status='accessible', use=50, access='read-write', path='/mnt/x'):
    return {'mount': path, 'source': source, 'fstype': 'nfs4', 'status': status, 'access': access, 'use_pct': use}


class PolicyTests(unittest.TestCase):
    def test_disk_percentage_grid(self):
        self.assertEqual(policy.disk(96, 20 * GIB, 0.8 * 20 * GIB)[0], 'critical')
        self.assertEqual(policy.disk(91, 20 * GIB, 1.8 * GIB)[0], 'warning')
        self.assertEqual(policy.disk(82, 20 * GIB, 3.6 * GIB)[0], 'preventive')
        self.assertEqual(policy.disk(70, 20 * GIB, 6 * GIB)[0], None)

    def test_large_free_space_lowers_urgency_but_never_hides(self):
        niveau, raisons = policy.disk(97, 10000 * GIB, 300 * GIB)
        self.assertEqual(niveau, 'warning')
        self.assertIn('urgence réduite', raisons[-1])
        self.assertEqual(policy.disk(83, 10000 * GIB, 1700 * GIB)[0], 'preventive')

    def test_under_one_gib_is_critical_whatever_the_percentage(self):
        self.assertEqual(policy.disk(85, 5 * GIB, 0.5 * GIB)[0], 'critical')

    def test_trend_projects_saturation(self):
        debut = datetime(2026, 9, 1, tzinfo=timezone.utc)
        total = 100 * GIB
        # +2 Gio par jour, 20 Gio restants : saturation dans 10 jours → préventif.
        points = [((debut + timedelta(days=d)).isoformat(), (70 + 2 * d) * GIB, total) for d in range(6)]
        jours = policy.days_to_full(points)
        self.assertAlmostEqual(jours, 10, places=3)
        self.assertEqual(policy.disk(80, total, 20 * GIB, jours)[0], 'preventive')
        self.assertEqual(policy.disk(60, total, 40 * GIB, 5)[0], 'warning')

    def test_trend_refuses_short_or_resized_or_shrinking_history(self):
        t = datetime(2026, 9, 1, tzinfo=timezone.utc)
        court = [((t + timedelta(hours=h)).isoformat(), 10 + h, 100) for h in range(3)]
        self.assertIsNone(policy.days_to_full(court))
        agrandi = [((t + timedelta(days=d)).isoformat(), 10 + d, 100 + d) for d in range(4)]
        self.assertIsNone(policy.days_to_full(agrandi))
        decroit = [((t + timedelta(days=d)).isoformat(), 50 - d, 100) for d in range(4)]
        self.assertIsNone(policy.days_to_full(decroit))

    def test_services_graded_by_role(self):
        self.assertEqual(policy.service('tomcat-demoapp.service')[0], 'critical')
        self.assertEqual(policy.service('postgresql@16-main.service')[0], 'critical')
        self.assertEqual(policy.service('zabbix-agent.service')[0], 'warning')
        self.assertEqual(policy.service('logrotate.service')[0], 'preventive')
        self.assertEqual(policy.service('inconnu.service')[0], 'warning')
        self.assertEqual(policy.service('logrotate.service', {'logrotate'})[0], 'critical')

    def test_cpu_requires_sustained_load(self):
        self.assertEqual(policy.cpu([99])[0], None)
        self.assertEqual(policy.cpu([95, 92, 97, 10])[0], 'warning')

    def test_zabbix_requalification(self):
        cas = {
            'Test Disaster Trigger for pagerduty': 'info',
            'Proxmox: VM [pve/VM 9000 (qemu/9000)]: Not running': 'info',
            'MS Nantissement DOWN': 'critical',
            'PostgreSQL service not running on db02': 'critical',
            'Zabbix agent on git01 is unreachable for 5 minutes': 'warning',
            'Cert: SSL certificate expires soon (less than 30 days)': 'preventive',
            'Free disk space is less than 20% on volume /': 'disk',
        }
        for description, attendu in cas.items():
            self.assertEqual(policy.zabbix(description, 'critical')[0], attendu, description)
        # Trigger inconnu : jamais repris tel quel, abaissé d'un cran et signalé.
        niveau, raison, couvert = policy.zabbix('Quelque chose d’inédit', 'critical')
        self.assertEqual((niveau, couvert), ('warning', False))


class ExportsProbeTests(unittest.TestCase):
    def test_exports_use_local_filesystem_without_extra_command(self):
        out = ('##DF\nFilesystem Type 1024-blocks Used Available Capacity Mounted on\n'
               '/dev/sda1 ext4 100 50 50 50% /\n/dev/sdb1 xfs 100 97 3 97% /var/nfs_share\n'
               '##EXPORTS\nNFS|/var/nfs_share/cb|10.0.0.0/8(ro)\nSMB|/srv/commun|commun\n')
        exports = storage_probe.parse(out)['exports']
        self.assertEqual(exports[0]['use_pct'], 97)
        self.assertEqual(exports[0]['filesystem'], '/var/nfs_share')
        self.assertEqual(exports[1], {'protocol': 'SMB', 'path': '/srv/commun', 'use_pct': 50,
                                      'filesystem': '/', 'name': 'commun'})
        bloc = storage_probe.COMMAND.split('##EXPORTS')[1].split('##SSHFAIL')[0]
        self.assertNotIn('df ', bloc)

    def test_older_probe_means_not_collected_not_empty(self):
        self.assertIsNone(storage_probe.parse('##DF\n')['exports'])
        self.assertEqual(storage_probe.parse('##EXPORTS\n')['exports'], [])


class SharesViewTests(unittest.TestCase):
    def test_one_share_many_clients_is_one_line(self):
        rows = [host('c%d' % i, '10.0.0.%d' % i, shares=[mount('10.0.0.50:/data', use=70)]) for i in range(9)]
        rows.append(host('nfs', '10.0.0.50'))
        view = shares_view.build(rows)
        self.assertEqual(len(view['shares']), 1)
        share = view['shares'][0]
        self.assertEqual((share['clients_count'], share['status'], share['server_host']['key']), (9, 'ok', 'nfs'))

    def test_stale_client_makes_share_critical_and_is_counted(self):
        rows = [host('a', '1.1.1.1', shares=[mount('srv:/d')]),
                host('b', '1.1.1.2', shares=[mount('srv:/d', status='stale', use=None)])]
        share = shares_view.build(rows)['shares'][0]
        self.assertEqual((share['status'], share['stale_clients']), ('critical', 1))
        self.assertIn('Injoignable depuis 1 client(s) sur 2', share['reasons'])

    def test_server_measure_wins_and_policy_grid(self):
        rows = [host('c', '1.1.1.1', shares=[mount('10.0.0.5:/d', use=70)]),
                host('srv', '10.0.0.5', exports=[{'protocol': 'NFS', 'path': '/d', 'use_pct': 96, 'clients': '*'}])]
        share = shares_view.build(rows)['shares'][0]
        self.assertEqual((share['use_pct'], share['status']), (96, 'critical'))
        rows[1]['storage']['exports'][0]['use_pct'] = 92
        self.assertEqual(shares_view.build(rows)['shares'][0]['status'], 'warning')
        rows[1]['storage']['exports'][0]['use_pct'] = 82
        self.assertEqual(shares_view.build(rows)['shares'][0]['status'], 'preventive')

    def test_unmeasured_is_unknown_never_ok(self):
        rows = [host('srv', '10.0.0.5', exports=[{'protocol': 'NFS', 'path': '/d', 'use_pct': None, 'clients': '*'}])]
        self.assertEqual(shares_view.build(rows)['shares'][0]['status'], 'unknown')

    def test_trailing_slash_is_one_share_and_stale_ok_is_not_counted_ok(self):
        # Audit UI du 31/10 (fiches 10.1 et 10.2).
        rows = [host('c', '1.1.1.1', shares=[mount('10.0.0.5:/var/DemoFiles/files/', use=40)]),
                host('srv', '10.0.0.5', exports=[{'protocol': 'NFS', 'path': '/var/DemoFiles/files', 'use_pct': 40, 'clients': '*'}])]
        view = shares_view.build(rows)
        self.assertEqual(len(view['shares']), 1)
        self.assertEqual(view['shares'][0]['path'], '/var/DemoFiles/files')
        self.assertEqual(sorted(view['shares'][0]['raw_paths']), ['/var/DemoFiles/files', '/var/DemoFiles/files/'])
        old = shares_view.build([host('c', '1.1.1.1', stale=True, at=OLD, shares=[mount('s:/d', use=40)])])
        self.assertEqual(old['shares'][0]['status'], 'ok')
        self.assertEqual((old['counts']['ok'], old['counts']['stale']), (0, 1))

    def test_old_measurements_are_not_fresh(self):
        rows = [host('c', '1.1.1.1', stale=True, at=OLD, shares=[mount('s:/d', use=99)])]
        self.assertFalse(shares_view.build(rows)['shares'][0]['fresh'])

    def test_recent_client_measure_beats_old_server_export(self):
        # OC-AUDIT-005 : export ancien à 20 %, client récent à 99 % → 99 %, critique, daté du client.
        rows = [host('c', '1.1.1.1', shares=[mount('10.0.0.5:/d', use=99)]),
                host('srv', '10.0.0.5', stale=True, at=OLD,
                     exports=[{'protocol': 'NFS', 'path': '/d', 'use_pct': 20, 'clients': '*'}])]
        share = shares_view.build(rows)['shares'][0]
        self.assertEqual((share['use_pct'], share['status'], share['fresh'], share['use_from']), (99, 'critical', True, 'client c'))
        self.assertEqual(share['observed_at'], rows[0]['collected_at'])
        # Inverse : export récent sain, client ancien saturé → l'ancienne valeur ne crée pas de criticité récente.
        rows = [host('c', '1.1.1.1', stale=True, at=OLD, shares=[mount('10.0.0.5:/d', use=99)]),
                host('srv', '10.0.0.5', exports=[{'protocol': 'NFS', 'path': '/d', 'use_pct': 20, 'clients': '*'}])]
        share = shares_view.build(rows)['shares'][0]
        self.assertEqual((share['use_pct'], share['status'], share['fresh'], share['use_from']), (20, 'ok', True, 'serveur'))
        self.assertEqual(share['observed_at'], rows[1]['collected_at'])

    def test_only_old_measure_keeps_its_own_date(self):
        rows = [host('c', '1.1.1.1', stale=True, at=OLD, shares=[mount('10.0.0.5:/d', use=20)]),
                host('d', '1.1.1.2', shares=[mount('10.0.0.5:/d', use=None)])]
        share = shares_view.build(rows)['shares'][0]
        self.assertEqual((share['use_pct'], share['fresh'], share['observed_at']), (20, False, OLD))

    def test_divergent_recent_measures_are_reported(self):
        rows = [host('c', '1.1.1.1', shares=[mount('10.0.0.5:/d', use=60)]),
                host('srv', '10.0.0.5', exports=[{'protocol': 'NFS', 'path': '/d', 'use_pct': 85, 'clients': '*'}])]
        share = shares_view.build(rows)['shares'][0]
        self.assertEqual(share['use_pct'], 85)
        self.assertTrue(any('divergentes' in r and '60 % (client c)' in r for r in share['reasons']), share['reasons'])


def context(rows, connections=()):
    return SimpleNamespace(rows=lambda: rows, api_connections=lambda: list(connections))


def source(provider, inventory, at=NOW, **extra):
    return {'key': provider.lower(), 'name': provider, 'provider': provider,
            'last_result': {'status': 'observed', 'collected_at': at, 'inventory': inventory, **extra}}


def ids(result):
    return {a['id']: a['severity'] for a in result['alerts']}


class AlertCenterTests(unittest.TestCase):
    def test_disks_graded_from_raw_measure_not_from_audit_finding(self):
        rows = [host('a', '1.1.1.1', fs=[volume('/', 97)],
                     findings=[{'id': 'disk_max', 'title': 'Disques : 97 %', 'severity': 'critical'}]),
                host('b', '1.1.1.2', fs=[volume('/data', 97, total_gib=10000, free_gib=300)])]
        alertes = {a['id']: a for a in alert_center.build(context(rows))['alerts']}
        self.assertEqual(set(alertes), {'SSH:disk:critical', 'SSH:disk:warning'})
        self.assertIn('/data : 97 % occupé', alertes['SSH:disk:warning']['targets'][0]['detail'])

    def test_same_service_on_many_hosts_is_one_alert_graded_by_role(self):
        f = {'id': 'service:tomcat.service', 'title': 'Service tomcat.service : failed', 'severity': 'critical'}
        g = {'id': 'service:logrotate.service', 'title': 'Service logrotate.service : failed', 'severity': 'critical'}
        result = alert_center.build(context([host('a', '1.1.1.1', findings=[f, g]), host('b', '1.1.1.2', findings=[f])]))
        alertes = {a['id']: a for a in result['alerts']}
        self.assertEqual(alertes['SSH:service:tomcat.service:critical']['count'], 2)
        self.assertEqual(alertes['SSH:service:logrotate.service:preventive']['source_severity'], 'Audit : critical')

    def test_stale_evidence_is_shown_but_not_confirmed(self):
        result = alert_center.build(context([host('a', '1.1.1.1', stale=True, at=OLD, fs=[volume('/', 99)])]))
        self.assertEqual((result['counts']['critical'], result['counts']['critical_stale']), (0, 1))

    def test_stale_mount_counted_once_per_share_not_per_client(self):
        f = {'id': 'mount:/mnt/x', 'title': 'Partage distant injoignable', 'severity': 'critical'}
        rows = [host('a', '1.1.1.1', findings=[f], shares=[mount('srv:/d', status='stale', use=None)]),
                host('b', '1.1.1.2', findings=[f], shares=[mount('srv:/d', status='stale', use=None)])]
        alerts = alert_center.build(context(rows))['alerts']
        self.assertEqual([a['source'] for a in alerts], ['Partages'])

    def test_zabbix_noise_becomes_info_in_one_group(self):
        problems = [{'description': 'Proxmox: VM [pve/VM %d (qemu/%d)]: Not running' % (i, i), 'severity': 'warning',
                     'severity_label': 'Moyenne', 'hosts': ['pve']} for i in range(42)]
        result = alert_center.build(context([], [source('Zabbix', {'problems': problems})]))
        self.assertEqual(len(result['alerts']), 1)
        alerte = result['alerts'][0]
        self.assertEqual((alerte['severity'], alerte['count'], alerte['source_severity']), ('info', 42, 'Zabbix : Moyenne'))

    def test_zabbix_disk_trigger_requalified_by_ssh_measure(self):
        rows = [host('big', '1.1.1.1', fs=[volume('/all_backup10', 83, total_gib=10000, free_gib=1700)]),
                host('root', '1.1.1.2', fs=[volume('/', 96)])]
        problems = [{'description': 'Free disk space is less than 20% on volume /all_backup10', 'severity': 'warning',
                     'severity_label': 'Avertissement', 'hosts': ['big']},
                    {'description': 'Free disk space is less than 20% on volume /', 'severity': 'warning',
                     'severity_label': 'Avertissement', 'hosts': ['root']},
                    {'description': 'Free disk space is less than 20% on volume /var', 'severity': 'warning',
                     'severity_label': 'Avertissement', 'hosts': ['inconnu']}]
        zabbix = {k: v for k, v in ids(alert_center.build(context(rows, [source('Zabbix', {'problems': problems})]))).items()
                  if k.startswith('Zabbix')}
        self.assertEqual(zabbix, {
            'Zabbix:Free disk space is less than 20% on volume /all_backup10:preventive': 'preventive',
            'Zabbix:Free disk space is less than 20% on volume /:critical': 'critical',
            'Zabbix:Free disk space is less than 20% on volume /var:preventive': 'preventive'})

    def test_bacula_reads_last_run_not_history(self):
        jobs = [{'jobid': 1, 'name': 'Backup-A', 'severity': 'critical', 'status_label': 'Erreur', 'client': 'a-fd'},
                {'jobid': 2, 'name': 'Backup-A', 'severity': 'ok', 'status_label': 'OK', 'client': 'a-fd'},
                {'jobid': 3, 'name': 'Backup-B', 'severity': 'critical', 'status_label': 'Erreur fatale', 'client': 'b-fd'}]
        result = alert_center.build(context([host('b', '1.1.1.2')], [source('Bacula', {'jobs': jobs})]))
        self.assertEqual([a['id'] for a in result['alerts']], ['Bacula:job:Backup-B:critical'])
        self.assertEqual(result['alerts'][0]['targets'][0]['host_key'], 'b')

    def test_bacula_etat_inconnu_alerte_au_lieu_d_etre_ignore(self):
        # Audit SUP-08 : un code JobStatus non reconnu était ignoré en silence.
        jobs = [{'jobid': 1, 'name': 'Backup-Z', 'severity': 'unknown', 'status_label': 'État non reconnu', 'client': 'z-fd'}]
        ids_ = ids(alert_center.build(context([], [source('Bacula', {'jobs': jobs})])))
        self.assertEqual(ids_, {'Bacula:job:Backup-Z:warning': 'warning'})

    def test_sonde_directe_muette_alerte(self):
        # Audit SUP-16 : fil de sonde arrêté → alerte serveur, plus seulement une tuile périmée.
        now = datetime.now(timezone.utc)
        etat = lambda age: {'enabled': True, 'last_probe_at': (now - timedelta(seconds=age)).isoformat(),
                            'observer': {'ok': True, 'checked_at': (now - timedelta(seconds=age)).isoformat()},
                            'hosts': [{'key': 'db', 'name': 'db', 'status': 'up', 'checked_at': now.isoformat()}]}
        ctx = context([])
        ctx.tier0_snapshot = lambda: etat(120)
        ids_ = ids(alert_center.build(ctx, now))
        self.assertIn('Sonde directe:observer:warning', ids_)
        ctx.tier0_snapshot = lambda: etat(3)
        self.assertNotIn('Sonde directe:observer:warning', ids(alert_center.build(ctx, now)))

    def test_bacula_job_bloque_en_cours_depasse_le_rpo(self):
        # Audit SUP-19 : un job « en cours » depuis des jours n'est plus exempté.
        import bacula_inventory
        import cockpit_v2
        now = datetime.now(timezone.utc)
        stamp = lambda hours: (now - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S+00:00')
        ok = lambda jobid, hours: {'jobid': jobid, 'name': 'Quotidien', 'client': 'c-fd', 'severity': 'ok',
                                   'status_code': 'T', 'endtime': stamp(hours)}
        jobs = [ok(i, 72 + 24 * k) for k, i in enumerate(range(10, 5, -1))]
        jobs.append({'jobid': 11, 'name': 'Quotidien', 'client': 'c-fd', 'severity': 'running',
                     'status_code': 'R', 'endtime': None, 'starttime': stamp(70)})
        late = bacula_inventory.overdue({'jobs': jobs}, now.timestamp())
        self.assertEqual([j['severity'] for j in late], ['running'])
        self.assertEqual(cockpit_v2._bacula({'jobs': jobs})['overdue_count'], 1)

    def test_bacula_derniere_reussite_trop_ancienne_selon_le_rythme_du_job(self):
        import bacula_inventory
        now = datetime.now(timezone.utc)
        stamp = lambda hours: (now - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S+00:00')
        ok = lambda jobid, name, hours: {'jobid': jobid, 'name': name, 'client': 'c-fd', 'severity': 'ok',
                                         'status_code': 'T', 'status_label': 'Terminé sans erreur', 'endtime': stamp(hours)}
        # Job quotidien arrêté depuis 3 jours : seuil 48 h dépassé.
        daily = [ok(i, 'Quotidien', 72 + 24 * k) for k, i in enumerate(range(10, 5, -1))]
        # Job hebdomadaire passé il y a 5 jours : dans son rythme, aucune alerte.
        weekly = [ok(i, 'Hebdo', 120 + 168 * k) for k, i in enumerate(range(30, 26, -1))]
        late = {j['name']: j for j in bacula_inventory.overdue({'jobs': daily + weekly}, now.timestamp())}
        self.assertEqual(set(late), {'Quotidien'})
        self.assertEqual((late['Quotidien']['age_hours'], late['Quotidien']['threshold_hours']), (72, 48))
        ids_ = ids(alert_center.build(context([], [source('Bacula', {'jobs': daily + weekly})])))
        self.assertIn('Bacula:rpo:Quotidien:warning', ids_)
        self.assertNotIn('Bacula:rpo:Hebdo:warning', ids_)
        # Un seul passage réussi connu : seuil par défaut (8 jours).
        single = bacula_inventory.overdue({'jobs': [ok(1, 'Seul', 100)]}, now.timestamp())
        self.assertEqual(single, [])

    def test_failed_source_is_an_alert_itself(self):
        conn = {'key': 'z', 'name': 'ZABBIX', 'provider': 'Zabbix',
                'last_result': {'status': 'unknown', 'error': 'TLS', 'collected_at': NOW}}
        result = alert_center.build(context([], [conn]))
        self.assertEqual(result['alerts'][0]['id'], 'Zabbix:collection:warning')
        self.assertFalse(result['sources'][0]['fresh'])

    def test_elastic_yellow_and_proxmox_memory(self):
        conns = [source('Elasticsearch', {}, indicators={'cluster_status': 'yellow', 'unassigned_shards': 41}),
                 source('Proxmox', {'nodes': [{'name': 'pve03', 'status': 'online', 'memory_bytes': 92, 'memory_total_bytes': 100}]})]
        self.assertEqual(ids(alert_center.build(context([], conns))),
                         {'Elastic:cluster:warning': 'warning', 'Proxmox:node-memory:warning': 'warning'})

    def test_uptime_and_memory_are_preventive_signals(self):
        rows = [host('a', '1.1.1.1', uptime='up 665 days,  6:52', ram=87.0)]
        self.assertEqual(ids(alert_center.build(context(rows))),
                         {'SSH:uptime:preventive': 'preventive', 'SSH:memory:preventive': 'preventive'})

    def test_policy_is_published_with_the_alerts(self):
        result = alert_center.build(context([]))
        self.assertEqual([l['key'] for l in result['levels']], ['critical', 'warning', 'preventive', 'info'])
        self.assertTrue(any(r['domain'] == 'Zabbix' for r in result['policy']))


class VisibilityTests(unittest.TestCase):
    """Audit SUP-01/02 : perte de visibilité signalée, journal d'incidents complet."""

    def test_serveur_deja_audite_devenu_injoignable_produit_l_alerte(self):
        retenu = host('web01', '10.0.0.1', stale=True, status='unknown', at=OLD, audit_retained=True,
                      last_attempt={'status': 'unreachable', 'collected_at': NOW,
                                    'issues': ['Connexion SSH : délai dépassé']})
        alertes = alert_center.build(context([retenu]))['alerts']
        injoignable = [a for a in alertes if a['id'].startswith('SSH:unreachable:')]
        self.assertEqual(len(injoignable), 1)
        self.assertEqual(injoignable[0]['targets'][0]['host_key'], 'web01')
        self.assertTrue(injoignable[0]['fresh'])

    def test_refus_d_authentification_et_empreinte_changee_alertent(self):
        # Audit SUP-01 (suite) : status='critical' sans mesure n'alertait jamais.
        auth = host('db01', '10.0.0.2', status='critical', coverage={'measured': 0},
                    issues=['Accès SSH refusé ou erreur de collecte: Permission denied (publickey)'],
                    findings=[{'id': 'ssh', 'title': 'SSH', 'severity': 'critical'}])
        cle = host('web02', '10.0.0.3', status='critical', coverage={'measured': 0},
                   issues=['Accès SSH refusé ou erreur de collecte: WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!'])
        mesure = host('app01', '10.0.0.4', status='critical', coverage={'measured': 12})
        alertes = {a['id']: a for a in alert_center.build(context([auth, cle, mesure]))['alerts']}
        refus = [a for i, a in alertes.items() if i.startswith('SSH:refused:')]
        empreinte = [a for i, a in alertes.items() if i.startswith('SSH:host_key:')]
        self.assertEqual([(a['severity'], a['targets'][0]['host_key']) for a in refus], [('warning', 'db01')])
        self.assertEqual([(a['severity'], a['targets'][0]['host_key']) for a in empreinte], [('critical', 'web02')])
        self.assertFalse(any('app01' == t['host_key'] for a in refus + empreinte for t in a['targets']),
                         'un audit mesuré n’est pas un échec d’accès')

    def test_echec_ancien_d_un_serveur_jamais_mesure_reste_alerte(self):
        jamais = host('new01', '10.0.0.9', stale=True, status='unknown', at=OLD, last_status='critical',
                      coverage={'measured': 0}, issues=['Accès SSH refusé ou erreur de collecte: Permission denied'])
        alertes = [a for a in alert_center.build(context([jamais]))['alerts'] if a['id'].startswith('SSH:refused:')]
        self.assertEqual(len(alertes), 1)
        self.assertFalse(alertes[0]['fresh'], 'preuve ancienne : à reconfirmer, mais visible')

    def test_audit_retenu_puis_refus_d_empreinte_alerte(self):
        retenu = host('web01', '10.0.0.1', stale=True, status='unknown', at=OLD, audit_retained=True,
                      coverage={'measured': 12},
                      last_attempt={'status': 'critical', 'collected_at': NOW,
                                    'issues': ['Accès SSH refusé : No ED25519 host key is known']})
        ids_ = [a['id'] for a in alert_center.build(context([retenu]))['alerts']]
        self.assertTrue(any(i.startswith('SSH:host_key:') for i in ids_), ids_)

    def test_audit_conserve_sans_echec_de_connexion_ne_cree_pas_d_alerte(self):
        retenu = host('web01', '10.0.0.1', stale=True, status='unknown', at=OLD, audit_retained=True,
                      last_attempt={'status': 'unknown', 'collected_at': NOW, 'issues': ['Collecte partielle']})
        ids_ = [a['id'] for a in alert_center.build(context([retenu]))['alerts']]
        self.assertFalse(any(i.startswith('SSH:unreachable:') for i in ids_))

    def test_echantillon_affiche_mais_toutes_les_cibles_pour_les_incidents(self):
        f = {'id': 'service:tomcat.service', 'title': 'Service tomcat.service : failed', 'severity': 'critical'}
        rows = [host(f'h{i:02}', f'10.0.0.{i}', findings=[f]) for i in range(30)]
        affiche = {a['id']: a for a in alert_center.build(context(rows))['alerts']}
        interne = {a['id']: a for a in alert_center.build(context(rows), for_incidents=True)['alerts']}
        cle = 'SSH:service:tomcat.service:critical'
        self.assertEqual((affiche[cle]['count'], len(affiche[cle]['targets'])), (30, alert_center.ECHANTILLON))
        self.assertTrue(affiche[cle]['truncated'])
        self.assertEqual(len(interne[cle]['targets']), 30)
        self.assertFalse(interne[cle]['truncated'])
        self.assertNotIn('probe', alert_center.build(context(rows)))   # contrat HTTP inchangé

    def test_group_start_uses_all_targets_and_observation_uses_real_instants(self):
        now = datetime(2026, 10, 27, 12, tzinfo=timezone.utc)
        collection = alert_center._Collecte(now)
        for n in range(30):
            collection.ajouter('SSH', 'test-date', 'warning', 'Date de test', f'h{n}',
                               observe='2026-10-27T10:00:00+01:00' if n < 29 else '2026-10-27T09:30:00Z',
                               started_at=(now - timedelta(days=2 if n < 29 else 7)).isoformat())
        collection.ajouter('SSH', 'test-date', 'warning', 'Date de test', 'sans-date')
        with mock.patch.object(alert_center, '_Collecte', return_value=collection):
            item = next(a for a in alert_center.build(context([]), now)['alerts'] if a['id'] == 'SSH:test-date:warning')
        self.assertTrue(item['truncated'])
        self.assertEqual(item['started_at'], (now - timedelta(days=7)).isoformat())
        self.assertFalse(item['started_at_complete'])
        self.assertEqual(item['observed_at'], '2026-10-27T09:30:00Z')


if __name__ == '__main__':
    unittest.main()
