"""Daily evidence must keep freshness and initial-audit policy explicit."""
from routers import all_routes  # routes des APIRouter inclus (FastAPI ne les recopie plus dans app.routes)
import unittest
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import FastAPI
import daily_view


class DailyTests(unittest.TestCase):
    def test_failed_api_keeps_indicators_with_failure_and_original_date(self):
        source = {'key':'es', 'name':'Elastic', 'provider':'Elasticsearch',
                  'last_result':{'status':'unknown', 'collected_at':'2026-09-17T10:01:00+00:00', 'error':'Timeout'},
                  'last_success_result':{'status':'observed', 'collected_at':'2026-09-17T10:00:00+00:00', 'indicators':{'number_of_nodes':3}}}
        context = SimpleNamespace(api_connections=lambda:[source], rows=lambda:[],
            network_rows=lambda:[], connect=lambda:nullcontext(None),
            batch_snapshot=lambda:{'counts':{},'fresh_failures':0,'coverage':[]}, api_sync_state=lambda:{})
        with patch.object(daily_view, 'federate', return_value={'assets':[]}), patch.object(daily_view, 'annotate'):
            row=daily_view.build(context)['sources'][0]
        self.assertEqual(row['indicators']['number_of_nodes'],3)
        self.assertEqual(row['collected_at'],source['last_success_result']['collected_at'])
        self.assertEqual(row['last_attempt_at'],source['last_result']['collected_at'])
        self.assertEqual(row['error'],'Timeout')
        self.assertFalse(row['fresh'])

    def test_old_findings_are_visible_but_not_counted_as_recent(self):
        hosts = [
            {'key':'old', 'name':'Old', 'ip':'192.0.2.1', 'registered':True,
             'active_scope':False, 'audit_recorded':True, 'stale':True,
             'findings':[{'severity':'critical','title':'Old disk alert'}]},
            {'key':'new', 'name':'New', 'ip':'192.0.2.2', 'registered':True,
             'active_scope':True, 'audit_recorded':False, 'stale':False,
             'findings':[{'severity':'warning','title':'Current warning'}]},
        ]
        context = SimpleNamespace(api_connections=lambda:[], rows=lambda:hosts,
            network_rows=lambda:[], connect=lambda:nullcontext(None),
            batch_snapshot=lambda:{'counts':{},'fresh_failures':0,'coverage':[]},
            api_sync_state=lambda:{})
        with patch.object(daily_view, 'federate', return_value={'assets':hosts}), patch.object(daily_view, 'annotate'):
            result=daily_view.build(context)
        self.assertEqual(result['counts']['critical_recent'],0)
        self.assertEqual(result['priorities'][0]['host_key'],'new')
        self.assertEqual(result['counts']['audit_recorded'],1)
        self.assertEqual([h['key'] for h in result['attention']],['new'])

    def test_refresh_keeps_measured_audits_and_runs_other_sources(self):
        hosts=[{'key':'old','audit_recorded':True},
               {'key':'new','audit_recorded':False},
               {'key':'disabled','audit_recorded':False,'collect_enabled':False}]
        context=SimpleNamespace(HOSTS=hosts,rows=lambda:hosts,
            launch=Mock(return_value={}),launch_api_sync=Mock(return_value={}),
            launch_network=Mock(return_value={}),launch_batches=Mock(return_value={}))
        app=FastAPI();daily_view.install(app,context)
        route=next(r for r in all_routes(app) if r.path=='/api/daily/refresh')
        self.assertEqual(route.status_code,202)
        route.endpoint()
        self.assertEqual(context.launch.call_args.args[0],[hosts[1]])
        context.launch_batches.assert_called_once()
        context.launch_api_sync.assert_called_once()
        self.assertEqual(context.launch_network.call_args.args[0],hosts)


if __name__ == '__main__':
    unittest.main()


class RegroupementTests(unittest.TestCase):
    """Une cause massive ne doit plus effacer les anomalies reellement mesurees."""

    def priorites(self):
        # 30 serveurs injoignables en debut d'alphabet, 2 anomalies reelles a la fin.
        p = [{'host_key': f'a{i:02d}', 'host_name': f'a{i:02d}', 'title': 'Connexion SSH indisponible',
              'severity': 'unreachable', 'domain': 'Connexion', 'collected_at': '2026-09-20T01:00:00',
              'stale': False} for i in range(30)]
        p += [
            {'host_key': 'z01', 'host_name': 'z01', 'title': 'Disques : 94 %', 'severity': 'critical',
             'domain': 'Ressources', 'collected_at': '2026-09-20T01:05:00', 'stale': False},
            {'host_key': 'z02', 'host_name': 'z02', 'title': 'Service nginx : failed', 'severity': 'critical',
             'domain': 'Services', 'collected_at': '2026-09-20T01:06:00', 'stale': False},
        ]
        return p

    def test_troncature_laisse_chaque_cause_representee(self):
        import daily_view
        retenus = daily_view.diversified(self.priorites(), 30)
        causes = {p['title'] for p in retenus}
        self.assertEqual(len(retenus), 30)
        self.assertIn('Disques : 94 %', causes, 'une anomalie reelle a ete effacee par la troncature')
        self.assertIn('Service nginx : failed', causes)

    def test_groupes_portent_le_total_exact_pas_l_echantillon(self):
        import daily_view
        groupes = daily_view.group_priorities(self.priorites())
        ssh = next(g for g in groupes if g['title'] == 'Connexion SSH indisponible')
        self.assertEqual(ssh['total'], 30, 'le total doit etre reel, jamais le nombre d echantillons')
        self.assertLessEqual(len(ssh['hosts']), daily_view.GROUP_SAMPLES)
        self.assertTrue(ssh['truncated'])

    def test_critiques_avant_injoignables(self):
        import daily_view
        groupes = daily_view.group_priorities(self.priorites())
        self.assertEqual(groupes[0]['severity'], 'critical')

    def test_preuves_anciennes_reculent(self):
        """Un groupe entierement ancien passe apres les groupes recents."""
        import daily_view
        p = [{'host_key': 'v', 'host_name': 'v', 'title': 'Ancienne', 'severity': 'critical',
              'domain': 'X', 'collected_at': '2026-09-01T00:00:00', 'stale': True},
             {'host_key': 'w', 'host_name': 'w', 'title': 'Recente', 'severity': 'warning',
              'domain': 'X', 'collected_at': '2026-09-20T00:00:00', 'stale': False}]
        groupes = daily_view.group_priorities(p)
        self.assertEqual(groupes[0]['title'], 'Recente')

    def test_liste_courte_inchangee(self):
        import daily_view
        courte = self.priorites()[:5]
        self.assertEqual(daily_view.diversified(courte, 30), courte)


class CollecteEtAffichageTests(unittest.TestCase):
    """Deux defauts constates en exploitation : compteur qui sous-declare,
    et 35 messages bruts identiques dans « Couverture a completer »."""

    def test_compteur_critique_annonce_le_total(self):
        p = [{'severity': 'critical', 'title': 'Disques : 100 %', 'stale': True},
             {'severity': 'critical', 'title': 'postgresql failed', 'stale': True},
             {'severity': 'critical', 'title': 'SSH indisponible', 'stale': False},
             {'severity': 'warning', 'title': 'Disques : 80 %', 'stale': False}]
        total = sum(x['severity'] == 'critical' for x in p)
        recent = sum(x['severity'] == 'critical' and not x['stale'] for x in p)
        stale = sum(x['severity'] == 'critical' and x['stale'] for x in p)
        # Un disque plein ne cesse pas d'etre critique parce que la preuve a vieilli.
        self.assertEqual((total, recent, stale), (3, 1, 2))
        self.assertGreater(total, recent, 'le total doit depasser le seul compte des preuves fraiches')

    def test_sortie_brute_ramenee_a_sa_cause(self):
        import daily_view
        brut = ('SSH/TCP inaccessible: Cible ou bastion inaccessible : vérifier VPN, route, port '
                'et configuration SSH. channel 0: open failed: connect failed: No route to host '
                'stdio forwarding failed Connection closed by UNKNOWN port 65535')
        cause = daily_view.summarize_issue(brut)
        self.assertEqual(cause, 'Aucune route vers l hote')
        self.assertLess(len(cause), 40, 'la cause doit tenir sur une ligne')
        self.assertNotIn('channel 0', cause, 'aucune sortie brute ne doit remonter')

    def test_causes_reconnues(self):
        import daily_view
        for message, attendu in [
            ('ssh: connect to host X port 22: Connection refused', 'Connexion refusee'),
            ('Permission denied (publickey)', 'Authentification refusee'),
            ('Connection timed out during banner exchange', 'Delai depasse'),
            ('Host key verification failed', 'Empreinte SSH non verifiee'),
            ('Audit initial requis', 'Audit initial requis'),
        ]:
            self.assertEqual(daily_view.summarize_issue(message), attendu)

    def test_cause_inconnue_reste_courte(self):
        import daily_view
        cause = daily_view.summarize_issue('X' * 300)
        self.assertLessEqual(len(cause), 71, 'une cause inconnue ne doit pas ramener 300 caracteres')

    def test_message_absent_n_invente_rien(self):
        import daily_view
        self.assertEqual(daily_view.summarize_issue(None), 'Cause non renseignee')
        self.assertEqual(daily_view.summarize_issue(''), 'Cause non renseignee')

    def test_regroupement_couverture_totaux_exacts(self):
        import daily_view
        attention = [{'key': f'h{i}', 'name': f'h{i}', 'ip': '10.0.0.1',
                      'issues': ['No route to host']} for i in range(20)]
        attention += [{'key': 'z', 'name': 'z', 'ip': '10.0.0.2', 'issues': ['Permission denied']}]
        groupes = daily_view.group_attention(attention)
        self.assertEqual(len(groupes), 2)
        self.assertEqual(groupes[0]['total'], 20)
        self.assertLessEqual(len(groupes[0]['hosts']), daily_view.GROUP_SAMPLES)
        self.assertTrue(groupes[0]['truncated'])
