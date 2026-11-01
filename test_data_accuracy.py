"""Regressions for source attribution and backup evidence used in daily operation."""
import unittest
from contextlib import nullcontext
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import asset_registry as registry
import bacula_inventory as bacula
import daily_view
import server_alerts
import alert_center


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc).isoformat()
        self.host = {'key':'web','name':'web','ip':'192.0.2.1', 'active_scope':True,
                     'audit_recorded':True,'stale':True,'findings':[]}

    def source(self, jobs):
        return {'key':'b','name':'Backup','provider':'Bacula','last_result':{
            'status':'observed','collected_at':self.now,'inventory':{'jobs':jobs}}}

    def test_same_job_name_different_clients_are_independent(self):
        inv = bacula.jobs({'output':[
            {'name':'Daily','client':'web-fd','jobid':1,'jobstatus':'E'},
            {'name':'Daily','client':'db-fd','jobid':2,'jobstatus':'T'}]})
        self.assertEqual(len(inv['latest']),2)
        self.assertEqual(inv['latest_counts']['critical'],1)

    def test_distinct_old_job_is_not_lost_in_ten_recent_passages(self):
        jobs = [{'name':'Daily','client':'web-fd','jobid':i,'severity':'ok'} for i in range(2,25)]
        jobs.append({'name':'Weekly','client':'web-fd','jobid':1,'severity':'critical','status_label':'Erreur'})
        source = self.source(jobs)
        detail = registry.source_details(self.host,[self.host],[source])
        self.assertEqual(detail[0]['evidence']['jobs_count'],2)
        alerts = server_alerts.build({**self.host,'source_details':detail})['items']
        self.assertEqual(len(alerts),1)
        self.assertIn('Weekly',alerts[0]['title'])

    def test_latest_outside_truncated_history_is_still_associated(self):
        source = self.source([])
        source['last_result']['inventory']['latest'] = [
            {'name':'Weekly','client':'web-fd','jobid':1,'severity':'ok'}]
        result = registry.backup_summaries([self.host],[source])['web']
        self.assertTrue(result['matched'])
        self.assertTrue(result['fresh'])
        source['last_success_result'] = source['last_result']
        source['last_result'] = {'status':'unknown','collected_at':self.now,'error':'Timeout'}
        self.assertFalse(registry.backup_summaries([self.host],[source])['web']['fresh'])

    def test_ambiguous_clients_are_not_assigned(self):
        other = {**self.host, 'key':'other', 'ip':'192.0.2.2'}
        source = self.source([{'name':'Daily','client':'web-fd','jobid':1,'severity':'ok'}])
        self.assertFalse(registry.backup_summaries([self.host,other],[source])['web']['matched'])

    def test_unknown_result_prevents_all_success_summary(self):
        source = self.source([{'name':str(i),'client':'web-fd','jobid':i,'severity':s}
                              for i,s in enumerate(['ok','unknown'])])
        self.assertEqual(registry.backup_summaries([self.host],[source])['web']['severity'],'unknown')

    def test_daily_includes_attributed_zabbix_and_keeps_failed_source_old(self):
        source = {'key':'z','name':'Zabbix','provider':'Zabbix','last_result':{
            'status':'observed','collected_at':self.now,'inventory':{
                'hosts':[{'host':'web','addresses':['192.0.2.1']}],
                'problems':[{'triggerid':'1','hosts':['web'],'description':'Disk full','severity':'critical'}]}}}
        context = SimpleNamespace(api_connections=lambda:[source], rows=lambda:[self.host],
            network_rows=lambda:[], connect=lambda:nullcontext(None),
            batch_snapshot=lambda:{'counts':{},'fresh_failures':0,'coverage':[]},api_sync_state=lambda:{})
        with patch.object(daily_view,'federate',return_value={'assets':[self.host]}), patch.object(daily_view,'annotate'):
            result = daily_view.build(context)
            self.assertEqual(result['counts']['critical_recent'],1)
            self.assertEqual(result['priorities'][0]['source'],'Zabbix')
            self.assertEqual(result['priorities'][0]['host_key'],'web')
            source['last_success_result'] = source['last_result']
            source['last_result'] = {'status':'unknown','error':'Timeout','collected_at':self.now}
            self.assertEqual(daily_view.build(context)['counts']['critical_recent'],0)

    def test_old_ssh_measure_cannot_override_current_zabbix(self):
        h = {**self.host,'storage':{'filesystems':[{'mount':'/','use_pct':20}]}}
        self.assertIsNone(alert_center._mesure_ssh({'web':h},'web','/')[0])

    def test_old_collection_error_is_not_a_recent_alert(self):
        source = self.source([])
        source['last_result'] = {'status':'unknown','error':'Timeout','collected_at':'2020-01-01T00:00:00Z'}
        context = SimpleNamespace(rows=lambda:[],api_connections=lambda:[source])
        self.assertFalse(alert_center.build(context)['alerts'][0]['fresh'])

    def test_ssh_login_failure_does_not_claim_critical_server_outage(self):
        self.host.update(stale=False, findings=[{'id':'ssh','title':'Connexion SSH indisponible','severity':'critical'}])
        alert = server_alerts.build(self.host)['items'][0]
        self.assertEqual(alert['category'], 'collection')
        self.assertEqual(alert['severity'], 'warning')
