import unittest
from datetime import datetime, timezone
from server_alerts import build
from asset_registry import source_details


class ServerAlertTests(unittest.TestCase):
    def setUp(self):
        self.now=datetime(2026,9,18,12,tzinfo=timezone.utc)
        self.host={'key':'web','ip':'192.0.2.1','fingerprint':'a','stale':False,
                   'collected_at':'2026-09-18T11:00:00+00:00',
                   'findings':[{'id':'disk','title':'Disque plein','severity':'critical'}]}

    def test_ssh_first_retained_observation_and_recurrence(self):
        snapshots=[dict(self.host,collected_at='2026-09-18T10:00:00+00:00'),
                   dict(self.host,collected_at='2026-09-18T09:00:00+00:00',findings=[]),
                   dict(self.host,collected_at='2026-09-18T08:00:00+00:00')]
        alert=build(self.host,snapshots,self.now)['items'][0]
        self.assertEqual(alert['duration_seconds'],7200)
        self.assertIn('début réel inconnu',alert['time_basis'])

    def test_stale_duration_is_frozen_and_config_history_is_isolated(self):
        self.host['stale']=True
        snapshots=[dict(self.host,collected_at='2026-09-18T10:00:00+00:00',fingerprint='other-ip')]
        alert=build(self.host,snapshots,self.now)['items'][0]
        self.assertEqual(alert['duration_seconds'],0)
        self.assertFalse(alert['fresh'])

    def test_zabbix_epoch_and_invalid_future_start(self):
        self.host['source_details']=[{'key':'z','provider':'Zabbix','fresh':True,
            'collected_at':self.host['collected_at'],'evidence':{'problems':[
                {'triggerid':'1','description':'Ping','last_change':str(int(self.now.timestamp())-3600),'severity':'warning'},
                {'triggerid':'2','description':'Future','last_change':str(int(self.now.timestamp())+1)}]}}]
        alerts={a['title']:a for a in build(self.host,now=self.now)['items']}
        self.assertEqual(alerts['Ping']['duration_seconds'],3600)
        self.assertIsNone(alerts['Future']['duration_seconds'])

    def test_unknown_onset_is_not_observation_time_for_wazuh_or_backup(self):
        self.host['source_details']=[{'key':'w','provider':'Wazuh','fresh':True,'collected_at':self.host['collected_at'],'evidence':{'agent':{'status':'disconnected'}}},
         {'key':'b','provider':'Bacula','fresh':True,'evidence':{'recent_jobs':[
             {'jobid':3,'name':'Daily','client':'web','severity':'ok'},
             {'jobid':2,'name':'Daily','client':'web','severity':'critical'}]}}]
        alerts=build(self.host,now=self.now)['items']
        self.assertIsNone(next(a for a in alerts if a['source']=='Wazuh')['duration_seconds'])
        self.assertFalse(any(a['source']=='Bacula' for a in alerts))

    def test_uncollected_zabbix_problems_are_not_measured_zero(self):
        source={'key':'z','provider':'Zabbix','last_result':{'inventory':{
            'hosts':[{'host':'web','addresses':['192.0.2.1']}],'problems':None}}}
        evidence=source_details(self.host,[self.host],[source])[0]['evidence']
        self.assertFalse(evidence['problems_measured'])


if __name__=='__main__':unittest.main()
