import sqlite3
import unittest
from contextlib import closing
from datetime import datetime, timezone
from asset_registry import enroll, discover, source_details, connection_evidence, initial_audit_hosts


class RegistryTests(unittest.TestCase):
    def test_existing_audits_are_not_automatically_repeated(self):
        old={'key':'old','audit_recorded':True,'stale':True}
        new={'key':'new','audit_recorded':False}
        disabled={'key':'disabled','audit_recorded':False,'collect_enabled':False}
        self.assertEqual(initial_audit_hosts([old,new,disabled]),[new])
    def test_retained_when_down_but_not_reused_for_other_ip(self):
        with closing(sqlite3.connect(':memory:')) as db:
            h={'key':'web','name':'web','ip':'192.0.2.1','active_scope':True}
            enroll(db,[h]); self.assertTrue(h['registered'])
            h['active_scope']=False
            enroll(db,[h]); self.assertTrue(h['registered'])
            h['ip']='192.0.2.2'
            enroll(db,[h]); self.assertFalse(h['registered'])

    def sources(self):
        now=datetime.now(timezone.utc).isoformat()
        return [dict(key='p',provider='Proxmox',last_result=dict(status='observed',collected_at=now,inventory={'nodes':[{'name':'n','guests':[{'name':'web','vmid':10,'status':'running'}]}]})),
                dict(key='z',provider='Zabbix',last_result=dict(status='observed',collected_at=now,inventory={'hosts':[{'host':'web','status':'monitored','addresses':['192.0.2.1']}]}))]

    def test_discovery_is_idempotent_and_requires_both_sources(self):
        s=self.sources(); added,pending=discover([],s)
        self.assertEqual(len(added),1); self.assertFalse(pending)
        self.assertEqual(discover(added,s),( [], [] ))
        self.assertFalse(discover([],s[:1])[0])
        s[1]['last_result']['status']='unknown'
        self.assertFalse(discover([],s)[0])

    def test_ambiguous_or_used_addresses_are_not_imported(self):
        s=self.sources()
        s[1]['last_result']['inventory']['hosts'][0]['addresses'].append('192.0.2.2')
        self.assertFalse(discover([],s)[0])
        s=self.sources()
        self.assertFalse(discover([{'key':'other','name':'other','ip':'192.0.2.1'}],s)[0])

    def test_bacula_client_suffix_and_ambiguity(self):
        hosts=[{'key':'web','name':'web','ip':'192.0.2.1'}]
        source={'key':'b','provider':'Bacula','last_result':{'inventory':{'jobs':[{'client':'web-fd','jobid':2}]}}}
        self.assertEqual(source_details(hosts[0],hosts,[source])[0]['evidence']['jobs_count'],1)
        hosts.append({'key':'web-fd','name':'web-fd','ip':'192.0.2.2'})
        self.assertFalse(source_details(hosts[0],hosts,[source]))

    def test_failure_keeps_old_evidence_but_never_fresh_success(self):
        source={'last_result':{'status':'unknown','error':'TLS'},'last_success_result':{'status':'observed','inventory':{'x':1},'collected_at':'old'}}
        r=connection_evidence(source)
        self.assertEqual(r['inventory'],{'x':1});self.assertEqual(r['status'],'unknown')
        self.assertEqual(r['collected_at'],'old')
