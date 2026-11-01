import json
import sqlite3
import unittest
from contextlib import closing, contextmanager
from types import SimpleNamespace
from unittest.mock import patch
from datetime import datetime,timedelta,timezone
import batch_remote as probe
import batch_monitor as monitor
import ssh


class BatchProbeTests(unittest.TestCase):
    def test_running_scripts_keep_pid_owner_without_command_arguments(self):
        rows = probe.process_rows('42 app 90 /usr/bin/python3 /opt/import.py --token secret-value\n'
                                  '43 root 3 /usr/sbin/nginx -g secret-value\n'
                                  '44 app 5 python3 -c "print(secret-value)"\n'
                                  '45 app 12 /bin/bash /var/batch/run.sh --password secret-value', 'UTC')
        self.assertEqual([r['pid'] for r in rows], [42,45])
        self.assertEqual(rows[0]['owner'], 'app')
        self.assertEqual(rows[0]['elapsed_seconds'], 90)
        self.assertTrue(all(r['state']=='running' for r in rows))
        self.assertNotIn('secret-value', json.dumps(rows))

    def test_refresh_selects_only_requested_server(self):
        from fastapi import FastAPI, HTTPException
        context = SimpleNamespace(HOSTS=[{'key':'a','ip':'192.0.2.1'},
                                        {'key':'b','ip':'192.0.2.2'},
                                        {'key':'c','ip':'192.0.2.3','collect_enabled':False}])
        monitor.install(FastAPI(), context)
        with patch.object(monitor.threading, 'Thread') as thread:
            state = context.launch_batches('b')
        self.assertEqual(state['total'], 1)
        self.assertEqual(thread.call_args.kwargs['args'][0][0]['key'], 'b')
        with self.assertRaises(HTTPException) as error:
            context.launch_batches('missing')
        self.assertEqual(error.exception.status_code, 404)
        with self.assertRaises(HTTPException) as error:
            context.launch_batches('c')
        self.assertEqual(error.exception.status_code, 409)

    def test_script_paths_from_interpreters_cd_and_report_wrapper(self):
        commands = [
            ('/bin/bash /opt/nightly.sh --password=secret-value', '/opt/nightly.sh'),
            ('python3 /opt/import.py --token secret-value', '/opt/import.py'),
            ('cd /var/batch/import && ./run_import.sh >> /var/log/import.log 2>&1', '/var/batch/import/run_import.sh'),
            ('/usr/local/bin/infraops-batch-report import /bin/sh -c "cd /var/batch/import && ./run_import.sh --token secret-value"', '/var/batch/import/run_import.sh'),
        ]
        for command, script in commands:
            with self.subTest(command=command):
                rows = probe.cron_rows('0 2 * * * '+command, 'crontab:app', 'app')
                self.assertEqual(rows[0]['script'], script)
                self.assertNotIn('secret-value', json.dumps(rows))
        for command in ('python3 -c "print(secret-value)"', '/bin/sh -c "echo secret-value"'):
            self.assertIsNone(probe.command_metadata(command)['script'])
            self.assertNotIn('secret-value', json.dumps(probe.command_metadata(command)))

    def test_systemd_script_metadata_omits_arguments(self):
        timer = {'Id':'import.timer', 'Unit':'import.service'}
        service = {'Id':'import.service', 'ExecStart':'{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 /opt/import.py --password=secret-value ; ignore_errors=no ; }'}
        row = probe.timer_rows([timer], [service], 'UTC')[0]
        self.assertEqual(row['script'], '/opt/import.py')
        self.assertEqual(row['executable'], '/usr/bin/python3')
        self.assertNotIn('secret-value', json.dumps(row))

    def test_probe_remains_python36_compatible(self):
        import ast
        from pathlib import Path
        ast.parse(Path(probe.__file__).read_text(encoding='utf-8'), feature_version=(3, 6))

    def test_main_reads_other_crontabs_and_lists_periodic_scripts(self):
        import io
        import sys
        from unittest.mock import mock_open
        output = io.StringIO()
        listing = {'/var/spool/cron/*':['/var/spool/cron/app'],
                   '/etc/cron.daily/*':['/etc/cron.daily/cleanup']}
        with patch.dict(sys.modules, {'pwd':SimpleNamespace(getpwuid=lambda uid:SimpleNamespace(pw_name='audit'))}), \
                patch.object(probe.os, 'getuid', return_value=1000, create=True), \
                patch.object(probe.glob, 'glob', side_effect=lambda pattern:listing.get(pattern, [])), \
                patch.object(probe.os.path, 'isfile', return_value=True), \
                patch.object(probe.os, 'access', return_value=True), \
                patch('builtins.open', mock_open(read_data='0 2 * * * /opt/import.sh --token secret-value')), \
                patch.object(probe.subprocess, 'run', return_value=SimpleNamespace(returncode=1,stdout='',stderr='no crontab for audit')) as run, \
                patch('sys.stdout', output):
            probe.main()
        result = json.loads(output.getvalue())
        imported = next(j for j in result['jobs'] if j['script']=='/opt/import.sh')
        self.assertEqual(imported['owner'], 'app')
        periodic = next(j for j in result['jobs'] if j['script']=='/etc/cron.daily/cleanup')
        self.assertEqual(periodic['state'], 'unknown')
        self.assertNotIn('secret-value', output.getvalue())
        self.assertTrue(all(c.args[0][0] in ('timedatectl','crontab','systemctl','ps') for c in run.call_args_list))

    def test_latest_bacula_outside_history_and_running_start(self):
        now = datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE batch_states(key TEXT,ip TEXT,payload TEXT)')
            @contextmanager
            def connect(): yield db
            source = {'key':'b', 'name':'Director', 'provider':'Bacula', 'last_result':{
                'status':'observed', 'collected_at':now, 'inventory':{
                    'latest':[{'jobid':1, 'name':'Weekly', 'client':'web-fd', 'severity':'running', 'starttime':now},
                              {'jobid':2, 'name':'Daily', 'client':'db-fd', 'severity':'ok'}],
                    'jobs':[{'jobid':3, 'name':'Daily', 'client':'db-fd', 'severity':'critical'}]}}}
            context = SimpleNamespace(connect=connect, HOSTS=[{'key':'web','name':'web','ip':'192.0.2.1'}], api_connections=lambda:[source])
            result = monitor.snapshot(context)
            self.assertEqual(len(result['jobs']), 2)
            weekly = next(j for j in result['jobs'] if j['name']=='Weekly')
            self.assertEqual(weekly['host_key'], 'web')
            self.assertEqual(weekly['last_run'], now)
            self.assertEqual(weekly['state'], 'running')
            daily = next(j for j in result['jobs'] if j['name']=='Daily')
            self.assertEqual(daily['state'], 'failed')
            self.assertIsNone(daily['host_key'])
            source['last_success_result'] = source['last_result']
            source['last_result'] = {'status':'unknown','collected_at':now}
            self.assertTrue(all(not j['fresh'] for j in monitor.snapshot(context)['jobs']))

    def test_cron_timezone_system_owner_and_secret_omission(self):
        rows=probe.cron_rows('CRON_TZ=Africa/Casablanca\nTOKEN=do-not-expose\n15 2 * * 1-5 app /opt/nightly --password=secret-value\n# disabled\n@reboot root /bin/sh -c "echo secret-command"','/etc/crontab','root',system=True)
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['schedule'],'15 2 * * 1-5')
        self.assertEqual(rows[0]['timezone'],'Africa/Casablanca')
        self.assertEqual(rows[0]['owner'],'app')
        self.assertEqual(rows[0]['name'],'nightly')
        self.assertEqual(rows[0]['state'],'scheduled')
        self.assertIsNone(rows[0]['last_run'])
        for secret in ('secret-value','secret-command','do-not-expose'):
            self.assertNotIn(secret,json.dumps(rows))

    def test_timer_inactive_success_requires_execution_evidence(self):
        timer={'Id':'backup.timer','Unit':'backup.service','ActiveState':'active','LastTriggerUSec':'Thu 02:00','NextElapseUSecRealtime':'Fri 02:00'}
        service={'Id':'backup.service','ActiveState':'inactive','Result':'success','ExecMainExitTimestamp':''}
        self.assertEqual(probe.timer_rows([timer],[service],'UTC')[0]['state'],'unknown')
        service['ExecMainExitTimestamp']='Thu 02:05'
        self.assertEqual(probe.timer_rows([timer],[service],'UTC')[0]['state'],'success')
        service['Result']='exit-code'
        self.assertEqual(probe.timer_rows([timer],[service],'UTC')[0]['state'],'failed')
        service.update(ActiveState='active',SubState='running',Result='success')
        self.assertEqual(probe.timer_rows([timer],[service],'UTC')[0]['state'],'running')

    def test_collect_failure_and_payload_are_separate(self):
        host={'key':'a','ip':'192.0.2.1'}
        cfg=ssh.SSHConfig(user='test',key_path='unused')
        with patch.object(ssh,'run_operation',return_value=ssh.RunResult(False,None,'','private-error',1,'host_key')) as run:
            r=monitor.collect_host(host,cfg)
            self.assertEqual(r['status'],'unknown');self.assertIn('Clé SSH',r['limitations'][0])
            self.assertEqual(run.call_args.args[1],'batch_inventory')
            self.assertNotIn('private-error',json.dumps(r))
        with patch.object(ssh,'run_operation',return_value=ssh.RunResult(True,0,'{"jobs": [], "limitations": ["partial"]}','',1,'')):
            self.assertEqual(monitor.collect_host(host,cfg)['limitations'],['partial'])

    def test_stale_snapshot_retained_and_bacula_latest_only(self):
        now=datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE batch_states(key TEXT,ip TEXT,payload TEXT)')
            db.execute('INSERT INTO batch_states VALUES(?,?,?)',('a','192.0.2.1',json.dumps({'status':'unknown','collected_at':now,'last_observation':{'jobs':[{'id':'x','state':'failed'}],'collected_at':'old'}})))
            @contextmanager
            def connect(): yield db
            context=SimpleNamespace(connect=connect,HOSTS=[{'key':'a','name':'web','ip':'192.0.2.1'}],api_connections=lambda:[{'key':'b','name':'Director','provider':'Bacula','last_result':{'status':'observed','collected_at':now,'inventory':{'jobs':[{'jobid':1,'name':'backup','client':'web-fd','severity':'critical'},{'jobid':2,'name':'backup','client':'web-fd','severity':'ok'}]}}}])
            r=monitor.snapshot(context)
            self.assertEqual(len(r['jobs']),2)
            self.assertFalse(r['jobs'][0]['fresh'])
            self.assertEqual(r['jobs'][1]['state'],'success')
            self.assertEqual(r['jobs'][1]['host_key'],'a')
            self.assertEqual(r['fresh_failures'],0)

    def test_old_failure_read_today_is_not_recent(self):
        # Audit UI du 31/10 (fiche 06.2) : un échec du 21/09 relu aujourd'hui reste daté du 21/09.
        now=datetime.now(timezone.utc)
        recent=(now-timedelta(hours=3)).isoformat()
        with closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE batch_states(key TEXT,ip TEXT,payload TEXT)')
            @contextmanager
            def connect(): yield db
            inv={'jobs':[{'jobid':1,'name':'copy-pg17','client':'pg-fd','severity':'critical','endtime':'2026-09-21 03:00:00'},
                         {'jobid':2,'name':'backup-web','client':'web-fd','severity':'critical','endtime':recent}]}
            context=SimpleNamespace(connect=connect,HOSTS=[],api_connections=lambda:[{'key':'b','name':'Director','provider':'Bacula',
                'last_result':{'status':'observed','collected_at':now.isoformat(),'inventory':inv}}])
            r=monitor.snapshot(context)
        by_name={j['name']:j for j in r['jobs']}
        self.assertTrue(by_name['copy-pg17']['fresh'])
        self.assertFalse(by_name['copy-pg17']['run_recent'])
        self.assertTrue(by_name['backup-web']['run_recent'])
        self.assertEqual(r['fresh_failures'],1)
        self.assertIsNone(monitor.run_recent(None))

    def test_remote_program_never_executes_cron_content(self):
        self.assertNotIn('shell=True',monitor.COMMAND)
        self.assertNotIn('sudo ',monitor.COMMAND)
        self.assertNotIn('systemctl start',monitor.COMMAND)
