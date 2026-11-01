import testing_env  # noqa: F401 — base temporaire AVANT tout import d'app (testing_env.py)
from testing_tools import run_tool
import unittest,tempfile,os,json,time,threading,socket,urllib.request,urllib.error,sys
from pathlib import Path
from unittest.mock import patch
from datetime import datetime,timezone,timedelta
from dataclasses import replace
from contextlib import ExitStack
temporary=tempfile.TemporaryDirectory()
os.environ['COCKPIT_DB']=str(Path(temporary.name)/'test.sqlite3')
os.environ['COCKPIT_AUDIT']=str(Path(temporary.name)/'audit.log')
# Les configurations SSH generees vont dans le dossier temporaire, pas dans data/.
os.environ['COCKPIT_SSH_DIR']=str(Path(temporary.name))
import app,ssh,collector,audit_engine,uvicorn
from fixtures import BASE
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  # Integration tests use a bounded fixture and never start production collectors.
  cls.isolation=ExitStack()
  cls.isolation.enter_context(patch.object(app,'HOSTS',[dict(h) for h in app.HOSTS[:8]]))
  cls.isolation.enter_context(patch.object(app,'api_connections',return_value=[]))
  for name in ('launch_network','launch_api_sync','launch_batches'):
   cls.isolation.enter_context(patch.object(app,name,return_value={'running':False}))
  sock=socket.socket();sock.bind(('127.0.0.1',0));cls.url='http://127.0.0.1:'+str(sock.getsockname()[1])
  cls.server=uvicorn.Server(uvicorn.Config(app.app,log_level='error'));cls.thread=threading.Thread(target=cls.server.run,kwargs={'sockets':[sock]},daemon=True);cls.thread.start()
  for _ in range(100):
   if cls.server.started:break
   time.sleep(.02)
  assert cls.server.started
 @classmethod
 def tearDownClass(cls):
  cls.server.should_exit=True;cls.thread.join(5);cls.isolation.close()
 def setUp(self):
  with app.connect() as db:db.execute('DELETE FROM states');db.execute('DELETE FROM history')
  with app.lock:app.monitor.update(interval=0,next_at=None)
 def test_launcher_auto_monitoring_configuration(self):
  # Valeur du lanceur : utilisée quand l'opérateur n'a encore rien choisi.
  with app.connect() as db:db.execute("DELETE FROM settings WHERE name='monitor_interval'")
  with patch.dict(os.environ, {'INFRAOPS_AUTO_INTERVAL':'300'}):
   configured=app.initial_monitoring()
   self.assertEqual(configured['interval'],300)
   self.assertLessEqual(configured['next_at'],time.time())
  for value in ('0','bad','-1','1'):
   with patch.dict(os.environ, {'INFRAOPS_AUTO_INTERVAL':value}):
    self.assertEqual(app.initial_monitoring(),{'interval':0,'next_at':None})
 def request(self,path,method='GET',data=None,headers=None):
  hdr={'X-Cockpit-Request':'1','Content-Type':'application/json'} if headers is None else headers
  req=urllib.request.Request(self.url+path,method=method,data=json.dumps(data).encode() if data is not None else None,headers=hdr)
  try:
   with urllib.request.urlopen(req,timeout=10) as r:return r.status,r.read()
  except urllib.error.HTTPError as e:return e.code,e.read()
 def collect(self,outputs=None,host=None):
  def fake(ip,op,cfg,who):
   out=(outputs or BASE)[op]
   return out if isinstance(out,ssh.RunResult) else ssh.RunResult(True,0,out,'',1)
  with patch.object(collector,'run_operation',fake),patch.object(ssh,'run_operation',fake):
   return collector.collect(host or {'ip':'192.0.2.1','services':[]},app.cfg,'test')
 def test_baseline_coverage(self):
  r=self.collect()
  self.assertEqual(r['cpu'],20);self.assertEqual(r['ram'],40)
  self.assertEqual(r['status'],'unknown')
  self.assertTrue(any(f['id']=='backups' for f in r['findings']))
  self.assertFalse(any(f['id'].startswith('service:') for f in r['findings']))
  self.assertGreater(r['coverage']['measured'],10)
 def test_service_and_runbook(self):
  out=dict(BASE,services=BASE['services'].replace('nginx.service loaded active running','nginx.service loaded failed failed'))
  r=self.collect(out)
  f=next(f for f in r['findings'] if f['id']=='service:nginx.service')
  self.assertEqual(r['status'],'critical')
  self.assertIn('sudo systemctl start',f['solution_command'])
  self.assertFalse(f['executable'])
  self.assertFalse(any('systemctl start' in cmd for cmd in ssh.OPERATIONS.values()))
 def test_unknown_services(self):
  r=self.collect(host={'ip':'192.0.2.1','services':['missing']})
  self.assertTrue(any(f['id']=='service:missing.service' and f['severity']=='unknown' for f in r['findings']))
 def test_security_clock_disk(self):
  out=dict(BASE,clock='NTP=no\nNTPSynchronized=no',ssh_policy='permitrootlogin yes\npasswordauthentication yes',permissions='666 root /etc/passwd\n644 root /etc/shadow',df=BASE['df'].replace('20%','94%'))
  r=self.collect(out);ids={f['id'] for f in r['findings']}
  self.assertTrue({'ntp','permitrootlogin','passwordauthentication','perms:/etc/passwd','perms:/etc/shadow','disk_max'}<=ids)
 def test_permission_denied_unknown(self):
  out=dict(BASE,ssh_policy=ssh.RunResult(False,1,'','Permission denied',1),errors=ssh.RunResult(True,0,'-- No entries --','You are not seeing messages from other users',1))
  r=self.collect(out);checks={c['id']:c for c in r['checks']}
  self.assertEqual(checks['ssh_policy']['status'],'unknown');self.assertEqual(checks['errors']['status'],'unknown')
 def test_redaction(self):
  out=dict(BASE,errors='error token=abc123 password=secret-value https://alice:secret@host/')
  r=self.collect(out);encoded=json.dumps(app.sanitize(r))
  self.assertNotIn('abc123',encoded);self.assertNotIn('secret-value',encoded);self.assertNotIn('alice:secret',encoded)
 def test_http_and_no_execute(self):
  for path in ['/','/app.js','/api/overview','/api/runtime','/api/inventory-report']:
   self.assertEqual(self.request(path)[0],200,path)
  self.assertEqual(len(json.loads(self.request('/api/overview')[1])['hosts']),len(app.HOSTS))
  self.assertIn(self.request('/api/execute','POST',{'command':'touch /tmp/forbidden'})[0],(404,405))
  self.assertEqual(self.request('/api/refresh','POST',headers={})[0],403)
  self.assertEqual(self.request('/api/refresh','POST',headers={'X-Cockpit-Request':'1','Origin':'https://evil.test'})[0],403)
 def test_monitoring(self):
  self.assertEqual(self.request('/api/monitoring','POST',{'interval':300})[0],200)
  self.assertEqual(app.monitor['interval'],300)
  self.assertEqual(self.request('/api/monitoring','POST',{'interval':1})[0],422)
  self.assertEqual(self.request('/api/monitoring','POST',{'interval':60,'command':'bad'})[0],422)
  self.request('/api/monitoring','POST',{'interval':0})
 def test_fiche_avec_enregistrements_publies(self):
  # Fiche serveur : enregistrements du WAF publiés vers ce serveur (published_sites.py).
  status,body=self.request('/api/hosts/'+app.HOSTS[0]['key'])
  self.assertEqual(status,200);self.assertIsInstance(json.loads(body)['published_sites'],list)
 def test_monitoring_non_enregistre_signale(self):
  # Audit BE-06 : un réglage perdu au redémarrage ne doit pas répondre OK.
  with patch.object(app,'write_setting',return_value=False):
   self.assertEqual(self.request('/api/monitoring','POST',{'interval':0})[0],503)
 def test_scheduler_runs(self):
  fired=threading.Event()
  # Le déclenchement ne dépend pas du nombre d’hôtes déjà audités par les autres tests.
  with patch.object(app,'launch',side_effect=lambda *a:fired.set()),patch('asset_registry.initial_audit_hosts',return_value=[app.HOSTS[0]]):
   with app.lock:app.monitor.update(interval=60,next_at=time.time()-1)
   self.assertTrue(fired.wait(3))
 def test_concurrency_persistence(self):
  active=peak=0;seen=[];gate=threading.Lock()
  def fake(h,cfg,who):
   nonlocal active,peak
   with gate:active+=1;peak=max(peak,active);seen.append(h['key'])
   time.sleep(.02)
   with gate:active-=1
   return {'status':'unknown','issues':['Backup non connecté'],'collected_at':datetime.now(timezone.utc).isoformat(),'coverage':{'measured':13,'total':15},'findings':[],'checks':[]}
  with patch.object(app,'collect',fake):
   self.assertEqual(self.request('/api/refresh','POST')[0],202)
   self.request('/api/refresh','POST')
   until=time.time()+8
   while app.job['running'] and time.time()<until:time.sleep(.02)
  self.assertFalse(app.job['running']);self.assertEqual(len(seen),len(app.HOSTS));self.assertLessEqual(peak,app.WORKERS);self.assertGreater(peak,1)
  h=app.HOSTS[0];detail=json.loads(self.request('/api/hosts/'+h['key'])[1]);self.assertEqual(len(detail['history']),1)
  self.assertIsNotNone(detail['collected_at'])
  with app.connect() as db:
   payload=json.loads(db.execute('SELECT payload FROM states WHERE key=?',(h['key'],)).fetchone()[0])
   payload['collected_at']=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
   db.execute('UPDATE states SET payload=? WHERE key=?',(json.dumps(payload),h['key']))
  self.assertTrue(app.rows()[0]['stale'])
 def test_native_allowlist_proxy(self):
  with self.assertRaises(ValueError):ssh.run_operation('192.0.2.1','restart',app.cfg)
  config=Path(temporary.name)/'ssh-config';config.write_text('Host 192.0.2.*\n ProxyJump user@192.0.2.10:3300\n')
  args=ssh.native_args('192.0.2.1',replace(app.cfg,config_path=str(config)))
  self.assertIn('StrictHostKeyChecking=yes',args)
  proc=run_tool(self,[args[0],'-G']+args[1:],kind='ssh',capture_output=True,text=True,timeout=10)
  # Temoin : le ssh disponible honore-t-il seulement un Include, ici et maintenant ?
  # Deux environnements l'en empechent, pour des raisons differentes :
  #  - OpenSSH de Windows refuse un fichier dont l'ACL du dossier temporaire
  #    donne acces a d'autres comptes (« Bad permissions ») ;
  #  - le ssh MSYS livre avec Git ne resout pas un chemin « C:/… » dans Include,
  #    et l'ignore alors en silence.
  # Dans ces deux cas le test ne mesure plus rien : on l'ignore avec sa raison
  # plutot que de laisser un echec rouge permanent masquer une vraie regression.
  # Si le temoin passe et que la configuration d'InfraOps echoue, c'est un defaut.
  control=Path(temporary.name)/'control-config';control.write_text('Include '+str(config).replace('\\','/')+'\n')
  ctl=run_tool(self,[args[0],'-G','-F',str(control).replace('\\','/'),'192.0.2.1'],kind='ssh',capture_output=True,text=True,timeout=10)
  if 'proxyjump user@192.0.2.10:3300' not in ctl.stdout.replace('[','').replace(']',''):
   pertinent=[l for l in ctl.stderr.splitlines() if any(t in l for t in ('Bad permissions','Bad owner','No such file','Permission denied'))]
   raison=pertinent[0].strip() if pertinent else 'Include ignore en silence par '+args[0]
   self.skipTest('Cet environnement empeche ssh d honorer un Include : '+raison)
  self.assertEqual(proc.returncode,0);self.assertIn('proxyjump user@192.0.2.10:3300',proc.stdout.replace('[','').replace(']',''))
 def test_native_output_limit(self):
  with patch.object(ssh,'native_args',return_value=[sys._base_executable,'-c','import sys;sys.stdout.write("x"*2200000)']):
   r=ssh.run_operation('192.0.2.1','os',app.cfg,'test');self.assertFalse(r.ok);self.assertIn('volumineuse',r.stderr)
 def test_lost_connection_stops_extra_probes(self):
  r=self.collect()
  calls=[]
  def failed(ip,op,cfg,who):
   calls.append(op);return ssh.RunResult(False,None,'','timeout',1,'network')
  r=audit_engine.enrich({'ip':'192.0.2.1','services':[]},app.cfg,r,runner=failed)
  self.assertEqual(calls,['identity'])
  self.assertTrue(any(c.get('executed') is False for c in r['checks'] if c['id']=='ssh_policy'))
 def test_history_retention_and_single_host(self):
  h=app.HOSTS[0]
  def fake(*a):return {'status':'unknown','issues':[],'collected_at':datetime.now(timezone.utc).isoformat(),'findings':[],'checks':[]}
  with patch.object(app,'collect',fake):
   for _ in range(22):app.refresh([h],'test')
   self.assertEqual(self.request('/api/hosts/'+h['key']+'/refresh','POST')[0],202)
   until=time.time()+4
   while app.job['running'] and time.time()<until:time.sleep(.01)
  data=json.loads(self.request('/api/hosts/'+h['key'])[1]);self.assertEqual(len(data['history']),20)
  self.assertEqual(self.request('/api/hosts/inconnu/refresh','POST')[0],404)
if __name__=='__main__':unittest.main()


class MonitoringPersistanceTests(unittest.TestCase):
 """L'intervalle choisi par l'operateur doit survivre au mode de lancement."""
 def test_reglage_enregistre_et_relu(self):
  app.write_setting('monitor_interval',300)
  self.assertEqual(app.read_setting('monitor_interval'),'300')
  with patch.dict(os.environ,{},clear=False):
   os.environ.pop('INFRAOPS_AUTO_INTERVAL',None)
   self.assertEqual(app.initial_monitoring()['interval'],300)
 def test_choix_operateur_prioritaire_sur_le_lanceur(self):
  # Le lanceur impose 300 s ; l'opérateur avait choisi 60 s : son choix doit survivre.
  app.write_setting('monitor_interval',60)
  with patch.dict(os.environ,{'INFRAOPS_AUTO_INTERVAL':'300'}):
   self.assertEqual(app.initial_monitoring()['interval'],60)
 def test_valeur_invalide_retombe_a_zero(self):
  app.write_setting('monitor_interval','n importe quoi')
  with patch.dict(os.environ,{},clear=False):
   os.environ.pop('INFRAOPS_AUTO_INTERVAL',None)
   self.assertEqual(app.initial_monitoring()['interval'],0)
 def test_aucun_intervalle_impose_sans_choix(self):
  """On ne lance jamais 87 audits periodiques sans que l'operateur l'ait demande."""
  app.write_setting('monitor_interval',0)
  with patch.dict(os.environ,{},clear=False):
   os.environ.pop('INFRAOPS_AUTO_INTERVAL',None)
   self.assertEqual(app.initial_monitoring(),{'interval':0,'next_at':None})
