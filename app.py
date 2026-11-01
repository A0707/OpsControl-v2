"""FastAPI app: read-only SSH audit of the inventory (hosts.yaml), plus the
network-reachability, WAF, API-connections and synchronization add-ons that
register their own routes via `management.install`/`synchronization.install`.
Collection loops only update local SQLite state, never supervised hosts.
The separate ITSM workflow can write to GLPI after explicit human confirmation."""
import json, os, sqlite3, threading, time, hashlib, getpass  # noqa: F401 — exports historiques du module app
from contextlib import contextmanager, asynccontextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed  # noqa: F401 — exports historiques du module app
from datetime import datetime, timezone, timedelta  # noqa: F401 — exports historiques du module app
from dataclasses import asdict
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import JSONResponse  # noqa: F401 — exports historiques du module app
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from config import load_config, inventory_path
from collector import collect as collect
from audit_engine import redact
from network_audit import collect_network as collect_network
from audit_retention import retain_attempt as retain_attempt, display_audit

# Identifiants API : on complete l'environnement depuis le coffre Windows AVANT
# toute lecture. Sans cela, demarrer le serveur autrement que par le lanceur
# donnait une instance sans aucun secret, ou les cinq collectes echouaient avec
# des messages sans rapport apparent. Une variable deja definie n'est jamais
# ecrasee : le lanceur et les surcharges manuelles gardent la priorite.
import secret_store
SECRETS_CHARGES=secret_store.charger()
BASE=Path(__file__).parent
INVENTORY=inventory_path(BASE/'hosts.yaml')
cfg,HOSTS=load_config(INVENTORY)
for h in HOSTS:
 h.setdefault('environment','À renseigner');h.setdefault('services',[]);h.setdefault('criticality','standard')
if len({h['key'] for h in HOSTS})!=len(HOSTS):raise ValueError('Clés inventaire dupliquées')
DB=Path(os.getenv('COCKPIT_DB',str(BASE/'data/state.sqlite3')))
DB.parent.mkdir(parents=True,exist_ok=True)
# Verrou d'instance pris AVANT tout DDL (WAL, migrations du cœur et des modules) : un
# second processus sur la même base migrait son schéma avant d'être refusé au lifespan
# (OC-AUDIT-014). Verrou déjà tenu (service actif, preflight lancé à côté) : schéma non
# touché, et le lifespan refusera le démarrage comme avant.
import self_monitor
instance_lock=None;SCHEMA_DEFERRED=False
if os.getenv('INFRAOPS_SINGLE_INSTANCE','1')!='0':
 try:instance_lock=self_monitor.acquire_instance_lock(str(DB)+'.lock')
 except RuntimeError:SCHEMA_DEFERRED=True
# WAL : les lectures (pages, SSE) ne bloquent plus pendant l'écriture d'une collecte,
# et synchronous=NORMAL suffit en WAL (pas de corruption, au pire la dernière
# transaction perdue sur coupure secteur). INFRAOPS_SQLITE_WAL=0 garde le mode historique.
SQLITE_WAL=os.getenv('INFRAOPS_SQLITE_WAL','1')!='0'
from read_model_cache import WriteRevisions
_read_model_writes=WriteRevisions()
read_model_revision=_read_model_writes.revision
@contextmanager
def connect():
 db=sqlite3.connect(DB,timeout=30)
 try:
  if SQLITE_WAL:db.execute('PRAGMA synchronous=NORMAL')
  # Clés étrangères appliquées (ON DELETE CASCADE de discovery_hosts) : désactivées par défaut
  # dans SQLite, elles restaient décoratives (audit DB-02). PRAGMA dans le try : une erreur
  # ici laissait la connexion ouverte (DB-07).
  db.execute('PRAGMA foreign_keys=ON')
  with _read_model_writes.track(db):
   with db:yield db
 finally:db.close()
if SQLITE_WAL and not SCHEMA_DEFERRED:
 try:
  _db=sqlite3.connect(DB,timeout=30)
  try:_db.execute('PRAGMA journal_mode=WAL')
  finally:_db.close()
 except sqlite3.Error:SQLITE_WAL=False  # système de fichiers sans mémoire partagée : mode historique
# Schéma du cœur : migrations versionnées (migrations.py), appliquées une seule fois chacune.
import migrations
MIGRATIONS_APPLIED=None
if not SCHEMA_DEFERRED:
 _mdb=sqlite3.connect(DB,timeout=30)
 try:MIGRATIONS_APPLIED=migrations.apply(_mdb)
 finally:_mdb.close()
WORKERS=max(1,min(16,int(os.getenv('COCKPIT_WORKERS','4'))))
SNAPSHOT_DAYS=7
BATCH_EVERY=1800
batch_last=[0.0]
# Rétention (retention.py) : première purge 5 min après le démarrage, puis toutes les heures.
RETENTION_EVERY=3600
retention_last=[time.time()-RETENTION_EVERY+300]
lock=threading.Lock();stop=threading.Event()
job={'running':False,'completed':0,'total':0,'error':None,'scope':'all','started_at':None}
def read_setting(name):
 try:
  with connect() as db:
   row=db.execute('SELECT value FROM settings WHERE name=?',(name,)).fetchone()
   return row[0] if row else None
 except sqlite3.Error:
  return None
def write_setting(name,value):
 # Échec signalé (et journalisé) : la route ne répond plus « OK » pour un réglage non
 # enregistré qui serait perdu au redémarrage (audit BE-06).
 try:
  with connect() as db:db.execute('INSERT OR REPLACE INTO settings(name,value) VALUES(?,?)',(name,str(value)))
  return True
 except sqlite3.Error:
  __import__('logging').getLogger('opscontrol').exception('Réglage %s non enregistré',name)
  return False
def initial_monitoring():
 """Intervalle d'actualisation au demarrage.

 Ordre : dernier choix enregistre de l'operateur, puis variable d'environnement
 (valeur par defaut du lanceur ou du service), puis 0. L'ordre inverse faisait
 ecraser le choix de l'operateur a chaque redemarrage par le lanceur (60 s
 choisi, 300 s impose : constate le 26/09). Sans la persistance, demarrer autrement que
 par le lanceur remettait l'intervalle a 0 : plus aucune collecte automatique,
 les audits vieillissaient, et les etats reels basculaient en « Incomplet ».
 Constate en exploitation : 52 hotes sur 87 figes depuis trois jours.

 On ne choisit jamais d'intervalle a la place de l'operateur : on restitue le
 sien. Lancer 87 audits SSH periodiques sans qu'il l'ait demande serait une
 charge imposee a son infrastructure."""
 brut=read_setting('monitor_interval') or os.getenv('INFRAOPS_AUTO_INTERVAL') or '0'
 try:interval=int(brut)
 except (TypeError,ValueError):interval=0
 if interval not in (0,60,300,900):interval=0
 return {'interval':interval,'next_at':time.time() if interval else None}
monitor=initial_monitoring()
net_lock=threading.Lock()
net_job={'running':False,'completed':0,'total':0,'error':None}
# asdict(cfg) était recalculé pour chaque serveur à chaque lecture (lot 7) ; cfg n'est jamais
# modifié en place (replace() crée un nouvel objet) : on le mémorise tant que l'objet est le même.
_cfg_memo=[None,None]
def cfg_dict():
 if _cfg_memo[0] is not cfg:_cfg_memo[:]=[cfg,asdict(cfg)]
 return _cfg_memo[1]
def data_revision():
 """Révision bon marché des données servies (lot 7) : toute écriture la change.

 INSERT OR REPLACE attribue un nouveau rowid : max(rowid) et count(*) suffisent à détecter
 un nouvel audit, une nouvelle sonde, un nouvel inventaire batch ou une inscription."""
 parts=[]
 with connect() as db:
  for table in ('states','network','batch_states','registered_assets'):
   try:parts.append(db.execute('SELECT max(rowid),count(*) FROM '+table).fetchone())
   except sqlite3.OperationalError:parts.append(None)
 with lock:progress=(dict(job),dict(monitor))
 with net_lock:net=dict(net_job)
 api=globals()['api_revision']() if 'api_revision' in globals() else None
 sync=globals()['api_sync_state']() if 'api_sync_state' in globals() else None
 return json.dumps([parts,progress,net,api,sync,len(HOSTS),[h.get('key') for h in HOSTS[:1]+HOSTS[-1:]]],sort_keys=True,default=str)
def fingerprint(h):
 """Hash of the host fields/config that affect what gets collected. A stored
 configuration changes require a new audit; a prior observation for the same
 IP remains visible with an explicit configuration-change warning."""
 data={'cfg':cfg_dict(),'host':{k:h.get(k) for k in ['ip','role','services','user','port','key_path','ssh_host','ssh_config','collect_enabled']},'version':5}
 from waf_audit import is_waf_host
 if is_waf_host(h):data['waf_version']=2
 return hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
def sanitize(v):
 """Recursively redact secrets from collected data before it is stored or served."""
 if isinstance(v,str):return redact(v)
 if isinstance(v,list):return [sanitize(x) for x in v]
 if isinstance(v,dict):return {k:sanitize(x) for k,x in v.items()}
 return v
# Charges d'audit déjà désérialisées, par clé : (texte, objet). Réanalyser les ~1,8 Mo de
# `states` coûtait ~100 ms par appel (mesuré le 06/10), et /api/tier0 appelle rows() toutes
# les quelques secondes. Les objets en cache sont PARTAGÉS : aucun consommateur ne les
# modifie en place (vérifié ; waf_findings.decorate recrée row['waf']).
_parsed={}
def rows():
 """Inventory joined with each host's last stored audit (or an 'Audit initial
 requis' placeholder), marking results older than 15 minutes as stale."""
 with connect() as db:raw=db.execute('SELECT key,ip,payload FROM states').fetchall()
 saved={}
 for k,ip,p in raw:
  memo=_parsed.get(k)
  if memo is None or memo[0]!=p:memo=_parsed[k]=(p,json.loads(p))
  saved[k]=(ip,memo[1])
 for k in set(_parsed)-set(saved):_parsed.pop(k,None)
 out=[]
 for h in HOSTS:
  prior=saved.get(h['key'])
  s=display_audit(prior[1] if prior and prior[0]==h['ip'] else None,fingerprint(h),copy=False)
  row={**h,**s}
  if row.get('waf'):
   from waf_findings import decorate
   decorate(row)
  out.append(row)
 return out
# Collectes en tâche de fond et planificateur : jobs.py (lot J60-J90). Les fonctions y lisent
# l'état de CE module au moment de l'appel ; réexportées ici sous leurs noms historiques.
import sys, jobs
jobs.bind(sys.modules[__name__])
refresh=jobs.refresh;launch=jobs.launch;refresh_network=jobs.refresh_network;launch_network=jobs.launch_network
enroll_assets=jobs.enroll_assets;collection_done=jobs.collection_done;run_retention=jobs.run_retention;scheduler=jobs.scheduler
# Rappels après collecte (rapprochement des incidents…), appelés par jobs.collection_done.
collection_hooks=[]
def network_rows():
 with connect() as db:saved={(k,ip):json.loads(p) for k,ip,p in db.execute('SELECT key,ip,payload FROM network')}
 empty={'collected_at':None,'ping':None,'ports':[],'ssh_key_known':None}
 return [{'key':h['key'],'name':h['name'],'ip':h['ip'],'environment':h['environment'],'role':h['role'],**saved.get((h['key'],h['ip']),empty)} for h in HOSTS]
import self_monitor
from self_monitor import MONITOR as MONITOR
lifespan_started=False;verrous_conserves=[]
retention_last_counts={}
@asynccontextmanager
async def lifespan(app):
 global instance_lock,lifespan_started
 # Un seul processus par base : tâches, verrous et planificateur vivent en mémoire.
 # Verrou déjà pris à l'import (avant les migrations) : conservé ; sinon pris ici, et
 # refusé si une autre instance le tient (schéma alors laissé intact, SCHEMA_DEFERRED).
 if os.getenv('INFRAOPS_SINGLE_INSTANCE','1')!='0' and instance_lock is None:
  instance_lock=self_monitor.acquire_instance_lock(str(DB)+'.lock')
 from run_infraops import application_tunnel
 restants=[]
 try:
  with application_tunnel(globals()['api_connections']):
   stop.clear();jobs.spawn(scheduler,name='planificateur')
   globals()['start_incident_sync']()  # après le verrou d'instance (incident_center, audit BE-03)
   globals()['start_itsm_sync']()  # relecture des statuts GLPI, lecture seule (itsm.py)
   lifespan_started=True
   try:yield
   finally:
    stop.set();globals()['stop_incident_sync']();globals()['stop_itsm_sync']()
    # Tous les producteurs (collectes, rétention, boucles) attendus avant de rendre le
    # verrou : sinon une collecte lente écrivait encore sous une nouvelle instance (OC-AUDIT-013).
    try:delai=float(os.getenv('INFRAOPS_STOP_SECONDS','20'))
    except ValueError:delai=20.0
    restants=jobs.drain(delai);lifespan_started=False
 finally:
  if 'security_read_cache_close' in globals():globals()['security_read_cache_close']()
  if restants:
   # Verrou conservé (référence gardée : fermer le fichier le libérerait) ; le système le
   # rend à la fin du processus, quand ces fils démons meurent avec lui.
   verrous_conserves.append(instance_lock)
   __import__('logging').getLogger('opscontrol').warning('Arrêt : travaux encore actifs, verrou d’instance conservé jusqu’à la fin du processus : %s',', '.join(restants))
  else:
   self_monitor.release_instance_lock(instance_lock)
  instance_lock=None
# Documentation OpenAPI désactivée par défaut : elle cartographie toutes les routes (INFRAOPS_API_DOCS=1 pour l'activer).
_docs=os.getenv('INFRAOPS_API_DOCS')=='1'
app=FastAPI(title='OpsControl — Infrastructure Operations Center',version='5.0.0',lifespan=lifespan,
            docs_url='/docs' if _docs else None,redoc_url=None,openapi_url='/openapi.json' if _docs else None)
# /api/overview pesait ~1,8 Mo avant payload_slim (environ 0,49 Mo sur le parc
# mesuré le 03/10/2026). GZip protège encore les parcs plus grands ; Starlette
# exclut text/event-stream, le flux SSE reste donc intact.
app.add_middleware(GZipMiddleware,minimum_size=2048)
# Politique d'accès centralisée (access_policy.py) : rôles, CSRF, quotas, request ID,
# audit des mutations, en-têtes de sécurité, erreurs sans chemin ni secret.
import access_policy, logging_setup
logging_setup.configure()  # journaux opscontrol.* en JSON (request_id, UTC) sur stderr
access_policy.install(app,connect,migrate_schema=not SCHEMA_DEFERRED)
# Noms d'hôte acceptés (en-tête Host) : INFRAOPS_ALLOWED_HOSTS, sinon accès local uniquement.
from starlette.middleware.trustedhost import TrustedHostMiddleware
_hosts=[h.strip() for h in os.getenv('INFRAOPS_ALLOWED_HOSTS','localhost,127.0.0.1,[::1],*.localhost').split(',') if h.strip()]
if '*' not in _hosts:app.add_middleware(TrustedHostMiddleware,allowed_hosts=_hosts)
import response_cache as response_cache
# Routes HTTP du cœur : routers/ (un APIRouter par domaine), mêmes chemins et même ordre
# d'enregistrement qu'avant. Les fonctions restent accessibles ici pour les tests et modules.
import sys
from routers import fleet as fleet_routes, hosts as hosts_routes, network as network_routes, system as system_routes
hosts_routes.install(app, sys.modules[__name__])
system_routes.install(app, sys.modules[__name__])
network_routes.install(app, sys.modules[__name__])
overview=fleet_routes.overview;services_all=fleet_routes.services_all;findings_all=fleet_routes.findings_all
federated=hosts_routes.federated
import management, sys
management.install(app, sys.modules[__name__])
# Accès SSH depuis l’interface : empreintes, test de connexion, modification groupée.
import host_access
host_access.install(app, sys.modules[__name__])
# Découverte réseau (plage privée) et ajout des machines nouvelles à l’inventaire.
import network_discovery
network_discovery.install(app, sys.modules[__name__])
import critical_monitor
critical_monitor.install(sys.modules[__name__])
import tier0
tier0.install(app, sys.modules[__name__])
import ssh_refresh
ssh_refresh.install(app, sys.modules[__name__])
import inventory_completion
inventory_completion.install(app, sys.modules[__name__])
import synchronization
synchronization.install(app, sys.modules[__name__])
import realtime
realtime.install(app, sys.modules[__name__])
import batch_monitor, daily_view
batch_monitor.install(app, sys.modules[__name__])
daily_view.install(app, sys.modules[__name__])
import shares_view, alert_center
shares_view.install(app, sys.modules[__name__])
alert_center.install(app, sys.modules[__name__])
# Contrôle au démarrage (sources API + réseau, sans SSH) et bilan à l’ouverture (/api/briefing).
import startup_check
startup_check.install(app, sys.modules[__name__])
# OpsControl V2 : synthèse compacte des sources (lecture des collectes enregistrées).
import cockpit_v2
cockpit_v2.install(app, sys.modules[__name__])
import apache_health
apache_health.install(app, sys.modules[__name__])
# Identité opérateur : reverse proxy de confiance uniquement (operator_identity.py).
import operator_identity
operator_identity.install(app)
# Journal d'incidents persistant (incident_center.py), alimenté par le centre d'alertes.
import incident_center
incident_center.install(app, sys.modules[__name__], start_thread=os.getenv('INFRAOPS_INCIDENT_SYNC','1')!='0')
import itsm
itsm.install(app, sys.modules[__name__])
# Sécurité & CVE (security_cve.py) : paquets relevés en SSH (liste fermée), Wazuh, veille
# publique, remédiation en texte ; les tickets passent par le workflow ITSM ci-dessus.
import security_cve
security_cve.install(app, sys.modules[__name__])
# Rapport de passation (/api/handover) : lecture seule du journal d'incidents et des dossiers ITSM.
import handover
handover.install(app, sys.modules[__name__])
# Vue globale, services et constats (réponses en cache) : routers/fleet.py, après les modules
# (comme avant) car la vue lit api_sync_state et batch_job qu'ils installent.
fleet_routes.install(app, sys.modules[__name__])
# Supervision d'OpsControl lui-même (self_monitor.py) : /health/live, /health/ready,
# /api/self-monitoring, /api/metrics (INFRAOPS_METRICS=1). Installé en dernier pour
# instrumenter la collecte API déclarée par management.
self_monitor.install(app, sys.modules[__name__])
# Assistant IA local : lecture seule, indépendant des outils de collecte.
import ai_service
ai_service.install(app, sys.modules[__name__])
app.mount('/',StaticFiles(directory=str(BASE/'web'),html=True),name='web')


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='127.0.0.1', port=int(os.environ.get('INFRAOPS_PORT', '8001')))
