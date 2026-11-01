"""Bounded, read-only scheduling inventory, stored independently of full audits."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
import json
import shlex
import threading

import ssh
from config import candidates

COMMAND = 'python3 -c ' + shlex.quote(Path(__file__).with_name('batch_remote.py').read_text(encoding='utf-8'))
ssh.OPERATIONS['batch_inventory'] = COMMAND


# Audit UI du 31/10 (fiche 06.2) : une source relue à l'instant ne rend pas récent un passage
# ancien. « Récent » se lit sur la date d'exécution (dernier passage), pas sur la date de lecture.
RECENT_RUN_HOURS = 48


def run_recent(last_run, now=None):
    """True/False selon l'âge du dernier passage ; None si la date est absente ou illisible."""
    from bacula_inventory import _epoch
    started = _epoch(last_run) if last_run else None
    if started is None:
        return None
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    return now - started <= RECENT_RUN_HOURS * 3600


def collect_host(host, cfg, requester='batch-local'):
    result = {'key':host['key'], 'ip':host['ip'], 'collected_at':datetime.now(timezone.utc).isoformat(),
              'jobs':[], 'status':'unknown', 'limitations':[]}
    if not host.get('collect_enabled', True):
        result['limitations'] = ['Collecte désactivée pour ce serveur']
        return result
    failures, skip_ports = [], set()
    for candidate in candidates(cfg, host):
        if candidate.port in skip_ports:
            continue
        raw = ssh.run_operation(host['ip'], 'batch_inventory', candidate, requester)
        if raw.rc is not None:
            if not raw.ok:
                result['limitations'] = ['Sonde indisponible : vérifier Python 3 et les droits du compte SSH']
                return result
            try:
                data = json.loads(raw.stdout)
                if not isinstance(data, dict) or not isinstance(data.get('jobs'), list):
                    raise ValueError('format')
                result.update(jobs=data['jobs'][:300], limitations=data.get('limitations', []),
                              timezone=data.get('timezone'), status='observed',
                              crontabs_read=data.get('crontabs_read'), batch_files=data.get('batch_files'),
                              batch_logs=(data.get('batch_logs') or [])[:200],
                              batch_runs=data.get('batch_runs'))
            except (ValueError, TypeError):
                result['limitations'] = ['Réponse de la sonde incomplète ou invalide']
            return result
        failures.append(raw.error_kind)
        if raw.error_kind != 'auth':
            skip_ports.add(candidate.port)
    failure = next((kind for kind in ('host_key','auth','local','ssh','network') if kind in failures), None)
    result['limitations'] = [{'host_key':'Clé SSH non vérifiée', 'auth':'Authentification SSH refusée',
                              'network':'Connexion SSH inaccessible'}.get(failure,'Connexion SSH non mesurée')]
    return result


def snapshot(context):
    from synchronization import fresh
    from asset_registry import connection_evidence, MatchIndex
    from bacula_inventory import latest_jobs
    with context.connect() as db:
        saved = {(k, ip):json.loads(p) for k,ip,p in db.execute('SELECT key,ip,payload FROM batch_states')}
    jobs, coverage = [], []
    hosts = list(context.HOSTS)
    index, by_key = MatchIndex(hosts), {h['key']: h for h in hosts}
    for host in hosts:
        last = saved.get((host['key'], host['ip']), {})
        current = last.get('status') == 'observed' and fresh(last.get('collected_at'))
        evidence = last if last.get('status') == 'observed' else last.get('last_observation', last)
        coverage.append({'host_key':host['key'], 'name':host['name'], 'ip':host['ip'], 'status':last.get('status','unknown'),
                         'fresh':current, 'collected_at':last.get('collected_at'),
                         'limitations':last.get('limitations', ['Inventaire Batch non collecté'])})
        for job in evidence.get('jobs', []):
            jobs.append({**job, 'host_key':host['key'], 'host_name':host['name'], 'ip':host['ip'],
                         'collected_at':evidence.get('collected_at'), 'fresh':current})
    # One row per latest Bacula job name and client, preserving source identity.
    for source in context.api_connections():
        if source['provider'] != 'Bacula':
            continue
        r = connection_evidence(source)
        for job in latest_jobs(r.get('inventory') or {}):
            name, client = job.get('name'), job.get('client')
            alias = str(client or '').lower().rstrip('.')
            aliases = {alias, alias[:-3] if alias.endswith('-fd') else alias} - {''}
            owners = index.owners(aliases)
            host = by_key[next(iter(owners))] if len(owners)==1 else {}
            jobs.append({'id':source['key']+':'+str(job.get('jobid')), 'name':name,'kind':'bacula',
                         'source':source['name'], 'host_key':host.get('key'), 'host_name':host.get('name') or client or 'Client non rapproché',
                         'ip':host.get('ip'), 'state':{'ok':'success','critical':'failed','running':'running','warning':'warning'}.get(job.get('severity'),'unknown'),
                         'schedule':'Horaire planifié non collecté via cette API', 'next_run':None,
                         'last_run':(job.get('starttime') or job.get('endtime')) if job.get('severity')=='running' else (job.get('endtime') or job.get('starttime')), 'timezone':'Fuseau du Director non mesuré',
                         'collected_at':r.get('collected_at'), 'fresh':r.get('status')=='observed' and fresh(r.get('collected_at')),
                         'evidence':job.get('status_label'), 'owner':'Compte du job non mesuré'})
    for job in jobs:
        job['run_recent'] = run_recent(job.get('last_run'))
    return {'jobs':jobs, 'coverage':coverage, 'counts':{s:sum(j['state']==s for j in jobs) for s in ('running','failed','success','scheduled','warning','unknown')},
            'fresh_failures':sum(j['state']=='failed' and j['fresh'] and j['run_recent'] is not False for j in jobs)}


def install(app, context):
    from fastapi import APIRouter, HTTPException
    router = APIRouter()
    # Table batch_states : migration versionnée core_v4_module_tables (migrations.py).
    guard = threading.Lock()
    state = {'running':False,'completed':0,'total':0,'error':None}

    def run(hosts):
        def one(host):
            result = collect_host(host, context.cfg)
            with context.connect() as db:
                prior = db.execute('SELECT ip,payload FROM batch_states WHERE key=?',(host['key'],)).fetchone()
                if result['status']!='observed' and prior and prior[0]==host['ip']:
                    previous=json.loads(prior[1])
                    observed=previous if previous.get('status')=='observed' else previous.get('last_observation')
                    if observed:result['last_observation']=observed
                db.execute('INSERT OR REPLACE INTO batch_states(key,ip,payload) VALUES(?,?,?)',(host['key'],host['ip'],json.dumps(result)))
            with guard:state['completed']+=1
        try:
            with ThreadPoolExecutor(max_workers=min(context.WORKERS,4)) as pool:
                list(pool.map(one,hosts))
        except Exception:
            __import__('logging').getLogger('opscontrol.batch').exception('Collecte batch interrompue')
            with guard:state['error']='Collecte Batch interrompue ; consulter les couvertures par serveur.'
        finally:
            with guard:state['running']=False

    def launch(host_key=None):
        selected = [dict(h) for h in context.HOSTS if host_key is None or h['key']==host_key]
        if host_key is not None and not selected:
            raise HTTPException(404, 'Serveur inconnu')
        if host_key is not None and not selected[0].get('collect_enabled',True):
            raise HTTPException(409, 'Collecte désactivée pour ce serveur')
        with guard:
            if not state['running']:
                hosts=[h for h in selected if h.get('collect_enabled',True)]
                state.update(running=True,completed=0,total=len(hosts),error=None)
                threading.Thread(target=run,args=(hosts,),daemon=True).start()
            return dict(state)

    context.launch_batches=launch
    context.batch_snapshot=lambda: snapshot(context)
    context.batch_job=lambda: dict(state)

    @router.get('/api/batches')
    def get_batches():
        import batch_catalog
        # Référentiel métier rapproché des observations (lecture seule, sans collecte).
        return {**snapshot(context),'job':dict(state),'catalog':batch_catalog.snapshot(context)}

    @router.post('/api/batches/refresh',status_code=202)
    def refresh_batches(host_key: str | None = None):
        return launch(host_key)
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
