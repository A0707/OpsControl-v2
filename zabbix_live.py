"""Métriques Zabbix en direct des serveurs critiques (item.get), toutes les 10 s.

Les tuiles des serveurs critiques affichaient CPU, RAM et disque issus du
dernier audit SSH, parfois vieux de plusieurs jours. Zabbix mesure ces valeurs
en continu : on lit sa dernière valeur (`lastvalue`) pour quelques items choisis,
sur ces seuls hôtes.

Honnêteté sur la fraîcheur : l'âge affiché est celui de la MESURE Zabbix
(`lastclock`), pas celui de notre requête. Sur le parc actuel, ces items sont
relevés toutes les minutes (constaté : délai `1m`) : lire Zabbix toutes les
10 s donne une valeur de moins de 70 s, pas de moins de 15 s. Pour descendre
sous 15 s, c'est l'intervalle des items qu'il faut réduire dans Zabbix
(deploy/README.md, §8) — et ce module affichera alors des mesures plus jeunes
sans modification.

Même garantie que le reste de la plateforme : méthode et paramètres figés ici ;
seule la liste d'identifiants d'hôtes varie, tirée de l'inventaire Zabbix déjà
collecté et validée (chiffres uniquement). Jamais d'entrée venant du client.
"""
from __future__ import annotations

import os
import re
import time

# Items lus, par motif de clé (jokers Zabbix). Choisis sur les modèles réellement
# déployés (« Linux by Zabbix agent ») : relevé du 26/09 sur les 3 hôtes critiques.
LIVE_KEYS = [
    'agent.ping',
    'system.cpu.util[,idle]',
    'system.cpu.util[,iowait]',
    'system.cpu.util',
    'system.cpu.load[percpu,avg1]',
    'vm.memory.size[available]',
    'vm.memory.size[total]',
    'vm.memory.size[pavailable]',
    'vm.memory.utilization',
    'vfs.fs.size[*,pused]',
    'vfs.fs.size[*,pfree]',
    'proc.num[,,run]',
    'system.uptime',
    # Résultats des batchs : fichiers d'état de deploy/infraops-batch-report.sh,
    # lus par l'agent (UserParameter, deploy/zabbix-agent-infraops-batch.conf).
    'infraops.batch.rc[*]',
    'infraops.batch.started[*]',
    'infraops.batch.finished[*]',
    'infraops.batch.duration[*]',
]
OUTPUT = ['itemid', 'hostid', 'key_', 'lastvalue', 'lastclock', 'delay', 'state', 'error']
MAX_HOSTS = 20
MAX_ITEMS_PER_HOST = 400   # ~85 batchs × 3 items + métriques système
BATCH_KEY = re.compile(r'infraops\.batch\.(rc|started|finished|duration)\[(.+)\]')


def body(hostids):
    ids = [str(h) for h in hostids][:MAX_HOSTS]
    if not ids or not all(re.fullmatch(r'\d{1,20}', i) for i in ids):
        raise ValueError('Identifiants d’hôtes Zabbix invalides')
    return {'jsonrpc': '2.0', 'id': 10, 'method': 'item.get', 'params': {
        'output': OUTPUT, 'hostids': ids, 'monitored': True,
        'search': {'key_': LIVE_KEYS}, 'searchByAny': True, 'searchWildcardsEnabled': True,
        'limit': MAX_ITEMS_PER_HOST * len(ids)}}


def batches(par_cle):
    """Dernier passage de chaque batch : succès, échec ou en cours. Pur.

    Valeurs lues dans le fichier d'état par l'agent : début et fin sont deux
    horodatages de la MÊME horloge (celle du serveur batch), donc comparables.
    « En cours » : début postérieur à la dernière fin. rc = -1 et fin = 0 :
    aucune exécution terminée depuis la mise en place — « inconnu », jamais « réussi ».
    """
    lots = {}
    for cle, (valeur, horloge) in par_cle.items():
        m = BATCH_KEY.fullmatch(cle)
        if m and valeur is not None:
            lots.setdefault(m.group(2), {})[m.group(1)] = int(valeur)
    resultat = []
    for nom, champs in lots.items():
        rc, fin, debut = champs.get('rc'), champs.get('finished') or None, champs.get('started') or None
        if debut and (fin is None or debut > fin):
            etat = 'running'
        elif rc is None or rc < 0 or fin is None:
            etat = 'unknown'
        else:
            etat = 'success' if rc == 0 else 'failed'
        resultat.append({'name': nom, 'state': etat, 'rc': rc if rc is not None and rc >= 0 else None,
                         'finished_at': fin, 'started_at': debut, 'duration_s': champs.get('duration') if fin else None})
    rang = {'failed': 0, 'running': 1, 'unknown': 2, 'success': 3}
    return sorted(resultat, key=lambda b: (rang[b['state']], -(b['finished_at'] or 0), b['name']))


def delay_seconds(text):
    """« 1m » -> 60, « 30s » -> 30, « 10 » -> 10 ; macro ou planification -> None."""
    m = re.fullmatch(r'(\d+)([smhdw]?)', str(text or '').split(';')[0].strip())
    if not m:
        return None
    return int(m.group(1)) * {'': 1, 's': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[m.group(2)]


def _num(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def summarize(items):
    """items bruts d'item.get -> {hostid: métriques}. Pur : testable sans Zabbix."""
    par_hote = {}
    for it in items:
        if not isinstance(it, dict) or not it.get('hostid'):
            continue
        par_hote.setdefault(str(it['hostid']), []).append(it)
    resultat = {}
    for hostid, lot in par_hote.items():
        par_cle, horloges, delais, erreurs = {}, [], [], []
        for it in lot:
            horloge = int(it.get('lastclock') or 0) or None
            if str(it.get('state')) == '1':
                # Item « non supporté » : on le dit, on n'invente pas de valeur.
                erreurs.append(f"{it.get('key_')} : {str(it.get('error') or 'non supporté')[:120]}")
                continue
            if horloge is None:
                continue
            par_cle[it['key_']] = (_num(it.get('lastvalue')), horloge)
            if BATCH_KEY.fullmatch(it['key_']):
                continue  # un batch d'hier ne doit pas faire paraître les métriques anciennes
            horloges.append(horloge)
            d = delay_seconds(it.get('delay'))
            if d:
                delais.append(d)

        def val(cle):
            return par_cle.get(cle, (None, None))

        m = {'measured_at': max(horloges) if horloges else None,
             'oldest_at': min(horloges) if horloges else None,
             'delay_s': min(delais) if delais else None, 'errors': erreurs[:5]}
        idle, t = val('system.cpu.util[,idle]')
        util, t2 = val('system.cpu.util')
        m['cpu_pct'] = (round(100 - idle, 1), t) if idle is not None else ((round(util, 1), t2) if util is not None else None)
        io, t = val('system.cpu.util[,iowait]')
        m['iowait_pct'] = (round(io, 1), t) if io is not None else None
        charge, t = val('system.cpu.load[percpu,avg1]')
        m['load_percpu'] = (round(charge, 2), t) if charge is not None else None
        dispo, t = val('vm.memory.size[available]')
        total, _ = val('vm.memory.size[total]')
        pdispo, t3 = val('vm.memory.size[pavailable]')
        utilisation, t4 = val('vm.memory.utilization')
        if dispo is not None and total:
            m['ram_pct'] = (round(100 * (1 - dispo / total), 1), t)
        elif pdispo is not None:
            m['ram_pct'] = (round(100 - pdispo, 1), t3)
        elif utilisation is not None:
            m['ram_pct'] = (round(utilisation, 1), t4)
        else:
            m['ram_pct'] = None
        disques = []
        for cle, (v, t) in par_cle.items():
            fs = re.fullmatch(r'vfs\.fs\.size\[(.+),(pused|pfree)\]', cle)
            if fs and v is not None:
                disques.append({'mount': fs.group(1), 'used_pct': round(v if fs.group(2) == 'pused' else 100 - v, 1),
                                'at': t})
        # Un même volume peut être relevé en pused et pfree : on garde une ligne.
        uniques = {}
        for d in disques:
            uniques.setdefault(d['mount'], d)
        m['disks'] = sorted(uniques.values(), key=lambda d: -d['used_pct'])
        m['disk_max'] = m['disks'][0] if m['disks'] else None
        ping, t = val('agent.ping')
        m['agent_ping'] = (ping, t) if ping is not None else None
        run, t = val('proc.num[,,run]')
        m['procs_running'] = (int(run), t) if run is not None else None
        up, t = val('system.uptime')
        m['uptime_s'] = (int(up), t) if up is not None else None
        m['batches'] = batches(par_cle)
        resultat[hostid] = m
    return resultat


def fetch(connection, hostids, timeout=10):
    """Un appel item.get, même chemin TLS et même jeton que la collecte Zabbix."""
    import management
    # Voie rapide : mêmes garde-fous que la collecte principale, sinon un fichier de
    # connexions modifié à la main envoyait le jeton vers un hôte non lié (audit SEC-05).
    # CA confinée à data/ca/ et résolue depuis la même racine que la collecte principale :
    # un chemin relatif était lu depuis le dossier courant (OC-AUDIT-010). Sans racine
    # connue (module non installé), une CA donnée par chemin est refusée.
    base = management.ACTIVE_BASE
    ca = str(connection.get('ca_bundle') or '').strip()
    if base is None and ca and not ca.startswith('-----BEGIN CERTIFICATE-----'):
        raise PermissionError('Certificat CA par chemin : racine data/ca/ inconnue de ce processus')
    refus = management.connection_refusal(connection, base)
    if refus:
        raise PermissionError(refus)
    token = os.getenv(connection.get('token_env') or '', '')
    if not token:
        raise PermissionError('Jeton Zabbix absent de ce processus')
    tls = management.ssl_context_for(management.transport_for(connection, base) if base is not None else connection)
    opener = management.api_opener(tls)
    requete = body(hostids)
    entetes = {'Accept': 'application/json', 'Authorization': 'Bearer ' + token}

    def appel(ancien):
        req = management.rpc_request(connection['url'], requete, entetes, 'application/json-rpc', ancien)
        with opener.open(req, timeout=timeout) as reponse:
            brut = reponse.read(2 * 1048576 + 1)
        if len(brut) > 2 * 1048576:
            raise ValueError('Réponse Zabbix trop volumineuse')
        return management.strict_json(brut)

    reponse = appel(None)
    if isinstance(reponse, dict) and reponse.get('error'):
        reponse = appel(token)  # Zabbix < 6.4 : jeton dans le champ auth
    if not isinstance(reponse, dict) or not isinstance(reponse.get('result'), list):
        erreur = (reponse.get('error') or {}) if isinstance(reponse, dict) else {}
        raise ValueError('Zabbix item.get : ' + str(erreur.get('data') or erreur.get('message') or 'réponse inattendue')[:200])
    return reponse['result']


def collect(connections, critical, now=None):
    """Métriques en direct des hôtes critiques -> ({clé hôte: métriques}, méta)."""
    from asset_registry import connection_evidence
    debut = time.perf_counter()
    for conn in connections:
        if conn.get('provider') != 'Zabbix' or conn.get('auth_configured') is False:
            continue
        hotes = (connection_evidence(conn).get('inventory') or {}).get('hosts') or []
        # Rapprochement par adresse IP, puis par nom court : aucune supposition.
        par_ip = {a: h['hostid'] for h in hotes for a in h.get('addresses') or []}
        par_nom = {str(n).lower().split('.')[0]: h['hostid'] for h in hotes for n in (h.get('host'), h.get('name')) if n}
        lien = {}
        for h in critical:
            hid = par_ip.get(h['ip']) or par_nom.get(str(h.get('name') or h['key']).lower().split('.')[0])
            if hid:
                lien[h['key']] = hid
        if not lien:
            return {}, {'error': 'Aucun serveur critique rapproché dans l’inventaire Zabbix', 'source': conn.get('name')}
        mesures = summarize(fetch(conn, sorted(set(lien.values()))))
        return ({cle: {**mesures.get(hid, {'errors': ['Aucun item correspondant sur cet hôte']}), 'hostid': hid}
                 for cle, hid in lien.items()},
                {'error': None, 'source': conn.get('name'), 'duration_ms': int((time.perf_counter() - debut) * 1000),
                 'unmatched': [h['key'] for h in critical if h['key'] not in lien]})
    return {}, {'error': 'Aucune connexion Zabbix configurée', 'source': None}
