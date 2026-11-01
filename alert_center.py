"""Centre d'alertes : les anomalies de TOUTES les sources, regroupées par cause,
graduées par UNE politique commune (alert_policy).

Pourquoi un module de plus alors que chaque page affiche déjà ses anomalies :
un exploitant ne doit pas ouvrir sept pages pour savoir s'il a un incident.
Mais agréger naïvement aurait reproduit le défaut constaté sur les données
réelles — 128 anomalies Zabbix dont 42 « VM not running », 10 alertes pour un
seul volume NFS, 4 758 « erreurs » Bacula pour un seul job en échec. D'où :

1. Une alerte = une CAUSE et un NIVEAU, avec la liste des cibles touchées et
   leur nombre exact. Le même service en échec sur 6 serveurs est une ligne.
2. La gravité vient de alert_policy, pas de la source. Les mesures SSH
   (disque, inodes, mémoire, services, partages) sont graduées à partir des
   valeurs brutes ; les triggers Zabbix sont requalifiés, et un disque mesuré en
   SSH l'emporte sur le texte du trigger. La gravité d'origine reste affichée.
3. Le préventif repose sur la TENDANCE : la pente de remplissage est calculée
   sur l'historique des audits déjà conservés (audit_snapshots).
4. Chaque alerte porte la date de sa preuve. Une alerte ancienne reste affichée
   (« à confirmer ») mais n'est jamais comptée comme confirmée.

Ce module lit ce qui a déjà été collecté ; il ne déclenche aucune collecte et
n'agit sur aucun système.
"""
from __future__ import annotations

import json
import logging
import re
import sqlite3
from datetime import datetime, timezone

import alert_policy as policy
# Au niveau du module : avec « from __future__ import annotations », FastAPI résout
# l'annotation Request dans les globales du module, pas dans install().
from fastapi import Request
from asset_registry import connection_evidence
from daily_view import summarize_issue
from synchronization import fresh
from pydantic import BaseModel, ConfigDict, Field

ECHANTILLON = 25
# Sonde directe toutes les 5 s : au-delà de 30 s sans mesure, elle est considérée muette.
SONDE_MUETTE_S = 30
# Au-delà, une anomalie ouverte n'est plus un incident à traiter dans l'heure :
# c'est une alerte jamais refermée (constaté le 26/09 : les 16 cibles critiques
# datées avaient TOUTES plus d'un an, jusqu'à 7 ans). Elle reste visible, à part.
CHRONIC_DAYS = 30
ACK_MAX_HOURS = 72


def _instant(valeur):
    """Epoch (Zabbix) ou ISO (sondes) -> secondes ; None si illisible."""
    if valeur in (None, ''):
        return None
    try:
        return float(valeur) if str(valeur).replace('.', '', 1).isdigit() else \
            datetime.fromisoformat(str(valeur).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return None
# Mémoire d'hyperviseur au-delà de laquelle un nœud ne peut plus absorber une
# bascule : constaté à 89 % sur prdlabpve03.
SEUIL_MEMOIRE_NOEUD = 90
# Systèmes de fichiers sans intérêt d'exploitation, pour l'ancien relevé `df`.
PSEUDO_FS = re.compile(r'^(tmpfs|devtmpfs|udev|overlay|shm|none|efivarfs)$')
# Constats d'audit déjà gradués ici à partir de la mesure brute.
GRADUES = re.compile(r'^(disk_max|ram|cpu|inode:.*|service:.*|mount:.*|ssh)$')


class _Collecte:
    def __init__(self, now=None):
        self.alertes = {}
        self.now = (now or datetime.now(timezone.utc)).timestamp()

    def ajouter(self, source, cause, severite, titre, cible=None, preuve=None, observe=None,
                recent=False, lien=None, detail=None, regle=None, origine=None,
                measurement_at=None, started_at=None):
        """Ajoute une cible à l'alerte `source:cause:niveau`, ou la crée."""
        if severite not in policy.RANK:
            return
        # Une cible ouverte depuis plus de CHRONIC_DAYS rejoint un groupe à part :
        # une nouvelle occurrence du même problème reste, elle, un incident.
        debut = _instant(started_at)
        chronique = debut is not None and self.now - debut > CHRONIC_DAYS * 86400
        cle = f'{source}:{cause}:{severite}' + (':chronique' if chronique else '')
        a = self.alertes.get(cle)
        if a is None:
            a = self.alertes[cle] = {'id': cle, 'source': source, 'severity': severite,
                                     'severity_label': policy.LABELS[severite], 'delay': policy.DELAYS[severite],
                                     'title': titre, 'evidence': preuve, 'rule': regle,
                                     'source_severity': origine, 'targets': [], 'count': 0,
                                     'observed_at': observe, 'fresh': False, '_titres': set(),
                                     'chronic': chronique, '_toutes': []}
        a['fresh'] = a['fresh'] or bool(recent)
        a['_titres'].add(titre)
        observed_time, previous_time = _instant(observe), _instant(a['observed_at'])
        if observed_time is not None and (previous_time is None or observed_time > previous_time):
            a['observed_at'] = observe
        if cible is not None:
            a['count'] += 1
            target = {'name': cible, 'host_key': lien, 'detail': detail or titre,
                      'observed_at': observe, 'fresh': bool(recent),
                      'measurement_at': measurement_at, 'started_at': started_at}
            # Échantillon pour l'affichage ; liste complète pour le journal d'incidents, qui
            # sinon voyait au plus 25 cibles et « résolvait » les autres à tort (audit SUP-02).
            a['_toutes'].append(target)
            if len(a['targets']) < ECHANTILLON:
                a['targets'].append(target)
        elif not a['count']:
            a['count'] = 1


def _cause_zabbix(description):
    """« Proxmox: VM [physical3/VM 9000 (qemu/9000)]: Not running » ×42 → une cause."""
    return re.sub(r'\[[^\]]*\]', '[…]', description or 'Trigger sans description').strip()


# --- Historique des audits : tendances disque et CPU soutenu ---------------------
_cache = {}
HISTORIQUE_MAX = 20 + 7 * 24


def historique(context):
    """{clé: {'disks': {montage: [(ts, used_kb, total_kb)]}, 'cpu': [récent d'abord]}}.

    Relit uniquement les serveurs dont un nouvel audit est apparu depuis le
    dernier appel : la page interroge cette vue chaque minute.
    """
    connect = getattr(context, 'connect', None)
    if connect is None:
        return {}
    try:
        with connect() as db:
            derniers = dict(db.execute('SELECT key, max(ts) FROM audit_snapshots GROUP BY key').fetchall())
            for cle, ts in derniers.items():
                if _cache.get(cle, (None,))[0] == ts:
                    continue
                disques, cpu = {}, []
                # Borné : 20 audits complets + un par heure sur 7 jours suffisent aux tendances ;
                # sans limite, le premier appel relisait tout l'historique (audit DB-08).
                for date, charge in db.execute('SELECT ts, payload FROM audit_snapshots WHERE key=? ORDER BY ts DESC '
                                               'LIMIT ?', (cle, HISTORIQUE_MAX)):
                    audit = json.loads(charge)
                    cpu.append(audit.get('cpu'))
                    stockage = audit.get('storage') if isinstance(audit.get('storage'), dict) else {}
                    for fs in stockage.get('filesystems') or []:
                        disques.setdefault(fs.get('mount'), []).append((date, fs.get('used_kb'), fs.get('total_kb')))
                _cache[cle] = (ts, {'disks': disques, 'cpu': cpu})
    except Exception:  # noqa: BLE001 — une base illisible prive de tendance, pas d'alertes
        # Les alertes préventives de tendance disparaissent : au moins le dire (audit BE-07).
        logging.getLogger('opscontrol.alerts').exception('Tendances disque/CPU indisponibles')
        return {}
    return {cle: v[1] for cle, v in _cache.items()}


def _mesures_disque(h):
    """Systèmes de fichiers locaux, du relevé détaillé si présent, sinon de df."""
    stockage = h.get('storage') if isinstance(h.get('storage'), dict) else {}
    if stockage.get('filesystems'):
        return stockage['filesystems']
    return [{'mount': f.get('mount'), 'use_pct': f.get('use_pct')} for f in h.get('filesystems') or []
            if not PSEUDO_FS.match(str(f.get('fs') or '')) and not str(f.get('mount') or '').startswith(('/dev', '/run', '/sys'))]


# Constat d'audit → contrôle qui le produit (audit_engine.enrich) : une absence de constat
# ne prouve rien si ce contrôle n'a pas été mesuré lors de la dernière collecte.
CONTROLE_DU_CONSTAT = {'ntp': 'clock', 'permitrootlogin': 'ssh_policy',
                       'passwordauthentication': 'ssh_policy',  # pragma: allowlist secret -- identifiant de constat sshd
                       'perms': 'permissions', 'journal': 'errors', 'backup': 'backups', 'zfs': 'storage',
                       'smart': 'storage', 'mount': 'storage', 'service': 'services', 'inode': 'inodes'}


def controle_mesure(h, type_incident):
    """Le contrôle à l'origine d'un incident SSH a-t-il été réellement mesuré dans `h` ?

    Sans cette preuve, une collecte partielle (disque illisible, CPU lu) résolvait
    l'incident disque critique faute d'alerte (audit OC-AUDIT-003)."""
    kind = str(type_incident or '')
    if kind.startswith(('unreachable:', 'refused:', 'host_key:')):
        return True   # connexion : la collecte réussie, déjà exigée, en est la preuve
    disques = _mesures_disque(h)
    valeur = {'disk': any(f.get('use_pct') is not None for f in disques),
              'inodes': any(f.get('inodes_use_pct') is not None for f in disques),
              'memory': h.get('ram') is not None, 'cpu': h.get('cpu') is not None,
              'uptime': h.get('uptime') is not None}
    if kind in valeur:
        return valeur[kind]
    controle = CONTROLE_DU_CONSTAT.get(kind.split(':', 1)[0], kind)
    return any(c.get('id') == controle and c.get('status') not in (None, 'unknown') for c in h.get('checks') or [])


def _echec_ssh(statut, mesure, preuve):
    """« unreachable » (réseau) ou « refused » (authentification, empreinte, collecte) ; None sinon.

    Un audit en échec non réseau a status='critical' SANS aucune mesure : son constat `ssh`
    est écarté par GRADUES, il n'alertait donc jamais — un changement d'empreinte compris.
    `preuve` : toutes les tentatives de connexion en échec, ou le message du collecteur."""
    if statut == 'unreachable':
        return 'unreachable'
    if statut == 'critical' and not mesure and preuve:
        return 'refused'
    return None


def _acces_refuse(h):
    tentatives = h.get('attempts') or []
    if tentatives and not any(t.get('ok') for t in tentatives):
        return True
    return any(str(i).startswith('Accès SSH refusé') for i in h.get('issues') or [])


def _ssh(c, rows, histo):
    injoignables, refuses = {}, {}
    for h in rows:
        recent, observe = not h.get('stale', True), h.get('collected_at')
        nom, cle = h.get('name') or h['key'], h['key']
        mesure = (h.get('coverage') or {}).get('measured')
        statut = h.get('status')
        if statut == 'unknown' and h.get('stale') and not mesure and not h.get('audit_retained'):
            # Serveur jamais mesuré : passé « unknown » après 15 min, sa cause d'échec
            # (last_status) doit rester une alerte, marquée ancienne (audit SUP-01).
            statut = h.get('last_status') or statut
        echec = _echec_ssh(statut, mesure, _acces_refuse(h))
        if echec:
            cible = injoignables if echec == 'unreachable' else refuses
            cible.setdefault(summarize_issue((h.get('issues') or [None])[0]), []).append(h)
            continue
        tentative = h.get('last_attempt') or {}
        echec = _echec_ssh(tentative.get('status'), False, _acces_refuse(tentative)) if h.get('audit_retained') else None
        if echec:
            # Un serveur déjà audité garde son ancienne observation (audit_retention) : sans
            # ce cas, sa perte de visibilité ne produisait aucune alerte (audit SUP-01).
            cible = injoignables if echec == 'unreachable' else refuses
            cible.setdefault(summarize_issue((tentative.get('issues') or [None])[0]), []).append(
                {'key': cle, 'name': nom, 'collected_at': tentative.get('collected_at'),
                 'issues': tentative.get('issues'), 'stale': not fresh(tentative.get('collected_at'))})
        passe = histo.get(cle, {})
        ajout = lambda cause, niveau, titre, detail, regle: c.ajouter(
            'SSH', cause, niveau, titre, nom, None, observe, recent, cle, detail, regle)

        for fs in _mesures_disque(h):
            jours = policy.days_to_full(passe.get('disks', {}).get(fs.get('mount'), []))
            niveau, raisons = policy.disk(fs.get('use_pct'), fs.get('total_kb'), fs.get('available_kb'), jours)
            if niveau:
                ajout('disk', niveau, f'Espace disque — {policy.LABELS[niveau].lower()}',
                      f"{fs.get('mount')} : {' · '.join(raisons)}", 'Disque')
            niveau, raisons = policy.inodes(fs.get('inodes_use_pct'))
            if niveau:
                ajout('inodes', niveau, f'Inodes — {policy.LABELS[niveau].lower()}',
                      f"{fs.get('mount')} : {' · '.join(raisons)}", 'Inodes')

        niveau, raisons = policy.memory(h.get('ram'))
        if niveau:
            ajout('memory', niveau, f'Mémoire — {policy.LABELS[niveau].lower()}', ' · '.join(raisons), 'Mémoire')
        cpus = passe.get('cpu') or [h.get('cpu')]
        niveau, raisons = policy.cpu(cpus)
        if niveau:
            ajout('cpu', niveau, 'Charge CPU soutenue', ' · '.join(raisons), 'CPU')
        niveau, raisons = policy.uptime(h.get('uptime'))
        if niveau:
            ajout('uptime', niveau, 'Serveurs sans redémarrage depuis plus d’un an', ' · '.join(raisons), 'Système')

        stockage = h.get('storage') if isinstance(h.get('storage'), dict) else {}
        for pool in stockage.get('zfs') or []:
            etat = str(pool.get('health') or '').upper()
            niveau = 'critical' if etat in ('FAULTED', 'UNAVAIL', 'SUSPENDED') else 'warning' if etat == 'DEGRADED' else None
            if niveau:
                ajout('zfs', niveau, 'Pool ZFS ' + etat, f"pool {pool.get('pool')}", 'ZFS / SMART')
        for d in stockage.get('smart') or []:
            if d.get('status') == 'failed':
                ajout('smart', 'critical', 'Disque physique en échec SMART', f"{d.get('device')} : {d.get('detail')}",
                      'ZFS / SMART')

        declares = set(h.get('services') or [])
        for f in h.get('findings') or []:
            ident = str(f.get('id', ''))
            if ident.startswith('service:'):
                unite = ident[len('service:'):]
                niveau, raisons = policy.service(unite, declares)
                c.ajouter('SSH', ident, niveau, f'Service {unite} en échec', nom, None, observe, recent, cle,
                          ' · '.join(raisons), 'Services', 'Audit : ' + str(f.get('severity')))
            elif not GRADUES.match(ident) and f.get('severity') in ('critical', 'warning'):
                # Constat d'audit hors grille (durcissement SSH, journaux…) : un
                # écart sans rupture de service se planifie, il ne réveille pas.
                niveau = 'critical' if f['severity'] == 'critical' else 'preventive'
                c.ajouter('SSH', ident, niveau, f.get('title') or ident, nom, None, observe, recent, cle,
                          f.get('title'), 'Constat d’audit', 'Audit : ' + f['severity'])

    for cause, hotes in injoignables.items():
        for h in hotes:
            c.ajouter('SSH', 'unreachable:' + cause, 'warning', 'Serveur injoignable en SSH — ' + cause,
                      h.get('name') or h['key'], 'Perte de visibilité : l’état réel du serveur est inconnu',
                      h.get('collected_at'), not h.get('stale', True), h['key'])
    for cause, hotes in refuses.items():
        for h in hotes:
            texte = ' '.join(h.get('issues') or []).lower()
            # Empreinte absente ou CHANGÉE : réinstallation… ou interception. Jamais un simple
            # avertissement, et jamais acceptée ici (procédure « Empreintes SSH à confirmer »).
            empreinte = any(m in texte for m in ('host key', 'identification has changed', 'empreinte'))
            c.ajouter('SSH', ('host_key:' if empreinte else 'refused:') + cause,
                      'critical' if empreinte else 'warning',
                      ('Empreinte SSH refusée — ' if empreinte else 'Accès SSH refusé — ') + cause,
                      h.get('name') or h['key'],
                      ('Clé d’hôte absente ou différente : vérifier à la console avant toute acceptation.'
                       if empreinte else 'Compte, clé ou collecte refusés : aucune mesure, état réel inconnu.'),
                      h.get('collected_at'), not h.get('stale', True), h['key'])


def _mesure_ssh(rows_par_cle, cle, volume):
    """Mesure SSH du volume nommé par un trigger Zabbix, local ou partage monté."""
    h = rows_par_cle.get(cle)
    if not h or not volume or h.get('stale', True):
        return None, None
    stockage = h.get('storage') if isinstance(h.get('storage'), dict) else {}
    for fs in list(_mesures_disque(h)) + list(stockage.get('remote_shares') or []):
        if fs.get('mount') == volume:
            return fs, h
    return None, h


def build(context, now=None, for_incidents=False):
    """Centre d'alertes. `for_incidents` : vue interne du journal d'incidents, avec toutes
    les cibles (pas d'échantillon) et l'état de la sonde directe nécessaire aux résolutions."""
    now = now or datetime.now(timezone.utc)
    import incident_timing
    journal, journal_available = incident_timing.journal_snapshot(context) if not for_incidents else ({}, False)
    rows = context.rows()
    sonde_etat = None
    connexions = context.api_connections()
    histo = historique(context)
    c = _Collecte(now)
    par_nom, par_cle = {}, {h['key']: h for h in rows}
    for h in rows:
        for nom in (h.get('key'), h.get('name'), h.get('ip')):
            if nom:
                par_nom.setdefault(str(nom).lower().rstrip('.'), set()).add(h['key'])

    def lien(nom):
        n = str(nom or '').lower()
        matches = par_nom.get(n.rstrip('.'), set())
        return next(iter(matches)) if len(matches) == 1 else None

    _ssh(c, rows, histo)

    # --- Voie rapide : sonde directe des serveurs critiques (tier0.py) ----------
    # Preuve de moins de 5 s : toujours « récente » tant que la sonde tourne.
    sonde = getattr(context, 'tier0_snapshot', None)
    if sonde is not None:
        etat_sonde = sonde()
        obs = etat_sonde.get('observer') or {}
        sonde_etat = {'enabled': etat_sonde.get('enabled', True), 'observer_ok': obs.get('ok'),
                      'observer_checked_at': obs.get('checked_at'),
                      'hosts': {s.get('key'): s.get('checked_at') for s in etat_sonde.get('hosts') or []}}
        derniere = _instant(etat_sonde.get('last_probe_at'))
        if (etat_sonde.get('enabled', True) and etat_sonde.get('hosts') and derniere is not None
                and now.timestamp() - derniere > SONDE_MUETTE_S):
            # Fil de sonde arrêté (exception, ping absent) : le dernier état « up » restait affiché
            # et aucune alerte ne le disait côté serveur (audit SUP-16).
            c.ajouter('Sonde directe', 'observer', 'warning', 'Sonde directe muette : serveurs critiques non vérifiés',
                      None, f"Dernière sonde il y a {int(now.timestamp() - derniere)} s (attendu : toutes les 5 s).",
                      etat_sonde.get('last_probe_at'), True, regle='Voie rapide')
        if obs.get('ok') is False:
            # La sonde ne conclut rien sur les serveurs pendant ce temps : ce trou de
            # surveillance est lui-même une alerte, jamais un silence.
            c.ajouter('Sonde directe', 'observer', 'warning', 'Chemin de mesure perturbé : serveurs critiques non vérifiables',
                      None, 'La référence ' + str(obs.get('reference')) + ' ne répond pas non plus (poste, VPN ou réseau).',
                      obs.get('checked_at'), fresh(obs.get('checked_at')), regle='Voie rapide')
        for s in etat_sonde['hosts']:
            if s.get('status') == 'down':
                c.ajouter('Sonde directe', 'down', 'critical', 'Serveur critique HORS SERVICE',
                          s['name'], 'ICMP et TCP ' + str(s.get('port')) + ' sans réponse sur deux sondes consécutives',
                          s.get('checked_at'), fresh(s.get('checked_at')), s['key'],
                          'Hors service depuis ' + str(s.get('down_since')), 'Voie rapide',
                          started_at=s.get('down_since'))
            elif s.get('status') == 'degraded':
                perdu = [n for n, ok in (('ICMP', s.get('ping')), ('TCP ' + str(s.get('port')), s.get('tcp'))) if ok is not True]
                c.ajouter('Sonde directe', 'degraded', 'warning', 'Serveur critique dégradé',
                          s['name'], None, s.get('checked_at'), fresh(s.get('checked_at')), s['key'],
                          'Sans réponse : ' + ', '.join(perdu), 'Voie rapide')

    # --- Veille sécurité (security_cve) : notifications non lues -------------------
    # Hors journal d'incidents : une vulnérabilité a son propre cycle (validation, correction,
    # GLPI) ; la reprendre en incident créerait un doublon jamais résolu automatiquement.
    alertes_securite = getattr(context, 'security_center_alerts', None)
    if alertes_securite is not None and not for_incidents:
        for n in alertes_securite():
            for cible in n['hosts'] or [{'key': None, 'name': None}]:
                c.ajouter('Sécurité', n['ref'], n['level'], n['title'], cible['name'], n['detail'], n['at'], True,
                          cible['key'], regle='Veille sécurité')

    # --- Partages : un partage = une alerte, pas une par client -----------------
    from shares_view import build as partages
    for p in partages(rows)['shares']:
        if p['status'] in policy.RANK:
            c.ajouter('Partages', p['key'], p['status'], 'Partage ' + p['key'] + ' — ' + ' · '.join(p['reasons']),
                      p['key'], f"{p['clients_count']} client(s) observé(s)", p['observed_at'], p['fresh'],
                      (p.get('server_host') or {}).get('key'), regle='Partages')

    # --- Batchs du référentiel : un passage en échec ou manqué = un incident -------
    # Une alerte par batch (pas par serveur) : chaque échec a son propre incident,
    # résolu au passage réussi suivant si l'inventaire batch du serveur est récent.
    lots = _batchs(context)
    for e in lots.get('entries', []):
        o = e.get('outcome') or {}
        fin = o.get('finished_at') or o.get('at')
        quand = datetime.fromtimestamp(fin, timezone.utc).isoformat() if fin else None
        if o.get('verdict') == 'failed':
            c.ajouter('Batch', 'echec:' + e['id'], 'critical' if (e.get('criticite') or 0) >= 3 else 'warning',
                      f"Batch {e['nom']} en échec au dernier passage", e['host_name'], o.get('reason'),
                      e.get('collected_at'), e.get('fresh'), e.get('host_key'), regle='Batch', started_at=quand)
        manque = next((f['text'] for f in e.get('findings') or [] if 'lancement manqué' in f['text']), None)
        if manque:
            c.ajouter('Batch', 'manque:' + e['id'], 'warning', f"Batch {e['nom']} : passage quotidien manqué",
                      e['host_name'], manque, e.get('collected_at'), e.get('fresh'), e.get('host_key'), regle='Batch')

    # --- Sources API --------------------------------------------------------------
    sources = []
    for conn in connexions:
        r = connection_evidence(conn)
        inv, provider = r.get('inventory') or {}, conn.get('provider')
        observe, recent = r.get('collected_at'), r.get('status') == 'observed' and fresh(r.get('collected_at'))
        if provider == 'Zabbix':
            try:
                age = (now - datetime.fromisoformat(observe)).total_seconds()
                recent = r.get('status') == 'observed' and 0 <= age <= 30
            except (TypeError, ValueError):
                recent = False
        sources.append({'key': conn.get('key'), 'name': conn.get('name'), 'provider': provider,
                        'collected_at': observe, 'fresh': recent, 'error': r.get('error'),
                        'max_age_seconds': 30 if provider == 'Zabbix' else 900})
        if r.get('error'):
            # Une source muette n'est pas une source saine : ses alertes sont anciennes.
            c.ajouter(provider, 'collection', 'warning', f"Collecte {conn.get('name')} en échec",
                      None, r.get('error'), (conn.get('last_result') or {}).get('collected_at'),
                      fresh((conn.get('last_result') or {}).get('collected_at')))

        if provider == 'Zabbix':
            for pb in inv.get('problems') or []:
                description, cause = pb.get('description'), _cause_zabbix(pb.get('description'))
                niveau, raison, requalifie = policy.zabbix(description, pb.get('severity'))
                origine = 'Zabbix : ' + str(pb.get('severity_label') or pb.get('severity'))
                for hote in pb.get('hosts') or [None]:
                    cle, niv, motif = lien(hote), niveau, raison
                    if niveau == 'disk':
                        fs, h = _mesure_ssh(par_cle, cle, policy.zabbix_volume(description))
                        if fs is not None:
                            niv, raisons = policy.disk(fs.get('use_pct'), fs.get('total_kb'), fs.get('available_kb'))
                            niv = niv or 'info'
                            motif = 'requalifié par la mesure SSH : ' + (' · '.join(raisons) or f"{fs.get('use_pct')} % occupé")
                        else:
                            # « moins de 20 % libre » = ≥ 80 % : préventif selon la grille disque.
                            niv, motif = 'preventive', 'seuil Zabbix sans mesure SSH du volume : grille disque ≥ 80 %'
                    c.ajouter('Zabbix', cause, niv, cause,
                              hote or 'Hôte non renseigné', None, observe, recent,
                              cle, motif, 'Zabbix' if requalifie else 'Zabbix (non couvert)', origine,
                              measurement_at=pb.get('measurement_at'), started_at=pb.get('last_change'))
        elif provider == 'Bacula':
            from bacula_inventory import latest_jobs, overdue
            courant = latest_jobs(inv)
            for j in courant:
                client = (j.get('client') or '').removesuffix('-fd')
                # Un état non reconnu n'est pas un état sain : il était ignoré en silence (audit SUP-08).
                niveau = 'warning' if j.get('severity') == 'unknown' else j.get('severity')
                c.ajouter('Bacula', 'job:' + j['name'], niveau,
                          f"Sauvegarde {j['name']} : {j.get('status_label')} au dernier passage",
                          client or j['name'], 'Fin : ' + str(j.get('endtime') or 'non terminée'),
                          observe, recent, lien(client), regle='Sauvegardes')
            for j in overdue(inv, now.timestamp()):
                client = (j.get('client') or '').removesuffix('-fd')
                c.ajouter('Bacula', 'rpo:' + j['name'], 'warning',
                          f"Sauvegarde {j['name']} : aucune réussite depuis {j['age_hours']} h",
                          client or j['name'], f"Seuil {j['threshold_hours']} h (rythme habituel du job)",
                          observe, recent, lien(client), regle='Sauvegardes')
        elif provider == 'Wazuh':
            for d in inv.get('daemons') or []:
                if d.get('status') == 'failed':
                    c.ajouter('Wazuh', 'daemon:' + d['name'], 'critical', 'Démon Wazuh en échec : ' + d['name'],
                              None, None, observe, recent)
            for etat in (inv.get('agents') or {}).get('states') or []:
                if etat.get('key') == 'disconnected' and etat.get('count'):
                    c.ajouter('Wazuh', 'agents:disconnected', 'warning',
                              f"{etat['count']} agent(s) Wazuh déconnecté(s)", None,
                              'Perte de visibilité sécurité sur ces serveurs', observe, recent)
        elif provider == 'Elasticsearch':
            ind = r.get('indicators') or {}
            statut = ind.get('cluster_status')
            if statut in ('red', 'yellow'):
                c.ajouter('Elastic', 'cluster', 'critical' if statut == 'red' else 'warning',
                          f"Cluster Elasticsearch {statut}", None,
                          f"{ind.get('unassigned_shards', 'N/A')} shard(s) non assigné(s) · "
                          + ('données indisponibles' if statut == 'red' else 'redondance des réplicas perdue'),
                          observe, recent)
        elif provider == 'Proxmox':
            for n in inv.get('nodes') or []:
                if n.get('status') not in (None, 'online'):
                    c.ajouter('Proxmox', 'node-offline', 'critical', 'Nœud Proxmox hors ligne',
                              n.get('name'), n.get('status'), observe, recent)
                total = n.get('memory_total_bytes')
                if total and n.get('memory_bytes') is not None:
                    pct = round(100 * n['memory_bytes'] / total)
                    if pct >= SEUIL_MEMOIRE_NOEUD:
                        c.ajouter('Proxmox', 'node-memory', 'warning',
                                  f'Mémoire hyperviseur ≥ {SEUIL_MEMOIRE_NOEUD} % : bascule compromise',
                                  f"{n.get('name')} ({pct} %)", None, observe, recent)

    alertes = sorted(c.alertes.values(),
                     key=lambda a: (a['chronic'], not a['fresh'], policy.RANK[a['severity']], -a['count'], a['title']))
    prises = acknowledgements(context, now)
    for a in alertes:
        a['max_age_seconds'] = 30 if a['source'] == 'Zabbix' else 900
        toutes = a.pop('_toutes')
        if not for_incidents:
            a.update(incident_timing.summarize(a, toutes, journal, journal_available, now))
        # Le début du groupe ne doit pas dépendre des 25 cibles échantillonnées à l'écran.
        starts = [_instant(t.get('started_at')) for t in toutes]
        known_starts = [v for v in starts if v is not None and -62135596800 <= v <= 253402300799]
        a['started_at'] = datetime.fromtimestamp(min(known_starts), timezone.utc).isoformat() if known_starts else None
        a['started_at_complete'] = bool(toutes) and len(known_starts) == len(toutes)
        identites = set(_identites(toutes))
        if for_incidents:
            a['targets'] = toutes
        a['truncated'] = a['count'] > len(a['targets'])
        # Un même titre ne peut pas décrire des valeurs différentes : le titre
        # devient générique, la valeur reste par cible.
        if len(a.pop('_titres')) > 1:
            a['title'] = a['title'].split(' : ')[0] + ' : seuil dépassé (valeur par serveur)'
        # Prise en charge valable tant qu'elle n'a pas expiré et que l'alerte ne
        # s'est pas étendue (nouvelle cible = nouvelle information à voir).
        # Une cible absente de la prise en charge l'annule, même à nombre égal (audit SUP-11) ;
        # les prises antérieures à cette règle (sans liste) gardent le contrôle par nombre.
        p = prises.get(a['id'])
        couvertes = p.pop('_targets', None) if p else None
        a['ack'] = p if p and a['count'] <= p['count'] and (couvertes is None or identites <= couvertes) else None
    # Les compteurs d'incidents excluent les chroniques : elles ont leur propre compte.
    actives = [a for a in alertes if not a['chronic']]
    compte = lambda sev, rec: sum(1 for a in actives if a['severity'] == sev and a['fresh'] == rec)
    counts = {}
    for sev in policy.LEVELS:
        counts[sev], counts[sev + '_stale'] = compte(sev, True), compte(sev, False)
    counts['targets_critical'] = sum(a['count'] for a in actives if a['severity'] == 'critical' and a['fresh'])
    counts['chronic'] = sum(1 for a in alertes if a['chronic'] and a['severity'] != 'info')
    counts['acknowledged'] = sum(1 for a in actives if a['ack'])
    result = {
        'generated_at': now.isoformat(),
        'alerts': alertes,
        'counts': counts,
        'levels': [{'key': k, 'label': policy.LABELS[k], 'delay': policy.DELAYS[k]} for k in policy.LEVELS],
        'policy': policy.RULES,
        'sources': sources,
        'scope': ('Anomalies déjà collectées, regroupées par cause et graduées par la politique InfraOps '
                  '(gravité d’origine conservée à titre indicatif). Zabbix : lecture API de moins de 30 secondes ; '
                  'autres sources : preuve de moins de 15 minutes. L’âge des items Zabbix est distinct ; '
                  'une alerte ancienne reste affichée mais n’est pas comptée comme confirmée. '
                  'Aucune collecte n’est déclenchée par cette vue et aucune action n’est exécutée.'),
    }
    if for_incidents:
        result['probe'] = sonde_etat
        result['batch_status'] = {str(s['host_key']).lower(): (bool(s.get('fresh')),
                                  None if s.get('fresh') else 'Inventaire batch ancien ou non collecté')
                                  for s in lots.get('servers', []) if s.get('host_key')}
    return result


def _batchs(context):
    """Référentiel des batchs rapproché ; une erreur ne doit jamais casser le centre d'alertes."""
    if not hasattr(context, 'connect') or not hasattr(context, 'HOSTS'):
        return {'entries': [], 'servers': []}  # contexte sans inventaire batch (outils, tests)
    try:
        import batch_catalog
        return batch_catalog.snapshot(context)
    except Exception:  # noqa: BLE001 — référentiel absent ou illisible : aucune alerte batch
        logging.getLogger('opscontrol.alerts').exception('Référentiel des batchs illisible')
        return {'entries': [], 'servers': []}


def acknowledgements(context, now):
    """Prises en charge en cours : {id d'alerte: {...}}. Expirées = ignorées."""
    connect = getattr(context, 'connect', None)
    if connect is None:
        return {}
    try:
        with connect() as db:
            lignes = db.execute('SELECT id, count, by, note, at, until, auth, targets FROM alert_acks WHERE until > ?',
                                (now.isoformat(),)).fetchall()
    except Exception:  # noqa: BLE001 — table absente ou base occupée : aucune prise en charge
        logging.getLogger('opscontrol.alerts').exception('Prises en charge illisibles')
        return {}
    return {i: {'count': n, 'by': b, 'note': t, 'at': a, 'until': u, 'authenticated': m == 'proxy',
                '_targets': set(json.loads(c)) if c else None}
            for i, n, b, t, a, u, m, c in lignes}


def _identites(cibles):
    """Identité stable d'une cible : serveur rattaché, sinon nom affiché."""
    return sorted({str(t.get('host_key') or t.get('name')) for t in cibles if t.get('host_key') or t.get('name')})


class Ack(BaseModel):
    """« Je m'en occupe » : visible par tous, arrête bandeau et notifications.

    Derrière le reverse proxy authentifié, l'auteur est l'identité transmise par
    nginx et « by » est ignoré. En accès direct (mode local), « by » est
    déclaratif et enregistré comme tel : coordination d'équipe, pas une preuve.
    """
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=3, max_length=400)
    by: str = Field(default='', max_length=60)
    note: str = Field(default='', max_length=300)
    hours: int = Field(default=8, ge=1, le=ACK_MAX_HOURS)

class Release(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=3, max_length=400)


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    from datetime import timedelta
    from fastapi import HTTPException

    # Table alert_acks : migration versionnée core_v4_module_tables (migrations.py).
    import response_cache

    def alerts_revision():
        # Prise en charge ou libération : INSERT OR REPLACE / DELETE changent rowid ou nombre.
        with context.connect() as db:
            acks = db.execute('SELECT max(rowid), count(*), max(until) FROM alert_acks').fetchone()
            try:
                incidents = db.execute('SELECT max(updated_at),count(*) FROM incidents').fetchone()
            except sqlite3.OperationalError:
                incidents = None
        base = context.data_revision() if hasattr(context, 'data_revision') else None
        return json.dumps([base, acks, incidents], default=str)

    @router.get('/api/alerts')
    @response_cache.cached_json('alerts', alerts_revision)
    def alerts():
        return build(context)

    @router.post('/api/alerts/ack')
    def acknowledge(ack: Ack, request: Request):
        import operator_identity
        auteur, mode = operator_identity.actor(request.headers, ack.by)
        if not auteur:
            raise HTTPException(422, 'Nom requis en mode local non authentifié')
        now = datetime.now(timezone.utc)
        # Seule une alerte réellement présente peut être prise en charge.
        alerte = next((a for a in build(context, now, for_incidents=True)['alerts'] if a['id'] == ack.id), None)
        if alerte is None:
            raise HTTPException(404, 'Alerte inconnue ou déjà résolue')
        fin = (now + timedelta(hours=ack.hours)).isoformat()
        with context.connect() as db:
            db.execute('DELETE FROM alert_acks WHERE until <= ?', (now.isoformat(),))
            db.execute('INSERT OR REPLACE INTO alert_acks(id, count, by, note, at, until, auth, targets) '
                       'VALUES(?,?,?,?,?,?,?,?)', (ack.id, alerte['count'], auteur, ack.note.strip(), now.isoformat(),
                                                   fin, mode, json.dumps(_identites(alerte['targets']))))
        return {'id': ack.id, 'count': alerte['count'], 'by': auteur, 'note': ack.note.strip(),
                'at': now.isoformat(), 'until': fin, 'authenticated': mode == 'proxy'}

    @router.post('/api/alerts/unack')
    def release(item: Release):
        with context.connect() as db:
            db.execute('DELETE FROM alert_acks WHERE id=?', (item.id,))
        return {'id': item.id, 'released': True}
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
