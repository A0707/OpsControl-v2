"""Vue des dossiers partagés : un partage, tous ses clients, une seule ligne.

Chaque audit SSH relève les montages NFS/CIFS du CLIENT (storage_probe) et,
depuis cette version, les exports servis par le SERVEUR. Pris serveur par
serveur, ces relevés disent « /var/nfs_share est à 80 % » neuf fois — Zabbix
levait d'ailleurs dix alertes pour un seul volume. Ici on croise les deux côtés
par la source « serveur:/chemin » : un partage plein est UN problème, et un
partage injoignable depuis 2 clients sur 9 pointe vers ces 2 clients (réseau,
montage) plutôt que vers le serveur.

Doctrine inchangée : rien n'est calculé qui n'a été mesuré. Un partage sans
mesure d'occupation reste « non mesuré », un export sans client observé n'est
pas « inutilisé » — seuls les serveurs audités par InfraOps sont visibles.
"""
from __future__ import annotations

import alert_policy as policy

# Seuils : ceux de la politique commune (alert_policy.DISK_PCT).
SEUIL_ALERTE = 90
SEUIL_CRITIQUE = 95
SEUIL_PREVENTIF = 80
# Écart (points) entre deux mesures récentes d'un même volume signalé à l'opérateur.
ECART_DIVERGENT = 10


def _serveur(source):
    """« 10.77.0.47:/var/nfs_share » -> (serveur, chemin). CIFS : //srv/partage."""
    if source.startswith('//'):
        serveur, _, reste = source[2:].partition('/')
        return serveur, '/' + reste
    serveur, _, chemin = source.partition(':')
    return (serveur, chemin) if chemin else ('', source)


def _occupation(export, clients):
    """Mesure d'occupation retenue et les autres, chacune avec sa source et sa date.

    Une mesure récente l'emporte toujours sur une ancienne. À âge égal, celle du
    serveur prime (c'est le volume lui-même), sinon la plus haute vue par un client
    (ils lisent tous le même volume)."""
    mesures = [{**c, 'from': 'client ' + c['name']} for c in clients if c['use_pct'] is not None]
    if export and export['use_pct'] is not None:
        mesures.append({**export, 'from': 'serveur', 'available_kb': None, 'total_kb': None, 'serveur': True})
    if not mesures:
        return None, []
    mesures.sort(key=lambda m: (not m['stale'], bool(m.get('serveur')), m['use_pct']), reverse=True)
    return mesures[0], mesures[1:]


def build(rows):
    par_ip = {h['ip']: h for h in rows if h.get('ip')}
    par_nom = {}
    for h in rows:
        for nom in (h.get('key'), h.get('name')):
            if nom:
                par_nom[nom.lower()] = h
                par_nom[nom.lower().split('.')[0]] = h

    def hote(serveur):
        s = (serveur or '').lower()
        return par_ip.get(serveur) or par_nom.get(s) or par_nom.get(s.split('.')[0])

    partages = {}

    def entree(serveur, chemin):
        proprietaire = hote(serveur)
        # « /var/DemoFiles/files/ » et « /var/DemoFiles/files » désignent le même export (audit UI
        # du 31/10, fiche 10.1) : clé sur le chemin sans « / » final, chemins bruts conservés.
        normal = chemin.rstrip('/') or '/'
        cle = ((proprietaire or {}).get('ip') or serveur) + ':' + normal
        if cle not in partages:
            partages[cle] = {
                'key': cle, 'server': serveur, 'path': normal, 'raw_paths': [],
                'server_host': {k: proprietaire[k] for k in ('key', 'name', 'ip')} if proprietaire else None,
                'protocol': None, 'export': None, 'clients': [],
            }
        if chemin not in partages[cle]['raw_paths']:
            partages[cle]['raw_paths'].append(chemin)
        return partages[cle]

    for h in rows:
        stockage = h.get('storage') if isinstance(h.get('storage'), dict) else {}
        mesure = {'collected_at': h.get('collected_at'), 'stale': bool(h.get('stale', True))}
        for m in stockage.get('remote_shares') or []:
            serveur, chemin = _serveur(m.get('source') or '')
            p = entree(serveur, chemin)
            p['protocol'] = p['protocol'] or (m.get('fstype') or '').upper()
            p['clients'].append({'key': h['key'], 'name': h.get('name') or h['key'], 'mount': m.get('mount'),
                                 'status': m.get('status'), 'access': m.get('access'),
                                 'use_pct': m.get('use_pct'), 'total_kb': m.get('total_kb'),
                                 'available_kb': m.get('available_kb'), **mesure})
        for e in stockage.get('exports') or []:
            p = entree(h.get('ip') or h['key'], e['path'])
            p['protocol'] = e['protocol']
            p['export'] = {'clients': e.get('clients'), 'name': e.get('name'), 'use_pct': e.get('use_pct'), **mesure}

    resultat = []
    for p in partages.values():
        clients, export = p['clients'], p['export']
        mesure, autres = _occupation(export, clients)
        use = mesure['use_pct'] if mesure else None
        gelés = [c for c in clients if c['status'] == 'stale']
        # Occupation graduée par la politique commune : pourcentage, espace libre
        # absolu (volume serveur ou vu d'un client) — même grille que les disques.
        # L'espace libre vient de la mesure retenue, ou d'un client d'âge comparable.
        libres = [c for c in clients if c.get('available_kb') is not None and c['use_pct'] is not None
                  and (not mesure or c['stale'] == mesure['stale'])]
        ref = mesure if mesure and mesure.get('available_kb') is not None else (
            max(libres, key=lambda c: c['use_pct']) if libres else {})
        statut, raisons = policy.disk(use, ref.get('total_kb'), ref.get('available_kb'))
        raisons = ['Occupé à ' + r.removesuffix(' occupé') if r.endswith(' % occupé') else r for r in raisons]
        ecart = [a for a in autres if not a['stale'] and abs(a['use_pct'] - use) >= ECART_DIVERGENT]
        if ecart:
            raisons.append('Mesures divergentes : ' + ', '.join(f"{a['use_pct']} % ({a['from']})" for a in ecart[:3]))
        if gelés:
            statut = 'critical'
            raisons.insert(0, f"Injoignable depuis {len(gelés)} client(s) sur {len(clients)}")
        if use is None and not gelés:
            statut = 'unknown'
            raisons.append('Occupation non mesurée')
        statut = statut or 'ok'
        if mesure and not gelés:
            # Fraîcheur et date sont celles de la valeur affichée, jamais d'une autre
            # observation : un export à 20 % ancien recevait la date d'un client récent
            # à 99 % et s'affichait « OK » récent (audit OC-AUDIT-005).
            fresh, observed_at = not mesure['stale'], mesure['collected_at']
        else:
            preuves = [c for c in (gelés or clients) if c['collected_at']] + (
                [export] if export and export['collected_at'] and not gelés else [])
            fresh = any(not c['stale'] for c in preuves)
            dates = [c['collected_at'] for c in preuves if not c['stale'] or not fresh]
            observed_at = max(dates) if dates else None
        resultat.append({
            **p, 'use_pct': use, 'status': statut, 'reasons': raisons,
            'use_from': mesure['from'] if mesure else None,
            'clients_count': len(clients), 'stale_clients': len(gelés),
            'read_only_clients': sum(c['access'] == 'read-only' for c in clients),
            'fresh': fresh, 'observed_at': observed_at,
        })
    rang = {'critical': 0, 'warning': 1, 'preventive': 2, 'unknown': 3, 'ok': 4}
    resultat.sort(key=lambda p: (rang[p['status']], -(p['use_pct'] or 0), p['key']))
    # Une preuve ancienne ne compte pas comme « OK » actuel (fiche 10.2) : elle a son compteur.
    compte = {s: sum(p['status'] == s and (s != 'ok' or p['fresh']) for p in resultat) for s in rang}
    compte['stale'] = sum(not p['fresh'] for p in resultat)
    audites = sum(1 for h in rows if isinstance(h.get('storage'), dict))
    exports_connus = sum(1 for h in rows if isinstance(h.get('storage'), dict) and h['storage'].get('exports') is not None)
    return {
        'shares': resultat, 'counts': compte,
        'thresholds': {'preventive': SEUIL_PREVENTIF, 'warning': SEUIL_ALERTE, 'critical': SEUIL_CRITIQUE},
        'scope': (f'{audites} serveur(s) avec relevé de stockage, dont {exports_connus} avec relevé des exports. '
                  'Un partage n’apparaît que s’il est monté ou exporté par un serveur audité ; '
                  'les clients hors inventaire InfraOps ne sont pas visibles.'),
    }


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    @router.get('/api/shares')
    def shares():
        return build(context.rows())
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
