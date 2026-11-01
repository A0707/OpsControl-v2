"""Normalize Baculum/Bacularis API v2 answers into backup job evidence.

Contrat identique aux autres normaliseurs : on ne convertit jamais une absence
de mesure en résultat sain. En particulier, un job marqué « terminé sans
erreur » prouve que Bacula a fini son travail — pas que la sauvegarde est
restaurable. Le vocabulaire choisi ici ne doit jamais laisser croire l'inverse.

Réponse attendue (Baculum API v2) : {"error": 0, "output": [ {...}, ... ]}
Les réponses en erreur portent un `error` non nul et sont déjà interceptées en
amont par collect_connection.
"""

# Codes JobStatus de Bacula. Seuls ceux dont le sens est stable sont traduits ;
# tout code inconnu reste 'unknown' plutôt que d'être rangé arbitrairement.
JOB_STATUS = {
    'T': ('Terminé sans erreur', 'ok'),
    'W': ('Terminé avec avertissements', 'warning'),
    'E': ('Terminé en erreur', 'critical'),
    'f': ('Erreur fatale', 'critical'),
    'A': ('Annulé', 'warning'),
    'R': ('En cours', 'running'),
    'C': ('Créé, pas encore lancé', 'pending'),
    'B': ('Bloqué', 'warning'),
    'D': ('Vérification différée', 'pending'),
    'I': ('Incomplet', 'warning'),
}

# Type de job Bacula (colonne Job.Type). Audit UI du 31/10 (fiche 09.1) : copies et
# restaurations ne sont pas des sauvegardes ; les compter comme telles gonflait la
# couverture et pouvait dater une « dernière réussite » sur une restauration.
JOB_TYPES = {
    'B': 'Sauvegarde', 'C': 'Copie', 'c': 'Copie (pilotage)', 'R': 'Restauration',
    'V': 'Vérification', 'D': 'Administration', 'A': 'Archive', 'M': 'Migrée',
    'g': 'Migration', 'U': 'Console', 'I': 'Interne', 'S': 'Analyse de volume',
}


def is_backup(entry):
    """Sauvegarde, ou type non renvoyé par l'API (collectes antérieures : comportement inchangé)."""
    return entry.get('type') in ('B', None)


# Familles utilisées pour les compteurs. 'unknown' n'est jamais fusionné
# avec 'ok' : un état non reconnu reste un trou de couverture.
FAMILIES = ('ok', 'warning', 'critical', 'running', 'pending', 'unknown')

# Passages conservés pour l'historique détaillé (les compteurs portent sur tous).
HISTORY_KEPT = 500


def latest_jobs(inventory):
    """Last observed passage per job AND client, including jobs outside history."""
    latest = {}
    for entry in [*(inventory.get('latest') or []), *(inventory.get('jobs') or [])]:
        identity = (entry.get('name'), entry.get('client'))
        previous = latest.get(identity)
        if previous is None or (entry.get('jobid') or 0) > (previous.get('jobid') or 0):
            latest[identity] = entry
    return list(latest.values())


# Ancienneté de la dernière sauvegarde réussie (audit SUP-08). Le seuil suit le rythme
# observé de chaque job (2 × l'intervalle habituel, au moins 26 h) pour ne pas alerter
# sur un job hebdomadaire ; sans historique suffisant, 8 jours.
SUCCESS_CODES = ('T', 'W')
MIN_RPO_HOURS = 26
DEFAULT_RPO_HOURS = 8 * 24


def _epoch(value):
    """Heure Baculum (« AAAA-MM-JJ HH:MM:SS », heure du directeur) → secondes ; None si illisible."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return None


def overdue(inventory, now=None):
    """Jobs dont la dernière réussite observée dépasse leur seuil d'ancienneté."""
    import statistics
    import time
    now = now if now is not None else time.time()
    successes = {}
    for entry in [*(inventory.get('latest') or []), *(inventory.get('jobs') or [])]:
        end = _epoch(entry.get('endtime')) if entry.get('status_code') in SUCCESS_CODES and is_backup(entry) else None
        if end:
            successes.setdefault((entry.get('name'), entry.get('client')), set()).add(end)
    late = []
    for job in filter(is_backup, latest_jobs(inventory)):
        # Un job « en cours » depuis des jours est un job bloqué : sa dernière RÉUSSITE vieillit
        # comme les autres, il n'est plus exempté du contrôle d'ancienneté (audit SUP-19).
        ends = sorted(successes.get((job.get('name'), job.get('client')), ()))
        if not ends:
            continue   # aucune réussite dans l'historique lu : l'échec courant est déjà alerté
        gaps = [b - a for a, b in zip(ends, ends[1:]) if b - a > 3600]
        threshold = max(MIN_RPO_HOURS, 2 * statistics.median(gaps) / 3600) if len(gaps) >= 2 else DEFAULT_RPO_HOURS
        age = (now - ends[-1]) / 3600
        if age > threshold:
            late.append({**job, 'age_hours': round(age), 'threshold_hours': round(threshold)})
    return late


def _text(value, limit=200):
    return str(value)[:limit] if value is not None else None


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return value


def _rows(payload):
    """Extrait la liste `output` d'une réponse Baculum, sinon lève."""
    if not isinstance(payload, dict) or not isinstance(payload.get('output'), list):
        raise ValueError('Bacula response invalid')
    return [row for row in payload['output'] if isinstance(row, dict)]


def jobs(payload):
    """Normalise /api/v2/jobs en évidences de sauvegarde exploitables."""
    rows = _rows(payload)
    counts = dict.fromkeys(FAMILIES, 0)
    entries = []
    last_success = None
    for row in rows:
        code = _text(row.get('jobstatus'), 2)
        label, family = JOB_STATUS.get(code, ('État non reconnu', 'unknown'))
        counts[family] += 1
        end = _text(row.get('endtime'), 32)
        kind = _text(row.get('type'), 2)
        if family == 'ok' and end and kind in ('B', None) and (last_success is None or end > last_success):
            last_success = end
        entries.append({
            'jobid': _number(row.get('jobid')),
            'name': _text(row.get('name')) or 'Job non nommé',
            'client': _text(row.get('client')) or _text(row.get('clientid'), 32),
            'clientid': _number(row.get('clientid')),
            'level': _text(row.get('level'), 2),
            'type': kind,
            'type_label': JOB_TYPES.get(kind, 'Type non renvoyé' if kind is None else 'Type ' + kind),
            'status_code': code,
            'status_label': label,
            'severity': family,
            'endtime': end,
            'starttime': _text(row.get('starttime'), 32),
            'bytes': _number(row.get('jobbytes')),
            'files': _number(row.get('jobfiles')),
        })
    # État ACTUEL : le dernier passage de chaque job. Les compteurs ci-dessus
    # portent sur tout l'historique renvoyé par l'API — 22 mois en exploitation,
    # soit 4 758 « erreurs » alors qu'un seul job échouait encore. Afficher ce
    # total comme un état revient à fabriquer de la fatigue d'alerte.
    rank = {'critical': 0, 'warning': 1, 'unknown': 2, 'running': 3, 'pending': 4, 'ok': 5}
    latest = {}
    for entry in entries:
        identity = (entry['name'], entry['client'])
        known = latest.get(identity)
        if known is None or (entry['jobid'] or 0) > (known['jobid'] or 0):
            latest[identity] = entry
    current = sorted(latest.values(), key=lambda j: (rank.get(j['severity'], 9), j['name']))
    latest_counts = dict.fromkeys(FAMILIES, 0)
    latest_types = {}
    for entry in current:
        latest_counts[entry['severity']] += 1
        latest_types[entry['type_label']] = latest_types.get(entry['type_label'], 0) + 1
    ends = [j['endtime'] for j in entries if j['endtime']]
    # Historique borné aux passages les plus récents : l'interface n'en montre
    # que 500, et stocker 12 000 jobs pesait 3 Mo à chaque lecture des connexions.
    recent = sorted(entries, key=lambda j: -(j['jobid'] or 0))[:HISTORY_KEPT]
    # Les anomalies d'abord, puis le plus récent : c'est l'ordre de lecture
    # d'un exploitant qui vient vérifier ses sauvegardes de la nuit.
    recent.sort(key=lambda j: (rank.get(j['severity'], 9), -(j['jobid'] or 0)))
    return {
        'jobs': recent,
        'jobs_truncated': len(entries) - len(recent),
        'latest': current,
        'latest_counts': latest_counts,
        'latest_types': latest_types,
        'history_since': min(ends) if ends else None,
        'counts': counts,
        'jobs_count': len(entries),
        'last_success': last_success,
        'scope': ('Jobs visibles par ce compte API. Un job « terminé sans erreur » prouve que Bacula a '
                  'terminé son traitement, pas que la sauvegarde est restaurable : seul un test de '
                  'restauration le démontre.'),
        'empty': not entries,
        'max_jobid': max((j['jobid'] for j in entries if j['jobid'] is not None), default=None),
        'collection': 'complète',
    }


def inventory(jobs_payload):
    """Assemble la vue Bacula. Une seule source pour l'instant."""
    return jobs(jobs_payload)


# Collecte incrémentale (audit UI du 31/10, fiche 09.3) : relire 12 000 passages (8 Mio, 14 s)
# à chaque cycle pour en afficher 500. Une fenêtre des derniers passages est fusionnée avec
# le dernier inventaire complet ; tout doute renvoie à une relecture complète.
WINDOW = 500
FULL_EVERY_SECONDS = 24 * 3600
# Fenêtre écartée (API qui ignore l'ordre attendu…) : pas de nouvel essai avant 7 jours, sinon
# chaque cycle ferait une fenêtre inutile PUIS une relecture complète.
RETRY_WINDOW_SECONDS = 7 * 86400


def _age(value, now):
    from datetime import datetime
    try:
        return (now - datetime.fromisoformat(value)).total_seconds()
    except (TypeError, ValueError):
        return None


def window_blocked(previous, now):
    """Date du dernier échec de fenêtre encore valable, sinon None."""
    at = (previous or {}).get('window_unsupported_at') if isinstance(previous, dict) else None
    age = _age(at, now)
    return at if age is not None and 0 <= age <= RETRY_WINDOW_SECONDS else None


def window_base(previous, now):
    """Inventaire complet récent servant de base à une fenêtre, sinon None."""
    if not isinstance(previous, dict) or not isinstance(previous.get('max_jobid'), int) or window_blocked(previous, now):
        return None
    age = _age(previous.get('full_at'), now)
    return previous if age is not None and 0 <= age <= FULL_EVERY_SECONDS else None


def merge(previous, payload, limit=WINDOW):
    """(inventaire, mode) ; (None, raison) si la fenêtre ne permet pas de conclure.

    mode 'full' : l'API a ignoré la limite et renvoyé tout l'historique.
    """
    window = jobs(payload)
    if window['jobs_count'] > limit:
        return window, 'full'
    ids = [j['jobid'] for j in window['jobs'] if j['jobid'] is not None]
    known = previous['max_jobid']
    if not ids:
        return None, 'fenêtre vide'
    if max(ids) < known:
        return None, 'fenêtre antérieure au dernier passage connu (ordre de tri non garanti)'
    if min(ids) > known:
        return None, 'plus de passages nouveaux que la fenêtre : trou possible'
    rank = {'critical': 0, 'warning': 1, 'unknown': 2, 'running': 3, 'pending': 4, 'ok': 5}
    kept = {j['jobid']: j for j in previous.get('jobs') or [] if j.get('jobid') is not None}
    counts = {**dict.fromkeys(FAMILIES, 0), **(previous.get('counts') or {})}
    total = previous.get('jobs_count') or 0
    last_success = previous.get('last_success')
    for entry in window['jobs']:
        old = kept.get(entry['jobid'])
        if entry['jobid'] is not None and entry['jobid'] > known:
            counts[entry['severity']] += 1
            total += 1
        elif old and old['severity'] != entry['severity']:
            # Passage déjà compté (en cours au cycle précédent) : seul son état change.
            counts[old['severity']] = max(0, counts[old['severity']] - 1)
            counts[entry['severity']] += 1
        if (entry['severity'] == 'ok' and entry['endtime'] and entry.get('type') in ('B', None)
                and (last_success is None or entry['endtime'] > last_success)):
            last_success = entry['endtime']
        kept[entry['jobid']] = entry
    latest = {}
    for entry in [*(previous.get('latest') or []), *window['jobs']]:
        identity = (entry.get('name'), entry.get('client'))
        known_entry = latest.get(identity)
        if known_entry is None or (entry.get('jobid') or 0) >= (known_entry.get('jobid') or 0):
            latest[identity] = entry
    current = sorted(latest.values(), key=lambda j: (rank.get(j['severity'], 9), j['name']))
    latest_counts, latest_types = dict.fromkeys(FAMILIES, 0), {}
    for entry in current:
        latest_counts[entry['severity']] += 1
        label = entry.get('type_label') or 'Type non renvoyé'
        latest_types[label] = latest_types.get(label, 0) + 1
    recent = sorted(kept.values(), key=lambda j: -(j['jobid'] or 0))[:HISTORY_KEPT]
    recent.sort(key=lambda j: (rank.get(j['severity'], 9), -(j['jobid'] or 0)))
    return {
        **previous, 'jobs': recent, 'jobs_truncated': total - len(recent), 'latest': current,
        'latest_counts': latest_counts, 'latest_types': latest_types, 'counts': counts,
        'jobs_count': total, 'last_success': last_success, 'max_jobid': max(known, max(ids)),
        'empty': not total,
        'collection': f'incrémentale : {len(ids)} derniers passages fusionnés avec la lecture complète du {previous["full_at"][:16]}',
    }, 'window'
