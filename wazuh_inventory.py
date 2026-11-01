"""Normalize Wazuh manager answers into daemons, agents and manager identity.

Three endpoints feed this view, all read-only:
  /manager/status              -> état des démons (collecte principale)
  /agents/summary/status       -> répartition des agents (collecte secondaire)
  /manager/info                -> version et identité du manager (secondaire)

Comme partout ailleurs dans la plateforme, une valeur non collectée reste
`None` et n'est jamais présentée comme un état sain.
"""

# États d'agent renvoyés par Wazuh, traduits une seule fois ici.
AGENT_STATES = {
    'active': 'Actifs',
    'disconnected': 'Déconnectés',
    'pending': 'En attente',
    'never_connected': 'Jamais connectés',
}


def _affected(payload):
    """Extrait data.affected_items d'une réponse Wazuh, sinon lève."""
    if not isinstance(payload, dict) or not isinstance(payload.get('data'), dict):
        raise ValueError('Wazuh response invalid')
    items = payload['data'].get('affected_items')
    return items if isinstance(items, list) else []


def daemons(payload):
    """Normalise /manager/status : un démon par clé, valeur running/stopped/failed."""
    items = _affected(payload)
    entries = []
    counts = {'running': 0, 'stopped': 0, 'failed': 0, 'unknown': 0}
    for item in items:
        if not isinstance(item, dict):
            continue
        for name, raw in item.items():
            state = raw if raw in ('running', 'stopped', 'failed') else 'unknown'
            counts[state] += 1
            entries.append({'name': str(name)[:120], 'status': state})
    entries.sort(key=lambda d: (d['status'] != 'failed', d['status'] != 'stopped', d['name']))
    return {'daemons': entries, 'counts': counts, 'daemons_count': len(entries)}


def agents(payload):
    """Normalise /agents/summary/status. Absent = non collecté, pas 'zéro agent'."""
    if payload is None:
        return None
    data = payload.get('data') if isinstance(payload, dict) else None
    connection = data.get('connection') if isinstance(data, dict) else None
    if not isinstance(connection, dict):
        raise ValueError('Wazuh agents summary invalid')

    def number(key):
        value = connection.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None

    states = [{'key': key, 'label': label, 'count': number(key)} for key, label in AGENT_STATES.items()]
    return {'states': states, 'total': number('total'),
            'scope': 'Agents visibles par ce compte ; un agent « actif » ne prouve pas que ses règles sont à jour.'}


def manager(payload):
    """Normalise /manager/info : version et identité, pour situer la collecte."""
    if payload is None:
        return None
    items = _affected(payload)
    item = next((x for x in items if isinstance(x, dict)), {})
    keep = ('version', 'compilation_date', 'type', 'path', 'max_agents', 'openssl_support')
    return {k: (str(item[k])[:200] if item.get(k) is not None else None) for k in keep} or None


def inventory(status_payload, agents_payload=None, info_payload=None):
    """Assemble la vue Wazuh complète, chaque source restant optionnelle."""
    result = daemons(status_payload)
    for key, builder, source in (('agents', agents, agents_payload), ('manager', manager, info_payload)):
        try:
            result[key] = builder(source)
        except Exception:
            # Une source secondaire illisible ne doit jamais faire échouer la
            # collecte principale : on la marque absente, l'interface le dira.
            result[key] = None
    result['empty'] = not result['daemons']
    result['scope'] = ('Démons du manager lus via /manager/status. Un démon « running » ne prouve ni '
                       'l’ingestion des événements ni la fraîcheur des règles.')
    return result
