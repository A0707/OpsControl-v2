"""Normalize Zabbix JSON-RPC answers into monitored hosts and active problems.

Same contract as proxmox_inventory: never invent a value, never promote an
absent measure to a healthy one, and keep the scope of what the token could
actually see explicit.
"""

from datetime import datetime, timezone


def item_observed_at(items):
    """Oldest contributing item; missing clocks are never replaced by fetch time."""
    if not isinstance(items, list) or not items:
        return None
    clocks = []
    try:
        for item in items:
            value = int(item['lastclock'])
            if value <= 0:
                return None
            clocks.append(value)
        return datetime.fromtimestamp(min(clocks), timezone.utc).isoformat()
    except (TypeError, ValueError, KeyError, OverflowError, OSError):
        return None

# Gravités Zabbix (priority du trigger) -> vocabulaire commun à la plateforme.
# 'unknown' n'est jamais produit ici : une gravité absente reste 'unknown'.
SEVERITIES = {
    0: ('not_classified', 'Non classée', 'unknown'),
    1: ('information', 'Information', 'unknown'),
    2: ('warning', 'Avertissement', 'warning'),
    3: ('average', 'Moyenne', 'warning'),
    4: ('high', 'Haute', 'critical'),
    5: ('disaster', 'Désastre', 'critical'),
}


def _text(value, limit=200):
    return str(value)[:limit] if value is not None else None


def _rpc_result(payload, expected=list):
    """Extrait `result` d'une réponse JSON-RPC, en refusant tout autre format.

    Les erreurs applicatives (`error`) sont déjà interceptées en amont par
    collect_connection ; ici on ne valide que la forme.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get('result'), expected):
        raise ValueError('Zabbix response invalid')
    return payload['result']


# Plafonds des requêtes figées (management.READ_ONLY_RPC). Atteindre le plafond signifie que la
# liste est peut-être incomplète : on le dit au lieu de présenter un total rassurant (audit CON-01).
HOST_LIMIT = 2000
TRIGGER_LIMIT = 500


def hosts_inventory(payload):
    """Normalise la réponse de host.get."""
    result = _rpc_result(payload)
    hosts = []
    counts = {'monitored': 0, 'unmonitored': 0, 'unknown': 0}
    ignored = 0
    for item in result:
        if not isinstance(item, dict) or not item.get('hostid'):
            ignored += 1
            continue
        # status : '0' surveillé, '1' non surveillé. Toute autre valeur reste inconnue.
        raw = str(item.get('status', ''))
        state = 'monitored' if raw == '0' else 'unmonitored' if raw == '1' else 'unknown'
        counts[state] += 1
        interfaces = item.get('interfaces')
        addresses = [_text(i.get('ip'), 64) for i in interfaces if isinstance(i, dict) and i.get('ip')] if isinstance(interfaces, list) else []
        hosts.append({
            'hostid': _text(item.get('hostid'), 32),
            'host': _text(item.get('host')) or _text(item.get('hostid'), 32),
            'name': _text(item.get('name')) or _text(item.get('host')),
            'status': state,
            'addresses': addresses[:8],
        })
    hosts.sort(key=lambda h: (h['name'] or '').lower())
    return {'hosts': hosts, 'counts': counts, 'hosts_count': len(hosts), 'ignored': ignored,
            'hosts_truncated': len(result) >= HOST_LIMIT,
            'scope': 'Hôtes visibles par ce jeton ; les permissions Zabbix peuvent limiter la liste.' +
                     (f' Liste plafonnée à {HOST_LIMIT} hôtes : elle peut être incomplète.'
                      if len(result) >= HOST_LIMIT else ''),
            'empty': not hosts}


def problems(payload):
    """Normalise la réponse de trigger.get (triggers actuellement en anomalie).

    Zabbix renvoie un trigger par problème actif, avec les hôtes concernés.
    On conserve l'identité de la source : aucun regroupement implicite.
    """
    result = _rpc_result(payload)
    items = []
    counts = {'critical': 0, 'warning': 0, 'unknown': 0}
    for item in result:
        if not isinstance(item, dict) or not item.get('triggerid'):
            continue
        try:
            priority = int(item.get('priority'))
        except (TypeError, ValueError):
            priority = None
        key, label, severity = SEVERITIES.get(priority, ('unknown', 'Gravité non renseignée', 'unknown'))
        counts[severity] += 1
        related = item.get('hosts')
        names = [_text(h.get('name') or h.get('host')) for h in related if isinstance(h, dict)] if isinstance(related, list) else []
        items.append({
            'triggerid': _text(item.get('triggerid'), 32),
            'description': _text(item.get('description'), 400) or 'Description non renseignée',
            'priority': priority,
            'severity_key': key,
            'severity_label': label,
            'severity': severity,
            'hosts': [n for n in names if n][:8],
            'last_change': _text(item.get('lastchange'), 32),
            'measurement_at': item_observed_at(item.get('items')),
        })
    # Le plus grave d'abord, puis le plus récent.
    items.sort(key=lambda p: (-(p['priority'] if p['priority'] is not None else -1), p['description'] or ''))
    # `problem_counts` et non `counts` : hosts_inventory publie déjà `counts`
    # pour les hôtes, et inventory() fusionne les deux dictionnaires.
    truncated = len(result) >= TRIGGER_LIMIT
    return {'problems': items, 'problem_counts': counts, 'problems_count': len(items),
            'problems_truncated': truncated,
            'problems_scope': 'Triggers en anomalie visibles par ce jeton, dépendances exclues. '
                     'Un trigger actif n’est pas une preuve d’indisponibilité : confirmer avant intervention.' +
                     (f' Liste plafonnée à {TRIGGER_LIMIT} triggers, les plus graves d’abord : '
                      'des problèmes moins graves peuvent manquer.' if truncated else '')}


def inventory(hosts_payload, triggers_payload=None):
    """Assemble la vue complète. `triggers_payload` absent = problèmes non collectés."""
    result = hosts_inventory(hosts_payload)
    if triggers_payload is None:
        result['problems'] = None
        result['problem_counts'] = None
        result['problems_scope'] = None
        result['problems_error'] = 'Problèmes non collectés.'
        return result
    result.update(problems(triggers_payload))
    return result
