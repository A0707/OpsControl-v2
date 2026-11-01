"""Analyse des IP bannies par Fail2ban sur un WAF (lecture des collectes enregistrées).

Pour chaque IP du jail apache-modsecurity : nature de l'adresse, conflit avec la liste
blanche, appartenance à l'inventaire, regroupement par réseau, activité observée dans les
échantillons de journaux, date et échéance du ban. Un VERDICT en découle :

- incohérent   : l'IP est à la fois bannie et dans la liste blanche (ignoreip) ;
- à vérifier   : adresse interne / privée, serveur de l'inventaire, ou ban sans aucune trace
                 dans les échantillons lus ;
- maintenir    : adresse publique avec activité ModSecurity ou accès observés.

Aucune requête externe (ni WHOIS, ni géolocalisation) : uniquement ce que la sonde a lu sur
le WAF. Aucune action : les commandes de vérification et de déblocage sont préparées par
waf_findings.command_plan, à copier et exécuter à la main.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
import re


def observe(db, host_key, host_ip, waf):
    section = (waf.get('sections') or {}).get('fail2ban') or {}
    if section.get('status') != 'observed' or not waf.get('collected_at'):
        return
    try:
        stamp = datetime.fromisoformat(waf['collected_at']).astimezone(timezone.utc).isoformat(timespec='microseconds')
    except (ValueError, TypeError):
        return
    previous = db.execute('SELECT last_at FROM waf_ban_sources WHERE host_key=? AND host_ip=?',
                          (host_key, host_ip)).fetchone()
    if previous and stamp <= previous[0]:
        return
    data = section.get('data') if isinstance(section.get('data'), dict) else {}
    # Réponse distante : une entrée malformée est ignorée, elle ne fait jamais échouer
    # l'enregistrement de la collecte (audit WAF-01).
    banned = set()
    for ip in data.get('banned_ips') if isinstance(data.get('banned_ips'), list) else []:
        try:
            banned.add(str(ip_address(str(ip))))
        except ValueError:
            continue
    times = (((waf.get('sections') or {}).get('bantimes') or {}).get('data') or {}).get('bans')
    times = times if isinstance(times, dict) else {}
    for ip in banned:
        known = db.execute('SELECT active,rebans,ban_epoch,current_since FROM waf_ban_history '
                           'WHERE host_key=? AND host_ip=? AND ip=?', (host_key, host_ip, ip)).fetchone()
        entry = times.get(ip) if isinstance(times.get(ip), dict) else {}
        epoch = entry.get('banned_at') if isinstance(entry.get('banned_at'), str) else None
        if known:
            active, rebans, old_epoch, since = known
            new_episode = not active or bool(epoch and isinstance(old_epoch, str) and epoch > old_epoch)
            db.execute('UPDATE waf_ban_history SET last_seen=?,current_since=?,ban_epoch=?,active=1,rebans=? '
                       'WHERE host_key=? AND host_ip=? AND ip=?',
                       (stamp, stamp if new_episode else since, epoch or old_epoch,
                        rebans + int(new_episode), host_key, host_ip, ip))
        else:
            db.execute('INSERT INTO waf_ban_history(host_key, host_ip, ip, first_seen, last_seen, current_since, '
                       'ban_epoch, active, rebans) VALUES(?,?,?,?,?,?,?,1,0)',
                       (host_key, host_ip, ip, stamp, stamp, stamp, epoch))
    # Une liste tronquée ou inconnue ne permet jamais de conclure à un déban.
    if data.get('currently_banned') == len(banned):
        for ip, in db.execute('SELECT ip FROM waf_ban_history WHERE host_key=? AND host_ip=? AND active=1',
                              (host_key, host_ip)).fetchall():
            if ip not in banned:
                db.execute('UPDATE waf_ban_history SET active=0 WHERE host_key=? AND host_ip=? AND ip=?',
                           (host_key, host_ip, ip))
    db.execute('INSERT OR REPLACE INTO waf_ban_sources(host_key, host_ip, last_at) VALUES(?,?,?)', (host_key, host_ip, stamp))


def observed_history(connect, host_key, host_ip):
    with connect() as db:
        return {ip: {'first_observed': first, 'last_observed': last,
                     'current_observed_since': since, 'reban_count': rebans}
                for ip, first, last, since, rebans in db.execute(
                    'SELECT ip,first_seen,last_seen,current_since,rebans FROM waf_ban_history '
                    'WHERE host_key=? AND host_ip=?', (host_key, host_ip))}


def campaign_recommendations(campaigns, waf):
    # Les UA sont des déclarations non authentifiées ; aucun WHOIS ni DNS ne les vérifie.
    from apache_probe import BOT_PATTERNS
    access = (((waf.get('apache') or {}).get('sections') or {}).get('access') or {}).get('data') or {}
    sampled = access.get('top_ips') or []
    sampled = list(sampled)
    traffic = (((waf.get('sections') or {}).get('traffic') or {}).get('data') or {})
    for ip, agents in (traffic.get('banned_user_agents') or {}).items():
        sampled.extend({'ip': ip, 'user_agent': agent} for agent, _ in agents)
    recommendations = []
    for network, count in campaigns[:20]:
        categories, patterns = set(), set()
        for item in sampled:
            try:
                inside = ip_address(item['ip']) in ip_network(network)
            except (KeyError, ValueError):
                continue
            if not inside:
                continue
            for name, pattern in BOT_PATTERNS:
                if name not in ('scanners', 'MicroMessenger') and re.search(pattern, item.get('user_agent') or '', re.I):
                    categories.add(name)
                    patterns.add(pattern)
                    break
        text = ('Examiner les motifs ModSecurity et la charge avant une décision sur ce réseau ; '
                'aucun robot d’indexation identifié dans les user-agents disponibles.')
        if categories:
            text = ('User-agents déclarant ' + ', '.join(sorted(categories)) + ' : proposer une limitation de débit '
                    'par vhost ou une règle ModSecurity par user-agent plutôt que des bans IP par IP. '
                    'Valider le seuil et retourner HTTP 429 au-delà ; un user-agent peut être usurpé, '
                    'ne pas créer de liste blanche automatique.')
        recommendations.append({'network': network, 'bans': count, 'bots': sorted(categories),
                                'user_agent_patterns': sorted(patterns), 'text': text,
                                'rule': ('User-Agent correspond à ' + ' | '.join(sorted(patterns)) +
                                         ' ⇒ quota validé par vhost, HTTP 429 au-delà.') if patterns else None,
                                'executable': False})
    return recommendations

VERDICTS = {'incoherent': 0, 'verify': 1, 'keep': 2}
CAMPAIGN_MIN = 3   # IP bannies d'un même /24 (ou /64) à partir desquelles on parle de campagne


def _valid_ip(value):
    """Entrée distante malformée : ignorée plutôt qu'une erreur 500 sur la page (audit WAF-01)."""
    try:
        ip_address(str(value))
        return isinstance(value, str)
    except ValueError:
        return False


def _network(ip):
    addr = ip_address(ip)
    # IPv4 encapsulée (::ffff:a.b.c.d) : regroupée avec son /24 et non dans un faux « ::/64 » (WAF-09).
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return str(ip_network(f'{addr}/{24 if addr.version == 4 else 64}', strict=False))


def _ignored(ip, entries):
    addr = ip_address(ip)
    for entry in entries or []:
        try:
            if addr in ip_network(entry, strict=False):
                return entry
        except ValueError:
            continue
    return None


def _kind(addr, waf_ip):
    if addr.is_loopback or addr.is_link_local:
        return 'locale'
    try:
        prefix = 64 if ip_address(waf_ip).version == 6 else 24
        if waf_ip and addr in ip_network(f'{waf_ip}/{prefix}', strict=False):
            return 'réseau du WAF'
    except ValueError:
        pass
    # CGNAT (100.64/10) et autres plages non routées : « privée », comme dans ip_location (WAF-04).
    return 'publique' if addr.is_global else 'privée'


def analyze(waf: dict, waf_ip: str, inventory: dict | None = None, history=None, locate=None) -> dict:
    """Lignes d'analyse et synthèse. `inventory` : {ip: nom} des serveurs suivis."""
    sections = (waf or {}).get('sections') or {}
    data = lambda name: (sections.get(name) or {}).get('data') or {}
    jail, ignore = data('fail2ban'), data('ignoreip')
    times = data('bantimes').get('bans') or {}
    requests = data('traffic').get('banned_requests') or {}
    alerts = data('modsecurity').get('banned_alerts') or {}
    inventory = inventory or {}
    apache_access = (((waf.get('apache') or {}).get('sections') or {}).get('access') or {}).get('data') or {}
    response_bytes = apache_access.get('sample_response_bytes') or {}
    traffic_counts = dict(data('traffic').get('top_ips') or [])
    traffic_ips = sorted(set(traffic_counts) | set(response_bytes),
                         key=lambda ip: (-(response_bytes.get(ip) or 0), -(traffic_counts.get(ip) or 0)))[:20]
    # Rapprochement bans / journaux disponible seulement avec une sonde récente : sinon,
    # l'absence de trace ne prouve rien et ne doit pas faire basculer le verdict.
    activity_known = 'banned_requests' in data('traffic') and 'banned_alerts' in data('modsecurity')
    banned = [ip for ip in (jail.get('banned_ips') or []) if _valid_ip(ip)]
    times = times if isinstance(times, dict) else {}
    networks = Counter(_network(ip) for ip in banned)
    rows = []
    for ip in banned:
        addr = ip_address(ip)
        kind, net = _kind(addr, waf_ip), _network(ip)
        modsec = alerts.get(ip) or {}
        reasons, verdict = [], 'keep'
        ignored = _ignored(ip, ignore.get('addresses'))
        if ignored:
            verdict = 'incoherent'
            reasons.append(f'Aussi en liste blanche ({ignored}) : configuration contradictoire.')
        if ip in inventory:
            verdict = min(verdict, 'verify', key=VERDICTS.get)
            reasons.append(f'Serveur de l’inventaire ({inventory[ip]}) : ban probablement involontaire.')
        if kind != 'publique':
            verdict = min(verdict, 'verify', key=VERDICTS.get)
            reasons.append(f'Adresse {kind} : vérifier qu’il ne s’agit pas du bastion, d’un proxy ou d’un poste d’exploitation.')
        # « Maintenir » exige une preuve positive : une alerte ModSecurity de cette IP dans
        # l'échantillon. Données absentes ou simple trafic HTTP ne justifient pas de
        # prolonger un ban peut-être faux positif (OC-AUDIT-011).
        if not activity_known:
            verdict = min(verdict, 'verify', key=VERDICTS.get)
            reasons.append('Activité non rapprochée : collecte antérieure à cette analyse, actualiser le WAF.')
        elif not modsec.get('lines') and verdict == 'keep':
            verdict = 'verify'
            reasons.append(f"{requests[ip]} requête(s) HTTP sans alerte ModSecurity : motif du ban à confirmer dans fail2ban.log."
                           if requests.get(ip) else
                           'Aucune trace dans les échantillons lus : motif du ban à confirmer dans fail2ban.log.')
        if not ignored and ignore.get('unparsed'):
            reasons.append(f"Liste blanche partiellement analysée : {ignore['unparsed']} entrée(s) DNS non résolue(s) ; "
                           'vérifier qu’aucune ne couvre cette IP.')
        if modsec:
            reasons.append(f'{modsec.get("lines", 0)} ligne(s) ModSecurity dans l’échantillon.')
        if networks[net] >= CAMPAIGN_MIN:
            reasons.append(f'{networks[net]} IP bannies dans {net} : campagne probable.')
        when = times.get(ip) if isinstance(times.get(ip), dict) else {}
        rows.append({'ip': ip, 'verdict': verdict, 'kind': kind, 'network': net, 'network_bans': networks[net],
                     **((history or {}).get(ip) or {}),
                     'location': locate(ip) if locate else {'status': 'unknown'},
                     'inventory': inventory.get(ip), 'whitelisted_by': ignored,
                     'modsec_lines': modsec.get('lines', 0), 'modsec_rules': [r for r, _ in modsec.get('rules') or []],
                     'requests': requests.get(ip, 0), 'sample_response_bytes': response_bytes.get(ip), 'banned_at': when.get('banned_at'),
                     'expires_at': when.get('expires_at'), 'duration_seconds': when.get('duration_seconds'),
                     'reasons': reasons})
    rows.sort(key=lambda r: (VERDICTS[r['verdict']], -r['modsec_lines'], -r['requests'], r['ip']))
    campaigns = sorted(((net, n) for net, n in networks.items() if n >= CAMPAIGN_MIN), key=lambda x: -x[1])
    status = lambda name: (sections.get(name) or {}).get('status')
    return {'rows': rows,
            'recommendations': campaign_recommendations(campaigns, waf),
            'top_traffic': [{'ip': ip, 'requests': traffic_counts.get(ip),
                             'sample_response_bytes': response_bytes.get(ip),
                             'location': locate(ip) if locate else {'status': 'unknown'}} for ip in traffic_ips],
            'summary': {'listed': len(rows), 'currently_banned': jail.get('currently_banned'),
                        'incoherent': sum(r['verdict'] == 'incoherent' for r in rows),
                        'verify': sum(r['verdict'] == 'verify' for r in rows),
                        'keep': sum(r['verdict'] == 'keep' for r in rows),
                        'campaigns': [{'network': n, 'bans': c} for n, c in campaigns[:20]]},
            'coverage': {'ban_times': bool(times), 'ban_times_status': status('bantimes'), 'activity_known': activity_known,
                         'traffic_sample': status('traffic'), 'modsecurity_sample': status('modsecurity'),
                         'list_limit': jail.get('list_limit'), 'clock': data('bantimes').get('clock')},
            'collected_at': (waf or {}).get('collected_at')}
