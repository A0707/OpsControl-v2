"""Politique de gravité InfraOps : UNE grille, appliquée à toutes les sources.

Pourquoi ne pas reprendre la gravité de Zabbix : elle dépend de chaque modèle
de trigger, écrit par des personnes différentes à des époques différentes. Sur
les données réelles, « VM arrêtée » (41 fois, dont des templates) était au
même niveau qu'un volume à 80 %, et un trigger de TEST était classé
« Désastre ». Une gravité doit répondre à une seule question : **en combien de
temps faut-il intervenir ?**

    critical    Intervention immédiate : service rompu ou rupture sous 48 h.
    warning     Majeur — intervenir sous 24 à 72 h : dégradation ou perte de
                redondance, pas encore de rupture.
    preventive  Préventif — planifier sous 2 à 4 semaines : dérive mesurée,
                correction avant qu'elle devienne un incident.
    info        Aucune intervention attendue : état voulu, bruit, test.

Principes (bonnes pratiques d'exploitation) :
- Un pourcentage seul ne suffit pas pour un disque : 95 % d'un volume de 10 To
  laisse 500 Go, 95 % d'une racine de 20 Go en laisse 1. On croise le
  pourcentage, l'espace libre ABSOLU et la vitesse de remplissage.
- La tendance est la seule vraie mesure préventive : « plein dans 6 jours » est
  plus urgent que « 91 % stable depuis un an ».
- Toute règle est écrite dans RULES : l'interface l'affiche, l'exploitant sait
  pourquoi une alerte a ce niveau. Aucune gravité n'est opaque.
"""
from __future__ import annotations

import re
from datetime import datetime

GIB = 1024 ** 2  # en Kio, l'unité de df

LEVELS = ('critical', 'warning', 'preventive', 'info')
RANK = {level: i for i, level in enumerate(LEVELS)}
LABELS = {'critical': 'Critique', 'warning': 'Majeur', 'preventive': 'Préventif', 'info': 'Information'}
DELAYS = {'critical': 'Intervention immédiate', 'warning': 'Sous 24 à 72 h',
          'preventive': 'À planifier sous 2 à 4 semaines', 'info': 'Aucune intervention'}


def worst(*levels):
    levels = [l for l in levels if l]
    return min(levels, key=RANK.get) if levels else None


def soften(level):
    """Un cran de moins, jamais sous « préventif » : l'écart reste visible."""
    return {'critical': 'warning', 'warning': 'preventive'}.get(level, level)


# --- Disques --------------------------------------------------------------------
DISK_PCT = ((95, 'critical'), (90, 'warning'), (80, 'preventive'))
DISK_LARGE_FREE_GIB = 50     # au-delà, le pourcentage surestime l'urgence
DISK_MIN_FREE_GIB = 1        # en deçà, rupture imminente quel que soit le %
TREND_DAYS = ((2, 'critical'), (7, 'warning'), (30, 'preventive'))
TREND_MIN_SPAN_H = 12        # sous 12 h d'historique, une pente n'est que du bruit
TREND_MIN_POINTS = 3


def disk(use_pct, total_kb=None, available_kb=None, days_to_full=None):
    """Gravité d'un système de fichiers. Renvoie (niveau|None, raisons)."""
    raisons, niveau = [], None
    if use_pct is not None:
        niveau = next((lvl for seuil, lvl in DISK_PCT if use_pct >= seuil), None)
        if niveau:
            raisons.append(f'{use_pct} % occupé')
    libre_gib = available_kb / GIB if available_kb is not None else None
    if niveau and libre_gib is not None and libre_gib >= DISK_LARGE_FREE_GIB:
        niveau = soften(niveau)
        raisons.append(f'{libre_gib:.0f} Gio encore libres : urgence réduite d’un cran')
    if libre_gib is not None and libre_gib < DISK_MIN_FREE_GIB and (total_kb or 0) >= 2 * GIB:
        niveau = 'critical'
        raisons.append(f'moins de {DISK_MIN_FREE_GIB} Gio libre')
    if days_to_full is not None:
        tendance = next((lvl for jours, lvl in TREND_DAYS if days_to_full <= jours), None)
        if tendance:
            niveau = worst(niveau, tendance)
            raisons.append(f'saturation projetée dans {max(days_to_full, 0):.1f} j au rythme observé')
    return niveau, raisons


def inodes(use_pct):
    niveau = next((lvl for seuil, lvl in DISK_PCT if use_pct is not None and use_pct >= seuil), None)
    return niveau, ([f'{use_pct} % des inodes utilisés'] if niveau else [])


def _instant(value):
    try:
        return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return None


def days_to_full(points):
    """Projection linéaire (moindres carrés) de la date de saturation.

    `points` : [(horodatage ISO, used_kb, total_kb)]. Renvoie None si
    l'historique est trop court, si le volume ne croît pas, ou si la taille a
    changé (extension, remontage) : une pente sur deux volumes différents ne
    veut rien dire.
    """
    serie = [(_instant(t), u, tot) for t, u, tot in points if u is not None and tot]
    serie = [p for p in serie if p[0] is not None]
    if len(serie) < TREND_MIN_POINTS or len({p[2] for p in serie}) > 1:
        return None
    serie.sort()
    if (serie[-1][0] - serie[0][0]) / 3600 < TREND_MIN_SPAN_H:
        return None
    n = len(serie)
    mx = sum(p[0] for p in serie) / n
    my = sum(p[1] for p in serie) / n
    var = sum((p[0] - mx) ** 2 for p in serie)
    if not var:
        return None
    pente = sum((p[0] - mx) * (p[1] - my) for p in serie) / var  # Kio par seconde
    if pente <= 0:
        return None
    restant = serie[-1][2] - serie[-1][1]
    return restant / pente / 86400


# --- Mémoire, CPU, uptime ---------------------------------------------------------
# La RAM est mesurée via MemAvailable : le cache n'y est pas compté, 95 % est
# donc une vraie pression mémoire, pas un effet du cache disque.
RAM_PCT = ((97, 'critical'), (92, 'warning'), (85, 'preventive'))
CPU_SUSTAINED_PCT, CPU_SUSTAINED_POINTS = 90, 3
UPTIME_DAYS = 365


def memory(ram_pct):
    niveau = next((lvl for seuil, lvl in RAM_PCT if ram_pct is not None and ram_pct >= seuil), None)
    return niveau, ([f'{ram_pct:.1f} % de mémoire utilisée (hors cache)'] if niveau else [])


def cpu(history):
    """Un relevé CPU instantané ne prouve rien : on exige une charge SOUTENUE."""
    recents = [v for v in history[:CPU_SUSTAINED_POINTS] if v is not None]
    if len(recents) == CPU_SUSTAINED_POINTS and all(v >= CPU_SUSTAINED_PCT for v in recents):
        return 'warning', [f'CPU ≥ {CPU_SUSTAINED_PCT} % sur {CPU_SUSTAINED_POINTS} audits consécutifs']
    return None, []


def uptime(text):
    m = re.search(r'up\s+(\d+)\s+day', text or '')
    jours = int(m.group(1)) if m else None
    if jours is not None and jours >= UPTIME_DAYS:
        return 'preventive', [f'{jours} jours sans redémarrage : correctifs noyau probablement non appliqués']
    return None, []


# --- Services systemd -------------------------------------------------------------
# Classement par RÔLE, faute d'inventaire des services critiques (2 déclarés
# sur 87 serveurs). Un service déclaré critique dans l'inventaire prime.
SERVICE_CLASSES = (
    ('preventive', 'tâche de maintenance planifiée (oneshot)',
     r'^(logrotate|sysstat|kdump|man-db|fstrim|apt-daily.*|e2scrub.*|NetworkManager-wait-online|'
     r'systemd-networkd-wait-online|motd-news|updatedb|mlocate|plocate-updatedb)\b'),
    ('warning', 'agent de supervision, de journalisation ou de sécurité : perte de visibilité',
     r'^(auditd|zabbix-agent2?|filebeat|metricbeat|auditbeat|wazuh-.*|fail2ban|rsyslog|'
     r'node_exporter|bacula-fd|chrony|chronyd|ntp|ntpd|systemd-timesyncd|crowdsec)\b'),
    ('critical', 'service de production, de données ou de réseau',
     r'^(tomcat.*|postgresql.*|mysql.*|mariadb.*|mongod.*|redis.*|nginx|apache2|httpd|haproxy|'
     r'keepalived|openvpn.*|wireguard.*|wg-quick.*|networking|systemd-networkd|NetworkManager|'
     r'postfix|docker|containerd|elasticsearch|kibana|logstash|php.*-fpm|nfs-server|nfs-kernel-server|'
     r'smbd|named|bind9|unbound|slapd|sshd?|zabbix-server|bacula-dir|bacula-sd|pve.*)\b'),
)


def service(unit, declared=()):
    nom = unit.removesuffix('.service')
    base = nom.split('@')[0]
    if nom in declared or base in declared:
        return 'critical', ['service déclaré critique dans l’inventaire']
    for niveau, motif, expr in SERVICE_CLASSES:
        if re.match(expr, nom):
            return niveau, [motif]
    return 'warning', ['service non classé : à qualifier dans l’inventaire']


# --- Requalification des triggers Zabbix -----------------------------------------
# (motif, niveau, raison). Premier motif trouvé gagne. `disk` est traité à part :
# une mesure SSH du même volume, si elle existe, prime sur le texte du trigger.
ZABBIX_RULES = (
    (r'\btest\b.*\btrigger\b|\btrigger\b.*\btest\b', 'info', 'trigger de test : à désactiver dans Zabbix'),
    # Modèle « InfraOps Batch » (deploy/zabbix-template-batch.yaml) : un batch en
    # échec ou qui ne s'est pas lancé est un incident, quel que soit le serveur.
    (r'^Batch \S+ (en échec|non exécuté)', 'critical',
     'résultat de batch remonté par infraops-batch-report : échec ou exécution manquante'),
    (r'\bCARP\b.*(role.*chang|state.*chang|failover|bascule|inversion|split.?brain|dual.?master|no master)|'
     r'(bascule|inversion|split.?brain).*\bCARP\b', 'critical',
     'transition ou conflit CARP signalé par un trigger actif : vérifier les deux pairs'),
    (r'Proxmox: VM .*Not running', 'info',
     'VM arrêtée : état voulu tant qu’elle n’est pas attendue en production (templates inclus)'),
    (r'configuration changed|recommended extension|information was changed|has (just )?been restarted|'
     r'gzip compression is off', 'info', 'changement ou optimisation, sans impact de service'),
    (r'free disk space|disk space is (low|critically)|filesystem space usage', 'disk', ''),
    (r'certificate (has )?expired', 'critical', 'certificat expiré : connexions refusées'),
    (r'certificate expires', 'preventive', 'certificat à renouveler avant expiration'),
    (r'agent .*(unreachable|not available)|unreachable for \d+ minutes', 'warning',
     'agent de supervision injoignable : perte de visibilité sur le serveur'),
    (r'is down|\bdown\b|is not reachable|unavailable by ICMP|service not running|has stopped|no route',
     'critical', 'service ou hôte indisponible'),
    (r'enough space|out of (memory|space)|OOM', 'warning', 'capacité insuffisante pour une opération prévue'),
    (r'slave|replica|replication|standby', 'warning', 'redondance de données dégradée'),
    (r'/etc/passwd has been changed|/etc/shadow|sudoers', 'warning',
     'changement de fichier sensible : vérifier qu’il est autorisé'),
    (r'failed to get items|no data|missing data|not supported', 'preventive',
     'trou de supervision : des mesures n’arrivent plus'),
    (r'poller|configuration cache|history cache|queue', 'preventive', 'santé interne de Zabbix à surveiller'),
    (r'update available|new version available', 'preventive', 'mise à jour disponible : à planifier'),
    (r'too many|too long|too high|too low|hit ratio|high (cpu|memory)|load average|utilization', 'preventive',
     'dérive de performance à analyser'),
)
ZABBIX_DEFAULT = {'critical': 'warning', 'warning': 'preventive', 'unknown': 'preventive'}


def zabbix(description, source_severity):
    """Gravité InfraOps d'un trigger. Renvoie (niveau|'disk', raison, requalifié)."""
    for expr, niveau, raison in ZABBIX_RULES:
        if re.search(expr, description or '', re.I):
            return niveau, raison, True
    # Trigger non couvert : on ne reprend PAS tel quel « Haute/Désastre » d'un
    # modèle inconnu, on descend d'un cran et on le signale comme non qualifié.
    return (ZABBIX_DEFAULT.get(source_severity, 'preventive'),
            'trigger non couvert par la politique : gravité Zabbix abaissée d’un cran, à qualifier', False)


def zabbix_volume(description):
    m = re.search(r'volume\s+(\S+)', description or '', re.I)
    return m.group(1).rstrip(':') if m else None


RULES = [
    {'domain': 'Disque', 'rule': 'Occupation ≥ 95 % : critique · ≥ 90 % : majeur · ≥ 80 % : préventif'},
    {'domain': 'Disque', 'rule': f'Plus de {DISK_LARGE_FREE_GIB} Gio libres : un cran de moins (grands volumes)'},
    {'domain': 'Disque', 'rule': f'Moins de {DISK_MIN_FREE_GIB} Gio libre : critique quel que soit le pourcentage'},
    {'domain': 'Disque', 'rule': 'Saturation projetée ≤ 2 j : critique · ≤ 7 j : majeur · ≤ 30 j : préventif '
                                 f'(régression sur l’historique des audits, ≥ {TREND_MIN_SPAN_H} h et ≥ {TREND_MIN_POINTS} mesures)'},
    {'domain': 'Inodes', 'rule': 'Mêmes seuils que l’occupation disque'},
    {'domain': 'Mémoire', 'rule': 'Hors cache : ≥ 97 % critique · ≥ 92 % majeur · ≥ 85 % préventif'},
    {'domain': 'CPU', 'rule': f'≥ {CPU_SUSTAINED_PCT} % sur {CPU_SUSTAINED_POINTS} audits consécutifs : majeur (un pic isolé n’alerte pas)'},
    {'domain': 'Services', 'rule': 'Production, données, réseau : critique · supervision et sécurité : majeur · '
                                   'maintenance planifiée : préventif · non classé : majeur'},
    {'domain': 'Partages', 'rule': 'Injoignable depuis un client : critique · occupation : seuils disque'},
    {'domain': 'ZFS / SMART', 'rule': 'Pool FAULTED/UNAVAIL ou disque SMART en échec : critique · pool DEGRADED : majeur'},
    {'domain': 'Système', 'rule': f'≥ {UPTIME_DAYS} jours sans redémarrage : préventif (correctifs noyau)'},
    {'domain': 'Zabbix', 'rule': 'Requalifié par règle ; disque mesuré en SSH : la mesure prime ; '
                                 'trigger non couvert : gravité Zabbix abaissée d’un cran'},
    {'domain': 'Sauvegardes', 'rule': 'Dernier passage en erreur : critique · avertissement : majeur'},
    {'domain': 'Batch', 'rule': 'Dernier passage en échec : majeur (critique si criticité ≥ 3) · '
                                'batch quotidien sans passage depuis 26 h : majeur'},
    {'domain': 'Voie rapide', 'rule': 'Serveur critique : ICMP et TCP muets sur 2 sondes consécutives (10 s) : critique · '
                                      'une seule des deux sondes muette : majeur'},
]
