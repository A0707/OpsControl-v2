"""Allègement des listes de serveurs (/api/overview, /api/sync).

Mesuré le 26/09 : /api/overview pesait 1,78 Mo par appel (227 Ko compressé),
toutes les 30 s par onglet ouvert et toutes les 5 s pendant une collecte. Trois
quarts du poids venaient de données que SEULE la fiche d'un serveur affiche :
  checks 31 % · all_services 28 % · storage 9 % · filesystems 6 %.

La fiche serveur (/api/hosts/{clé}) est construite à part, depuis rows() : elle
garde TOUT. Ici, on ne retire que ce qu'aucune vue de liste ne lit (vérifié dans
web/*.js), et on le dit dans la réponse (`detail_trimmed`).

`all_services` : la liste du parc n'en utilise que les unités en échec (colonne
« Services ») ; seules ces unités restent, avec le total. Les milliers d'unités
inactive ne sont ni des échecs ni utilisées par une vue de liste. La page
Services charge la liste complète par /api/services.
"""
from __future__ import annotations

# Lus uniquement dans la fiche d'un serveur ou par une page à chargement dédié.
DETAIL_ONLY = ('checks', 'storage', 'filesystems', 'attempts', 'waf', 'findings',
               'proxmox_matches', 'issues', 'inventory_sources', 'fingerprint',
               # Relevé des applications : lu par l'onglet « Applications » de la fiche seulement.
               'applications')
ATTEMPT_KEEP = ('collected_at', 'issues', 'status')
# Configuration SSH locale du poste OpsControl (chemins de clé et de configuration) :
# aucune vue ne les lit, et leur place est /api/runtime, réservé à l'administrateur.
LOCAL_SSH_FIELDS = ('key_path', 'ssh_config', 'ssh_host')


# Dictionnaire des environnements (audit UI du 31/10, fiches 03.1 et 14.3) : « PROD » et « Prod »
# formaient deux valeurs de filtre. Les listes affichent la forme canonique ; la valeur saisie
# reste dans hosts.yaml et la fiche serveur (`environment_raw` quand elle diffère).
ENVIRONMENTS = {
    'prod': 'PROD', 'production': 'PROD', 'prd': 'PROD',
    'preprod': 'PRÉPROD', 'pre-prod': 'PRÉPROD', 'préprod': 'PRÉPROD', 'pré-prod': 'PRÉPROD',
    'recette': 'RECETTE', 'rec': 'RECETTE', 'qualif': 'RECETTE', 'qualification': 'RECETTE',
    'dev': 'DEV', 'developpement': 'DEV', 'développement': 'DEV',
    'test': 'TEST', 'tests': 'TEST',
    'à renseigner': 'À renseigner', 'a renseigner': 'À renseigner',
}


def canonical_environment(value):
    if not isinstance(value, str) or not value.strip():
        return value
    text = value.strip()
    # Valeur hors dictionnaire : conservée telle quelle (pas de mise en majuscules arbitraire).
    return ENVIRONMENTS.get(text.lower(), text)


def without_local_ssh(host):
    return {k: v for k, v in host.items() if k not in LOCAL_SSH_FIELDS}


def slim(host):
    allege = {k: v for k, v in host.items() if k not in DETAIL_ONLY and k not in LOCAL_SSH_FIELDS}
    services = host.get('all_services')
    if isinstance(services, list):
        allege['all_services'] = [s for s in services if isinstance(s, dict) and s.get('status') == 'failed']
        allege['services_total'] = len(services)
    tentative = host.get('last_attempt')
    if isinstance(tentative, dict):
        allege['last_attempt'] = {k: tentative[k] for k in ATTEMPT_KEEP if k in tentative}
    # Cause principale et contrôles non observés (audit UI du 31/10, fiches 03.3 et 05.1) :
    # dérivés des constats et contrôles avant leur retrait, pour qu'une ligne critique ou un
    # audit partiel s'explique sans ouvrir la fiche.
    reason = status_reason(host)
    if reason:
        allege['status_reason'] = reason
    checks = host.get('checks')
    if isinstance(checks, list):
        allege['coverage_missing'] = [str(c.get('title') or c.get('id'))[:80] for c in checks
                                      if isinstance(c, dict) and c.get('status') == 'unknown'][:20]
    documented = host.get('documented')
    if isinstance(documented, dict):
        # Les vues de liste ne lisent que la documentation de sauvegarde.
        allege['documented'] = {'backup': documented['backup']} if documented.get('backup') else {}
    environment = canonical_environment(host.get('environment'))
    if environment != host.get('environment'):
        allege['environment'], allege['environment_raw'] = environment, host.get('environment')
    allege['detail_trimmed'] = True
    return allege


def status_reason(host):
    """Titre du premier constat de la gravité de l'audit (constats triés, critiques en tête).

    Un audit ancien garde sa gravité mesurée dans `audit_status` : la cause reste celle de
    cette mesure, la colonne d'état disant déjà qu'elle est à actualiser.
    """
    severity = host.get('audit_status') or host.get('status')
    if severity not in ('critical', 'warning', 'unreachable'):
        return None
    for finding in host.get('findings') or []:
        if isinstance(finding, dict) and finding.get('severity') == severity and finding.get('title'):
            return str(finding['title'])[:160]
    return None


def services(rows):
    """{clé serveur: toutes les unités observées} pour la page Services."""
    return {h['key']: h.get('all_services') or h.get('service_states') or [] for h in rows}


def findings(rows):
    """{clé serveur: constats complets} pour Problèmes et Sécurité."""
    return {h['key']: h.get('findings') or [] for h in rows}
