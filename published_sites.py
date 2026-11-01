"""Enregistrements web publiés vers chaque serveur (rapprochement WAF → serveur applicatif).

Les noms DNS et les sites sont déclarés sur le WAF (reverse proxy) : chaque site y renvoie
vers « serveur:port ». Ce module retrouve, pour un serveur de l'inventaire, tous les
enregistrements dont la cible est ce serveur, et l'application qui écoute sur le port visé
d'après le relevé des applications du serveur lui-même.

Lecture seule : uniquement des relevés déjà collectés (audit SSH), aucune connexion.
"""
from __future__ import annotations

import re

_CIBLE = re.compile(r'^(?P<hote>.*):(?P<port>\d{1,5})(?P<chemin>/.*)?$')
_PORT_DOCKER = re.compile(r':(\d+)->\d+/tcp')
LOCAUX = {'127.0.0.1', 'localhost', '::1', ''}


def _identites(host: dict) -> set[str]:
    valeurs = (host.get('ip'), host.get('key'), host.get('name'), host.get('fqdn'), host.get('ssh_host'))
    noms = {str(v).lower().rstrip('.') for v in valeurs if v}
    # Nom court : « app01.domaine.local » est aussi visé par « app01 ».
    return noms | {n.split('.')[0] for n in noms if not n.replace('.', '').isdigit()}


def _cible(entree: dict) -> tuple[str, int | None, str]:
    """(hôte, port, chemin) d'une cible ; relevés antérieurs : champ texte « hôte:port/chemin »."""
    if entree.get('hote') is not None and entree.get('port') is not None:
        return str(entree['hote']).lower(), int(entree['port']), entree.get('chemin_cible') or '/'
    m = _CIBLE.match(str(entree.get('cible') or ''))
    if not m:
        return '', None, '/'
    return m['hote'].lower(), int(m['port']), m['chemin'] or '/'


def application_locale(apps: dict, port: int | None, chemin: str) -> str:
    """Ce qui écoute sur `port` d'après le relevé du serveur cible ; jamais une supposition."""
    if not apps or apps.get('status') != 'observed':
        return 'Relevé des applications indisponible sur ce serveur : relancer son audit'
    elements = apps.get('elements') or []
    for e in elements:
        if e.get('categorie') == 'Conteneur' and str(port) in _PORT_DOCKER.findall(e.get('detail') or ''):
            return 'Conteneur Docker ' + str(e.get('nom'))
    contexte = (chemin or '/').strip('/').split('/')[0]
    if contexte:
        for e in elements:
            if e.get('categorie') == 'Application web (Tomcat)' and e.get('nom') == contexte:
                return 'Application Tomcat ' + contexte
    if str(port) in (apps.get('ports') or []):
        return f'Service en écoute sur le port {port} (processus non nommé sans droits root)'
    return f'Port {port} non en écoute sur ce serveur (application arrêtée ou mauvaise cible ?)'


def published_to(host: dict, assets: list[dict]) -> list[dict]:
    """Enregistrements des AUTRES serveurs (WAF, répartiteurs) qui renvoient vers `host`."""
    identites = _identites(host)
    publies = []
    for source in assets:
        if source.get('key') == host.get('key'):
            continue
        releve = source.get('applications') or {}
        if releve.get('status') != 'observed':
            continue
        for site in releve.get('sites') or []:
            for entree in site.get('cibles') or []:
                hote, port, chemin = _cible(entree)
                if not hote or hote in LOCAUX or hote.rstrip('.') not in identites:
                    continue
                publies.append({
                    'site': site.get('nom'), 'url': site.get('url'), 'https': bool(site.get('https')),
                    'dns': site.get('dns'), 'chemin': entree.get('chemin') or '/', 'port': port,
                    'chemin_cible': chemin, 'via': {'key': source.get('key'), 'name': source.get('name') or source.get('key')},
                    'releve_le': releve.get('collected_at'), 'repartiteur': entree.get('repartiteur'),
                    'application': application_locale(host.get('applications') or {}, port, chemin)})
    return sorted(publies, key=lambda p: (str(p['site']).lower(), p['port'] or 0, p['chemin']))


def annotate_targets(host: dict, assets: list[dict]) -> None:
    """Sur le WAF : chaque cible distante reçoit le serveur de l'inventaire qu'elle désigne."""
    releve = host.get('applications') or {}
    index = []
    for autre in assets:
        if autre.get('key') != host.get('key'):
            index.append((_identites(autre), {'key': autre.get('key'), 'name': autre.get('name') or autre.get('key')}))
    for site in releve.get('sites') or []:
        for entree in site.get('cibles') or []:
            hote, _port, _chemin = _cible(entree)
            if hote and hote not in LOCAUX:
                entree['serveur'] = next((ref for noms, ref in index if hote.rstrip('.') in noms), None)
