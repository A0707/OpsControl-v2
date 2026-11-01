"""Compléter l'inventaire : propositions PROUVÉES, jamais appliquées sans l'opérateur.

Constat du 26/09 : 32 serveurs sur 87 avaient le rôle « À renseigner », et 2
services seulement étaient déclarés critiques sur tout le parc. Conséquences
concrètes : la politique de gravité classait les services par défaut (faute de
liste), la carte du parc et les alertes ne disaient pas À QUOI sert un serveur.

Deux sources de preuve, chacune citée dans la proposition :
1. Services observés en fonctionnement par l'audit SSH (elasticsearch → ELASTIC,
   postgresql → DB, nfs-server → NFS…). Preuve forte : c'est ce qui tourne.
2. Convention de nommage APPRISE de l'inventaire lui-même : le code
   (prdlab<b>swr</b>01) vaut le rôle majoritaire des serveurs déjà classés qui le
   portent (9 « swr » classés SWARM → SWARM). Preuve moyenne : un nom ment parfois.

Confiance : élevée si les deux preuves concordent, ou si un service fort parle
seul ; moyenne si seul le nom parle ; « conflit » si elles divergent — alors rien
n'est proposé d'office, les deux lectures sont montrées.

Rien n'est écrit ici sans une demande explicite (POST /api/inventory/apply).
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from fastapi import HTTPException
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

import alert_policy

A_RENSEIGNER = ('', 'À renseigner', None)

# Service observé -> rôle. Premier motif trouvé gagne ; l'ordre va du plus
# spécifique au plus générique (un serveur Tomcat avec Apache devant est APPLICATION).
ROLE_BY_SERVICE = (
    (r'^elasticsearch|^kibana|^logstash|^opensearch', 'ELASTIC', 'forte'),
    (r'^wazuh-manager|^wazuh-indexer', 'SÉCURITÉ', 'forte'),
    (r'^zabbix-server|^zabbix-proxy', 'MONITORING', 'forte'),
    (r'^bacula-dir|^bacula-sd', 'BACKUP', 'forte'),
    # Un moteur de base tourne souvent AUPRÈS d'autre chose (application, outil,
    # bastion : PostgreSQL sur prddcxans01, le 26/09) : indice, pas preuve de rôle.
    (r'^(rh-)?postgresql|^mysql|^mariadb|^mongod', 'DB', 'moyenne'),
    (r'^nfs-server|^nfs-kernel-server', 'NFS', 'forte'),
    (r'^named|^bind9|^unbound', 'DNS', 'forte'),
    (r'^openvpn|^wg-quick|^wireguard', 'VPN', 'forte'),
    (r'^gitlab', 'GIT', 'forte'),
    (r'^squid', 'PROXY', 'forte'),
    (r'^haproxy|^keepalived', 'RÉPARTITEUR', 'forte'),
    (r'^(apache-)?tomcat', 'APPLICATION', 'forte'),
    (r'^vsftpd|^proftpd|^pure-ftpd', 'FTP', 'forte'),
    (r'^nginx|^apache2|^httpd', 'WEB', 'moyenne'),
)
# Services « critiques » proposés : production, données, réseau applicatif. On
# écarte l'outillage générique (réseau de base, SSH, messagerie locale, agents) :
# le déclarer critique ferait sonner une alerte critique pour rien.
EXCLUS_CRITIQUES = re.compile(r'^(networking|systemd-networkd|NetworkManager|sshd?|postfix(@.*)?|containerd|'
                              r'kmod-static-nodes|postgresql)(\.service)?$')
MAX_SERVICES = 12


def _code(nom):
    """prdlabswr01 -> 'swr' ; prddcxans01 -> 'ans'. Convention prd|rec + site + code."""
    m = re.match(r'^(prd|rec|dev|pre)(lab|dcx|dcy)([a-z]{3})\d', str(nom or '').lower())
    return m.group(3) if m else None


def _prefixe(nom):
    m = re.match(r'^(prd|rec|dev|pre)', str(nom or '').lower())
    return m.group(1) if m else None


def learn(hosts):
    """Conventions apprises de l'inventaire déjà renseigné (au moins 2 exemples, 75 % d'accord)."""
    par_code, par_prefixe = defaultdict(Counter), defaultdict(Counter)
    for h in hosts:
        if h.get('role') not in A_RENSEIGNER and _code(h.get('name')):
            par_code[_code(h.get('name'))][h['role']] += 1
        if h.get('environment') not in A_RENSEIGNER and _prefixe(h.get('name')):
            par_prefixe[_prefixe(h.get('name'))][h['environment']] += 1

    def majoritaire(compteur):
        valeur, n = compteur.most_common(1)[0]
        total = sum(compteur.values())
        return (valeur, n) if n >= 2 and n / total >= 0.75 else None
    return ({c: majoritaire(v) for c, v in par_code.items() if majoritaire(v)},
            {p: majoritaire(v) for p, v in par_prefixe.items() if majoritaire(v)})


def _actifs(row):
    return sorted({str(s.get('name', '')).removesuffix('.service') for s in row.get('all_services') or []
                   if s.get('status') == 'active'})


def suggest(hosts, rows):
    codes, prefixes = learn(hosts)
    par_cle = {r['key']: r for r in rows}
    propositions = []
    for h in hosts:
        row = par_cle.get(h['key'], {})
        actifs = _actifs(row)
        p = {'key': h['key'], 'name': h.get('name') or h['key'], 'ip': h.get('ip'),
             'current': {'role': h.get('role'), 'environment': h.get('environment'), 'services': h.get('services') or []},
             'audited': bool(actifs), 'collected_at': row.get('collected_at')}

        if h.get('role') in A_RENSEIGNER:
            par_service = next(((role, force, s) for expr, role, force in ROLE_BY_SERVICE
                                for s in actifs if re.match(expr, s)), None)
            code = _code(h.get('name'))
            par_nom = codes.get(code) if code else None
            preuves, role, confiance = [], None, None
            if par_service:
                preuves.append(f'service « {par_service[2]} » en fonctionnement')
            if par_nom:
                preuves.append(f'code « {code} » : {par_nom[1]} serveur(s) déjà classé(s) {par_nom[0]}')
            if par_service and par_nom and par_service[0] != par_nom[0]:
                confiance = 'conflit'
                preuves.append(f'lectures divergentes : {par_service[0]} (services) / {par_nom[0]} (nom)')
            elif par_service:
                role = par_service[0]
                confiance = 'élevée' if par_service[1] == 'forte' or par_nom else 'moyenne'
            elif par_nom:
                role, confiance = par_nom[0], 'moyenne'
            if confiance:
                p['role'] = {'value': role, 'confidence': confiance, 'evidence': preuves}

        if h.get('environment') in A_RENSEIGNER:
            env = prefixes.get(_prefixe(h.get('name')))
            if env:
                p['environment'] = {'value': env[0], 'confidence': 'élevée',
                                    'evidence': [f'préfixe « {_prefixe(h.get("name"))} » : {env[1]} serveur(s) en {env[0]}']}

        declares = set(h.get('services') or [])
        candidats = [s for s in actifs if s not in declares and not EXCLUS_CRITIQUES.match(s)
                     and alert_policy.service(s)[0] == 'critical']
        if candidats:
            p['services'] = {'value': candidats[:MAX_SERVICES], 'confidence': 'élevée',
                             'evidence': ['observés en fonctionnement ; rôle « production, données ou réseau » '
                                          'dans la politique de gravité']}
        if any(k in p for k in ('role', 'environment', 'services')):
            propositions.append(p)

    ordre = {'élevée': 0, 'moyenne': 1, 'conflit': 2}
    propositions.sort(key=lambda p: (ordre.get((p.get('role') or {}).get('confidence'), 3), p['name']))
    manquants = sum(1 for h in hosts if h.get('role') in A_RENSEIGNER)
    return {'suggestions': propositions,
            'counts': {'hosts': len(hosts), 'role_missing': manquants,
                       'role_proposed': sum(1 for p in propositions if (p.get('role') or {}).get('value')),
                       'services_declared': sum(len(h.get('services') or []) for h in hosts),
                       'services_proposed': sum(len((p.get('services') or {}).get('value') or []) for p in propositions)},
             'conventions': {'codes': {c: v[0] for c, v in codes.items()}, 'prefixes': {c: v[0] for c, v in prefixes.items()}},
             'scope': ('Propositions tirées des services observés par l’audit SSH et des conventions de nommage '
                       'de l’inventaire déjà renseigné. Rien n’est appliqué sans votre validation. Changer le rôle '
                       'ou les services d’un serveur invalide son dernier audit jusqu’au suivant (≤ 10 min en rotation).')}


class Change(BaseModel):
    model_config = ConfigDict(extra='forbid')
    key: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')
    role: str | None = Field(default=None, min_length=1, max_length=80)
    environment: str | None = Field(default=None, min_length=1, max_length=80)
    services: list[str] = Field(default_factory=list, max_length=100)
    # D'où vient la valeur : une proposition InfraOps validée, ou une saisie de
    # l'opérateur (ex. prddcxans01 « ANSIBLE / OUTILS INFRA », qu'InfraOps
    # proposait en DB). Écrit dans classification_source / environment_source.
    source: Literal['proposition', 'operateur'] = 'proposition'


PROVENANCE = {'proposition': 'Validé par l’opérateur (proposition InfraOps)',
              'operateur': 'Saisi par l’opérateur'}


class Batch(BaseModel):
    model_config = ConfigDict(extra='forbid')
    changes: list[Change] = Field(min_length=1, max_length=100)


def install(app, context):
    from fastapi import APIRouter
    router = APIRouter()
    @router.get('/api/inventory/suggestions')
    def suggestions():
        return suggest(context.HOSTS, context.rows())

    @router.post('/api/inventory/apply')
    def apply(batch: Batch):
        """Applique des propositions VALIDÉES : fusion dans hosts.yaml, champs existants préservés."""
        from management import atomic_json
        for c in batch.changes:
            if any(not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,150}', s) for s in c.services):
                raise HTTPException(422, 'Nom de service invalide pour ' + c.key)
        # Pas de refus pendant une collecte : rôle, environnement et services ne
        # changent PAS la façon de joindre un serveur (IP, port, compte). Avec la
        # rotation SSH et le réseau à 60 s, une collecte tourne presque toujours :
        # l'ancien refus (409) rendait l'écriture impossible (constaté le 26/09,
        # 12 essais sur 2 min). Au pire, un audit en cours est marqué « configuration
        # modifiée » et refait au lot suivant.
        with context.lock, context.net_lock:
            par_cle = {h['key']: h for h in context.HOSTS}
            inconnus = [c.key for c in batch.changes if c.key not in par_cle]
            if inconnus:
                raise HTTPException(404, 'Serveur(s) inconnu(s) : ' + ', '.join(inconnus))
            chemin = getattr(context, 'INVENTORY', context.BASE / 'hosts.yaml')
            # L’exemple et les inventaires externes peuvent être en YAML classique.
            import yaml
            document = yaml.safe_load(chemin.read_text(encoding='utf-8-sig'))
            modifies = []
            for c in batch.changes:
                h = next(x for x in document['hosts'] if x['key'] == c.key)
                if c.role:
                    h['role'] = c.role.strip()
                    h['classification_source'] = PROVENANCE[c.source]
                if c.environment:
                    h['environment'] = c.environment.strip()
                    h['environment_source'] = PROVENANCE[c.source]
                if c.services:
                    h['services'] = list(dict.fromkeys(list(h.get('services') or []) + c.services))
                modifies.append(c.key)
            atomic_json(chemin, document)
            # Mise à jour en place : les autres modules gardent la même liste.
            nouveaux = {h['key']: h for h in document['hosts']}
            for h in context.HOSTS:
                if h['key'] in nouveaux:
                    h.update({k: nouveaux[h['key']][k] for k in ('role', 'environment', 'services',
                                                                  'classification_source', 'environment_source')
                              if k in nouveaux[h['key']]})
        return {'updated': modifies}
    app.include_router(router)  # routes de ce module : APIRouter, inclus en fin d'installation
