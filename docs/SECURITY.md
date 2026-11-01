# Sécurité d'OpsControl

## Principes

- **Lecture seule vers le parc** : commandes SSH en liste fermée (`ssh.OPERATIONS`),
  arguments en liste, jamais de shell local ; API interrogées en GET, sauf
  l'authentification Wazuh et le JSON-RPC Zabbix limité aux méthodes `*.get`.
- **Aucun secret dans le code, l'interface ou les fichiers de configuration** : les
  jetons ne vivent que dans l'environnement du processus (coffre DPAPI ou
  `/etc/infraops/secrets.env`, 0640 root:infraops).
- **Fermé par défaut** : toute route d'écriture non classée exige le rôle admin ; le
  webhook est fermé sans jeton ; l'accès direct à uvicorn est refusé dès que le secret
  proxy est configuré.

## Identité et rôles

| Mode | Condition | Identité |
|---|---|---|
| proxy | nginx présente `X-OpsControl-Proxy` = `INFRAOPS_TRUSTED_PROXY_SECRET` | Adresse transmise par oauth2-proxy (MFA portée par l'annuaire) |
| local | accès direct à uvicorn | Non authentifiée ; refusée (401) si le secret proxy est configuré. Sur la VM, `INFRAOPS_REQUIRE_PROXY=1` refuse le démarrage sans secret valide : jamais d'ouverture silencieuse en admin. Une identité invalide présentée avec le bon secret est refusée (401), même si `INFRAOPS_LOCAL_ROLE` est défini. |

| Rôle | Droits |
|---|---|
| viewer | Lecture. Ne voit ni URL, ni certificat, ni nom de variable des connexions API. |
| operator | + collectes, acquittements, cycle de vie des incidents, plan de commandes WAF (texte) |
| admin | + inventaire, connexions API, réglages, journal des mutations, diagnostic local |

Chaque écriture est tracée dans `mutation_audit` (90 jours) : horodatage, request_id,
auteur, mode, rôle, chemin, statut. nginx écrase `X-Forwarded-For` : l'adresse
enregistrée est celle du client réel.

## Routes d’accès SSH, de découverte et d’analyse WAF

Les rôles ci-dessous sont les minima définis par `access_policy` ; les rôles
supérieurs héritent de leurs droits. Les GET non sensibles sont accessibles au
viewer. Les POST restent soumis au contrôle CSRF et à l’audit des mutations,
y compris lorsqu’ils ne font que lire ou préparer du texte.

| Méthode et route | Rôle minimal | Groupe de quota | Portée |
|---|---|---|---|
| `GET /api/ssh/host-keys` | viewer | — | Liste des empreintes absentes/changées et des serveurs jamais audités avec clé inconnue ; aucune capture active. |
| `POST /api/ssh/host-keys/scan` | admin | `probe` | Connexions SSH par le chemin configuré, capture dans un fichier jetable ; aucune approbation de clé. |
| `POST /api/ssh/host-keys/accept` | admin | `mutation` | Enregistre les clés capturées dans le magasin local OpsControl après confirmation `OUI`, ou `REMPLACER` si une clé déjà enregistrée change ; la capture n’envoie aucune authentification à l’hôte non vérifié ; ne modifie pas les clés du serveur ni le magasin personnel. |
| `POST /api/hosts/{key}/test` | operator | `collect_one` | Diagnostic et essais SSH de la commande autorisée `uptime` ; aucune correction distante. |
| `POST /api/hosts/test-params` | operator | `collect_one` | Test d’une IP, d’un compte et d’un port saisis, non enregistrés ; uniquement `uptime`, avec vérification stricte des empreintes. IP de l’inventaire ou IPv4 privée RFC 1918 seulement, port SSH déjà utilisé dans le parc : pas de sondage arbitraire IP/port. |
| `POST /api/manage/hosts/bulk` | admin | `mutation` | Modification groupée de l’inventaire local uniquement. |
| `GET /api/discovery` | viewer | — | État et résultats du scan ; pas de nouveau sondage. |
| `GET /api/discovery/history` | viewer | — | Historique SQLite paginé (50 scans par défaut, 100 au plus), sans balayage ; différences uniquement sur des scans terminés de même plage. |
| `POST /api/discovery/scan` | admin | `collect_all` | Scan actif IPv4 privée, 1 024 adresses au plus ; ICMP/TCP, bannière SSH et DNS inverse, sans authentification SSH. |
| `POST /api/discovery/add` | admin | `mutation` | Ajout local des IP vues dans le dernier scan, sans approbation automatique des empreintes. |
| `GET /api/waf/{key}/bans` | viewer | — | Analyse de la collecte WAF enregistrée ; aucune requête au WAF ou à un service externe. |
| `POST /api/waf/commands` | operator | `mutation` | Plans de vérification, déblocage et autres actions WAF : texte à copier, `executable=false`. |
| `POST /api/security/scan`, `/api/security/sync` | operator | `collect_all` | Relevé SSH figé `security_packages` (lecture des paquets, sans sudo) ; veille publique en HTTPS GET et Wazuh en lecture. Voir [SECURITE-CVE.md](SECURITE-CVE.md). |
| `POST /api/security/hosts/{key}/scan` | operator | `collect_one` | Même relevé pour un serveur. |
| `POST /api/security/vulns/action` | operator | `mutation` | Workflow local d’une vulnérabilité (validation, planification, justification) ; rien n’est exécuté sur le serveur. |
| `POST /api/security/matches/decide` | operator | `mutation` | Applicabilité potentielle confirmée ou écartée après vérification, justifiée et journalisée. |
| `POST /api/security/settings` | admin | `mutation` | Fréquence de la veille (horaire par défaut), relevé SSH périodique (désactivé par défaut), destinataires e-mail, seuil EPSS. |
| `POST /api/security/mail/test` | admin | `probe` | Message de test aux destinataires configurés. |

Quotas actuels : `probe` **5/minute par acteur**, `collect_one` **10/minute par
acteur**, `mutation` **60/minute par acteur** ; `collect_all` **1/minute partagé
entre tous les acteurs et toutes les routes de ce groupe**. Ils ne limitent pas
le nombre de machines d’une requête : la capture d’empreintes est bornée à 50
serveurs, la modification groupée à 500, et la découverte à 1 024 adresses.

Une capture d’empreinte expire après 15 minutes. Comparer chaque empreinte à la
console avant d’accepter, particulièrement en cas de clé changée ; le mode
`accept-new` n’est utilisé que dans un magasin jetable pour la capture. Les
collectes normales gardent `StrictHostKeyChecking=yes`. Le scan réseau peut
déclencher des alertes IDS et doit cibler un périmètre autorisé. Voir les
procédures correspondantes dans [RUNBOOK.md](RUNBOOK.md).

## Protections applicatives

| Menace | Protection |
|---|---|
| CSRF | En-tête `X-Cockpit-Request`, contrôle d'`Origin` et de `Sec-Fetch-Site` |
| XSS | CSP `script-src 'self'`, aucun gestionnaire inline, échappement systématique (`esc`) |
| Exfiltration de jetons | Jeton lié à l'hôte:port de son premier usage (`data/token-bindings.json`) |
| SSRF | Adresses résolues contrôlées à la connexion, puis utilisées directement sans nouvelle résolution ; loopback, lien local, multicast et adresse nulle refusés, y compris IPv4 encapsulée en IPv6 |
| Fuite dans les preuves | `redact()` : clés privées, `password=`, `Bearer`/`Basic`, `-pSECRET`, `--password X`, `sshpass -p`, `curl -u` |
| Déni de service | Quotas par groupe d'actions, flux SSE plafonnés (3 par acteur, 6 par adresse côté nginx), corps de requête limités à 256 Ko, éléments de liste bornés, réponses API bornées, lecture des empreintes mise en cache |
| Usurpation d'hôte SSH | `StrictHostKeyChecking=yes`, `RejectPolicy` (Paramiko), empreintes vérifiées à la main |
| Webhook | Jeton ≥ 32 caractères comparé en temps constant, IP Zabbix seule (nginx), corps ≤ 64 Ko |

### Transport des API internes et DNS

Les collectes des sources de supervision, l'authentification et les vulnérabilités
Wazuh, la voie rapide Zabbix, l'export Proxmox et l'inspection des certificats
utilisent un transport direct. Il résout le nom, refuse toute réponse
contenant une adresse interdite, puis connecte uniquement les adresses numériques
contrôlées. Un changement DNS après le précontrôle de configuration ne permet donc
plus de joindre une adresse locale. Une erreur de résolution ou une réponse vide ne
déclenche aucun repli vers une destination non contrôlée.

Le nom d'origine reste celui de l'en-tête Host, du SNI et de la vérification du
certificat. La vérification TLS des collectes reste obligatoire. Seule l'inspection
manuelle du certificat utilise sa récupération sans confiance préalable ; elle
n'envoie aucun identifiant et contrôle aussi la destination réseau.

**Depuis le 24/10/2026, les proxies hérités de l'environnement sont ignorés pour ces
API internes** (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` et variantes minuscules).
Un tunnel HTTP CONNECT explicite est également refusé. Le poste ou la VM OpsControl
doit disposer d'une route directe vers les API (réseau interne ou VPN). Cette règle
ne change pas les paramètres du reverse proxy d'accès à l'interface utilisateur.

L'exception HTTP Bacula reste explicite : GET vers
`http://127.0.0.1:19096/api/v2/jobs` et `/api/v2/clients`, uniquement pour la collecte
configurée sur le tunnel Bacula. Aucun autre port, chemin, nom local ou POST en
clair n'est accepté par ce transport.

Le DNS inverse de la découverte conserve au maximum 32 travaux en cours ou en file,
avec 8 workers. Un appel expiré rend la main au demandeur sans annuler sa future :
sa place n'est rendue qu'à la fin réelle de la résolution. Au-delà du plafond, le
nom reste non résolu. Le résolveur système en cours n'est pas interrompu ; s'il se
bloque, les workers peuvent rester occupés et retarder l'arrêt du processus, mais
les appels suivants n'empilent pas de nouvelles tâches sans borne.

## Comptes de service

État constaté : la collecte utilise un compte nominatif, et `root` sur deux serveurs.
Procédure de bascule vers un compte `infraops` dédié : [SERVICE-ACCOUNT.md](SERVICE-ACCOUNT.md).

`sudo` n'est nécessaire que sur les serveurs WAF / Apache, et uniquement par
[deploy/remote/sudoers-infraops](../deploy/remote/sudoers-infraops) : commandes écrites en
entier, lectures de fichiers par le script `infraops-read` qui vérifie le chemin réel.
**Jamais de `*` dans les arguments d'une règle sudoers** : il y accepte espaces et `..`, si
bien que `tail -c * -- /var/log/apache2/*` permettrait de lire `/etc/shadow`.

## Outils

`python deploy/ci.py` : tests, bandit, detect-secrets (référence `.secrets.baseline`),
pip-audit. Le crochet pre-commit (`--install-hook`) bloque un secret avant le commit.

## Signaler un problème

Équipe Infra. Ne jamais joindre de jeton, de clé ou de sortie non masquée à un ticket.
