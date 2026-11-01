# Sécurité & gestion des CVE

Onglet **Sécurité** d'OpsControl V2 : vulnérabilités prouvées par serveur, veille,
procédures de correction et suivi jusqu'à la clôture, avec ticket GLPI. Le module
s'ajoute à l'existant (même application, même version, même base) ; l'ancienne vue
« Contrôles de sécurité SSH » reste disponible dans l'onglet **Contrôles SSH**.

## Composants

| Fichier | Rôle |
|---|---|
| `security_cve.py` | Schéma `sec_*`, relevé SSH des paquets, Wazuh, corrélation, workflow, routes `/api/security/*` |
| `security_feeds.py` | Collecteurs : CISA KEV, NVD 2.0, FIRST EPSS, CERT-FR, Debian DSA/DLA, avis officiels PHP et WordPress, PHP, WordPress, Fortinet PSIRT, Proxmox |
| `security_watch.py` | Synchronisation en ligne : état des sources, requêtes conditionnelles, débit, backoff, NVD par produit, EPSS, historique des CVE |
| `security_correlation.py` | Applicabilité par technologie : confirmée, potentielle ou non applicable, priorité P1-P4 |
| `security_alerts.py` | Règles d'alerte, déduplication, centre d'alertes, résumé e-mail (SMTP) |
| `security_versions.py` | Comparaison de versions dpkg, rpm et amont (plages des éditeurs) |
| `security_remediation.py` | Procédure de correction en **texte** (sans LLM) |
| `web/security.js` | Page paresseuse : six sections + contrôles SSH historiques |

Réutilisés : liste fermée `ssh.OPERATIONS` (opération `security_packages`), comptes et
ports SSH déjà connus, connexions Wazuh de `management` (jeton, liaison d'hôte, CA
confinée), rapprochement agents/serveurs `asset_registry.MatchIndex`, workflow ITSM/GLPI
`itsm.py` (nouvelle origine `vulnerability`), planificateur `jobs.py`, RBAC et audit
`access_policy.py`.

## Ce qui fait une vulnérabilité (et ce qui n'en fait pas)

Une vulnérabilité n'est **jamais** déduite d'un numéro de version qui « semble ancien ».
Trois preuves seulement en ouvrent une :

1. **Debian** : version *source* installée (`dpkg-query ${source:Version}`) strictement
   inférieure à la version corrigée publiée par Debian (listes DSA/DLA du Security
   Tracker) **pour la même release** (bookworm, bullseye…), comparée selon dpkg. Un
   correctif rétroporté porte une version de la release (`3.0.11-1~deb12u3`) : il est
   reconnu comme corrigé.
2. **Wazuh Vulnerability Detection** (flux des éditeurs, rétroportages inclus) : API du
   manager ≤ 4.7 (`/vulnerability/<agent>`) ou indexeur ≥ 4.8
   (`wazuh-states-vulnerabilities-*`).
3. **Version amont relevée dans une plage publiée** (NVD ou avis de l'éditeur), quand la
   version vient d'un artefact de l'éditeur : image Docker officielle, fichier
   `wp-includes/version.php`, paquet `pve-manager`, version du démon Docker. Voir
   « Veille en ligne » ci-dessous.

Niveaux de confiance : **confirmé** (Debian, ou Debian et Wazuh concordants), **détecté**
(Wazuh seul), **à vérifier** (la CVE figure dans le changelog du paquet installé :
correctif probablement rétroporté ; ou version installée différente de celle analysée
par Wazuh). Les bulletins amont (PHP, Fortinet, Proxmox, CERT-FR sans CVE du parc)
restent de la **veille** : « composant présent, à vérifier », jamais une détection.

Une entrée = un serveur + une CVE : les paquets binaires d'un même paquet source et les
deux sources sont dédupliqués.

**Corrigée (constatée)** : uniquement quand une nouvelle analyse ne retrouve plus la CVE
et que **chacune** de ses sources a mesuré le serveur (relevé SSH complet et correctifs
Debian disponibles ; données Wazuh complètes de moins de 72 h). Une source en panne laisse
l'état inchangé. Une vulnérabilité corrigée qui réapparaît (retour arrière) est rouverte.

Hors périmètre, dit dans l'interface : Ubuntu et RHEL ne sont couverts que par Wazuh ;
les images Docker sont listées (fin de support amont datée, tag `latest`) mais leur
contenu n'est pas scanné.

## Relevé SSH (`security_packages`)

Commande figée, sans sudo ni paramètre : `/etc/os-release`, `uname -r`,
`/var/run/reboot-required`, liste des paquets (dpkg ou rpm), mises à jour proposées par
les dépôts (`apt list --upgradable`, `dnf -C check-update`), CVE citées dans les
changelogs d'une liste fermée de paquets, versions annoncées (`php -v`, `apache2 -v`,
`openssl version`…), `docker ps` / `docker images` si le compte y a accès. Sortie
bornée. Un relevé incomplet ne remplace jamais le précédent.

## Workflow

Détectée → **Validée** (par un opérateur) → **Correction planifiée** → Corrigée
(constatée par l'analyse). Sorties : **Faux positif** ou **Risque accepté**, avec
justification obligatoire (10 caractères), réversibles par « Rouvrir ». Responsable
désignable ; chaque action est journalisée (`sec_events`, auteur, mode proxy ou
déclaratif) en plus de l'audit des mutations d'`access_policy`.

**Préparer la correction** (GET, rien n'est enregistré ni exécuté) : serveur, CVE,
paquet, versions actuelle et corrigée, vérifications préalables (simulation apt, changelog),
sauvegarde (instantané Proxmox si la VM est connue, versions exactes, configuration),
commandes de mise à jour, prise en compte (needrestart en liste seule ; redémarrage
toujours à planifier), vérification (`dpkg --compare-versions … ge <corrigée>`) et
retour arrière exact (versions installées relevées, cache apt, `dnf history undo`,
`qm rollback` en dernier recours). Les noms et versions sont revalidés par liste blanche
avant d'entrer dans une commande.

## Recommandations de correction par serveur

`GET /api/security/hosts/<clé>/recommendations` (fiche serveur, onglet Sécurité) et
`GET /api/security/recommendations` (Sécurité > Correctifs) : un **plan consolidé** par
serveur, au lieu d'une procédure par CVE. Chaque recommandation porte sa priorité (P1
immédiate, P2 sous 7 jours, P3 sous 30 jours, P4 planifiable), ses preuves et ses étapes
(vérifier, sauvegarder, appliquer, prise en compte, contrôler, retour arrière) ; le plan
complet se copie en un clic (ticket, fiche d'intervention).

| Recommandation | Contenu |
|---|---|
| Paquets du système | UNE mise à jour pour toutes les CVE corrigées par la distribution, contrôle `dpkg --compare-versions` par paquet, versions d'origine pour le retour arrière |
| Composant applicatif | Une par conteneur, service Swarm, WordPress, Proxmox, démon Docker ou FortiGate, avec la version cible |
| Vérification | CVE potentielles : commandes de preuve (changelog, version réelle) avant toute correction ; jamais plus urgente que P2 |
| Système | Hors support (P1 si exposé, sinon P2) ou fin de support à moins de 180 jours (P3), chemin de migration publié par l'éditeur |
| Redémarrage | `/var/run/reboot-required` présent : correctifs installés mais inactifs |
| Mises à jour | Paquets à jour disponibles hors CVE suivies (P3 si dépôt de sécurité) |
| Images Docker | Version amont hors support ou tag non figé |
| Audit SSH | Constats de sécurité de l'audit (SSH, pare-feu, auditd, fail2ban…) avec leurs commandes |
| Couverture | Jamais analysé, relevé ancien, Wazuh absent : ce qui empêche de conclure |

Tout découle des données collectées ; rien n'est inventé ni exécuté, aucun LLM.

## GLPI

Bouton « Consulter / prendre en charge » (dialogue ITSM existant) sur une vulnérabilité
**validée ou planifiée** : refusé (409) avant validation. Le ticket reprend serveur, IP,
environnement, CVE, paquet, versions, preuve, CVSS/KEV, responsable désigné et résumé du
plan de correction. Prévisualisation et confirmation inchangées (docs/GLPI.md). La
relecture des statuts GLPI et la résolution automatique s'appliquent : le ticket est
résolu quand la vulnérabilité est constatée corrigée.

## Veille en ligne

La collecte part **uniquement du serveur OpsControl** (jamais du navigateur), en GET HTTPS
vérifié, sans redirection, à taille bornée.

| Source | Point d'accès | Usage |
|---|---|---|
| CERT-FR (avis, alertes) | `cert.cyber.gouv.fr/{avis,alerte}/feed/` puis `…/<bulletin>/json/` | Bulletins, CVE et produits cités |
| CISA KEV | catalogue JSON officiel | Exploitation active connue (priorité, alerte) |
| NVD CVE API 2.0 | `?cveId=` et `?virtualMatchString=cpe:…&lastModStartDate=…` | Score CVSS, statut, **configurations** (produits et plages de versions) |
| FIRST EPSS | `api.first.org/data/v1/epss?cve=` (lots de 100) | Probabilité d'exploitation à 30 jours |
| Debian Security Tracker | listes DSA et DLA | Version corrigée par release (rétroportages) |
| PHP | avis GitHub de `php/php-src` + flux des versions | CVE, gravité, plages par branche, version corrigée |
| WordPress | avis GitHub de `WordPress/wordpress-develop` + annonces de sécurité | CVE ou GHSA, plages par branche |
| Fortinet PSIRT | flux `ir.xml` | Bulletins FG-IR (CVE citées) |
| Proxmox | annonces officielles | Veille (versions à comparer) |

Fonctionnement :

- **Fréquence** : toutes les heures par défaut, réglable (1, 3, 6, 12, 24 h) ou désactivée ;
  premier passage 5 minutes après le démarrage. Bouton « Synchroniser veille et Wazuh » :
  immédiat.
- **Indépendance** : la veille ne dépend pas du relevé SSH du parc ; les deux peuvent
  tourner en même temps (un seul de chaque). Une échéance automatique n'est consommée que
  si la veille a réellement démarré.
- **Requêtes conditionnelles** (ETag, Last-Modified) : une source inchangée répond 304,
  rien n'est retéléchargé.
- **Erreurs** : chaque source échoue seule ; espacement exponentiel (5 min, doublé, 6 h au
  plus ; ×4 sur une limitation HTTP 403/429/503). L'action manuelle ignore l'espacement.
- **Débit** : NVD 5 requêtes / 30 s sans clé (règle publiée par NVD), 50 avec
  `NVD_API_KEY` ; GitHub et FIRST une requête par seconde.
- **Déduplication** : un bulletin = (source, identifiant), mis à jour s'il est révisé ; une
  CVE = un enregistrement, ses changements (score, statut NVD, configurations) sont
  historisés (« CVE mises à jour par NVD »).
- **NVD par produit** : seules les technologies présentes sur le parc sont interrogées,
  sur la fenêtre de modification écoulée depuis la dernière synchronisation.
- **État de chaque source** : opérationnelle, en erreur (avec message et prochain essai),
  désactivée, jamais synchronisée ; dernière tentative et dernier succès.

### Corrélation avec les serveurs

Instances relevées par l'opération SSH (lecture seule, sans sudo) et l'inventaire :

| Technologie | Version relevée depuis | Origine |
|---|---|---|
| PHP, Apache, ModSecurity (WAF), PostgreSQL, OpenSSL, OpenSSH, nginx | paquets dpkg/rpm (Debian, Ubuntu, CentOS, Rocky) | distribution |
| PHP, WordPress, PostgreSQL, httpd, nginx | conteneurs et services Docker Swarm (tag de l'image officielle) | image |
| WordPress hors conteneur | `wp-includes/version.php` sous `/var/www`, `/srv`, `/home/*/public_html` | fichier |
| Docker Engine (nœuds Swarm) | `docker info` | démon |
| Proxmox VE (hyperviseurs) | paquet `pve-manager` | éditeur |
| FortiGate | `firmware_version` déclaré dans `hosts.yaml` | déclarée |

Résultat par instance, affiché séparément :

- **Confirmée** : version dans une plage publiée et origine fiable (image, fichier, éditeur,
  démon), ou avis de la distribution publié et non appliqué (DSA), ou Wazuh. Entre dans le
  workflow (validation, correction, GLPI).
- **Potentielle** : version amont dans la plage mais **paquet de distribution** sans avis
  (correctif rétroporté possible), version incomplète (tag `8.2`), version déclarée, ou
  plateforme requise non vérifiable. Bouton « Confirmer après vérification » (justification
  obligatoire) : la vulnérabilité est alors ouverte et validée ; « Non applicable » la
  classe avec justification. Les décisions sont journalisées et réversibles.
- **Non applicable** : hors plage, plateforme exclue (ex. réel : CVE-2024-4577 exige
  Windows, un serveur Linux n'est pas concerné), correctif rétroporté prouvé (DSA installée,
  CVE citée dans le changelog).

Les avis par branche (PHP : « < 8.2.35 », « < 8.3.36 »…) sont lus branche par branche : la
borne la plus basse couvre les branches plus anciennes, les autres seulement la leur. Sans
plage publiée, aucune CVE n'est corrélée ; aucune donnée n'est inventée.

**Priorité de remédiation** (P1 à P4, motifs affichés) : gravité CVSS (ou gravité de
l'éditeur), +3 si KEV, +1 ou +2 selon EPSS (≥ 10 % / ≥ 50 %), +2 si un serveur concerné
est exposé à Internet, +1 si l'applicabilité est confirmée. P1 : score ≥ 12, ou KEV confirmée.

**Exposition à Internet** : serveur de rôle WAF, serveur publié via le WAF (relevé des
sites), ou `exposure: internet` dans l'inventaire.

### Alertes

| Raison | Déclencheur |
|---|---|
| Critique et applicable | CVSS ≥ 9 ou avis « critical », confirmée ou potentielle sur au moins un serveur |
| Exploitée (CISA KEV) | CVE KEV applicable |
| Service exposé à Internet | serveur exposé concerné, gravité ≥ élevée ou KEV |
| Nouveau correctif | avis Debian ou éditeur de moins de 7 jours corrigeant une CVE applicable |
| Risque d'exploitation élevé | EPSS ≥ seuil (0,5 par défaut, réglable) |
| Bulletin concernant le parc | bulletin de moins de 30 jours citant une CVE applicable |

Diffusion par les mécanismes existants : page Sécurité (notifications, historique des
alertes), **centre d'alertes** (source « Sécurité », prise en charge habituelle ; les
alertes de veille ne créent pas d'incident, la vulnérabilité ayant son propre cycle), et
**e-mail** : un résumé par passage, au plus toutes les 10 minutes, seulement pour ce qui
n'a pas déjà été envoyé. Une alerte ne revient que si de nouveaux serveurs sont concernés
ou si son niveau monte ; un échec SMTP laisse les alertes en attente du prochain envoi.

Configuration e-mail (environnement du service ; le mot de passe dans le coffre DPAPI ou
`/etc/infraops/secrets.env`, jamais en base) :

| Variable | Rôle |
|---|---|
| `INFRAOPS_SMTP_HOST`, `INFRAOPS_SMTP_PORT` (587) | Relais SMTP de l'entreprise |
| `INFRAOPS_SMTP_SECURITY` | `starttls` (défaut) ou `ssl` ; certificat vérifié, pas de SMTP en clair |
| `INFRAOPS_SMTP_USER`, `INFRAOPS_SMTP_PASSWORD` | Authentification, si le relais l'exige |
| `INFRAOPS_SMTP_FROM` | Expéditeur |
| `INFRAOPS_SECURITY_MAIL_TO` | Destinataires par défaut (sinon le réglage de l'interface) |

Destinataires, niveau envoyé (critique, ou critique et majeur) et seuil EPSS se règlent
dans **Veille de sécurité > Sources et réglages** ; bouton « Envoyer un e-mail de test ».

## Routes et droits

| Route | Rôle | Quota |
|---|---|---|
| `GET /api/security/*` (summary, vulns, hosts, watch, matches/plan, feeds, sources, history, report, notifications, job, packages) | viewer | — |
| `POST /api/security/scan`, `POST /api/security/sync` | operator | collect_all (1/min) |
| `POST /api/security/hosts/<clé>/scan` | operator | collect_one |
| `POST /api/security/vulns/action`, `/notifications/read`, `/matches/decide` | operator | mutation |
| `POST /api/security/settings` | admin | mutation |
| `POST /api/security/mail/test` | admin | probe |

## Automatismes

Dans **Veille de sécurité > Sources et réglages** (administrateur) :

- synchronisation de la veille et de Wazuh : **active, toutes les heures** par défaut
  (GET HTTPS sortants uniquement), désactivable ;
- relevé SSH automatique des paquets : manuel (défaut), 24 h ou 7 jours — le premier
  passage attend une période entière après le démarrage ;
- indexeur Wazuh ≥ 4.8 : une connexion **Elasticsearch** déclarée vers l'indexeur
  (jeton `ELASTIC_…`, CA, liaison d'hôte habituels). Équivalent : `INFRAOPS_WAZUH_INDEXER=<clé>`.

Variables d'environnement facultatives :

| Variable | Effet |
|---|---|
| `NVD_API_KEY` | Clé NVD (secret) : 200 CVE enrichies par passage au lieu de 40, débit ×10 |
| `GITHUB_TOKEN` | Jeton GitHub en lecture (secret), facultatif : 60 requêtes / heure suffisent sans |
| `INFRAOPS_SECURITY_FEED_<SOURCE>` | URL de remplacement (miroir interne) ou `off` ; sources : `KEV`, `CERTFR_AVIS`, `CERTFR_ALERTES`, `DEBIAN_DSA`, `DEBIAN_DLA`, `PHP_ADVISORIES`, `PHP`, `WORDPRESS_ADVISORIES`, `WORDPRESS`, `FORTINET`, `PROXMOX` |

Saisie des secrets : `sudo python3 deploy/secrets_env.py` sur la VM (questions facultatives
pour `NVD_API_KEY`, `GITHUB_TOKEN`, `INFRAOPS_SMTP_PASSWORD`), `InfraOps-Secrets.ps1` sur
le poste Windows.

Flux sortants (HTTPS 443, GET, sans redirection) : `www.cisa.gov`, `services.nvd.nist.gov`,
`api.first.org`, `cert.cyber.gouv.fr`, `salsa.debian.org`, `api.github.com`,
`www.php.net`, `wordpress.org`, `filestore.fortinet.com`, `forum.proxmox.com` ; SMTP vers
le relais configuré. Le proxy d'entreprise est pris depuis
`HTTPS_PROXY`. Sans accès Internet : miroir interne ou sources désactivées ; les
détections Wazuh restent disponibles.

## Tests

`test_security_watch.py` rejoue des **réponses réelles** des API officielles, enregistrées le
21/10/2026 dans `test_fixtures/security/` (`MANIFEST.json` : URL de chaque fichier ; seuls
des éléments ont été retirés, aucune valeur modifiée). Scénario principal : publication des
vulnérabilités PHP critiques CVE-2026-109618 et CVE-2026-109619 (avis PHP, NVD 9.8, relais
WordPress et Fortinet) sur plusieurs VPS WordPress — image PHP 8.3.30 (confirmée), branche
7.4 (confirmée), PHP Debian 12 sans avis (potentielle), Debian 13 avec DSA-6574-1 non
appliquée (confirmée), PHP 8.3.36 (non applicable). Aussi : doublons, erreurs réseau et
limitation, 304, faux positifs (Windows seul, branches hors plage), mise à jour d'une CVE
par NVD, absence de score EPSS, alertes et e-mail sans répétition, décisions humaines.

## Exploitation

Première mise en service :

1. Redémarrer OpsControl (migrations `security_v1` et `security_v2`, tables `sec_*`, aucune donnée existante modifiée).
   La veille démarre seule 5 minutes plus tard (toutes les heures ensuite).
2. Onglet Sécurité > « Synchroniser veille et Wazuh » (correctifs Debian, KEV, bulletins).
3. « Analyser le parc » (une session SSH par serveur, lecture seule).
4. Traiter d'abord les CVE KEV et critiques ; valider ; préparer la correction ; GLPI.

## Retour arrière

Le module est additif. Pour le retirer :

1. Revenir au commit précédent (ou retirer `security_cve.install` d'`app.py` et l'entrée
   `'Sécurité'` de `lazyPageScripts` dans `web/app.js`, puis `python deploy/assets_version.py`) ;
   la page Sécurité revient à la vue SSH historique.
2. Redémarrer OpsControl. Les tables `sec_*` restent dans la base sans effet ; les supprimer
   n'est pas nécessaire (sauvegarder la base avant toute suppression manuelle).
3. Les dossiers ITSM d'origine `vulnerability` restent consultables ; ils ne sont plus
   rapprochés (état d'origine inconnu, aucune résolution automatique).

Retirer seulement la veille en ligne (commit « Veille sécurité en ligne ») : revenir au
commit précédent et redémarrer. La migration `security_v2` n'ajoute que des colonnes et des
tables (`sec_source_state`, `sec_matches`, `sec_match_decisions`, `sec_cve_changes`) que
l'ancien code ignore ; aucune restauration de base n'est nécessaire. Couper la collecte sans
retour arrière : décocher « Synchronisation automatique » (ou `security_feeds_auto=0`),
ou `INFRAOPS_SECURITY_FEED_<SOURCE>=off` par source ; couper l'e-mail : retirer
`INFRAOPS_SMTP_HOST`.

Aucune modification n'a été faite sur les serveurs supervisés : rien à défaire côté parc.
