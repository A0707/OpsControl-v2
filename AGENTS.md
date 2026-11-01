# Consignes pour les agents — OpsControl

## Projet

OpsControl est une application de supervision IT interne en lecture seule :
FastAPI, Python 3.11+, SQLite en mode WAL et frontend JavaScript vanilla sans
bundler. L’interface est en français.

La collecte couvre SSH (liste fermée `ssh.OPERATIONS`), les API
Proxmox, Zabbix, Wazuh, Elasticsearch (Elastic) et Bacula, la découverte réseau
ainsi que le WAF ModSecurity et Fail2ban.

## Règles impératives

- **Lecture seule vers le parc** : aucune commande ne doit modifier un serveur
  supervisé. Les actions correctives sont uniquement du **TEXTE à copier**,
  notamment via `waf_findings.command_plan`.
- **Aucun secret** dans le code, les tests ou les commits. `hosts.yaml`, `data/`,
  `audit.log` et `*.sqlite3` restent hors Git.
- Toute route d’écriture doit être classée dans `access_policy.POST_RULES`,
  avec son rôle et son quota. Une route non classée exige le rôle `admin` par défaut.
- Toute entrée JSON passe par un modèle Pydantic avec `extra='forbid'`
  et des bornes de longueur.
- Les tests qui importent `app` commencent par `import testing_env`,
  afin d’utiliser une base temporaire.
- Aucun appel réseau réel dans les tests : simuler les appels à `subprocess`,
  `socket` et `urllib` avec des patches.
- Après toute modification de `web/*.js` ou de fichiers `*.css`, exécuter
  `python deploy/assets_version.py`. Les versions `?v=` sont calculées depuis
  le contenu des fichiers.
- Les fichiers exécutés sur Linux (`deploy/*.sh`, `*.service`, `*.timer`,
  `deploy/remote/*`) doivent utiliser des fins de ligne **LF**.
- Respecter le style du fichier modifié : `app.py` est compact ; les nouveaux
  modules suivent PEP 8. Les commentaires sont en français et expliquent le pourquoi.
- Toute évolution s’ajoute à `CHANGELOG.md`, et à la documentation de `docs/`
  si l’exploitation change.

## Validation avant de terminer

Exécuter depuis la racine du dépôt, avec le Python du projet (`.venv`, où
`requirements-dev.txt` est installé) :

```sh
.venv/Scripts/python.exe deploy/ci.py --offline   # Windows ; .venv/bin/python sous Linux
```

Cette validation couvre les tests, Bandit, detect-secrets, les versions web et
Ruff (erreurs E9/F bloquantes sur les fichiers Python nouveaux ou modifiés).
Elle doit afficher **RÉSULTAT : OK** avant de terminer. Lancée avec un autre
interpréteur, elle signale les outils absents et échoue.

Après une modification de `web/`, ajouter `--ui` (tests navigateur sur données
simulées ; `OPS_BROWSER_CHANNEL=msedge` utilise le navigateur installé si Chromium
de Playwright n'est pas téléchargé).
