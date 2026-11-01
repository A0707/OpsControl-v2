# Présentation du dépôt et activation de la démo

## Description à utiliser dans About

```text
Cockpit IT en français : supervision, incidents, sécurité et sauvegardes. FastAPI, audit SSH en lecture seule et démo interactive sur données fictives.
```

URL du site après activation : `https://a0707.github.io/OpsControl-v2/`.

Topics proposés : `monitoring`, `infrastructure`, `devops`, `cybersecurity`,
`fastapi`, `python`, `zabbix`, `wazuh`, `proxmox`, `modsecurity`, `dashboard`.

## GitHub Pages

1. Ouvrir les [réglages Pages](https://github.com/A0707/OpsControl-v2/settings/pages).
2. Dans **Build and deployment → Source**, sélectionner **GitHub Actions**.
3. Ouvrir [le workflow de démonstration](https://github.com/A0707/OpsControl-v2/actions/workflows/demo.yml),
   puis **Run workflow** sur `main`.
4. Attendre la fin du job de publication et utiliser l'URL affichée dans le déploiement.

Le workflow ne distribue que `public-demo/`. Si Pages n'est pas activé, il affiche
une notice et ignore la publication. Cela n'empêche pas de lancer la démo localement.

L'activation initiale et les champs About nécessitent l'accès aux réglages du dépôt.
Aucun jeton administrateur n'est stocké dans Git ou demandé par ce workflow.
