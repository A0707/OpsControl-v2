# Contribuer

Décrire le problème, le résultat attendu et un exemple entièrement fictif dans une
issue. Proposer les changements sur une branche, puis ouvrir une pull request ciblée.
Les intégrations doivent pouvoir être testées sans accès réseau réel.

## Règles de développement

- Respecter [AGENTS.md](AGENTS.md) et la frontière de lecture seule vers le parc.
- Ne jamais joindre d'inventaire, jeton, clé, journal réel ou capture non anonymisée.
- Valider les entrées JSON avec Pydantic, `extra='forbid'` et des limites explicites.
- Classer chaque route POST dans `access_policy.POST_RULES` ; appliquer les quotas.
- Faire précéder les imports d'`app` par `import testing_env` dans les tests.
- Simuler `subprocess`, `socket` et `urllib` pour les interactions d'infrastructure.
- Conserver LF pour les scripts et unités Linux ; commentaires en français.
- Ajouter une entrée à `CHANGELOG.md` et mettre à jour les guides concernés.

## Vérifier une pull request

Installer `requirements.txt` et `requirements-dev.txt` dans `.venv`, puis exécuter
`python deploy/ci.py --offline` avec cet environnement. La commande doit terminer
avec `RÉSULTAT : OK`.

Après un changement de JavaScript ou CSS sous `web/`, exécuter
`python deploy/assets_version.py`, installer les dépendances Playwright décrites dans
le README et lancer `python deploy/ci.py --offline --ui`.

La description de PR précise le comportement modifié, la validation effectuée et
les limites connues. Les évolutions PostgreSQL, HA et automatisation distante
doivent commencer par une décision d'architecture.
