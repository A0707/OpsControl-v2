# Démonstration OpsControl v2

Démo interactive entièrement statique, avec 12 serveurs fictifs et des adresses
RFC 5737. Aucune API, collecte SSH, donnée réelle ou authentification.

```sh
python -m http.server 8080 --bind 127.0.0.1 --directory public-demo
```

Depuis la racine du dépôt, ouvrir http://127.0.0.1:8080.
Depuis ce dossier, omettre `--directory public-demo`.

Les vues couvrent parc, sécurité, sauvegardes, réseau et sources. Les fiches,
filtres, thèmes et simulations fonctionnent dans le navigateur. Le backend
Python est fourni séparément à la racine.

La publication GitHub Pages utilise uniquement ce dossier ; elle n'expose
jamais le backend, un inventaire réel ou le dossier data.
