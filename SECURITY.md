# Sécurité

Ce dépôt est une édition publique destinée à l'évaluation et au développement.
Il n'existe pas encore de politique de support par version ni de délai de réponse garanti.

Pour signaler une vulnérabilité, utiliser la fonction GitHub **Report a vulnerability**
si elle est disponible. Ne pas publier de secret, de détail exploitable ou de donnée
client dans une issue publique. Si ce canal est absent, demander un canal privé dans
une issue sans inclure la vulnérabilité elle-même.

Décrire la version ou le commit, le périmètre, l'impact et une reproduction synthétique.
Ne pas tester sur une infrastructure tierce ou de production sans autorisation.

## Frontières de confiance

- Les collectes du parc restent en lecture seule et SSH utilise une liste fermée.
- Les comptes et jetons des sources doivent avoir des droits de consultation minimaux.
- Les jetons et secrets proviennent de l'environnement ou d'un coffre local, jamais de Git.
- Les API HTTPS vérifient TLS ; ne pas désactiver cette vérification pour contourner une erreur.
- L'exposition réseau exige authentification, TLS, filtrage et configuration du proxy.
- Les actions ITSM explicitement activées écrivent dans GLPI ; elles ne modifient pas les serveurs.

Lire [docs/SECURITY.md](docs/SECURITY.md) avant un déploiement.

## Données à exclure

`hosts.yaml`, `data/`, sauvegardes, journaux, bases, `.env`, coffres, clés et exports
restent locaux. `.gitignore` est une protection complémentaire, pas un audit de contenu.
Si un secret a été publié, le révoquer avant de traiter l'historique Git et les caches.
