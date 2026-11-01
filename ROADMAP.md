# Roadmap OpsControl v2

Les éléments ci-dessous décrivent une direction de travail, sans engagement de date.
Une case cochée indique une capacité présente dans le code, pas une certification
ni une qualification universelle en production.

## Socle livré

- [x] Backend FastAPI et stockage SQLite WAL, interface française sans bundler.
- [x] Collectes SSH contrôlées et sources Proxmox, Zabbix, Wazuh, Elastic, Bacula.
- [x] Parc, incidents, passation, sécurité CVE, WAF et suivi des sauvegardes.
- [x] Politique d'accès, quotas, validations d'entrée et journalisation des mutations.
- [x] Inventaire synthétique, démo statique et contrôles CI.

## Priorité 1 — Publication et fiabilité

- [ ] Qualifier les intégrations sur une matrice de versions publiée.
- [ ] Ajouter un scénario de démarrage reproductible et une vidéo de prise en main.
- [ ] Étendre les scénarios de panne : délai API, certificat invalide, source obsolète.
- [ ] Documenter des mesures de performance sur jeux synthétiques reproductibles.
- [ ] Compléter les contrôles d'accessibilité et les tests de navigation mobile.

Critère de sortie : installation depuis un clone neuf, tests sans accès au parc,
dégradation visible des sources et documentation cohérente avec les versions testées.

## Priorité 2 — API et visibilité réseau

- [ ] Étudier un connecteur FortiGate en lecture seule : santé, interfaces, HA et VPN.
- [ ] Définir les droits minimaux et la compatibilité FortiOS avant développement.
- [ ] Uniformiser les délais, retries bornés, pagination et budgets d'appels.
- [ ] Enrichir le diagnostic WAF/Keepalived : VIP, VRRP unicast et incohérences de rôle.

Critère de sortie : tests contractuels simulés, TLS vérifié, secrets côté serveur,
aucun appel de configuration et aucune bascule déclenchée par le cockpit.

## Priorité 3 — Stockage et déploiement

- [ ] Rédiger une décision d'architecture pour PostgreSQL 17 : schémas, migrations, RBAC.
- [ ] Définir une migration SQLite → PostgreSQL avec sauvegarde et retour arrière testés.
- [ ] Séparer planificateur et API avant toute mise à l'échelle horizontale.
- [ ] Étudier un packaging Docker Compose, puis Swarm si le besoin est confirmé.
- [ ] Étudier des playbooks Ansible de déploiement de l'application, idempotents et testés.

Critère de sortie : migration et restauration vérifiées sur données synthétiques,
verrous de collecte explicites, pas de doublons de planification, moindre privilège.
La compatibilité avec un ancien Ansible doit être qualifiée séparément.

## Priorité 4 — Aide à la remédiation

- [ ] Améliorer les plans textuels avec prérequis, impact, vérifications et rollback.
- [ ] Lier les constats CVE aux tickets et aux fenêtres de maintenance approuvées.
- [ ] Ajouter des campagnes de validation sur laboratoire et des preuves de résultat.

Le produit conserve sa frontière de lecture seule vers le parc. Toute future exécution
distante exigerait une décision d'architecture, un périmètre distinct, une approbation
humaine et une qualification de sécurité. Aucune promesse de « zéro risque ».
