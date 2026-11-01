# Validation de l'assistant IA

L'assistant est facultatif et doit être qualifié séparément avec le fournisseur,
le modèle, les droits et les ressources retenus pour votre environnement.
Les anciens comptes rendus de poste et mesures internes ne sont pas distribués.

## Scénarios à vérifier

- Fonction désactivée : aucune fonctionnalité IA exposée involontairement.
- Authentification, CSRF, rôles, quotas et bornes de taille des messages.
- Fournisseur absent : erreur explicite, sans bloquer la supervision.
- Sources documentaires : citations, permissions, indexation et retrait cohérents.
- Contenus malveillants : aucun outil d'administration exécuté sur le parc.
- Confidentialité : aucune donnée sensible transmise sans une politique adaptée.
- Modèle et licence : vérifier les conditions avant usage et redistribution.

Les tests `test_ai.py` et `test_ui_ai.cjs` utilisent des simulations. Ils ne
qualifient pas les performances ou la sûreté d'un modèle réel. Voir
[ASSISTANT-IA.md](ASSISTANT-IA.md) pour les réglages.
