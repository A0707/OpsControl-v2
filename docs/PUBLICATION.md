# Publication et confidentialité

L'édition publique est construite dans un répertoire indépendant à partir des fichiers
de code suivis. Les inventaires, bases, journaux, exports, sauvegardes, coffres et clés
locaux ne font pas partie de cette copie. Les anciens rapports d'exploitation et le
journal de travail ont été retirés ; les références d'environnement sont synthétiques.

Les noms d'utilisateurs de test sont fictifs. Les adresses `10.77.0.0/24` présentes
dans certains tests servent uniquement aux scénarios RFC1918 ; elles ne constituent
pas un inventaire à scanner. La démo statique utilise les plages RFC 5737.

Le crédit public de l'auteur figure volontairement dans le README et la démo,
à sa demande. Les références techniques de l'environnement restent anonymisées.

Les captures et ressources de démonstration sont indépendantes des vues d'exploitation.
Les fichiers PNG distribués sont débarrassés des métadonnées textuelles, EXIF et dates.
Les fixtures de veille peuvent citer des organismes et adresses de contact publics.

## Avant chaque publication

1. Partir des fichiers explicitement suivis, jamais d'une copie complète du poste.
2. Examiner le diff et rechercher identités, domaines, adresses et chemins internes.
3. Exécuter tests, analyse de secrets, Bandit et validation des assets.
4. Tester la démo dans un navigateur sans accès aux API d'infrastructure.
5. Vérifier les auteurs et messages de l'historique qui sera publié.

Le compte propriétaire du dépôt reste visible sur GitHub. Remplacer un historique
ne garantit pas la disparition d'anciens objets, copies ou caches externes.
