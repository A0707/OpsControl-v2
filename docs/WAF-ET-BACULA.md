# Organisation WAF et diagnostic de l'API Baculum

## Navigation WAF

La page **WAF / HA** conserve un sélecteur de serveur et une preuve de collecte
datée. Les données sont réparties dans sept rubriques :

1. **Vue d'ensemble** : compteurs et constats à examiner.
2. **Apache et backends** : charge, latences et saturation.
3. **Trafic et ModSecurity** : HTTP, règles et événements observés.
4. **IP et Fail2ban** : bans, liste blanche et commandes préparées.
5. **Certificats TLS** : déclarations et dates d'expiration disponibles.
6. **Réseau et TCP** : sockets, CLOSE_WAIT et conntrack.
7. **Preuves et historique** : couverture des sondes et observations conservées.

Les compteurs de navigation indiquent le nombre de panneaux, pas le nombre
d'alertes. Une preuve absente reste explicitement non mesurée. La sélection du
thème est conservée lors d'un changement de WAF ou d'un rafraîchissement.
Les flèches, Home et End permettent de parcourir les onglets au clavier.
L'historique Apache est lu à l'ouverture de sa rubrique, sans nouvelle sonde.

Les commandes de diagnostic, ban, déban et liste blanche restent du texte à
copier. OpsControl ne les exécute pas sur les WAF. Le certificat déclaré dans
les fichiers n'est pas une preuve du certificat réellement servi sur la VIP.

## Anciennes pastilles des serveurs critiques

La rangée de pastilles et les anciennes tuiles des serveurs critiques sont
retirées de l'affichage. La criticité de l'inventaire, les sondes, les alertes et
les notifications ne sont pas désactivées. Le mode NOC conserve la vue générale
du parc et la fraîcheur de ses observations.

## Baculum : HTML au lieu de JSON

Un statut HTTP 200 ne garantit pas une API fonctionnelle. Si la réponse HTML
Prado porte `TInvalidOperationException` et `DOMDocument`, OpsControl classe
l'échec `bacula_php_dom`, conserve la dernière réussite et affiche le composant
à vérifier. Le contenu HTML et les chemins internes ne sont pas renvoyés au client.
Une chaîne DOMDocument à l'intérieur d'un vrai JSON ne déclenche pas ce diagnostic.

En laboratoire, vérifier que le moteur PHP utilisé par Apache charge les mêmes
extensions que le moteur CLI. Une réponse JSON valide et une collecte réussie
constituent les critères de validation.
