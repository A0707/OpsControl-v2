# Console d'exploitation et tickets de sécurité

La Vue globale présente les accès directs, la situation du parc, les priorités et
les sources de supervision. Les détails de capacité restent dépliables. Les couleurs
gardent leur sens : une preuve absente ou ancienne ne devient jamais un état sain.
Les thèmes clair et sombre et la navigation sur petit écran sont conservés.

## Depuis une fiche serveur

Les cinq dernières notifications de veille sont également présentées, filtrées
par identifiant exact du serveur. **Préparer un ticket de vérification** ouvre un
dossier distinct : la qualification des vérifications attendues est obligatoire
(10 caractères minimum). Une CVE potentielle n'est pas validée par cette action.
Ce ticket est clôturé manuellement dans GLPI après investigation ; marquer une
notification comme lue ne constitue jamais une preuve de correction.

1. Ouvrir **Incidents**, puis **Alertes de sécurité**. La liste porte sur les CVE
   actives de ce serveur, dix par page, avec leur source et dernière observation.
2. Choisir **Examiner / ticket GLPI**. Les données de détail sont relues ; le nom,
   le composant, les versions et la confiance restent visibles.
3. Pour une détection non validée, vérifier l'applicabilité, les versions de la
   distribution et les correctifs rétroportés. Cocher l'attestation, saisir son
   nom en session locale et une note de contexte si nécessaire.
4. **Valider et préparer le ticket** enregistre la validation locale et ouvre le
   parcours ITSM existant. Un lecteur peut consulter les preuves ; la préparation
   du ticket est réservée aux administrateurs.
5. Prendre en charge / consulter le dossier, puis prévisualiser le ticket. Relire
   le contenu et la destination avant **Confirmer et créer dans GLPI**.

Une lecture ne valide aucune CVE, ne crée aucun dossier ni ticket et ne lance pas
de scan. Le workflow existant réutilise un dossier de même origine/identifiant/type
et protège les reprises de création. Le contenu externe est construit côté serveur
depuis les preuves ; aucun HTML provenant des preuves n'est exécuté.

Les CVE potentielles de la veille restent à vérifier dans l'onglet Sécurité : elles
ne sont pas automatiquement converties en vulnérabilités validées. Une liste vide
n'est pas une preuve de couverture. En cas d'erreur de lecture, un message apparaît
et les derniers résultats de la fiche sont conservés.

## API de lecture et performances

- `/api/security/vulns` accepte `offset` (0 à 1 000 000), `limit` (1 à 5 000),
  les filtres existants et `projection=list` pour omettre les preuves inutiles à la
  liste. Tri stable : priorité, nom du serveur, CVE, identifiant. Les détails restent
  dans `/api/security/vulns/{id}`. La cohérence entre pages dépend de l'évolution
  des données ; ces pages ne sont pas un instantané transactionnel multi-requêtes.
- `/api/security/watch` est paginé : `limit=50` par défaut, maximum 500, `offset`
  positif. Les compteurs globaux et les totaux filtrés sont distincts des lignes
  de la page. `projection=list` omet les correspondances détaillées par serveur ;
  elles sont relues à l'ouverture avec le filtre exact `cve=…`.
- Les recommandations ignorent l'historique résolu pour le plan actif ; elles
  lisent une fois les gravités communes des bulletins et chargent les CVE par lot.
- La synthèse utilise des agrégats SQLite et ne décode que ses dix priorités.
  Ces GET lisent des données conservées ; ils ne déclenchent aucun relevé SSH.

## Validation Windows

Exécuter avec le venv du projet :

```powershell
$env:OPS_BROWSER_CHANNEL = 'msedge'
.venv/Scripts/python.exe deploy/ci.py --offline --ui
```

Le runner décode les sorties capturées en UTF-8, indépendamment de la locale.
Un octet invalide n'empêche plus l'affichage du diagnostic ; un outil en échec
reste en échec. Les tests utilisent des preuves et des API simulées, sans ticket
réel ni connexion aux serveurs supervisés.
