# Revue fonctionnelle du WAF

Les vues WAF réunissent les observations Apache/ModSecurity, les bans Fail2ban,
les connexions et les éléments de disponibilité. Une observation ne prouve ni
une saturation ni une attaque : vérifier sa date, son périmètre et sa source.

Les seuils livrés sont des valeurs initiales à qualifier dans un laboratoire.
Avant une conclusion, examiner le volume de requêtes, les fenêtres temporelles,
les erreurs applicatives, les workers et les observations répétées. Une collecte
absente ou obsolète doit rester visible comme telle.

Les procédures correctives sont produites en texte. Le cockpit ne bannit pas
d'IP, ne modifie pas les règles et ne déclenche aucune bascule HA.
Les états VRRP et VIP nécessitent une confrontation des observations des deux
nœuds ; l'absence d'une source ne suffit pas à conclure à un split-brain.

La validation publique utilise les fixtures synthétiques de `test_fixtures/waf/`
et les tests `test_waf*.py`, `test_apache_health.py` et `test_ui_waf*.cjs`.
Les anciens relevés d'exploitation ne sont pas distribués.

Voir [architecture](ARCHITECTURE.md), [sécurité](SECURITY.md) et
[runbook](RUNBOOK.md) pour les prérequis d'exploitation.
