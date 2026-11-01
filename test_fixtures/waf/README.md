# Fixtures dorées de la sonde WAF

Sorties brutes au format exact des commandes lues par `waf_probe.py` (fail2ban-client 0.11+,
`ss -H` avec son alignement de colonnes, journal d'accès Apache « combined » et « vhost_combined »,
journal d'erreurs Apache 2.4 avec ModSecurity 2.9 / CRS 3).

**Origine.** La base locale ne conserve que les valeurs déjà analysées, pas les sorties brutes.
Ces fichiers reproduisent les formats, identifiants de règles (949110, 930130, 920350), durées
de ban (604 800 s) et ordres de grandeur relevés sur les deux WAF de production le 2026-10-27.
Ils sont anonymisés : adresses dans 192.0.2.0/24, 198.51.100.0/24 et 2001:db8::/32, noms en
`example.test`, aucun secret (le `password=SECRET` de l'accès doit disparaître de la sortie).
Pour les remplacer par des captures réelles : protocole dans `docs/WAF-VERIFICATION.md`.

## Valeurs attendues, comptées à la main

| Source | Valeur | Attendu | Comment |
|---|---|---|---|
| `fail2ban_status.txt` | currently_banned / total_banned | 5 / 412 | lignes « Currently banned », « Total banned » |
| | currently_failed / total_failed | 3 / 1287 | cumul depuis le dernier démarrage de Fail2ban |
| | banned_ips | 5 adresses | dont 1 IPv6 |
| `fail2ban_banip_with_time.txt` | bans datés | 3 | durée 604 800 s (7 jours) |
| `ss_all.txt` | total sockets | 20 | 3 LISTEN, 6 ESTAB, 5 TIME-WAIT, 4 CLOSE-WAIT, 1 FIN-WAIT-2, 1 LAST-ACK |
| `ss_close_wait_processes.txt` | CLOSE_WAIT total / sortant / entrant | 4 / 3 / 1 | entrant = port local 443 en écoute |
| | FIN non lu (Recv-Q = 1) | 2 | 40122 et 40124 |
| | données non lues (Recv-Q > 1) | 1 socket, 516 octets | 517 − 1 octet de FIN |
| | par destination | 192.0.2.20:8080 → 2, 192.0.2.21:8069 → 1 | |
| | par PID | apache2:2101 → 2 | |
| accès (2 fichiers) | requêtes reconnues / non reconnues | 9 / 1 | la ligne tronquée est rejetée |
| | codes | 200×5, 403×1, 500×1, 502×1, 503×1 | |
| | 5xx | 3 / 9 = 33,33 % | sous le minimum de 50 requêtes : non concluant |
| | IP comptées | 8 | la ligne « vhost_combined » compte le code mais pas l'IP |
| | top URL | /catalogue → 3 | paramètres retirés : /catalogue?page=2 et ?page=3 confondus |
| | fenêtres par fichier | 60 s et 21 600 s | 6 lignes en 1 min ; 3 lignes sur 6 h |
| | requêtes d'IP bannies | 198.51.100.4 → 1, 192.0.2.66 → 1 | |
| `error.log` | lignes d'alerte ModSecurity | 4 | les 2 notices de démarrage ne sont pas des alertes |
| | règles | 920350 → 2, 949110 → 1, 930130 → 1 | |
| | score d'anomalie max | 10 | « Total Score: 10 » |
| | clients | 198.51.100.4, 2001:db8::50, 2001:db8::51, 127.0.0.1 | IPv6 suivie de « :port » |
| | refus rapportés | 1 | « Access denied » |
| `*.tpl` (sonde Apache, fenêtre 30 min ; `{-5m}` = il y a 5 min) | refus ModSecurity | 4 | error.log 1 (celui de −120 min est hors fenêtre), shop 2 (−45 min hors fenêtre), api 1 |
| | refus dans error.log principal seul | 1 | ancien décompte, avant correction |
| | lignes d'alerte ModSecurity | 5 | error.log 1 + shop 3 + api 1 ; notices de rechargement exclues |
| | AH03490 | 1 | error.log, il y a 5 min |
| | refus par journal | shop 2, api 1 | journal « quiet » non modifié depuis 2 h : ignoré sans lecture |
