#!/bin/sh
# Compte-rendu des traitements batch pour Zabbix (et donc pour InfraOps).
#
# Sans lui, Zabbix et InfraOps ne connaissent que la PLANIFICATION d'un batch,
# jamais son résultat. Il ne change rien au batch : il le lance tel quel, note
# son début, son code de sortie et sa durée, et rend le MÊME code de sortie.
#
#   infraops-batch-report NOM commande [arguments...]   lancer un batch (crontab)
#   infraops-batch-report --discovery                   JSON de découverte (agent Zabbix)
#   infraops-batch-report --get NOM champ               une valeur (agent Zabbix)
#
# Pourquoi un fichier lu par l'agent plutôt que zabbix_sender : depuis
# prdlabjob06 et prddcyjob02, le port 10051 du serveur Zabbix est FERMÉ
# (constaté le 26/09). zabbix_sender y perdrait chaque résultat en silence.
# L'agent, lui, est déjà interrogé par Zabbix sur le port 10050 : aucune
# ouverture de pare-feu n'est nécessaire.
#
# État d'un batch : /var/lib/infraops-batch/NOM.state (une ligne clé=valeur) :
#   started   début de l'exécution en cours ou de la dernière (epoch)
#   finished  fin de la dernière exécution TERMINÉE (epoch ; 0 = jamais)
#   rc        code de sortie de la dernière exécution terminée (-1 = jamais)
#   duration  durée de la dernière exécution terminée (secondes)
# « En cours » = started > finished. La valeur précédente reste lisible pendant
# qu'un nouveau passage tourne : un batch en cours n'efface pas son dernier résultat.
#
# Cause d'un passage : /var/lib/infraops-batch/NOM.tail, les 40 dernières lignes
# de sa sortie d'erreur, mots de passe et jetons masqués (lue par la sonde SSH
# d'OpsControl). Seule différence visible : une dernière ligne d'erreur sans
# saut de ligne en reçoit un.
#
# Garanties : l'écriture de l'état ne fait jamais échouer ni retarder le batch ;
# rien n'est ajouté à la sortie du batch, le code de sortie est rendu tel quel.

DIR="${INFRAOPS_BATCH_DIR:-/var/lib/infraops-batch}"

valide() {
  case "$1" in *[!A-Za-z0-9_.-]*|""|.*) return 1 ;; esac
  return 0
}

lire() {  # NOM champ -> valeur (vide si absente)
  [ -r "$DIR/$1.state" ] || return 0
  sed -n "s/^$2=\(-\{0,1\}[0-9][0-9]*\)$/\1/p" "$DIR/$1.state" | head -n 1
}

ecrire() {  # NOM started finished rc duration — atomique (fichier temporaire + mv)
  tmp="$DIR/.$1.$$"
  printf 'started=%s\nfinished=%s\nrc=%s\nduration=%s\n' "$2" "$3" "$4" "$5" > "$tmp" 2>/dev/null \
    && chmod 0644 "$tmp" 2>/dev/null && mv -f "$tmp" "$DIR/$1.state" 2>/dev/null
  rm -f "$tmp" 2>/dev/null
  return 0
}

case "${1:-}" in
  --discovery)
    printf '{"data":['
    sep=''
    for f in "$DIR"/*.state; do
      [ -e "$f" ] || continue
      n=$(basename "$f" .state)
      valide "$n" || continue
      printf '%s{"{#BATCH}":"%s"}' "$sep" "$n"
      sep=','
    done
    printf ']}\n'
    exit 0 ;;
  --get)
    valide "${2:-}" || exit 1
    case "${3:-}" in started|finished|rc|duration) ;; *) exit 1 ;; esac
    v=$(lire "$2" "$3")
    printf '%s\n' "${v:-0}"
    exit 0 ;;
esac

NAME="${1:-}"
[ $# -ge 2 ] || { echo "usage: infraops-batch-report NOM commande [arguments...]" >&2; exit 64; }
valide "$NAME" || { echo "infraops-batch-report: NOM invalide (lettres, chiffres, _ . - ; pas de point initial)" >&2; exit 64; }
shift

START=$(date +%s)
PREV_FIN=$(lire "$NAME" finished); PREV_RC=$(lire "$NAME" rc); PREV_DUR=$(lire "$NAME" duration)
ecrire "$NAME" "$START" "${PREV_FIN:-0}" "${PREV_RC:--1}" "${PREV_DUR:-0}"

# Fin de la sortie d'erreur (40 lignes, secrets masqués) gardée dans NOM.tail :
# c'est elle qui dit POURQUOI un passage échoue. La sortie standard n'est pas
# touchée. La sortie d'erreur passe par awk, qui renvoie chaque ligne aussitôt
# vers sa destination d'origine (mail cron, fichier) et garde en mémoire les 40
# dernières : aucun /dev/stderr, aucun fichier qui grossit. Le code de sortie
# est relu par un descripteur dédié. Sans awk/sed ou si le dossier n'est pas
# inscriptible : exécution directe, comme avant.
TMP_RAW="$DIR/.$NAME.raw.$$"
TMP_TAIL="$DIR/.$NAME.tail.$$"
if command -v awk >/dev/null 2>&1 && command -v sed >/dev/null 2>&1 \
   && ( umask 077; : > "$TMP_RAW" ) 2>/dev/null; then
  exec 3>&1
  RC=$( { { "$@" 2>&1 1>&3 3>&- 4>&-; echo $? >&4; } \
        | awk -v n=40 -v out="$TMP_RAW" '{ print; fflush(); b[NR % n] = $0 }
            END { for (i = (NR > n ? NR - n + 1 : 1); i <= NR; i++) print b[i % n] > out }' >&2 3>&- 4>&-; } 4>&1 )
  exec 3>&-
  # Ne jamais rendre un code vide (exit "" vaudrait 0, un faux succès).
  case "$RC" in ''|*[!0-9]*) RC=1 ;; esac
  # Fichier brut (0600) masqué avant publication en 0644 pour la sonde.
  sed -E 's/((pass(word|wd)?|pwd|secret|token|api[_-]?key|authorization)"?[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1***/Ig; s#(//[^/:@[:space:]]+):[^@/[:space:]]+@#\1:***@#g' \
    "$TMP_RAW" > "$TMP_TAIL" 2>/dev/null \
    && chmod 0644 "$TMP_TAIL" 2>/dev/null && mv -f "$TMP_TAIL" "$DIR/$NAME.tail" 2>/dev/null
  rm -f "$TMP_RAW" "$TMP_TAIL" 2>/dev/null
else
  rm -f "$TMP_RAW" 2>/dev/null
  "$@"
  RC=$?
fi

FIN=$(date +%s)
ecrire "$NAME" "$START" "$FIN" "$RC" "$((FIN - START))"
exit "$RC"
