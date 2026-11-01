#!/bin/bash
# infraops-read — lecture bornée pour le compte de supervision OpsControl, appelé via sudo.
#
# À installer sur les serveurs WAF / Apache (voir docs/SERVICE-ACCOUNT.md) :
#   install -o root -g root -m 0755 infraops-read.sh /usr/local/sbin/infraops-read
#
# Pourquoi un script plutôt qu'une règle sudoers « tail -c * -- /var/log/apache2/* » :
# dans les ARGUMENTS d'une règle sudoers, « * » accepte aussi les espaces et « .. ».
# Une telle règle permettrait à un compte infraops compromis de lire /etc/shadow.
# Ici, le chemin réel (liens résolus) est vérifié AVANT toute lecture.
#
#   infraops-read head OCTETS CHEMIN    configuration Apache / ModSecurity
#   infraops-read tail OCTETS CHEMIN    journaux Apache
#   infraops-read cert CHEMIN           métadonnées d'un certificat (jamais son contenu brut)
set -euo pipefail
export LC_ALL=C
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
MAX_BYTES=262144
# Journaux : la sonde Apache lit jusqu'à 16 Mio d'access.log (apache_probe.ACCESS_BYTES_PER_FILE)
# et l'analyse sur le WAF ; seule la synthèse remonte. Avec 256 Ko pour tout, le script
# refusait chaque lecture et l'analyse des journaux devenait aveugle (audit CON-03).
MAX_TAIL_BYTES=16777216

die() { echo "infraops-read: $*" >&2; exit 2; }

[ $# -ge 2 ] || die "usage : head|tail OCTETS CHEMIN | cert CHEMIN"
op=$1
shift
case "$op" in
  head|tail)
    [ $# -eq 2 ] || die "usage : $op OCTETS CHEMIN"
    bytes=$1
    path=$2
    limit=$MAX_BYTES
    [ "$op" = tail ] && limit=$MAX_TAIL_BYTES
    [[ "$bytes" =~ ^[0-9]{1,8}$ ]] || die "taille refusée"
    [ "$bytes" -ge 1 ] && [ "$bytes" -le "$limit" ] || die "taille refusée (1 à $limit)"
    ;;
  cert)
    [ $# -eq 1 ] || die "usage : cert CHEMIN"
    path=$1
    ;;
  *) die "opération refusée" ;;
esac

real=$(realpath -e -- "$path" 2>/dev/null) || die "chemin introuvable"
[ -f "$real" ] || die "pas un fichier régulier"
# realpath ne voit pas un lien DUR : « /var/log/apache2/x » peut désigner /etc/shadow si
# quelqu'un a pu l'y créer. Un fichier à plusieurs liens est refusé (audit SSH-11).
[ "$(stat -c %h -- "$real")" = 1 ] || die "fichier à liens multiples : lecture refusée"

allowed=0
case "$op" in
  head)
    # Fichiers de configuration uniquement : jamais un répertoire de clés (ex. /etc/apache2/ssl/).
    case "$real" in
      /etc/apache2/apache2.conf|/etc/apache2/ports.conf) allowed=1 ;;
      /etc/apache2/sites-enabled/*|/etc/apache2/sites-available/*) allowed=1 ;;
      /etc/apache2/conf-enabled/*|/etc/apache2/conf-available/*) allowed=1 ;;
      /etc/apache2/mods-enabled/*|/etc/apache2/mods-available/*) allowed=1 ;;
      /etc/modsecurity/*.conf) allowed=1 ;;
    esac
    ;;
  tail)
    case "$real" in /var/log/apache2/*) allowed=1 ;; esac
    ;;
  cert)
    # openssl x509 n'affiche que des métadonnées et échoue sur une clé privée.
    case "$real" in /etc/ssl/*|/etc/letsencrypt/*|/etc/apache2/*) allowed=1 ;; esac
    ;;
esac
[ "$allowed" = 1 ] || die "chemin hors périmètre"

if [ "$op" = head ] && grep -q -- '-----BEGIN [A-Z ]*PRIVATE KEY-----' "$real"; then
  die "fichier contenant une clé privée : lecture refusée"
fi

case "$op" in
  head) exec head -c "$bytes" -- "$real" ;;
  tail) exec tail -c "$bytes" -- "$real" ;;
  cert) exec openssl x509 -in "$real" -noout -startdate -enddate -subject -issuer -serial -fingerprint -sha256 ;;
esac
