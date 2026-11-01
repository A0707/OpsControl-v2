#!/bin/bash
# Installation d'OpsControl (InfraOps) sur une VM Debian 12 (ou Ubuntu 22.04+), en root.
#
#   tar -xzf /tmp/infraops-vm-*.tar.gz -C /tmp
#   sudo bash /tmp/infraops/deploy/install-vm.sh [--sha256 EMPREINTE --archive /tmp/infraops-vm-….tar.gz]
#   sudo bash /tmp/infraops/deploy/install-vm.sh --reprendre-donnees     # basculement : data/ de l'archive
#
# Garanties :
# - MANIFEST.sha256 est vérifié AVANT toute installation ; archive incorrecte = refus, rien n'est touché ;
# - le code va dans /opt/infraops/releases/<id> ; /opt/infraops/current bascule atomiquement ;
# - la release précédente est conservée ; si le contrôle de code ou le démarrage échoue, retour arrière ;
# - données, inventaire, clé SSH, empreintes et secrets déjà présents ne sont JAMAIS écrasés
#   (sauf --reprendre-donnees, et l'ancien data/ est alors sauvegardé avant).
set -euo pipefail

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST=/opt/infraops
SVC=infraops
REPRENDRE=0
ARCHIVE=""
EMPREINTE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --reprendre-donnees) REPRENDRE=1 ;;
    --archive) ARCHIVE="$2"; shift ;;
    --sha256) EMPREINTE="$2"; shift ;;
    *) echo "Option inconnue : $1"; exit 1 ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || { echo "À lancer en root (sudo)."; exit 1; }
command -v python3 >/dev/null || { echo "python3 requis pour vérifier l'archive (apt install python3)."; exit 1; }

echo "== 0/9 Vérification de l'archive (avant toute modification)"
VERIF=(python3 "$SRC/deploy/release.py" verify "$SRC")
if [ -n "$ARCHIVE" ] && [ -n "$EMPREINTE" ]; then VERIF+=(--archive "$ARCHIVE" --sha256 "$EMPREINTE"); fi
"${VERIF[@]}" || { echo "Installation annulée : archive refusée. Rien n'a été modifié."; exit 2; }
. /etc/os-release
echo "== OpsControl : installation sur $PRETTY_NAME"

echo "== 1/9 Paquets"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv openssh-client iputils-ping sqlite3 nginx >/dev/null
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || { echo "Python >= 3.11 requis"; exit 1; }

echo "== 2/9 Compte de service $SVC"
id "$SVC" >/dev/null 2>&1 || useradd --system --home-dir "$DEST" --shell /usr/sbin/nologin "$SVC"
# Code immuable pour le compte de service (OC-AUDIT-007) : $DEST, releases/ et le lien
# current appartiennent à root. $DEST reste inscriptible par le groupe, avec le bit
# sticky : le service y remplace hosts.yaml (fichier temporaire puis renommage) mais
# ne peut ni supprimer ni remplacer current ou releases/, qui ne sont pas à lui.
install -d -o root -g "$SVC" -m 1770 "$DEST"
install -d -o root -g "$SVC" -m 0750 "$DEST/releases"
install -d -o "$SVC" -g "$SVC" -m 0750 "$DEST/data" "$DEST/backups"
install -d -o "$SVC" -g "$SVC" -m 0700 "$DEST/.ssh"

echo "== 3/9 Données partagées (jamais écrasées)"
if [ "$REPRENDRE" = 1 ]; then
  # Reprise : aucun écrivain SQLite pendant la copie. Une base WAL ouverte copiée
  # par cp n'est pas une sauvegarde cohérente, et un ancien -wal appliqué à la base
  # reprise la corromprait (OC-AUDIT-022). Le service redémarre à la bascule.
  if systemctl is-active --quiet "$SVC" 2>/dev/null; then
    echo "   arrêt du service $SVC pendant la reprise des données"
    systemctl stop "$SVC"
    trap 'if [ "$?" != 0 ]; then echo "   le service $SVC reste ARRÊTÉ : vérifier data/ puis sudo systemctl start $SVC"; fi' EXIT
  fi
  if [ -f "$DEST/data/state.sqlite3" ]; then
    SAUVE="$DEST/data.avant-reprise-$(date +%Y%m%d-%H%M%S)"
    cp -a "$DEST/data" "$SAUVE"
    echo "   ancien data/ sauvegardé dans $SAUVE (service arrêté : copie cohérente)"
  fi
  rm -f "$DEST/data/state.sqlite3-wal" "$DEST/data/state.sqlite3-shm"
fi
for f in "$SRC"/data/*; do
  [ -e "$f" ] || continue
  b="$(basename "$f")"
  case "$b" in *.sqlite3-wal|*.sqlite3-shm|*.lock) continue ;; esac   # état d'un autre processus
  if [ "$REPRENDRE" = 1 ] || [ ! -e "$DEST/data/$b" ]; then cp -a "$f" "$DEST/data/$b"; fi
done
if [ "$REPRENDRE" = 1 ] || [ ! -f "$DEST/hosts.yaml" ]; then cp -a "$SRC/hosts.yaml" "$DEST/hosts.yaml"; fi
# Empreintes SSH déjà acceptées sur le PC : même confiance, ni plus ni moins.
if [ -f "$SRC/ssh/known_hosts" ] && [ ! -f "$DEST/.ssh/known_hosts" ]; then cp "$SRC/ssh/known_hosts" "$DEST/.ssh/known_hosts"; fi
touch "$DEST/audit.log"

echo "== 4/9 Ancienne disposition (code directement dans $DEST)"
# Première migration : le code historique devient une release « legacy », cible du
# retour arrière si la nouvelle release ne démarre pas.
if [ ! -L "$DEST/current" ] && [ -f "$DEST/app.py" ]; then
  LEGACY="legacy-$(date +%Y%m%d-%H%M%S)"
  install -d -o "$SVC" -g "$SVC" "$DEST/releases/$LEGACY"
  ( cd "$DEST" && for x in *.py requirements.txt web deploy; do if [ -e "$x" ]; then cp -a "$x" "releases/$LEGACY/"; fi; done )
  ln -s ../../data "$DEST/releases/$LEGACY/data"
  ln -s ../../hosts.yaml "$DEST/releases/$LEGACY/hosts.yaml"
  if [ -d "$DEST/.venv" ]; then ln -s ../../.venv "$DEST/releases/$LEGACY/.venv"; fi
  ln -s "releases/$LEGACY" "$DEST/current"
  echo "   code historique conservé comme release $LEGACY"
fi

echo "== 5/9 Nouvelle release"
RID="$(python3 "$SRC/deploy/release.py" stage "$SRC" "$DEST")"
REL="$DEST/releases/$RID"
echo "   release $RID"
python3 -m venv "$REL/.venv"
"$REL/.venv/bin/pip" install -q --upgrade pip
"$REL/.venv/bin/pip" install -q -r "$REL/requirements.txt"
# Toutes les releases (legacy comprise) : lisibles par le service, modifiables par root seul.
# chown -R ne suit pas les liens data/ et hosts.yaml, qui restent au service.
chown -R root:"$SVC" "$DEST/releases"
chmod -R u=rwX,g=rX,o= "$DEST/releases"
if [ -L "$DEST/current" ]; then chown -h root:"$SVC" "$DEST/current"; fi

echo "== 6/9 Contrôle du code de la release (avant bascule)"
if ! sudo -u "$SVC" env COCKPIT_AUDIT="$DEST/audit.log" "$REL/.venv/bin/python" "$REL/deploy/preflight.py" --release-check; then
  rm -rf "$REL"
  echo "Installation annulée : la release $RID ne passe pas le contrôle. La version en service n'a pas changé."
  exit 1
fi

echo "== 7/9 Clé SSH dédiée au service"
if [ ! -f "$DEST/.ssh/id_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N '' -C "infraops@$(hostname)" -f "$DEST/.ssh/id_ed25519"
fi
if [ ! -f "$DEST/.ssh/config" ]; then
  cat > "$DEST/.ssh/config" <<'EOF'
# Configuration SSH du service InfraOps.
# InfraOps ajoute lui-même, en tête, StrictHostKeyChecking yes et ses fichiers
# known_hosts (data/known_hosts puis ~/.ssh/known_hosts) : ne rien affaiblir ici.
Host *
    IdentityFile /opt/infraops/.ssh/id_ed25519
    IdentitiesOnly yes
    ConnectTimeout 15
    ServerAliveInterval 15

# La VM est DANS 10.77.0.0/24 : connexion directe, sans rebond.
# Si elle ne l'est pas, décommenter pour passer par le bastion prddcxans01 :
# Match host 10.77.0.*,!10.77.0.41
#     ProxyJump infraops@10.77.0.41
EOF
fi
chown -R "$SVC:$SVC" "$DEST/.ssh" "$DEST/data" "$DEST/backups"
chown "$SVC:$SVC" "$DEST/hosts.yaml" "$DEST/audit.log"
chmod 600 "$DEST/.ssh/id_ed25519" "$DEST/.ssh/config"
if [ -f "$DEST/.ssh/known_hosts" ]; then chmod 644 "$DEST/.ssh/known_hosts"; fi

echo "== 8/9 Secrets et identité du reverse proxy"
install -d -m 0750 -o root -g "$SVC" /etc/infraops
python3 "$REL/deploy/secrets_env.py" --etat
# Secret partagé nginx → OpsControl : seul un appel portant ce secret peut transmettre
# l'identité de l'opérateur. Créé une fois, jamais réécrit, jamais affiché.
touch /etc/infraops/secrets.env
chmod 0640 /etc/infraops/secrets.env
chown root:"$SVC" /etc/infraops/secrets.env
if ! grep -q '^INFRAOPS_TRUSTED_PROXY_SECRET=' /etc/infraops/secrets.env; then
  JETON="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  printf 'INFRAOPS_TRUSTED_PROXY_SECRET=%s\n' "$JETON" >> /etc/infraops/secrets.env
  install -d -m 0755 /etc/nginx/snippets
  ( umask 077; printf 'proxy_set_header X-OpsControl-Proxy "%s";\n' "$JETON" > /etc/nginx/snippets/infraops-proxy-secret.conf )
  chgrp www-data /etc/nginx/snippets/infraops-proxy-secret.conf 2>/dev/null && chmod 0640 /etc/nginx/snippets/infraops-proxy-secret.conf
  unset JETON
fi

echo "== 9/9 Sauvegarde, service, bascule et contrôle de démarrage"
# Sauvegarde AVANT bascule : la nouvelle release peut appliquer des migrations au
# démarrage, et le retour arrière de release.py ne restaure que le code.
if [ -f "$DEST/data/state.sqlite3" ]; then
  if ! sudo -u "$SVC" "$REL/.venv/bin/python" "$REL/deploy/backup_state.py" --base "$DEST" \
       --db "$DEST/data/state.sqlite3" --dest "$DEST/backups" --tag "pre-$RID"; then
    rm -rf "$REL"
    echo "Installation annulée : sauvegarde avant bascule impossible. La version en service n'a pas changé."
    exit 1
  fi
fi
if [ -f /etc/systemd/system/infraops.service ]; then cp -a /etc/systemd/system/infraops.service "$DEST/releases/.infraops.service.previous"; fi
install -m 0644 "$REL/deploy/infraops.service" /etc/systemd/system/infraops.service
install -m 0644 "$REL/deploy/infraops-backup.service" "$REL/deploy/infraops-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable infraops >/dev/null
systemctl enable --now infraops-backup.timer >/dev/null
set +e
python3 "$REL/deploy/release.py" activate "$DEST" "$RID"
ETAT=$?
set -e
if [ "$ETAT" != 0 ]; then
  # Retour vers une release « legacy » : son unité systemd pointait sur /opt/infraops.
  case "$(readlink "$DEST/current")" in
    releases/legacy-*)
      if [ -f "$DEST/releases/.infraops.service.previous" ]; then
        cp -a "$DEST/releases/.infraops.service.previous" /etc/systemd/system/infraops.service
        systemctl daemon-reload
        systemctl restart infraops || true
      fi ;;
  esac
  echo "ÉCHEC : la release $RID n'a pas démarré correctement ; retour à la release précédente."
  echo "Journal : journalctl -u infraops -n 100 --no-pager"
  exit "$ETAT"
fi
python3 "$REL/deploy/release.py" status "$DEST"
install -m 0644 "$REL/deploy/nginx-infraops.conf" /etc/nginx/sites-available/infraops.conf
if [ -f /etc/nginx/tls/infraops.crt ] && [ -f /etc/nginx/tls/infraops.key ]; then
  ln -sf /etc/nginx/sites-available/infraops.conf /etc/nginx/sites-enabled/infraops.conf
  nginx -t && systemctl reload nginx
else
  echo "   nginx : site préparé mais NON activé (certificat /etc/nginx/tls/infraops.crt absent)."
fi

cat <<EOF

================================================================================
Release $RID active ($DEST/current). Release précédente conservée.
Retour arrière manuel :   sudo python3 $DEST/current/deploy/release.py rollback $DEST

Étapes restantes :
1. Secrets :      sudo python3 $DEST/current/deploy/secrets_env.py
2. Clé publique à autoriser sur les serveurs audités (décision de votre équipe) :
     $(cat "$DEST/.ssh/id_ed25519.pub")
3. Contrôle :     sudo -u $SVC $DEST/current/.venv/bin/python $DEST/current/deploy/preflight.py
   Sauvegarde :   quotidienne (infraops-backup.timer) dans $DEST/backups — À COPIER HORS DE LA VM.
                  Immédiate : sudo systemctl start infraops-backup.service
4. Accès :        certificat TLS + oauth2-proxy, puis relancer ce script pour activer nginx.
                  D'ici là : ssh -L 8000:127.0.0.1:8000 <admin>@<IP-VM>  puis http://127.0.0.1:8000
                  (accès direct = mode local NON authentifié, identité déclarative)
================================================================================
EOF
