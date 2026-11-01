"""Sonde détaillée : stockage, partages distants, processus, sécurité locale.

Trois décisions de conception, toutes contraintes par l'existant :

1. UNE seule opération SSH, pas huit.
   `run_operation` ouvre une connexion par opération. Avec 84 hôtes, huit sondes
   séparées coûteraient 672 connexions SSH supplémentaires par cycle. On envoie
   donc une commande unique dont la sortie est découpée en sections `##NOM`.

2. Aucune commande ne peut geler la collecte.
   Un montage NFS mort fait bloquer `df` indéfiniment — c'est le piège classique
   de ce type de collecteur. On lit donc les montages avec `findmnt`, qui lit
   /proc/self/mountinfo et ne touche JAMAIS au réseau ; et toute commande visant
   un chemin distant est bornée par `timeout`. Une enveloppe de 25 s limite
   aussi l'accumulation de montages lents ; la sortie partielle reste identifiable.
   Un processus bloqué dans le noyau peut survivre au signal : ce n'est pas
   une garantie de terminaison de toute opération NFS au niveau système.

3. La commande reste figée dans l'allowlist.
   Le client ne choisit ni la commande ni ses paramètres : c'est la garantie
   centrale de la plateforme. C'est aussi pourquoi cette sonde n'utilise pas
   asyncssh avec des commandes construites dynamiquement — ce serait plus
   souple, et ce serait précisément la propriété qu'on ne veut pas perdre.
"""
import math
import re
import shlex

# Systèmes de fichiers virtuels : bruit sans valeur d'exploitation.
VIRTUELS = 'tmpfs devtmpfs squashfs overlay proc sysfs cgroup2 devpts efivarfs'
DISTANTS = 'nfs,nfs4,cifs,smb3,fuse.sshfs'

# Commande unique, figée. Chaque section est délimitée pour un découpage sûr.
COMMAND = (
    "LC_ALL=C; export LC_ALL; "
    # --- Montages : lecture de /proc uniquement, jamais d'accès réseau -------
    "echo '##MOUNTS'; findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null; "
    # --- Espace et inodes : systèmes locaux seulement -----------------------
    "echo '##DF'; timeout -k 1 6 df -lPT " + ' '.join('-x ' + f for f in VIRTUELS.split()) + " 2>/dev/null; "
    "echo '##INODES'; timeout -k 1 6 df -lPiT " + ' '.join('-x ' + f for f in VIRTUELS.split()) + " 2>/dev/null; "
    # --- Partages distants : un timeout court PAR montage --------------------
    # stat -f interroge le serveur distant ; sur un montage mort il bloque.
    # timeout 3 borne chaque test : un partage gelé coûte 3 s, pas l'audit.
    "echo '##REMOTE'; findmnt -rn -t " + DISTANTS + " -o TARGET,SOURCE,FSTYPE,OPTIONS 2>/dev/null | "
    "while IFS=' ' read -r t s f o; do "
    "v=$(timeout -k 1 3 stat -f -c '%S %b %a' \"$t\" 2>/dev/null); r=$?; "
    "case $r in 0) echo \"ALIVE|$t|$s|$f|$o|$v\";; "
    "124|137) echo \"TIMEOUT|$t|$s|$f|$o|\";; *) echo \"ERROR|$t|$s|$f|$o|\";; esac; done; "
    # --- LVM et ZFS : absents sur la plupart des hôtes, d'où le repli --------
    "echo '##LVM'; timeout -k 1 3 lvs --noheadings --units b --nosuffix --separator '|' -o vg_name,lv_name,lv_size,lv_attr,pool_lv,data_percent,metadata_percent 2>/dev/null || echo 'INDISPONIBLE'; "
    "echo '##VG'; timeout -k 1 3 vgs --noheadings --units b --nosuffix -o vg_name,vg_size,vg_free 2>/dev/null || echo 'INDISPONIBLE'; "
    "echo '##ZFS'; timeout -k 1 3 zpool list -H -o name,health,capacity,fragmentation 2>/dev/null || echo 'INDISPONIBLE'; "
    # --- SMART : exige root. On tente et on rapporte honnêtement l'échec -----
    "echo '##SMART'; for d in /sys/block/sd? /sys/block/nvme?n?; do "
    "[ -e \"$d\" ] || continue; n=$(basename \"$d\"); "
    "echo \"$n|$(timeout 4 smartctl -H /dev/$n 2>/dev/null | grep -iE 'overall-health|SMART Health' | tail -1 || echo 'NON_ACCESSIBLE')\"; done; "
    # --- I/O : deux relevés de /proc/diskstats à 1 s d'intervalle -----------
    "echo '##IO1'; cat /proc/diskstats 2>/dev/null; echo '##CPU1'; head -n 1 /proc/stat; "
    "sleep 1; "
    "echo '##IO2'; cat /proc/diskstats 2>/dev/null; echo '##CPU2'; head -n 1 /proc/stat; "
    # --- Processus les plus consommateurs ------------------------------------
    "echo '##PROC'; ps -eo pid,comm,pcpu,pmem --sort=-pcpu 2>/dev/null | head -n 11; "
    # --- Ports en écoute avec le processus (nécessite root pour les noms) ----
    "echo '##PORTS'; ss -tulpn 2>/dev/null | head -n 60; "
    # --- Sécurité locale ------------------------------------------------------
    "echo '##FIREWALL'; ufw status 2>/dev/null | head -n 3 || echo 'INDISPONIBLE'; "
    "echo '##FAIL2BAN'; fail2ban-client status 2>/dev/null | head -n 5 || echo 'INDISPONIBLE'; "
    # --- Partages SERVIS par cet hôte : exports NFS et partages Samba ---------
    # /etc/exports et testparm se lisent sans root. Aucun df par export : le
    # taux d'occupation se déduit du ##DF déjà relevé (point de montage le plus
    # long contenant le chemin), sans commande ni délai supplémentaire.
    "echo '##EXPORTS'; cat /etc/exports /etc/exports.d/*.exports 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | head -n 30 | "
    "while read -r p c; do echo \"NFS|$p|$c\"; done; "
    "command -v testparm >/dev/null 2>&1 && timeout 5 testparm -s 2>/dev/null | "
    "sed -n -e 's/^\\[\\(.*\\)\\]$/N|\\1/p' -e 's/^[[:space:]]*path = /P|/p' | head -n 60 | "
    "while IFS='|' read -r k v; do case $k in N) n=$v;; P) echo \"SMB|$v|$n\";; esac; done; "
    "echo '##SSHFAIL'; timeout 6 journalctl -u ssh -u sshd --since '24 hours ago' --no-pager 2>/dev/null "
    "| grep -ci 'failed password' || echo '0'"
)

# Conserver les sections déjà produites, puis expliciter l'interruption. Sans
# cette enveloppe, N montages multiplient le délai par N avant les autres sondes.
COMMAND = "timeout -k 1 25 sh -c " + shlex.quote(COMMAND) + "; r=$?; echo '##PROBESTATUS'; echo $r"


def _sections(sortie):
    """Découpe la sortie brute en sections ##NOM -> lignes."""
    blocs, courant = {}, None
    for ligne in (sortie or '').splitlines():
        if ligne.startswith('##'):
            courant = ligne[2:].strip()
            blocs[courant] = []
        elif courant:
            blocs[courant].append(ligne)
    return blocs


def _nombre(valeur):
    try:
        nombre = float(valeur)
        return int(nombre) if math.isfinite(nombre) and nombre >= 0 and nombre.is_integer() else None
    except (TypeError, ValueError):
        return None


def _pourcentage(valeur):
    try:
        n = int(str(valeur).rstrip('%'))
        return n if 0 <= n <= 100 else None
    except (TypeError, ValueError):
        return None


def _filesystems(lignes_df, lignes_inodes):
    """Croise `df -PT` et `df -PiT` par point de montage."""
    espace = {}
    for ligne in lignes_df[1:]:
        p = ligne.split()
        if len(p) < 7:
            continue
        espace[' '.join(p[6:])] = {
            'device': p[0], 'fstype': p[1],
            'total_kb': _nombre(p[2]), 'used_kb': _nombre(p[3]), 'available_kb': _nombre(p[4]),
            'use_pct': _pourcentage(p[5]),
        }
    for ligne in lignes_inodes[1:]:
        p = ligne.split()
        if len(p) < 7:
            continue
        cible = espace.get(' '.join(p[6:]))
        if cible is not None:
            cible['inodes_use_pct'] = _pourcentage(p[5])
            cible['inodes_total'] = _nombre(p[2])
            cible['inodes_used'] = _nombre(p[3])
            cible['inodes_free'] = _nombre(p[4])
    return [{'mount': m, **v} for m, v in sorted(espace.items())]


def _remote(lignes):
    """Partages distants et leur accessibilité réelle."""
    partages = []
    for ligne in lignes:
        champs = ligne.split('|')
        if len(champs) < 5:
            continue
        etat, cible, source, fstype, options = champs[:5]
        mesures = champs[5].split() if len(champs) > 5 else []
        entree = {
            'mount': cible, 'source': source, 'fstype': fstype,
            # Options de montage : elles ne prouvent pas les droits applicatifs.
            'access': 'read-only' if re.search(r'(^|,)ro(,|$)', options) else 'read-write',
            # 'stale' n'est pas 'inconnu' : le montage existe et ne répond pas.
            'status': 'accessible' if etat == 'ALIVE' else 'stale' if etat in ('STALE', 'TIMEOUT') else 'unknown',
            'error_kind': None if etat == 'ALIVE' else 'timeout' if etat == 'TIMEOUT' else 'unavailable' if etat == 'STALE' else 'probe_error',
            'total_kb': None, 'available_kb': None, 'use_pct': None,
        }
        if len(mesures) == 3:
            taille, blocs, libres = (_nombre(x) for x in mesures)
            if None not in (taille, blocs, libres) and blocs > 0:
                entree['total_kb'] = blocs * taille // 1024
                entree['available_kb'] = libres * taille // 1024
                entree['use_pct'] = round((blocs - libres) * 100 / blocs)
        partages.append(entree)
    return partages


def _io(avant, apres, cpu_avant, cpu_apres):
    """Débit disque sur l'intervalle de 1 s, et iowait CPU."""
    def lire(lignes):
        stats = {}
        for ligne in lignes:
            p = ligne.split()
            if len(p) >= 14 and not re.match(r'^(loop|ram|dm-)', p[2]):
                stats[p[2]] = (_nombre(p[5]), _nombre(p[9]))  # secteurs lus / écrits
        return stats

    a, b = lire(avant), lire(apres)
    disques = []
    for nom, (lus_b, ecrits_b) in b.items():
        lus_a, ecrits_a = a.get(nom, (None, None))
        if None in (lus_a, ecrits_a, lus_b, ecrits_b):
            continue
        # Un secteur = 512 octets. Intervalle de 1 s, donc delta = débit.
        disques.append({'device': nom,
                        'read_kbps': max(0, (lus_b - lus_a)) // 2,
                        'write_kbps': max(0, (ecrits_b - ecrits_a)) // 2})
    iowait = None
    try:
        x = [int(v) for v in cpu_avant[0].split()[1:9]]
        y = [int(v) for v in cpu_apres[0].split()[1:9]]
        total = sum(y) - sum(x)
        if total > 0:
            iowait = round((y[4] - x[4]) * 100 / total, 1)
    except (IndexError, ValueError, ZeroDivisionError):
        iowait = None
    return {'devices': sorted(disques, key=lambda d: -(d['read_kbps'] + d['write_kbps']))[:8],
            'iowait_pct': iowait}


def _exports(lignes, systemes):
    """Partages servis : NFS (/etc/exports) et Samba (testparm).

    L'occupation est celle du système de fichiers local qui porte le chemin —
    exactement ce que renverrait `df chemin`, sans le relancer.
    """
    montages = sorted((f for f in systemes if f.get('mount')), key=lambda f: -len(f['mount']))

    def occupation(chemin):
        for f in montages:
            m = f['mount'].rstrip('/') or '/'
            if chemin == m or chemin.startswith(m + '/') or m == '/':
                return f.get('use_pct'), f['mount']
        return None, None

    partages = []
    for ligne in lignes:
        champs = ligne.split('|')
        if len(champs) < 3 or champs[0] not in ('NFS', 'SMB') or not champs[1].startswith('/'):
            continue
        protocole, chemin, detail = champs[0], champs[1].strip('"'), champs[2].strip()
        use, montage = occupation(chemin)
        entree = {'protocol': protocole, 'path': chemin, 'use_pct': use, 'filesystem': montage}
        # NFS : clients autorisés et options ; Samba : nom du partage.
        if protocole == 'NFS':
            entree['clients'] = detail or None
        else:
            entree['name'] = detail.strip('[]') or None
        partages.append(entree)
    return partages


def parse(sortie):
    """Transforme la sortie brute en structure exploitable par l'interface.

    Toute section illisible ou absente vaut `None` ou liste vide — jamais une
    valeur par défaut qui se ferait passer pour une mesure.
    """
    s = _sections(sortie)
    systemes = _filesystems(s.get('DF', []), s.get('INODES', []))
    lvm_brut = s.get('LVM', [])
    zfs_brut = s.get('ZFS', [])
    smart = []
    for ligne in s.get('SMART', []):
        nom, _, verdict = ligne.partition('|')
        if not nom:
            continue
        v = verdict.strip()
        indisponible = not v or 'NON_ACCESSIBLE' in v
        statut = 'unknown'
        if not indisponible:
            if re.search(r'\bFAILED\b|\bBAD\b|\bFAILING\b', v, re.I):
                statut = 'failed'
            elif re.search(r'\bPASSED\b|\bOK\b', v, re.I):
                statut = 'ok'
        smart.append({'device': nom,
                      'status': statut,
                      # Jamais de jeton brut dans l'interface : on explique pourquoi
                      # la mesure manque, sinon l'exploitant croit à une panne disque.
                      'detail': 'Non accessible : droits, outil absent ou collecte incomplète (root peut être nécessaire)' if indisponible else v})
    pare_feu = ' '.join(s.get('FIREWALL', [])).strip()
    f2b = ' '.join(s.get('FAIL2BAN', [])).strip()
    echecs = next((_nombre(l.strip()) for l in s.get('SSHFAIL', []) if l.strip().isdigit()), None)
    return {
        'collection_complete': (s['PROBESTATUS'] == ['0']) if 'PROBESTATUS' in s else None,
        'filesystems': systemes,
        'remote_shares': _remote(s.get('REMOTE', [])),
        # None = sonde antérieure (section absente) ; [] = aucun partage servi.
        'exports': _exports(s['EXPORTS'], systemes) if 'EXPORTS' in s else None,
        'lvm': [v for v in (_lvm(l) for l in lvm_brut) if v],
        'volume_groups': [{'name': p[0], 'size_bytes': _nombre(p[1]), 'free_bytes': _nombre(p[2])}
                          for p in (l.split() for l in s.get('VG', [])) if len(p) == 3],
        'zfs': [] if (not zfs_brut or 'INDISPONIBLE' in zfs_brut[0]) else [
            {'pool': p[0], 'health': p[1], 'capacity_pct': _pourcentage(p[2]), 'fragmentation_pct': _pourcentage(p[3])}
            for p in (l.split() for l in zfs_brut) if len(p) >= 4],
        'smart': smart,
        'io': _io(s.get('IO1', []), s.get('IO2', []), s.get('CPU1', []), s.get('CPU2', [])),
        'top_processes': _processes(s.get('PROC', [])[1:]),
        'listening_ports': len([l for l in s.get('PORTS', [])[1:] if l.strip()]) or None,
        'firewall': pare_feu or None,
        'fail2ban': f2b if f2b and 'INDISPONIBLE' not in f2b else None,
        'ssh_failed_24h': echecs,
        'scope': ('Relevé en lecture seule. SMART et les noms de processus derrière les ports '
                  'exigent root : sans lui, ils restent « non accessibles », jamais « sains ». '
                  'Les partages distants sont testés avec un délai borné ; un montage gelé est '
                  'signalé comme tel et ne bloque pas la collecte.'),
    }


def _processes(lines):
    """Une ligne coupée ne doit pas invalider les autres mesures de l'audit."""
    rows = []
    for line in lines:
        p = line.split()
        if len(p) < 4 or not p[0].isdigit():
            continue
        try:
            cpu, mem = float(p[2]), float(p[3])
        except ValueError:
            continue
        if math.isfinite(cpu) and cpu >= 0 and math.isfinite(mem) and 0 <= mem <= 100:
            rows.append({'pid': _nombre(p[0]), 'command': p[1], 'cpu_pct': cpu, 'mem_pct': mem})
    return rows


def _lvm(line):
    """Accepter les anciens relevés et les colonnes thin pool facultatives."""
    p = [v.strip() for v in line.split('|')] if '|' in line else line.split()
    if len(p) < 4:
        return None
    def ratio(value):
        try:
            n = float(value)
            return n if math.isfinite(n) and 0 <= n <= 100 else None
        except (ValueError, TypeError):
            return None
    return {'vg': p[0], 'lv': p[1], 'size_bytes': _nombre(p[2]), 'attr': p[3],
            'pool': p[4] if len(p) > 4 else None,
            'data_pct': ratio(p[5]) if len(p) > 5 else None,
            'metadata_pct': ratio(p[6]) if len(p) > 6 else None}
