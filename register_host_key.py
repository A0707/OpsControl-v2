"""Enregistrement manuel et supervise d'une empreinte SSH dans data/known_hosts.

La plateforme n'accepte jamais automatiquement une empreinte : en fonctionnement
normal, StrictHostKeyChecking reste "yes" (voir ssh.persistent_config). C'est le
seul outil du cockpit qui ecrit dans data/known_hosts, et il ne le fait qu'apres
confirmation tapee au clavier par l'operateur. Il ne touche jamais ~/.ssh/known_hosts.

Usage :
    python register_host_key.py <cle-ou-nom-ou-ip-de-hosts.yaml>
    python register_host_key.py --tous [--limite N]

Le mode --tous existe parce qu'une configuration SSH avec
UserKnownHostsFile /dev/null (cas frequent avec VS Code Remote-SSH) ne memorise
JAMAIS d'empreinte : le parc entier reste alors inaccessible a la plateforme, et
enregistrer 87 serveurs un par un n'est pas praticable. Il collecte toutes les
empreintes par le meme chemin SSH, les affiche groupees pour relecture, puis
demande UNE confirmation. La verification humaine est conservee ; c'est sa
repetition qui est supprimee.

Ce script capture la cle hote presentee lors de la connexion (via le meme chemin
SSH que la plateforme : meme ~/.ssh/config, meme ProxyJump/bastion), l'affiche
sous forme d'empreinte (SHA256) pour verification, puis - seulement si vous tapez
OUI apres l'avoir comparee a une source de confiance (console du serveur, CMDB,
un administrateur qui la connait deja) - l'ajoute a data/known_hosts.
"""
from __future__ import annotations

import argparse
import os
from concurrent.futures import ThreadPoolExecutor

CHR_NL = chr(10)  # saut de ligne, ecrit ainsi pour rester lisible dans les f-strings
import subprocess
import tempfile
from pathlib import Path


def capture_key(ip: str, candidate, timeout: int) -> str:
    """Etablit la session (via le meme chemin SSH que la plateforme, y compris
    ProxyJump) avec une verification temporaire acceptant la premiere empreinte
    presentee, isolee dans un fichier jetable. N'ecrit rien de definitif."""
    from ssh import native_args
    raw = native_args(ip, candidate)
    filtered, skip = [raw[0]], False
    for i, a in enumerate(raw[1:], 1):
        if skip:
            skip = False
            continue
        if a == '-o' and i + 1 < len(raw) and raw[i + 1] == 'StrictHostKeyChecking=yes':
            skip = True
            continue
        filtered.append(a)
    with tempfile.TemporaryDirectory() as tmp:
        scratch = Path(tmp) / 'known_hosts'
        scratch.touch()
        # La clé hôte est enregistrée dans le fichier jetable dès l'échange de clés, AVANT
        # toute authentification : on n'en tente donc aucune (« none » seul, clé publique
        # désactivée). Un hôte non vérifié ne reçoit ni tentative de clé ni agent (audit SSH-02).
        argv = [filtered[0], '-o', 'StrictHostKeyChecking=accept-new',
                '-o', f'UserKnownHostsFile={scratch}',
                '-o', 'PreferredAuthentications=none', '-o', 'PubkeyAuthentication=no'] + filtered[1:] + ['exit']
        # Sous le plafond global de sessions, comme toute connexion de la plateforme (audit SSH-08).
        from ssh import SESSIONS
        with SESSIONS:
            run_bounded(argv, timeout)
        return scratch.read_text(encoding='utf-8') if scratch.is_file() else ''


def run_bounded(argv, timeout):
    """Lance ssh avec son propre groupe de processus et arrête TOUT l'arbre au délai :
    un processus ProxyJump ne doit pas survivre à une capture expirée (audit SSH-07)."""
    from ssh import ssh_environment, stop_native
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, env=ssh_environment(),
                            stderr=subprocess.DEVNULL, shell=False,
                            start_new_session=os.name != 'nt',
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_native(proc)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def empreintes_lisibles(lignes):
    """Rend les lignes known_hosts sous forme d'empreintes SHA256 lisibles."""
    with tempfile.NamedTemporaryFile('w', suffix='.tmp', delete=False, encoding='utf-8') as f:
        f.write(CHR_NL.join(lignes) + CHR_NL)
        chemin = f.name
    try:
        r = subprocess.run(['ssh-keygen', '-l', '-f', chemin], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except (subprocess.SubprocessError, OSError):
        return ''
    finally:
        Path(chemin).unlink(missing_ok=True)


def enregistrer_en_lot(cfg, hosts, candidates, base, limite=0, confirme=False):
    """Collecte les empreintes de tout l'inventaire, puis demande UNE confirmation.

    Rien n'est ecrit avant la reponse. Les serveurs injoignables sont listes
    separement : une empreinte absente n'est pas une empreinte refusee, et la
    difference doit rester visible.
    """
    # Même magasin que la plateforme, y compris avec COCKPIT_SSH_DIR (audit SSH-06).
    from host_access import known_hosts_path
    store = known_hosts_path(base)
    store.parent.mkdir(parents=True, exist_ok=True)
    connues = store.read_text(encoding='utf-8') if store.is_file() else ''
    cibles = hosts[:limite] if limite else hosts
    print(f'Collecte des empreintes de {len(cibles)} serveur(s), par le meme chemin SSH')
    print('que la plateforme (bastion et ProxyJump inclus). Rien n est ecrit a ce stade.' + CHR_NL)

    def collecter(host):
        """Capture l'empreinte d'un hote, en essayant ses combinaisons compte/port."""
        for candidate in candidates(cfg, host):
            lignes = capture_key(host['ip'], candidate, cfg.timeout + 10)
            capturees = [l for l in lignes.splitlines() if l.strip()]
            if capturees:
                return host, capturees
        return host, []

    # En serie, un hote injoignable epuise ses 4 combinaisons a 18 s : l'inventaire
    # entier depasserait l'heure. Meme parallelisme que la collecte de la plateforme.
    ouvriers = max(1, min(16, int(os.getenv('COCKPIT_WORKERS', '8'))))
    nouvelles, deja, injoignables = {}, [], []
    termines = 0
    with ThreadPoolExecutor(max_workers=ouvriers) as pool:
        for host, capturees in pool.map(collecter, cibles):
            termines += 1
            prefixe = f"  [{termines}/{len(cibles)}] {host['key']:<18} {host['ip']:<16} "
            if not capturees:
                injoignables.append(host)
                print(prefixe + 'injoignable', flush=True)
                continue
            inedites = [l for l in capturees if l.strip() not in connues]
            if not inedites:
                deja.append(host)
                print(prefixe + 'deja connue', flush=True)
                continue
            nouvelles[host['key']] = (host, inedites)
            print(prefixe + f'{len(inedites)} empreinte(s)', flush=True)

    print(f'{CHR_NL}{len(nouvelles)} serveur(s) avec une empreinte inedite, '
          f'{len(deja)} deja connue(s), {len(injoignables)} injoignable(s).')
    if injoignables:
        print(CHR_NL + 'Injoignables (aucune empreinte, rien a decider les concernant) :')
        print('  ' + ', '.join(h['key'] for h in injoignables[:20])
              + (' ...' if len(injoignables) > 20 else ''))
    if not nouvelles:
        print(CHR_NL + 'Rien a enregistrer.')
        return 0

    print(CHR_NL + '=== Empreintes a enregistrer ===')
    for cle, (host, lignes) in nouvelles.items():
        lisible = empreintes_lisibles(lignes)
        print(CHR_NL + f"{host['name']} ({host['ip']})")
        for ligne in (lisible or '(lecture impossible)').splitlines():
            print('   ' + ligne)

    print(CHR_NL + '=' * 70)
    print("Comparez ces empreintes a une source de confiance avant de repondre.")
    print("Repondre OUI revient a declarer que ces serveurs sont bien les votres.")
    print("Ensuite, la plateforme refusera toute empreinte differente : c'est ce")
    print("qui protege des interceptions, et c'est pourquoi la reponse compte.")
    print('=' * 70)
    if confirme:
        print(CHR_NL + 'Confirmation fournie en ligne de commande (--oui).')
        reponse = 'oui'
    else:
      try:
        reponse = input(CHR_NL + f'Enregistrer ces {len(nouvelles)} empreinte(s) dans data/known_hosts ? [oui/NON] ')
      except EOFError:
        # Execution non interactive : on refuse. Enregistrer des empreintes sans
        # qu'un operateur ait pu les relire viderait la confirmation de son sens.
        print(CHR_NL + 'Entree non interactive : rien enregistre. Utiliser --oui pour confirmer.')
        return 1
    if reponse.strip().lower() not in ('oui', 'o', 'yes', 'y'):
        print('Rien enregistre.')
        return 1
    with store.open('a', encoding='utf-8') as f:
        for host, lignes in nouvelles.values():
            f.write(CHR_NL.join(lignes) + CHR_NL)
    print(f'{CHR_NL}{len(nouvelles)} serveur(s) enregistre(s) dans {store}.')
    print('Relancez une collecte : les connexions SSH devraient aboutir.')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('host', nargs='?', help='Cle, hostname ou IP figurant dans hosts.yaml')
    parser.add_argument('--tous', action='store_true', help='Collecter les empreintes de tout l inventaire')
    parser.add_argument('--limite', type=int, default=0, help='Limiter le nombre de serveurs traites (essai)')
    parser.add_argument('--oui', action='store_true',
                        help='Confirmation donnee en ligne de commande, apres relecture des empreintes. '
                             'Equivaut a repondre OUI : a n employer qu en connaissance de cause.')
    args = parser.parse_args()
    if not args.host and not args.tous:
        parser.error('Indiquer un serveur, ou --tous pour traiter l inventaire complet.')
    from config import load_config, candidates
    base = Path(__file__).resolve().parent
    cfg, hosts = load_config(str(base / 'hosts.yaml'))
    if args.tous:
        return enregistrer_en_lot(cfg, hosts, candidates, base, args.limite, args.oui)
    matches = [h for h in hosts if args.host in (h['key'], h['name'], h['ip'])]
    if len(matches) != 1:
        print('Serveur absent ou ambigu dans hosts.yaml. Rien enregistre.')
        return 2
    host = matches[0]
    # Même magasin que la plateforme, y compris avec COCKPIT_SSH_DIR (audit SSH-06).
    from host_access import known_hosts_path
    store = known_hosts_path(base)
    store.parent.mkdir(parents=True, exist_ok=True)
    existing = store.read_text(encoding='utf-8') if store.is_file() else ''
    for candidate in candidates(cfg, host):
        print(f"\nTentative : {candidate.user}@{host['ip']} port {candidate.port}"
              + (f" via {candidate.target}" if candidate.target else ''))
        lines = capture_key(host['ip'], candidate, cfg.timeout + 10)
        new_lines = [l for l in lines.splitlines() if l.strip() and l.strip() not in existing]
        if not new_lines:
            print('Aucune nouvelle empreinte capturee (deja connue, ou serveur/bastion injoignable).')
            continue
        with tempfile.NamedTemporaryFile('w', suffix='.tmp', delete=False, encoding='utf-8') as f:
            f.write('\n'.join(new_lines) + '\n')
            scratch_path = f.name
        try:
            fp = subprocess.run(['ssh-keygen', '-l', '-f', scratch_path], capture_output=True, text=True, timeout=5)
            print('Empreinte(s) presentee(s) :')
            print(fp.stdout.strip() or '(lecture impossible)')
        finally:
            Path(scratch_path).unlink(missing_ok=True)
        print('\nVerifiez cette empreinte aupres d\'une source de confiance (console du serveur,')
        print('CMDB, administrateur qui la connait deja) AVANT de continuer.')
        reply = input(f"Enregistrer cette empreinte pour {host['name']} ({host['ip']}) dans data/known_hosts ? [oui/NON] ")
        if reply.strip().lower() not in ('oui', 'o', 'yes', 'y'):
            print('Non enregistre.')
            continue
        with store.open('a', encoding='utf-8') as f:
            f.write('\n'.join(new_lines) + '\n')
        existing += '\n'.join(new_lines)
        print(f"Empreinte enregistree dans {store}.")
        return 0
    print('\nAucune empreinte enregistree pour ce serveur.')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
