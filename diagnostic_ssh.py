"""Diagnostic read-only, one inventory host. Never prints private key contents."""
import argparse
import getpass
import json
import os
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='Diagnostic SSH InfraOps, un serveur uniquement')
    parser.add_argument('host', help='Clé, hostname ou IP figurant dans hosts.yaml')
    args = parser.parse_args()
    from config import load_config, candidates
    from ssh import run_operation, AUDIT_PATH
    from ssh import native_args
    import subprocess
    base = Path(__file__).resolve().parent
    cfg, hosts = load_config(str(base / 'hosts.yaml'))
    matches = [h for h in hosts if args.host in (h['key'], h['name'], h['ip'])]
    if len(matches) != 1:
        print('Serveur absent ou ambigu dans hosts.yaml. Aucun essai effectué.')
        return 2
    host = matches[0]
    print('Compte local :', getpass.getuser())
    print('Dossier utilisateur :', Path.home())
    print('Inventaire :', base / 'hosts.yaml')
    print('known_hosts par défaut :', Path.home() / '.ssh' / 'known_hosts')
    try:
        known = (Path.home() / '.ssh' / 'known_hosts').is_file()
    except OSError:
        known = 'Vérification impossible (permissions)'
    print('known_hosts présent :', known)
    print('Journal :', AUDIT_PATH.resolve())
    print('Serveur :', host['name'], host['ip'])
    print('Transport :', cfg.transport)
    print('Lecture seule : opération os, sans modification du serveur.')
    success = False
    for selected in candidates(cfg, host):
        path = Path(os.path.expanduser(selected.key_path)).resolve()
        print('\nTentative :', selected.user, 'port', selected.port)
        print('Chemin de clé privée :', path)
        if cfg.transport == 'openssh':
            try:
                argv = native_args(host['ip'], selected)
                effective = subprocess.run([argv[0], '-G'] + argv[1:], capture_output=True, text=True, timeout=10)
                if effective.returncode:
                    print('Erreur lecture configuration OpenSSH :', effective.stderr)
                for line in effective.stdout.splitlines():
                    if line.split(' ',1)[0] in ('hostname','user','port','proxyjump','identityfile','userknownhostsfile'):
                        print('Configuration effective :', line)
                    elif line.startswith('proxycommand '):
                        print('Configuration effective : ProxyCommand présent (contenu masqué)')
            except Exception:
                effective = None
        try:
            with path.open('rb'):
                pass
        except OSError as exc:
            print('CLÉ INACCESSIBLE :', str(exc))
            continue
        try:
            result = run_operation(host['ip'], 'os', selected, 'diagnostic:' + getpass.getuser())
        except Exception as exc:
            print('ERREUR LOCALE / AUDIT :', str(exc))
            continue
        print(json.dumps({'ok': result.ok, 'rc': result.rc, 'type': result.error_kind,
                          'erreur': result.stderr, 'duree_ms': result.duration_ms}, ensure_ascii=False))
        if result.rc is not None:
            print('CONNEXION SSH ÉTABLIE :', selected.user, 'port', selected.port)
            success = True
            break
    if not success:
        print('\nAucune connexion établie. Copier ce rapport pour identifier la cause.')
    return 0 if success else 1

if __name__ == '__main__':
    raise SystemExit(main())
