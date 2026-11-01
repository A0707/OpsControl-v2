"""Contrôle de démarrage d'InfraOps sur la VM — à lancer AVANT le service.

    sudo -u infraops /opt/infraops/current/.venv/bin/python /opt/infraops/current/deploy/preflight.py

Répond à une question : « si je démarre le service maintenant, qu'est-ce qui
marchera et qu'est-ce qui ne marchera pas ? ». Rien n'est modifié :
- réseau : connexion TCP au port SSH de chaque serveur (sans session), puis aux
  API configurées ;
- SSH : une vraie opération en lecture (« uptime ») sur les serveurs critiques,
  par le même chemin qu'InfraOps (clé, empreintes, configuration) ;
- secrets : présence des variables, jamais leur valeur.
"""
from __future__ import annotations

import os
import sqlite3
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
SECRETS = Path(os.environ.get('INFRAOPS_SECRETS', '/etc/infraops/secrets.env'))
resultats = []


def verdict(ok, titre, detail=''):
    resultats.append(ok)
    marque = {True: 'OK  ', False: 'KO  ', None: 'INFO'}[ok]
    print(f'[{marque}] {titre}' + (f' — {detail}' if detail else ''))


def syntax_errors(fichiers):
    """Erreurs de syntaxe des modules, sans rien écrire sur disque.

    compile() en mémoire plutôt que py_compile : sous Linux, py_compile refuse
    cfile=/dev/null (fichier non régulier, FileExistsError) et bloquait toute release.
    """
    erreurs = []
    for fichier in fichiers:
        try:
            compile(Path(fichier).read_bytes(), str(fichier), 'exec', dont_inherit=True)
        except SyntaxError as e:
            erreurs.append(f'{Path(fichier).name}: ligne {e.lineno} : {e.msg}'[:160])
        except (OSError, ValueError) as e:  # illisible, octet nul : refusé aussi
            erreurs.append(f'{Path(fichier).name}: {type(e).__name__} : {e}'[:160])
    return erreurs


def release_check(base=BASE):
    """Contrôle du CODE d'une release, avant bascule. Indépendant du réseau et des secrets.

    Utilisé par install-vm.sh : un échec interdit la bascule de `current`. La base
    réelle n'est pas ouverte en écriture : l'import se fait sur une copie temporaire.
    """
    import re
    import tempfile
    print('== Release', base)
    verdict(sys.version_info >= (3, 11), 'Python', sys.version.split()[0])
    try:
        import fastapi, uvicorn, yaml  # noqa: F401
        verdict(True, 'Dépendances', 'fastapi, uvicorn, PyYAML')
    except ImportError as e:
        verdict(False, 'Dépendances', str(e))
        return 1
    erreurs = syntax_errors(sorted([*Path(base).glob('*.py'), *Path(base).glob('routers/*.py')]))
    verdict(not erreurs, 'Syntaxe Python', '; '.join(erreurs[:3]) or 'tous les modules compilent')
    index = Path(base) / 'web/index.html'
    manquants = [s for s in re.findall(r'(?:src|href)="/([^"?]+)', index.read_text(encoding='utf-8'))
                 if not (Path(base) / 'web' / s).is_file()] if index.is_file() else ['web/index.html']
    verdict(not manquants, 'Fichiers de l’interface', ', '.join(manquants[:5]) or 'tous présents')
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        copie = Path(tmp) / 'state.sqlite3'
        reelle = Path(base) / 'data/state.sqlite3'
        if reelle.is_file():
            source = sqlite3.connect(f'file:{reelle}?mode=ro', uri=True)
            cible = sqlite3.connect(copie)
            source.backup(cible)
            source.close()
            cible.close()
        os.environ['COCKPIT_DB'] = str(copie)
        os.environ.setdefault('COCKPIT_AUDIT', str(Path(tmp) / 'audit.log'))
        # Contrôle de code : aucun travail de fond (rapprochement d'incidents) sur la copie.
        os.environ['INFRAOPS_INCIDENT_SYNC'] = '0'
        try:
            import app
            from routers import all_routes  # routes des routeurs inclus comprises
            routes = {getattr(r, 'path', '') for r in all_routes(app.app)}
            verdict('/api/health' in routes and '/api/overview' in routes, 'Import de l’application',
                    f'{len(app.HOSTS)} serveur(s) en inventaire, /api/health présent')
        except Exception as e:  # noqa: BLE001 — tout échec d'import interdit la bascule
            verdict(False, 'Import de l’application', type(e).__name__ + ' : ' + str(e)[:200])
    echecs = resultats.count(False)
    print(f'\n{echecs} point(s) bloquant(s) : bascule refusée.' if echecs else '\nRelease valide.')
    return 1 if echecs else 0


def main():
    if '--release-check' in sys.argv:
        return release_check()
    print('== Système')
    verdict(sys.version_info >= (3, 11), 'Python', sys.version.split()[0])
    try:
        import fastapi, uvicorn, yaml  # noqa: F401
        verdict(True, 'Dépendances', 'fastapi, uvicorn, PyYAML')
    except ImportError as e:
        verdict(False, 'Dépendances', str(e))
        return 1
    import shutil
    verdict(bool(shutil.which('ssh')), 'Client OpenSSH', shutil.which('ssh') or 'introuvable : apt install openssh-client')

    print('== Données')
    try:
        db = sqlite3.connect(f'file:{BASE / "data/state.sqlite3"}?mode=ro', uri=True)
        n = db.execute('SELECT count(*) FROM states').fetchone()[0]
        verdict(n > 0, 'Base d’état reprise', f'{n} serveur(s) avec audit')
    except sqlite3.Error as e:
        verdict(False, 'Base d’état', str(e))
    verdict(os.access(BASE / 'data', os.W_OK) and os.access(BASE, os.W_OK), 'Écriture data/ et inventaire',
            'compte ' + __import__('getpass').getuser())

    import app  # charge l'inventaire et la configuration exactement comme le service
    cfg, hosts = app.cfg, app.HOSTS
    cle = Path(os.path.expanduser(os.environ.get('COCKPIT_SSH_KEY', '/opt/infraops/.ssh/id_ed25519')))
    print('== SSH')
    if cle.is_file():
        droits = stat.S_IMODE(cle.stat().st_mode)
        verdict(droits & 0o077 == 0, 'Clé du service', f'{cle} (droits {oct(droits)})')
    else:
        verdict(False, 'Clé du service', f'{cle} absente')
    for fichier in (BASE / 'data/known_hosts', Path.home() / '.ssh/known_hosts'):
        lignes = sum(1 for l in fichier.read_text().splitlines() if l.strip() and not l.startswith('#')) if fichier.is_file() else 0
        verdict(lignes > 0 or None, 'Empreintes ' + str(fichier), f'{lignes} entrée(s)')

    print('== Secrets (noms seulement)')
    presents = {}
    if SECRETS.is_file() and os.access(SECRETS, os.R_OK):
        for ligne in SECRETS.read_text(encoding='utf-8').splitlines():
            nom, sep, valeur = ligne.partition('=')
            if sep and not nom.startswith('#'):
                presents[nom.strip()] = bool(valeur.strip().strip('"'))
    else:
        verdict(False, 'Fichier de secrets', f'{SECRETS} absent ou illisible par ce compte')
    for c in app.api_connections():
        if c.get('token_env'):
            verdict(presents.get(c['token_env'], False), f"{c['provider']} ({c['token_env']})",
                    'renseigné' if presents.get(c['token_env']) else 'VIDE : sudo python3 deploy/secrets_env.py')
    verdict(presents.get('INFRAOPS_WEBHOOK_TOKEN') or None, 'Jeton webhook Zabbix',
            'renseigné' if presents.get('INFRAOPS_WEBHOOK_TOKEN') else 'absent : webhook fermé (503)')

    print('== Réseau depuis la VM (TCP, sans session)')
    from ssh import tcp_reachable
    actifs = [h for h in hosts if h.get('collect_enabled', True)]
    with ThreadPoolExecutor(max_workers=16) as pool:
        joignables = list(pool.map(lambda h: tcp_reachable(h['ip'], int(h.get('port') or cfg.port), 3.0)[0], actifs))
    muets = [h['name'] for h, ok in zip(actifs, joignables) if not ok]
    verdict(not muets or None, 'Port SSH des serveurs', f'{len(actifs) - len(muets)}/{len(actifs)} joignables'
            + (f' ; muets : {", ".join(muets[:12])}' + (' …' if len(muets) > 12 else '') if muets else ''))
    for c in app.api_connections():
        u = urlsplit(c.get('url', ''))
        if u.hostname in ('127.0.0.1', 'localhost'):
            verdict(None, f"API {c['name']}", 'par tunnel local (Bacula) : ouvert par le service au démarrage')
            continue
        port = u.port or (443 if u.scheme == 'https' else 80)
        verdict(tcp_reachable(u.hostname, port, 4.0)[0] if u.hostname else False, f"API {c['name']}", f'{u.hostname}:{port}')

    print('== Opération SSH réelle sur les serveurs critiques (lecture : uptime)')
    import ssh
    from config import candidates
    for h in [h for h in actifs if h.get('criticality') == 'critical'][:5]:
        dernier = None
        for candidat in candidates(cfg, h):
            dernier = ssh.run_operation(h['ip'], 'uptime', candidat, 'preflight-vm')
            if dernier.ok or dernier.error_kind != 'auth':
                break
        cause = {'auth': 'clé du service non autorisée pour ce compte', 'host_key': 'empreinte inconnue ou différente',
                 'network': 'serveur injoignable'}.get(getattr(dernier, 'error_kind', ''), getattr(dernier, 'error_kind', ''))
        verdict(bool(dernier and dernier.ok), h['name'], 'audit possible' if dernier and dernier.ok else cause)

    echecs = resultats.count(False)
    print(f'\n{echecs} point(s) bloquant(s).' if echecs else '\nPrêt : sudo systemctl restart infraops')
    return 1 if echecs else 0


if __name__ == '__main__':
    sys.exit(main())
