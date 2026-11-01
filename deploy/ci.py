"""Contrôle qualité local d'OpsControl (en attendant un dépôt distant et sa CI).

    python deploy/ci.py                  # tout : tests, bandit, secrets, dépendances (en ligne)
    python deploy/ci.py --offline        # sans pip-audit (aucun accès réseau)
    python deploy/ci.py --quick          # crochet pre-commit : secrets + syntaxe et Ruff des fichiers indexés
    python deploy/ci.py --update-baseline    # après revue : accepter les détections actuelles
    python deploy/ci.py --install-hook   # installe .git/hooks/pre-commit (appelle --quick)

Étapes et seuils (un échec = code de sortie 1) :
1. tests      unittest discover (API et SSH simulés, bases temporaires : aucun accès au parc)
2. bandit     analyse statique ; bloque sur gravité HIGH, ou MEDIUM avec confiance HIGH.
              Une exception voulue se justifie dans le code par « # nosec Bxxx » et un commentaire.
3. secrets    detect-secrets sur les fichiers suivis par Git ; bloque sur toute détection
              absente de .secrets.baseline (faux positifs revus : UUID Zabbix, jetons de test).
4. ruff       fichiers Python nouveaux/modifiés seulement : E9/F bloquants, style informatif.
5. pip-audit  vulnérabilités connues des dépendances de requirements.txt (base OSV en ligne).

Aucun outil n'est installé par ce script : bandit, detect-secrets et pip-audit sont
déjà dans .venv, ainsi que ruff (requirements-dev.txt). Aucune correction automatique.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
BASELINE = BASE / '.secrets.baseline'
BIN = Path(sys.executable).parent
SKIP_SUFFIXES = ('.png', '.jpg', '.mp4', '.webm', '.ico')
# Identifiants de modèles Zabbix (« uuid: » + 32 hexadécimaux), pas des secrets. Motif
# volontairement simple : detect-secrets n'appliquait pas une classe [0-9a-f]{32} (constaté).
EXCLUDE_LINES = r'\buuid: '


def tool(name):
    for candidate in (BIN / name, BIN / (name + '.exe')):
        if candidate.exists():
            return str(candidate)
    return name


def git_files(staged=False):
    # Hors pre-commit : fichiers suivis ET nouveaux fichiers non ignorés (pas encore ajoutés).
    args = (['git', 'diff', '--cached', '--name-only', '--diff-filter=ACM'] if staged
            else ['git', 'ls-files', '--cached', '--others', '--exclude-standard'])
    out = subprocess.run(args, cwd=BASE, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True).stdout
    return [f for f in out.splitlines() if f and not f.endswith(SKIP_SUFFIXES) and f != BASELINE.name
            and (BASE / f).is_file()]


def step(title):
    print(f'\n== {title}', flush=True)


def changed_python_files(staged=False):
    """En CI, comparer au commit de base ; localement, comparer le travail à HEAD."""
    base = os.environ.get('INFRAOPS_RUFF_BASE', '').strip() if not staged else ''
    if base:
        if not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}', base):
            raise ValueError('INFRAOPS_RUFF_BASE doit être un SHA de commit Git')
        if set(base) == {'0'}:
            # Premier push : tous les fichiers suivis sont nouveaux.
            commands = [['git', 'ls-files', '-z']]
        else:
            commands = [['git', 'diff', '--name-only', '--diff-filter=ACMR', '-z', base, 'HEAD', '--']]
    elif staged:
        commands = [['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z', '--']]
    else:
        commands = [['git', 'diff', 'HEAD', '--name-only', '--diff-filter=ACMR', '-z', '--'],
                    ['git', 'ls-files', '--others', '--exclude-standard', '-z']]
    names = set()
    for command in commands:
        done = subprocess.run(command, cwd=BASE, capture_output=True, text=True, encoding='utf-8', errors='replace')
        if done.returncode != 0 and base and command[:3] == ['git', 'diff', '--name-only']:
            # Commit de base absent (force-push, historique réécrit) : on retombe sur le dernier
            # commit plutôt que d'échouer sans rien analyser (audit CI-06).
            print('  Base Ruff introuvable dans l’historique : comparaison avec le commit précédent.')
            command = ['git', 'diff', '--name-only', '--diff-filter=ACMR', '-z', 'HEAD~1', 'HEAD', '--']
            done = subprocess.run(command, cwd=BASE, capture_output=True, text=True, encoding='utf-8', errors='replace')
            if done.returncode != 0:
                # Un historique public neuf n'a pas de parent : analyser tout le code suivi.
                print('  Aucun parent disponible : analyse de tous les fichiers suivis.')
                command = ['git', 'ls-files', '-z']
                done = subprocess.run(command, cwd=BASE, capture_output=True, text=True, encoding='utf-8', errors='replace')
        if done.returncode != 0:
            raise subprocess.CalledProcessError(done.returncode, command, done.stdout, done.stderr)
        names.update(done.stdout.split('\0'))
    excluded = {'release', '.venv', '.graphify-packages'}
    return sorted(name for name in names if name.endswith(('.py', '.pyi'))
                  and not excluded.intersection(Path(name).parts) and (BASE/name).is_file())


def run_ruff(files):
    step('Ruff : E9/F bloquants, style informatif (fichiers nouveaux/modifiés)')
    if not files:
        print('  aucun fichier Python nouveau ou modifié')
        return True
    try:
        command = [tool('ruff'), 'check', '--config', str(BASE/'pyproject.toml'), '--no-fix']
        blocking = subprocess.run(command + ['--select', 'E9,F', '--', *files], cwd=BASE)
        style = subprocess.run(command + ['--select', 'E,W,I', '--ignore', 'E9',
                                          '--exit-zero', '--statistics', '--', *files], cwd=BASE)
    except OSError:
        print('  Ruff indisponible : installer requirements-dev.txt.')
        return False
    return blocking.returncode == 0 and style.returncode == 0


def run_changed_ruff(staged=False):
    try:
        files = changed_python_files(staged)
    except (ValueError, subprocess.CalledProcessError) as error:
        step('Sélection des fichiers Ruff impossible')
        print(f'  {error} ; vérifier INFRAOPS_RUFF_BASE et l’historique Git disponible.')
        return False
    return run_ruff(files)


def run_tests():
    step('Tests unitaires')
    # Ligne d'accès HTTP coupée : sinon chaque requête de test s'affiche en JSON.
    env = {**os.environ, 'INFRAOPS_ACCESS_LOG': '0'}
    return subprocess.run([sys.executable, '-m', 'unittest', 'discover', '-p', 'test_*.py'], cwd=BASE, env=env).returncode == 0


def run_bandit():
    step('Bandit (analyse statique)')
    files = [f for f in git_files() if f.endswith('.py') and not Path(f).name.startswith('test_')]
    try:
        run = subprocess.run([tool('bandit'), '-q', '-f', 'json', *files], cwd=BASE, capture_output=True, text=True,
                             encoding='utf-8', errors='replace')
    except OSError:
        return unavailable('Bandit')
    # Un échec de l'outil n'est jamais « aucun constat » : une sortie vide devenait {} et
    # validait la chaîne (audit A4, 15/10). Codes de Bandit : 0 sans constat, 1 avec constats.
    try:
        report = json.loads(run.stdout) if run.returncode in (0, 1) else None
    except ValueError:
        report = None
    if not isinstance(report, dict) or not isinstance(report.get('results'), list):
        detail = (run.stderr or run.stdout or '').strip().splitlines()[-1:] or ['sortie vide']
        print(f'  ÉCHEC de Bandit (code {run.returncode}) : {detail[0][:200]}')
        return False
    if report.get('errors'):
        # Analyse partielle : un fichier non analysé peut cacher un constat bloquant.
        for e in report['errors'][:10]:
            print(f"  NON ANALYSÉ {e.get('filename')} : {str(e.get('reason'))[:200]}")
        print(f"  Analyse partielle : {len(report['errors'])} fichier(s) non analysé(s)")
        return False
    results = report['results']
    blocking = [r for r in results if r['issue_severity'] == 'HIGH'
                or (r['issue_severity'] == 'MEDIUM' and r['issue_confidence'] == 'HIGH')]
    for r in blocking:
        print(f"  BLOQUANT {r['test_id']} {r['filename']}:{r['line_number']} {r['issue_text']}")
    print(f'  {len(results)} constat(s), dont {len(blocking)} bloquant(s)')
    return not blocking


def secret_scan(files):
    out = subprocess.run([tool('detect-secrets'), 'scan', '--exclude-lines=' + EXCLUDE_LINES, *files],
                         cwd=BASE, capture_output=True, text=True, encoding='utf-8', errors='replace', check=True).stdout
    return json.loads(out)


def fingerprints(scan):
    return {(f.replace('\\', '/'), s['type'], s['hashed_secret']) for f, items in scan['results'].items() for s in items}


def run_secrets(files):
    step('Secrets (detect-secrets)')
    if not files:
        print('  aucun fichier')
        return True
    known = fingerprints(json.loads(BASELINE.read_text(encoding='utf-8'))) if BASELINE.is_file() else set()
    try:
        found = secret_scan(files)
    except OSError:
        return unavailable('detect-secrets')
    new = sorted(fingerprints(found) - known)
    lines = {(f.replace('\\', '/'), s['type'], s['hashed_secret']): s['line_number']
             for f, items in found['results'].items() for s in items}
    for f, kind, digest in new:
        print(f'  NOUVEAU {f}:{lines[f, kind, digest]} {kind}')  # jamais la valeur
    print(f'  {len(new)} nouvelle(s) détection(s) hors référence')
    return not new


def run_assets():
    step('Versions des fichiers web (?v= = empreinte du contenu)')
    return subprocess.run([sys.executable, str(BASE / 'deploy/assets_version.py'), '--check'], cwd=BASE).returncode == 0


def run_pip_audit():
    step('Dépendances (pip-audit, en ligne)')
    try:
        return subprocess.run([tool('pip-audit'), '-r', 'requirements.txt', '--progress-spinner', 'off'],
                              cwd=BASE).returncode == 0
    except OSError:
        return unavailable('pip-audit')


def unavailable(name):
    # Échec explicite plutôt qu'une trace Python : le plus souvent, ci.py a été lancé avec
    # un autre interpréteur que celui du projet (audit CI-02).
    print(f'  {name} indisponible : installer requirements-dev.txt, ou lancer ci.py avec le Python de .venv.')
    return False


def interpreter_note():
    venv = (BASE / '.venv').resolve()
    if venv.is_dir() and venv not in Path(sys.executable).resolve().parents:
        print(f'Note : ci.py tourne avec {sys.executable}, pas avec le Python de .venv ; '
              'les outils absents de cet interpréteur feront échouer la validation.')


def run_syntax(files):
    step('Syntaxe Python des fichiers indexés')
    py = [f for f in files if f.endswith('.py')]
    if not py:
        return True
    return subprocess.run([sys.executable, '-m', 'py_compile', *py], cwd=BASE).returncode == 0


# Recette sur une instance réelle (http://127.0.0.1:8001, données du parc) : hors CI tant
# qu'elles ne sont pas réécrites sur des données simulées (audit TST-03).
UI_LIVE = {'test_ui.cjs', 'test_ui_proxmox.cjs'}
UI_TIMEOUT = 240


def run_ui():
    """Tests navigateur sur données simulées (requêtes interceptées, aucune instance réelle).

    Jusqu'ici exécutés seulement à la main (audit CI-03). Prérequis : Node.js et Playwright
    (data/browser-test ou OPS_PLAYWRIGHT_PATH) ; OPS_BROWSER_CHANNEL=msedge utilise le
    navigateur installé si le Chromium de Playwright n'est pas téléchargé."""
    step('Tests navigateur (données simulées)')
    tests = sorted(p.name for p in BASE.glob('test_ui*.cjs') if p.name not in UI_LIVE)
    failed = []
    for name in tests:
        try:
            done = subprocess.run(['node', name], cwd=BASE, capture_output=True, text=True,
                                  encoding='utf-8', errors='replace', timeout=UI_TIMEOUT)
        except OSError:
            return unavailable('Node.js')
        except subprocess.TimeoutExpired:
            failed.append(name + ' (délai dépassé)')
            continue
        if done.returncode != 0:
            last = (done.stderr or done.stdout).strip().splitlines()
            failed.append(name + ' : ' + (last[0][:200] if last else f'code {done.returncode}'))
    for line in failed:
        print('  ÉCHEC', line)
    print(f'  {len(tests) - len(failed)}/{len(tests)} réussi(s) ; hors CI (instance réelle) : ' + ', '.join(sorted(UI_LIVE)))
    return not failed


def install_hook():
    hook = BASE / '.git/hooks/pre-commit'
    python = Path(sys.executable).resolve().as_posix()
    hook.write_text('#!/bin/sh\n# Installé par deploy/ci.py --install-hook\n'
                    f'exec "{python}" deploy/ci.py --quick\n', encoding='utf-8', newline='\n')
    os.chmod(hook, 0o755)  # nosec B103 — un crochet Git doit être exécutable ; aucun secret dedans
    print('Crochet installé :', hook)


def main(argv=None):
    a = argparse.ArgumentParser(description='Contrôle qualité local OpsControl')
    a.add_argument('--offline', action='store_true')
    a.add_argument('--quick', action='store_true')
    a.add_argument('--update-baseline', action='store_true')
    a.add_argument('--install-hook', action='store_true')
    a.add_argument('--ui', action='store_true', help='ajoute les tests navigateur sur données simulées')
    args = a.parse_args(argv)
    interpreter_note()
    if args.install_hook:
        install_hook()
        return 0
    if args.update_baseline:
        BASELINE.write_text(json.dumps(secret_scan(git_files()), indent=2) + '\n', encoding='utf-8', newline='\n')
        print('Référence mise à jour :', BASELINE.name, '— à relire avant de la valider dans Git')
        return 0
    if args.quick:
        staged = git_files(staged=True)
        ok = run_secrets(staged) and run_syntax(staged) and run_changed_ruff(staged=True)
    else:
        results = [run_tests(), run_bandit(), run_secrets(git_files()), run_assets(),
                   run_changed_ruff()]
        if args.ui:
            results.append(run_ui())
        if not args.offline:
            results.append(run_pip_audit())
        ok = all(results)
    print('\nRÉSULTAT :', 'OK' if ok else 'ÉCHEC')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
