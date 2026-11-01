"""Lancement des outils locaux de test, sans connexion au parc supervisé."""
import os
import shutil
import subprocess
from functools import lru_cache

WINDOWS = os.name == 'nt'
WARMUP_TIMEOUT = 180
WINDOWS_TIMEOUT = 30
_states = {}


def _skip(test, key, reason):
    # Un outil bloqué ne doit pas ralentir chacun des tests suivants de la suite.
    _states[key] = reason
    test.skipTest(reason)


def _warm_up(test, executable, kind):
    key = os.path.normcase(os.path.abspath(executable))
    if key in _states:
        if _states[key]:
            test.skipTest(_states[key])
        return
    probe = [executable, '-V'] if kind == 'ssh' else [executable, '-c', 'exit 0']
    for timeout in (WARMUP_TIMEOUT, WINDOWS_TIMEOUT):
        try:
            result = subprocess.run(probe, stdin=subprocess.DEVNULL, capture_output=True,
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            if timeout == WARMUP_TIMEOUT:
                continue
            _skip(test, key, f'{kind} indisponible sous Windows : lancement à blanc sans '
                  f'réponse après {WARMUP_TIMEOUT} s puis {WINDOWS_TIMEOUT} s.')
        except OSError as error:
            _skip(test, key, f'{kind} indisponible sous Windows : lancement à blanc '
                  f'impossible ({type(error).__name__}).')
        else:
            if result.returncode:
                _skip(test, key, f'{kind} indisponible sous Windows : lancement à blanc '
                      f'refusé (code {result.returncode}).')
            _states[key] = None
            return


@lru_cache(maxsize=2)
def _linux_shell_available(executable):
    # Conserver la vérification courte qui existait déjà pour les shells Linux.
    try:
        result = subprocess.run([executable, '-c', 'exit 0'], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def shell_path(test, name='bash'):
    executable = shutil.which(name)
    if not executable:
        test.skipTest(f'{name} absent du PATH.')
    if WINDOWS:
        _warm_up(test, executable, name)
    elif not _linux_shell_available(executable):
        test.skipTest(f'{name} absent ou inutilisable.')
    return executable


def run_tool(test, args, *, kind, timeout=None, **kwargs):
    """Sous Linux, transmettre l’appel original ; sous Windows, chauffer puis borner."""
    if not WINDOWS:
        return subprocess.run(args, timeout=timeout, **kwargs)
    executable = os.fspath(args[0])
    key = os.path.normcase(os.path.abspath(executable))
    _warm_up(test, executable, kind)
    limit = max(timeout or 0, WINDOWS_TIMEOUT)
    try:
        return subprocess.run(args, timeout=limit, **kwargs)
    except subprocess.TimeoutExpired:
        _skip(test, key, f'{kind} indisponible sous Windows : commande de test sans réponse '
              f'après {limit} s malgré le lancement à blanc.')
    except OSError as error:
        _skip(test, key, f'{kind} indisponible sous Windows : commande de test impossible '
              f'({type(error).__name__}).')
