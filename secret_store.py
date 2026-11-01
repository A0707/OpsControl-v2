"""Chargement des identifiants API depuis le coffre Windows (DPAPI).

Pourquoi ce module existe
-------------------------
Les secrets ne vivent que dans l'environnement du processus : c'est le principe
de la plateforme, et il est bon. Mais il avait une conséquence non voulue :
démarrer le serveur autrement que par LANCER-INFRAOPS.ps1 — un `uvicorn app:app`
tapé à la main, une configuration PyCharm, un service — donnait une instance
sans aucun secret, où les cinq collectes API échouaient avec des messages
techniques sans rapport apparent entre eux. Constaté trois fois en exploitation.

Le lanceur chiffre déjà les secrets avec DPAPI sous le compte Windows courant.
Ce module lit ce même coffre au démarrage. Aucun secret nouveau n'est exposé :
tout processus tournant sous ce compte pouvait déjà les déchiffrer, le lanceur
compris. On supprime seulement l'obligation de passer par un script précis.

Règle de précédence : une variable déjà définie dans l'environnement n'est
JAMAIS écrasée. Le lanceur, une variable posée à la main ou un secret de test
gardent la priorité sur le coffre.
"""
from __future__ import annotations

import ctypes
import os
import re
from pathlib import Path

try:  # ctypes.wintypes lève ValueError hors Windows sous Python < 3.12 (VM Debian 12).
    from ctypes import wintypes
except (ImportError, ValueError):
    wintypes = None

# Emplacement écrit par InfraOps-Secrets.ps1.
DOSSIER = Path(os.environ.get('LOCALAPPDATA', '')) / 'InfraOps' / 'credentials'
SUFFIXE = '.dpapi'


class _Blob(ctypes.Structure):
    _fields_ = [('cbData', wintypes.DWORD if wintypes else ctypes.c_uint32), ('pbData', ctypes.POINTER(ctypes.c_char))]


def _dechiffrer(donnees: bytes) -> str | None:
    """Déchiffre un blob DPAPI protégé pour l'utilisateur courant.

    Renvoie None si le blob n'appartient pas à ce compte ou est illisible :
    un coffre inaccessible n'est pas une erreur fatale, la plateforme démarre
    et le dira source par source.
    """
    entree = _Blob(len(donnees), ctypes.cast(ctypes.create_string_buffer(donnees), ctypes.POINTER(ctypes.c_char)))
    sortie = _Blob()
    crypt = ctypes.windll.crypt32.CryptUnprotectData
    crypt.restype = wintypes.BOOL
    if not crypt(ctypes.byref(entree), None, None, None, None, 0, ctypes.byref(sortie)):
        return None
    try:
        brut = ctypes.string_at(sortie.pbData, sortie.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(sortie.pbData)
    # ConvertFrom-SecureString chiffre la représentation UTF-16LE de la chaîne.
    try:
        return brut.decode('utf-16-le')
    except UnicodeDecodeError:
        return None


# Dernier chargement : noms et raison uniquement, jamais de valeur. Sert au diagnostic.
ETAT = {'disponible': False, 'raison': 'Coffre non lu', 'charges': []}
NOM_VALIDE = re.compile(r'^[A-Z_][A-Z0-9_]{0,127}$')


def _indisponible(raison: str) -> list[str]:
    ETAT.update(disponible=False, raison=raison, charges=[])
    return []


def charger(dossier: Path | None = None) -> list[str]:
    """Pose dans l'environnement les secrets absents. Renvoie les noms chargés.

    Ne renvoie et ne journalise que des NOMS de variables, jamais de valeurs.
    Un coffre absent, illisible ou refusé (PermissionError, OSError) est un coffre
    INDISPONIBLE : l'application démarre quand même et le signale source par source.
    Rien ici ne doit lever : ce module est appelé à l'import d'app.py.
    """
    if os.name != 'nt':
        return _indisponible('Coffre DPAPI propre à Windows')
    base = Path(dossier) if dossier else DOSSIER
    try:
        if not base.is_dir():
            return _indisponible('Coffre absent')
        fichiers = sorted(base.glob('*' + SUFFIXE))
    except OSError as exc:  # PermissionError inclus : dossier refusé au compte courant
        return _indisponible('Coffre inaccessible (' + type(exc).__name__ + ')')
    charges = []
    for fichier in fichiers:
        nom = fichier.name[: -len(SUFFIXE)]
        if not NOM_VALIDE.match(nom):
            continue
        # Précédence : ce qui est déjà défini gagne.
        if os.environ.get(nom):
            continue
        try:
            valeur = _dechiffrer(bytes.fromhex(fichier.read_text(encoding='utf-8').strip()))
        except (OSError, ValueError, AttributeError, ctypes.ArgumentError):
            valeur = None
        if not valeur or not valeur.strip():
            continue
        os.environ[nom] = valeur
        charges.append(nom)
    ETAT.update(disponible=True, raison=None, charges=list(charges))
    return charges
