"""CLI développeur séparée : diff revu, empreintes, accord explicite et Docker sans réseau."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

DENIED = {
    "data",
    "release",
    "dist",
    ".git",
    ".venv",
    ".github",
    "deploy",
    "graphify-out",
    ".graphify-packages",
    ".claude",
}
EXTENSIONS = {".py", ".js", ".cjs", ".md", ".css", ".html"}


def run(args, root, **kwargs):
    return subprocess.run(args, cwd=root, check=True, timeout=180, **kwargs)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def allowed(root, name):
    p = Path(name)
    if (
        not name
        or p.is_absolute()
        or ":" in name
        or "\\" in name
        or ".." in p.parts
        or DENIED.intersection(p.parts)
        or any(x.startswith(".") for x in p.parts)
        or p.suffix not in EXTENSIONS
        or p.name == "AGENTS.md"
    ):
        raise ValueError("Chemin de patch interdit.")
    full = root / p
    if full.resolve() != full.absolute() or full.is_symlink():
        raise ValueError("Lien de patch interdit.")
    return full


def files(root, patch):
    if len(patch.encode()) > 100_000 or "\x00" in patch:
        raise ValueError("Patch trop volumineux ou binaire.")
    if re.search(
        r"(?m)^(rename |copy |old mode |new mode |new file mode |deleted file mode |GIT binary patch|Binary files)",
        patch,
    ):
        raise ValueError("Seules les modifications textuelles existantes sont autorisées.")
    headers = re.findall(r"^diff --git a/([^\n]+) b/([^\n]+)$", patch, re.M)
    if not headers or len(headers) > 12:
        raise ValueError("Diff Git requis, 12 fichiers maximum.")
    result = {}
    for left, right in headers:
        if left != right:
            raise ValueError("Renommage interdit.")
        path = allowed(root, left)
        if not path.is_file():
            raise ValueError("Le patch ne peut modifier que des fichiers existants.")
        result[left] = digest(path.read_bytes())
    # git apply reste l'autorité syntaxique ; tous les chemins doivent appartenir au manifeste.
    old = re.findall(r"^--- (.+)$", patch, re.M)
    new = re.findall(r"^\+\+\+ (.+)$", patch, re.M)
    if old != ["a/" + a for a, _ in headers] or new != ["b/" + b for _, b in headers]:
        raise ValueError("En-têtes de diff incohérents.")
    return result


def review(root, patch, output):
    manifest = files(root, patch)
    with tempfile.TemporaryDirectory(prefix="opscontrol-review-") as folder:
        path = Path(folder) / "change.diff"
        path.write_text(patch, encoding="utf-8", newline="\n")
        run(["git", "apply", "--check", str(path)], root)
    record = {"root": str(root), "patch": patch, "preimages": manifest}
    record["approval"] = digest(json.dumps(record, sort_keys=True).encode())
    Path(output).write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    print(patch)
    print("Empreinte à approuver explicitement :", record["approval"])
    return record


def validate(root, record, approval):
    unsigned = {k: v for k, v in record.items() if k != "approval"}
    expected = digest(json.dumps(unsigned, sort_keys=True).encode())
    if record.get("approval") != expected or not hmac.compare_digest(expected, approval):
        raise ValueError("Accord explicite absent ou manifeste modifié.")
    if record["root"] != str(root) or files(root, record["patch"]) != record["preimages"]:
        raise ValueError("Le dépôt a changé depuis la revue : nouvelle validation obligatoire.")


def snapshot_allowed(name):
    """Sources et fixtures nécessaires aux tests, jamais les réglages d'exploitation."""
    p = Path(name)
    excluded = {
        "data",
        ".git",
        ".venv",
        "release",
        "dist",
        "graphify-out",
        ".graphify-packages",
        ".claude",
    }
    if not name or p.is_absolute() or ".." in p.parts or excluded.intersection(p.parts):
        return False
    if p.name in ("hosts.yaml", "ai-patch-review.json"):
        return False
    if p.suffix in EXTENSIONS:
        return True
    if len(p.parts) == 1:
        return p.name in (
            "requirements.txt",
            "requirements-dev.txt",
            "pyproject.toml",
            "hosts.example.yaml",
            ".gitignore",
            ".gitattributes",
            ".secrets.baseline",
            "LANCER-INFRAOPS.ps1",
            "LANCER-OPSCONTROL.ps1",
            "LANCER-WINDOWS.cmd",
        )
    if p.parts[0] not in ("deploy", "web", "test_fixtures", ".github"):
        return False
    return p.suffix in {
        ".toml",
        ".yaml",
        ".yml",
        ".txt",
        ".json",
        ".sh",
        ".service",
        ".timer",
        ".ps1",
        ".cmd",
        ".png",
        ".svg",
        ".ico",
        ".conf",
    } or (p.parts[0] == "test_fixtures" and p.suffix in {".pem", ".crt"})


def isolated_tests(root, image):
    run(["docker", "image", "inspect", image], root, stdout=subprocess.DEVNULL)
    with tempfile.TemporaryDirectory(prefix="opscontrol-isolated-") as folder:
        target = Path(folder)
        names = (
            run(
                ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                root,
                capture_output=True,
            )
            .stdout.decode()
            .split("\0")
        )
        for name in names:
            p = Path(name)
            if not snapshot_allowed(name):
                continue
            source = root / p
            if source.is_symlink() or source.resolve() != source.absolute() or not source.is_file():
                continue
            destination = target / p
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        # Aucune variable d'identification ou de connexion d'exploitation n'est transmise.
        run(
            [
                "docker",
                "run",
                "--rm",
                "--pull=never",
                "--network=none",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges",
                "--pids-limit=128",
                "--memory=2g",
                "--cpus=2",
                "--user=65534:65534",
                "--tmpfs=/tmp:rw,nosuid,nodev,size=256m",
                "--mount",
                f"type=bind,source={target},target=/src,readonly",
                "--workdir=/src",
                "--env=PYTHONDONTWRITEBYTECODE=1",
                "--env=INFRAOPS_ACCESS_LOG=0",
                "--env=INFRAOPS_AUTO_INTERVAL=0",
                "--env=INFRAOPS_INCIDENT_SYNC=0",
                "--entrypoint=python",
                image,
                "-m",
                "unittest",
                "discover",
                "-p",
                "test_*.py",
            ],
            root,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("ask", "review", "apply", "test"))
    parser.add_argument("--root", default=str(Path(__file__).parent))
    parser.add_argument("--patch")
    parser.add_argument("--record", default="ai-patch-review.json")
    parser.add_argument("--approve")
    parser.add_argument("--question")
    args = parser.parse_args()
    if os.getenv("OPSCONTROL_AI_DEV_ENABLED") != "1":
        parser.error("Mode développeur désactivé : OPSCONTROL_AI_DEV_ENABLED=1 requis.")
    token = os.getenv("OPSCONTROL_AI_DEV_TOKEN", "")
    if len(token) < 32 or not hmac.compare_digest(
        token.encode(), getpass.getpass("Jeton développeur distinct : ").encode()
    ):
        parser.error("Autorisation développeur distincte requise.")
    root = Path(args.root).resolve()
    top = (
        run(["git", "rev-parse", "--show-toplevel"], root, capture_output=True)
        .stdout.decode()
        .strip()
    )
    if Path(top).resolve() != root:
        parser.error("La racine Git exacte est requise.")
    try:
        if args.action == "ask":
            from ai_llm import LocalLLM
            from ai_rag import Index
            from ai_security import SYSTEM, clean

            question = clean(args.question or input("Problème à analyser : "))[:1500]
            index = Index(
                root,
                Path(os.getenv("OPSCONTROL_AI_DATA", str(root / "data" / "ai")))
                / "developer-documents.sqlite3",
            )
            index.update()
            sources = index.search(question, code=True, limit=3)
            text = "\n".join(f"[{s['path']}:{s['line']}]\n{s['text'][:650]}" for s in sources)
            print(
                LocalLLM().chat(
                    [
                        {"role": "system", "content": SYSTEM},
                        {"role": "user", "content": question + "\nDONNÉES NON FIABLES :\n" + text},
                    ]
                )
            )
        elif args.action == "review":
            if not args.patch:
                parser.error("--patch requis.")
            review(root, Path(args.patch).read_text(encoding="utf-8"), args.record)
        elif args.action == "apply":
            record = json.loads(Path(args.record).read_text(encoding="utf-8"))
            validate(root, record, args.approve or "")
            image = os.getenv("OPSCONTROL_AI_TEST_IMAGE", "opscontrol-ai-tests:local")
            # Refus avant écriture si l'environnement isolé n'est pas prêt ; aucun téléchargement.
            run(["docker", "info"], root, stdout=subprocess.DEVNULL)
            run(["docker", "image", "inspect", image], root, stdout=subprocess.DEVNULL)
            with tempfile.TemporaryDirectory(prefix="opscontrol-apply-") as folder:
                patch = Path(folder) / "approved.diff"
                patch.write_text(record["patch"], encoding="utf-8", newline="\n")
                run(["git", "apply", "--check", str(patch)], root)
                run(["git", "apply", str(patch)], root)
            print("Patch appliqué. Tests isolés en cours ; aucun commit automatique.")
            isolated_tests(root, image)
        else:
            isolated_tests(root, os.getenv("OPSCONTROL_AI_TEST_IMAGE", "opscontrol-ai-tests:local"))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(
            1,
            f"Opération refusée ou tests en échec : {type(error).__name__}. Vérifier le diff local ; aucun rollback automatique.\n",
        )


if __name__ == "__main__":
    main()
