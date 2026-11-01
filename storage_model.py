"""Projection des preuves de stockage pour la fiche, sans collecte ni écriture."""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone

import alert_policy

TECHNICAL = {
    "tmpfs",
    "devtmpfs",
    "squashfs",
    "overlay",
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "efivarfs",
}
REMOTE = {"nfs", "nfs4", "cifs", "smb3", "fuse.sshfs"}
RANK = {"critical": 0, "warning": 1, "preventive": 2, "unknown": 3, "ok": 4, "info": 5}


def number(value):
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        return None
    return value if math.isfinite(value) and value >= 0 else None


def percent(value):
    value = number(value)
    return value if value is not None and value <= 100 else None


def size_kib(value):
    """Les anciens df -hP restent lisibles, sans inventer leur précision."""
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([KMGTPE]?)(?:i?B)?", str(value or ""), re.I)
    if not match:
        return None
    scale = {
        "": 1 / 1024,
        "K": 1,
        "M": 1024,
        "G": 1024**2,
        "T": 1024**3,
        "P": 1024**4,
        "E": 1024**5,
    }
    result = float(match[1]) * scale[match[2].upper()]
    return round(result) if math.isfinite(result) else None


def technical(fs):
    device = str(fs.get("device") or fs.get("fs") or "")
    mount = str(fs.get("mount") or "")
    kind = str(fs.get("fstype") or device).lower()
    return (
        kind in TECHNICAL
        or device.startswith("/dev/loop")
        or mount.startswith(("/snap/", "/var/lib/snapd/snap/"))
    )


def filesystems(host):
    """Une ligne par montage ; le relevé détaillé prime sur df -h arrondi."""
    storage = host.get("storage") or {}
    merged = {}
    for fs in host.get("filesystems") or []:
        if not isinstance(fs, dict) or not fs.get("mount"):
            continue
        merged[fs["mount"]] = {
            **fs,
            "device": fs.get("device") or fs.get("fs"),
            "total_kb": fs.get("total_kb", size_kib(fs.get("size"))),
            "used_kb": fs.get("used_kb", size_kib(fs.get("used"))),
            "available_kb": fs.get("available_kb", size_kib(fs.get("avail"))),
        }
    for fs in storage.get("filesystems") or []:
        if isinstance(fs, dict) and fs.get("mount"):
            merged[fs["mount"]] = {**merged.get(fs["mount"], {}), **fs}
    return list(merged.values())


def capacity_candidate(fs):
    device = str(fs.get("device") or fs.get("fs") or "")
    return (
        not technical(fs)
        and fs.get("fstype") not in REMOTE
        and not device.startswith("//")
        and ":/" not in device
    )


def current(host):
    if any(host.get(k) for k in ("stale", "audit_retained", "configuration_changed")):
        return False
    storage = host.get("storage") or {}
    try:
        at = datetime.fromisoformat(
            str(storage.get("collected_at") or host.get("collected_at")).replace(
                "Z", "+00:00"
            )
        )
        return (
            at.tzinfo is not None
            and 0 <= (datetime.now(timezone.utc) - at).total_seconds() <= 900
        )
    except (TypeError, ValueError):
        return False


def volume(fs):
    out = {k: fs.get(k) for k in ("mount", "device", "fstype")}
    for key in (
        "total_kb",
        "used_kb",
        "available_kb",
        "inodes_total",
        "inodes_used",
        "inodes_free",
    ):
        out[key] = number(fs.get(key))
    out["use_pct"] = percent(fs.get("use_pct"))
    out["inodes_use_pct"] = percent(fs.get("inodes_use_pct"))
    out["technical"] = technical(fs)
    out["remote"] = not capacity_candidate(fs) and not out["technical"]
    cap, reasons = alert_policy.disk(
        out["use_pct"], out["total_kb"], out["available_kb"]
    )
    inode, inode_reasons = alert_policy.inodes(out["inodes_use_pct"])
    out["capacity_severity"] = cap or (
        "ok" if out["use_pct"] is not None else "unknown"
    )
    out["inode_severity"] = inode or (
        "ok" if out["inodes_use_pct"] is not None else "unknown"
    )
    out["severity"] = alert_policy.worst(cap, inode) or (
        "ok"
        if out["use_pct"] is not None and out["inodes_use_pct"] is not None
        else "unknown"
    )
    out["reasons"] = reasons + inode_reasons
    if out["inodes_use_pct"] is None:
        out["reasons"].append(
            "Inodes non mesurés ou non applicables à ce système de fichiers."
        )
    if out["technical"]:
        out["severity"] = "info"
        out["reasons"] = ["Volume technique : exclu du maximum de capacité utile."]
    return out


def assess(host, snapshots=()):
    fresh = current(host)
    volumes = [volume(fs) for fs in filesystems(host)][:256]
    # L'identité du montage ET du périphérique évite de relier deux disques différents.
    history = []
    timestamps = []
    for snapshot in sorted(snapshots, key=lambda s: s.get("collected_at") or "")[-20:]:
        at = snapshot.get("collected_at")
        if not at:
            continue
        timestamps.append(at)
        for fs in filesystems(snapshot)[:256]:
            if capacity_candidate(fs):
                history.append({"at": at, **volume(fs)})
    index = {(p["mount"], p["device"], p["at"]): p for p in history}
    for v in volumes:
        points = []
        for at in timestamps:
            p = index.get((v["mount"], v["device"], at))
            if not p or p["total_kb"] != v["total_kb"] or p["used_kb"] is None:
                points = []
            else:
                points.append((p["at"], p["used_kb"], p["total_kb"]))
        days = alert_policy.days_to_full(points)
        v["days_to_full"] = days if days is not None and days >= 0 else None
        if v["technical"] or v["days_to_full"] is None:
            continue
        cap, reasons = alert_policy.disk(
            v["use_pct"], v["total_kb"], v["available_kb"], days
        )
        v["capacity_severity"] = cap or v["capacity_severity"]
        v["severity"] = (
            alert_policy.worst(cap, alert_policy.inodes(v["inodes_use_pct"])[0])
            or v["severity"]
        )
        v["reasons"] = reasons + alert_policy.inodes(v["inodes_use_pct"])[1]
    volumes.sort(
        key=lambda v: (
            v["technical"],
            RANK[v["severity"]],
            -(v["use_pct"] or 0),
            v["mount"],
        )
    )
    useful = [
        v
        for v in volumes
        if not v["technical"] and not v["remote"] and v["use_pct"] is not None
    ]
    capacity = sorted(
        useful, key=lambda v: (RANK[v["capacity_severity"]], -(v["use_pct"] or 0))
    )
    return {
        "volumes": volumes,
        "capacity": capacity[0] if capacity else None,
        "fresh": fresh,
        "collected_at": (host.get("storage") or {}).get("collected_at")
        or host.get("collected_at"),
        "history": history,
        "history_timestamps": timestamps,
        "history_scope": "Les 20 derniers audits conservés ; les changements de volume ou de taille et les mesures absentes interrompent la courbe.",
        "scope": "Gravité par volume : capacité, espace disponible et inodes. Une donnée manquante ne prouve pas un état sain.",
    }
