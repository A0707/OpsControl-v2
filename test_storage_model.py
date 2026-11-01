"""Ressources identifiées, gravité partagée et absence de faux état sain."""

import unittest
from datetime import datetime, timedelta, timezone

import alert_policy
import storage_model as sm


def fs(mount="/", device="/dev/sda1", **changes):
    return dict(
        mount=mount,
        device=device,
        fstype="ext4",
        total_kb=10 * alert_policy.GIB,
        used_kb=5 * alert_policy.GIB,
        available_kb=5 * alert_policy.GIB,
        use_pct=50,
        inodes_total=1000,
        inodes_used=200,
        inodes_free=800,
        inodes_use_pct=20,
        **changes,
    )


def host(volumes, **changes):
    return dict(
        storage={"filesystems": volumes},
        collected_at=datetime.now(timezone.utc).isoformat(),
        **changes,
    )


class StorageModelTests(unittest.TestCase):
    def test_snap_et_distant_exclus_du_maximum_utile(self):
        root = fs()
        snap = {**fs("/snap/core/1", "/dev/loop0"), "use_pct": 100}
        remote = {**fs("/mnt/nas", "nas:/data"), "fstype": "nfs4", "use_pct": 99}
        a = sm.assess(host([root, snap, remote]))
        self.assertEqual(a["capacity"]["mount"], "/")
        self.assertTrue(
            next(v for v in a["volumes"] if v["mount"].startswith("/snap"))["technical"]
        )

    def test_inodes_critiques_independants_de_la_capacite(self):
        v = sm.assess(host([{**fs(), "inodes_use_pct": 100, "inodes_free": 0}]))[
            "volumes"
        ][0]
        self.assertEqual(v["severity"], "critical")
        self.assertEqual(v["capacity_severity"], "ok")
        self.assertEqual(v["inodes_free"], 0)

    def test_meme_grille_que_le_centre_d_alertes(self):
        for used, free in [(93, 4), (97, 100), (40, 0.2)]:
            raw = {**fs(), "use_pct": used, "available_kb": free * alert_policy.GIB}
            self.assertEqual(
                sm.volume(raw)["capacity_severity"],
                alert_policy.disk(used, raw["total_kb"], raw["available_kb"])[0]
                or "ok",
            )

    def test_ancien_absent_futur_et_echec_ne_sont_pas_frais(self):
        a = host([fs()])
        self.assertTrue(sm.assess(a)["fresh"])
        for flag in ["stale", "audit_retained", "configuration_changed"]:
            self.assertFalse(sm.assess({**a, flag: True})["fresh"])
        for stamp in [
            None,
            "invalide",
            (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "2020-01-01T00:00:00+00:00",
        ]:
            self.assertFalse(sm.assess({**a, "collected_at": stamp})["fresh"])

    def test_non_fini_absent_et_legacy(self):
        self.assertIsNone(sm.volume({"use_pct": float("nan")})["use_pct"])
        self.assertEqual(sm.volume({"use_pct": 40})["severity"], "unknown")
        a = sm.assess(
            {
                "filesystems": [
                    {
                        "mount": "/",
                        "fs": "/dev/sda1",
                        "size": "10G",
                        "used": "4G",
                        "avail": "6G",
                        "use_pct": 40,
                    }
                ]
            }
        )
        self.assertEqual(a["capacity"]["total_kb"], 10 * alert_policy.GIB)
        self.assertIsNone(a["capacity"]["inodes_free"])
        self.assertEqual(sm.assess({})["volumes"], [])

    def test_historique_reste_par_disque_et_montage(self):
        snapshots = [
            host([fs("/", "/dev/sda1"), fs("/data", "/dev/sdb1")]),
            host([fs("/", "/dev/sdc1")]),
        ]
        a = sm.assess(host([fs()]), snapshots)
        self.assertEqual(
            {(v["mount"], v["device"]) for v in a["history"]},
            {("/", "/dev/sda1"), ("/data", "/dev/sdb1"), ("/", "/dev/sdc1")},
        )

    def test_projection_exige_serie_comparable_et_suffisante(self):
        now = datetime.now(timezone.utc)
        points = []
        for days, used in [(2, 4), (1, 6), (0, 8)]:
            v = {
                **fs(),
                "used_kb": used * alert_policy.GIB,
                "available_kb": (10 - used) * alert_policy.GIB,
                "use_pct": used * 10,
            }
            points.append(
                {**host([v]), "collected_at": (now - timedelta(days=days)).isoformat()}
            )
        result = sm.assess(points[-1], points)["volumes"][0]
        self.assertAlmostEqual(result["days_to_full"], 1)
        self.assertEqual(result["capacity_severity"], "critical")
        resized = {**v, "total_kb": 20 * alert_policy.GIB}
        self.assertIsNone(
            sm.assess(host([resized]), points)["volumes"][0]["days_to_full"]
        )
