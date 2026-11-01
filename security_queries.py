"""Projections SQLite de sécurité : ne décoder les preuves que pour la page affichée."""

import json


def scope(hosts, where, params, *, aggregate=False):
    """Les fragments SQL proviennent uniquement des routes ; les valeurs sont liées."""
    if aggregate:
        # Une recherche déterministe dans le dictionnaire du parc évite une
        # jointure des vulnérabilités avec une table JSON sans index de noms.
        prefix, join = 'WITH ', ''
        host_fields = 'ops_host_name(v.host_key) AS name, ops_host_env(v.host_key) AS environment,'
        values = tuple(params)
    else:
        names = json.dumps([{k: h.get(k) for k in ("key", "name", "environment")} for h in hosts])
        prefix = """WITH names AS MATERIALIZED (
        SELECT json_extract(value,'$.key') AS key,
               json_extract(value,'$.name') AS name,
               json_extract(value,'$.environment') AS environment FROM json_each(?)
    ), """
        host_fields = "COALESCE(NULLIF(n.name,''),v.host_key) AS name, n.environment,"
        join = 'LEFT JOIN names n ON n.key=v.host_key '
        values = (names, *params)
    sql = (
        prefix + 'facts AS ' + ('MATERIALIZED ' if aggregate else '') + """(
        SELECT v.id, v.host_key, v.cve, v.package, v.status, v.confidence,
        """ + host_fields + """
               COALESCE(c.kev,0) AS kev,
               COALESCE(c.cvss,json_extract(v.evidence,'$.wazuh.cvss')) AS score,
               CASE WHEN c.cvss IS NULL THEN json_extract(v.evidence,'$.wazuh.severity') END AS fallback
        FROM sec_vulns v LEFT JOIN sec_cve c ON c.cve=v.cve
        """ + join + 'WHERE '
        + where
        + """
    ), ranked AS """ + ('MATERIALIZED ' if aggregate else '') + """(
        SELECT *, CASE WHEN score>=9 THEN 'critical' WHEN score>=7 THEN 'high'
            WHEN score>=4 THEN 'medium' WHEN score>0 THEN 'low' WHEN score=0 THEN 'none'
            WHEN fallback IN ('critical','high','medium','low','none') THEN fallback
            ELSE 'unknown' END AS severity,
            (CASE WHEN kev THEN 1000 ELSE 0 END + CAST(COALESCE(score,0)*10 AS INTEGER)
            + CASE WHEN lower(COALESCE(environment,'')) LIKE 'prod%' THEN 50 ELSE 0 END) AS priority
        FROM facts
    ) """
    )
    return sql, values


def page(db, hosts, where, params=(), *, severity="", q="", limit=50, offset=0):
    db.create_function("ops_lower", 1, lambda value: str(value).lower(), deterministic=True)
    prefix, values = scope(hosts, where, params)
    filters = ["1=1"]
    if severity:
        filters.append("severity=?")
        values += (severity,)
    if q:
        # instr garde % et _ littéraux, contrairement à LIKE.
        filters.append("instr(ops_lower(cve || ' ' || package || ' ' || name),?)>0")
        values += (q.lower(),)
    clause = " WHERE " + " AND ".join(filters)
    total = db.execute(prefix + "SELECT count(*) FROM ranked" + clause, values).fetchone()[0]
    ids = [
        r[0]
        for r in db.execute(
            prefix
            + "SELECT id FROM ranked"
            + clause
            + " ORDER BY priority DESC,name,cve,id LIMIT ? OFFSET ?",
            (*values, limit, offset),
        )
    ]
    return ids, total


def summary(db, hosts):
    names = {h['key']: h for h in hosts}
    db.create_function('ops_host_name', 1, lambda key: names.get(key, {}).get('name') or key, deterministic=True)
    db.create_function('ops_host_env', 1, lambda key: names.get(key, {}).get('environment'), deterministic=True)
    prefix, values = scope(hosts, "v.status IN ('open','validated','in_progress')", (), aggregate=True)
    counts = dict.fromkeys(("open", "kev", "to_verify", "validated", "in_progress"), 0)
    by_severity, by_host, ids = {}, {}, []
    # Matérialiser une seule fois les faits légers évite de relire et décoder
    # les preuves volumineuses pour chacun des compteurs et les dix priorités.
    for kind, key, name, env, severity, status, confidence, count, kev, score, ident, position in db.execute(
        prefix
        + "SELECT 0 AS kind,host_key,name,environment,severity,status,confidence,count(*),sum(kev!=0),max(score),"
        "NULL AS ident,NULL AS position "
        "FROM ranked GROUP BY host_key,severity,status,confidence "
        "UNION ALL SELECT 1,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,id,position FROM ("
        "SELECT id,row_number() OVER (ORDER BY priority DESC,name,cve,id) AS position "
        "FROM ranked ORDER BY priority DESC,name,cve,id LIMIT 10) ORDER BY kind,position",
        values,
    ):
        if kind:
            ids.append(ident)
            continue
        counts["open"] += count
        counts["kev"] += kev
        counts["to_verify"] += count if confidence == "à vérifier" else 0
        if status in ("validated", "in_progress"):
            counts[status] += count
        by_severity[severity] = by_severity.get(severity, 0) + count
        entry = by_host.setdefault(
            key,
            {
                "host_key": key,
                "name": name,
                "environment": env,
                "count": 0,
                "kev": 0,
                "critical": 0,
                "max_cvss": None,
            },
        )
        entry["count"] += count
        entry["kev"] += kev
        entry["critical"] += count if severity == "critical" else 0
        if score is not None and (entry["max_cvss"] is None or score > entry["max_cvss"]):
            entry["max_cvss"] = score
    counts["hosts_affected"] = len(by_host)
    # Unités distinctes (audit UI du 31/10, fiche 13.1) : « ouvertes » compte des couples
    # serveur/CVE ; une même CVE sur 40 serveurs y pèse 40. Le nombre de CVE uniques
    # est donné à côté pour que les totaux se réconcilient.
    counts["unique_cves"], counts["critical_cves"] = db.execute(
        prefix + "SELECT count(DISTINCT cve), count(DISTINCT CASE WHEN severity='critical' THEN cve END) FROM ranked",
        values,
    ).fetchone()
    top = sorted(
        by_host.values(), key=lambda h: (-h["kev"], -h["critical"], -h["count"], h["host_key"])
    )[:10]
    return counts, by_severity, top, ids
