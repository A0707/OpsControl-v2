"""Verify every inventory SSH route, without trusting keys or changing servers."""
import json
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

from config import candidates, load_config
from ssh import run_operation


def verify(host, cfg):
    row = {k: host[k] for k in ('key', 'name', 'ip')}
    row.update(status='unknown', attempts=[])
    if not host.get('collect_enabled', True):
        row['status'] = 'disabled'
        return row
    skip_ports = set()
    for candidate in candidates(cfg, host):
        if candidate.port in skip_ports:
            continue
        result = run_operation(host['ip'], 'os', candidate, 'verification-parc-ssh')
        row['attempts'].append({'user': candidate.user, 'port': candidate.port,
                                'ok': result.ok, 'rc': result.rc,
                                'error_kind': result.error_kind,
                                'duration_ms': result.duration_ms})
        if result.rc is not None:
            row.update(status='connected', user=candidate.user, port=candidate.port,
                       probe_ok=result.ok)
            break
        if result.error_kind != 'auth':
            skip_ports.add(candidate.port)
    else:
        errors = {a['error_kind'] for a in row['attempts']}
        row['status'] = next((k for k in ('host_key','auth','local','ssh','network') if k in errors), 'unknown')
    return row


def main():
    base = Path(__file__).resolve().parent
    cfg, hosts = load_config(str(base / 'hosts.yaml'))
    results = []
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(verify, h, cfg): h for h in hosts}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                h = futures[future]
                results.append({'key':h['key'],'name':h['name'],'ip':h['ip'],
                                'status':'local','attempts':[]})
            if len(results) % 10 == 0:
                print(f'Verifies : {len(results)} / {len(hosts)}', flush=True)
    report = {'checked_at':datetime.now(timezone.utc).isoformat(),
              'counts':dict(Counter(r['status'] for r in results)),
              'hosts':sorted(results,key=lambda r:r['name'])}
    target = base / 'data/ssh-access-report.json'
    target.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'counts':report['counts'],'report':str(target)}),flush=True)


if __name__ == '__main__':
    main()
