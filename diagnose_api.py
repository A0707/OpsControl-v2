"""Read-only connectivity and credential diagnostics. Never prints credentials or bodies."""
import concurrent.futures
import json
import os
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from management import api_opener, collection_error, connect_checked, credential_shape, ssl_context_for, wazuh_token


def check(item):
    result = {'provider': item['provider']}
    token = os.getenv(item.get('token_env', ''), '')
    result['credentials'] = credential_shape(item['provider'], token) if token else 'absents'
    if item['provider'] == 'Zabbix' and token:
        import re
        if not re.fullmatch('[0-9a-fA-F]{64}', token):
            result['credentials'] = 'Jeton incomplet ou format invalide (64 caracteres hexadecimaux attendus).'
    try:
        parsed = urlsplit(item['url'])
        context = ssl_context_for(item)
        with connect_checked((parsed.hostname, parsed.port or 443), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname):
                result['tls'] = 'ok'
        if result['credentials']:
            return result
        headers = {'Accept': 'application/json'}
        provider = item['provider']
        if provider == 'Wazuh':
            token = 'Bearer ' + wazuh_token(item['url'], token, context, 8)
        elif provider == 'Zabbix':
            token = 'Bearer ' + token
        headers['Authorization'] = token
        data = None
        if provider == 'Zabbix':
            headers['Content-Type'] = 'application/json-rpc'
            data = json.dumps({'jsonrpc': '2.0', 'method': 'host.get', 'params': {'countOutput': True}, 'id': 1}).encode()
        opener = api_opener(context)
        with opener.open(urllib.request.Request(item['url'], data=data, headers=headers), timeout=8) as response:
            payload = json.loads(response.read(1048576))
        result['api'] = 'application_error' if isinstance(payload, dict) and payload.get('error') else 'ok'
    except Exception as exc:
        # Only the established safe classifier, never exception text or response bodies.
        result.update(collection_error(exc))
    return result


if __name__ == '__main__':
    items = json.loads((Path(__file__).parent / 'data/api-connections.json').read_text(encoding='utf-8-sig'))
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        for result in pool.map(check, items):
            print(json.dumps(result, ensure_ascii=True))
