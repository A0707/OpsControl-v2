"""Advanced WAF evidence, based on the supplied Apache/ModSecurity monitor."""
import base64
import json
import shlex
import zlib
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import ssh

# Extends the shared SSH allowlist at import time (same pattern as audit_engine.py):
# anything reading ssh.OPERATIONS before this module is imported sees it incomplete.
ssh.OPERATIONS['waf_detail'] = 'python3 -c ' + shlex.quote(Path(__file__).with_name('waf_probe.py').read_text(encoding='utf-8'))
# Santé et saturation Apache : sonde séparée, en lecture seule ; son échec n'affecte pas la sonde WAF.
# Envoyée compressée : en clair (32 Ko + échappement) elle dépasse la limite de 32 767
# caractères d'une ligne de commande Windows. Le code exécuté est exactement apache_probe.py.
ssh.OPERATIONS['waf_apache'] = 'python3 -c ' + shlex.quote(
    'import base64,zlib;exec(zlib.decompress(base64.b64decode(%r)))'
    % base64.b64encode(zlib.compress(Path(__file__).with_name('apache_probe.py').read_bytes(), 9)).decode())

WAF_ROLE = 'WAF ModSecurity'


def is_waf_host(host):
    """True for any inventory host explicitly labelled with the exact role this
    probe supports (Apache + ModSecurity + Fail2ban). Deliberately not a fuzzy
    match on 'WAF' : a host only gets probed once its stack is confirmed."""
    return host.get('role') == WAF_ROLE


def collect_waf(host, cfg, system_result, requester):
    result = {'collected_at': datetime.now(timezone.utc).isoformat(), 'status': 'unknown', 'sections': {}}
    if not system_result.get('ssh_user'):
        result['error'] = 'SSH indisponible : consulter les tentatives de connexion du serveur.'
        return result
    selected = replace(cfg, user=system_result['ssh_user'], port=system_result['ssh_port'],
                       timeout=30, target=host.get('ssh_host', ''),
                       key_path=host.get('key_path', cfg.key_path), config_path=host.get('ssh_config', cfg.config_path))
    probe = ssh.run_operation(host['ip'], 'waf_detail', selected, requester)
    if not probe.ok:
        result['error'] = 'Collecte WAF impossible : ' + probe.error_kind
        return result
    try:
        payload = json.loads(probe.stdout)
        sections = payload['sections']
        if not isinstance(sections, dict) or not all(isinstance(s, dict) for s in sections.values()):
            raise ValueError('Invalid sections')
        # L'horodatage et le statut sont ceux d'OpsControl, jamais ceux annoncés par le WAF :
        # une réponse distante ne doit pas pouvoir rajeunir ou valider sa propre mesure (audit WAF-01).
        result.update({k: v for k, v in payload.items() if k not in ('collected_at', 'status', 'coverage')})
        measured = sum(s.get('status') == 'observed' for s in sections.values())
        result['coverage'] = {'measured': measured, 'total': len(sections)}
        result['status'] = 'observed' if measured == len(sections) and measured else 'unknown'
        result['recommendations'] = recommendations(sections)
    except (ValueError, KeyError, TypeError):
        result['error'] = 'Réponse WAF invalide ou tronquée ; aucune mesure déduite.'
    result['apache'] = collect_apache(host, selected, requester)
    return result


def collect_apache(host, selected, requester):
    """Sonde apache_probe.py : même compte, même liste blanche. N/A si elle échoue."""
    probe = ssh.run_operation(host['ip'], 'waf_apache', selected, requester)
    if not probe.ok:
        return {'sections': {}, 'error': 'Sonde Apache impossible : ' + probe.error_kind}
    try:
        payload = json.loads(probe.stdout)
        if not isinstance(payload.get('sections'), dict):
            raise ValueError('Invalid sections')
        return payload
    except (ValueError, TypeError, AttributeError):
        return {'sections': {}, 'error': 'Réponse de la sonde Apache invalide ou tronquée ; aucune mesure déduite.'}


def recommendations(sections):
    out = []
    modules = sections.get('apache_modules', {}).get('data', {})
    if modules.get('security_module_loaded') is False:
        out.append('Le module ModSecurity n’apparaît pas dans apache2ctl -M. Vérifier le moteur chargé et la configuration Apache.')
    modes = sections.get('engine', {}).get('data', {}).get('declarations', [])
    if any(x.get('mode', '').lower() in ('off', 'detectiononly') for x in modes):
        out.append('Au moins une déclaration SecRuleEngine Off ou DetectionOnly est présente. Vérifier sa portée effective avant de conclure que le trafic est bloqué.')
    traffic = sections.get('traffic', {}).get('data', {})
    if (traffic.get('errors_5xx_pct') or 0) >= 5:
        out.append('Au moins 5 % de réponses 5xx dans l’échantillon : examiner Apache et les applications amont.')
    for name in ('traffic', 'modsecurity'):
        if sections.get(name, {}).get('data', {}).get('scope', {}).get('partial'):
            out.append('Échantillon ' + name + ' partiel : certains journaux sont inaccessibles ou dépassent la limite de fichiers.')
    if any(s.get('status') == 'unknown' for s in sections.values()):
        out.append('Des contrôles sont incomplets. Consulter leurs preuves : droits sudo non interactifs, outils ou sources absents.')
    return out
