"""Localisation approximative depuis un CSV local, sans requête externe."""
import csv
import os
from functools import lru_cache
from ipaddress import ip_address, ip_network
from pathlib import Path


@lru_cache(maxsize=1)
def _load(path, modified, size):
    if size > 32 * 1024 * 1024:
        raise ValueError('Base trop volumineuse')
    entries = {}
    with open(path, encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        if 'network' not in (reader.fieldnames or []):
            raise ValueError('Colonne network requise')
        for index, row in enumerate(reader):
            if index >= 250000:
                raise ValueError('Trop de réseaux')
            try:
                network = ip_network((row.get('network') or '').strip(), strict=False)
            except ValueError:
                continue   # une ligne fautive ne désactive plus toute la base (audit WAF-08)
            values = {name: (row.get(name) or '').strip()[:200]
                      for name in ('country', 'city', 'asn', 'organization')}
            entries[(network.version, network.prefixlen, int(network.network_address))] = values
    return entries


@lru_cache(maxsize=1)
def _load_once(path, modified, size):
    """Comme _load, mais l'échec est mémorisé pour ce (fichier, date, taille) : une base
    invalide n'est plus relue à chaque requête de la page WAF (audit WAF-08)."""
    try:
        return _load(path, modified, size)
    except (OSError, ValueError, csv.Error, UnicodeError) as exc:
        return exc


def locator():
    configured = os.environ.get('INFRAOPS_GEOIP_CSV', '').strip()
    entries, status = {}, 'unconfigured'
    if configured:
        try:
            path = Path(configured).expanduser()
            stat = path.stat()
            loaded = _load_once(str(path), stat.st_mtime_ns, stat.st_size)
            entries, status = (loaded, 'not_found') if isinstance(loaded, dict) else ({}, 'unavailable')
        except OSError:
            status = 'unavailable'

    def locate(value):
        try:
            address = ip_address(value)
        except ValueError:
            return {'status': 'unknown', 'note': 'Adresse non identifiée dans l’échantillon.'}
        if not address.is_global:
            return {'status': 'private', 'note': 'Adresse non publique ; aucune localisation géographique déduite.'}
        bits = address.max_prefixlen
        for prefix in range(bits, -1, -1):
            base = int(address) >> (bits - prefix) << (bits - prefix)
            match = entries.get((address.version, prefix, base))
            if match:
                return {**match, 'status': 'observed', 'source': 'CSV GeoIP local',
                        'note': 'Localisation approximative du point de sortie réseau, pas d’une personne.'}
        return {'status': status, 'note': 'Localisation non mesurée ; configurer une base GeoIP locale à jour.'}
    return locate
