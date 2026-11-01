"""Adapters must supply timestamped evidence, never inferred OK."""
from typing import Protocol

class IntegrationAdapter(Protocol):
    def fetch(self) -> list[dict]:
        """Return source, host_key, observed_at, status and evidence."""
        ...

def integration_status():
    return [{'name': name, 'status': 'not_connected', 'message': 'Non connecté — aucune donnée collectée'} for name in ['Zabbix', 'Wazuh', 'Proxmox', 'PBS']]
