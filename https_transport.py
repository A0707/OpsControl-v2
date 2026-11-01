"""Transport direct : l'adresse contrôlée est celle passée au socket, sans nouveau DNS."""

from __future__ import annotations

import http.client
import socket
import urllib.error
import urllib.request
from ipaddress import ip_address

BACULA_TUNNEL_URL = "http://127.0.0.1:19096/api/v2/jobs"
BACULA_READ_URLS = {BACULA_TUNNEL_URL, "http://127.0.0.1:19096/api/v2/clients"}


class DestinationRefused(PermissionError):
    """Destination interdite, même si un contrôle antérieur l'avait acceptée."""


def forbidden_ip(value):
    try:
        ip = ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6:
        ip = ip.ipv4_mapped or ip
    return ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified


def connect_checked(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None):
    """Résout une fois, valide toutes les réponses puis connecte leurs adresses numériques.

    Les réseaux privés du parc restent autorisés. Une réponse mixte contenant une
    adresse interdite est refusée entièrement ; une erreur DNS ne donne aucun repli.
    """
    host, port = address
    if forbidden_ip(host):
        raise DestinationRefused("Destination refusée : adresse locale ou de lien local")
    resolved = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    if not resolved:
        raise socket.gaierror(socket.EAI_NONAME, "Aucune adresse DNS disponible")
    for family, _kind, _proto, _canon, sockaddr in resolved:
        try:
            ip_address(str(sockaddr[0]).split("%", 1)[0])
        except (ValueError, IndexError, TypeError):
            raise DestinationRefused("Destination refusée : réponse DNS invalide") from None
        if family not in (socket.AF_INET, socket.AF_INET6) or forbidden_ip(sockaddr[0]):
            raise DestinationRefused("Destination refusée : réponse DNS locale ou de lien local")
    last_error = None
    for family, kind, proto, _canon, sockaddr in resolved:
        sock = None
        try:
            sock = socket.socket(family, kind, proto)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sockaddr)
            return sock
        except OSError as error:
            last_error = error
            if sock is not None:
                sock.close()
    raise last_error


class CheckedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # HTTPSConnection conserve Host, SNI et vérification du nom d'origine.
        self._create_connection = connect_checked

    def connect(self):
        if self._tunnel_host:
            raise DestinationRefused("Proxy CONNECT non autorisé pour les API internes")
        super().connect()


class CheckedHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request):
        return self.do_open(CheckedHTTPSConnection, request, context=self._context)


class BaculaHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, enabled=False):
        super().__init__()
        self.enabled = enabled

    def http_open(self, request):
        # Aucun autre HTTP en clair ni autre service de boucle locale n'est accessible.
        if (
            not self.enabled
            or request.full_url not in BACULA_READ_URLS
            or request.get_method() != "GET"
        ):
            raise urllib.error.URLError(DestinationRefused("HTTPS requis hors tunnel Bacula"))
        return super().http_open(request)
