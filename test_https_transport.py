"""Transport HTTPS : changement DNS, TLS, proxy et exception Bacula, sans réseau réel."""

import testing_env  # noqa: F401 — garde réseau active même pour cette suite seule

import io
import socket
import ssl
import unittest
import urllib.error
import urllib.request
from unittest.mock import MagicMock, patch

import https_transport as transport
import management
import security_cve
import zabbix_live


def addresses(*ips):
    return [
        (
            socket.AF_INET6 if ":" in ip else socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            (ip, 443, 0, 0) if ":" in ip else (ip, 443),
        )
        for ip in ips
    ]


def fake_socket(body=b"{}"):
    sock = MagicMock()
    sock.makefile.return_value = io.BytesIO(
        b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    return sock


def fake_tls(sock):
    context = MagicMock()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.wrap_socket.return_value = sock
    return context


class CheckedSocketTests(unittest.TestCase):
    def test_refuse_adresses_interdites_avant_toute_creation_socket(self):
        for ip in (
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "169.254.169.254",
            "fe80::1",
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
        ):
            with self.subTest(ip=ip), patch("socket.socket") as create:
                with self.assertRaises(transport.DestinationRefused):
                    transport.connect_checked((ip, 443))
                create.assert_not_called()

    def test_reponse_mixte_refusee_avant_tout_contact(self):
        with (
            patch("socket.getaddrinfo", return_value=addresses("192.0.2.1", "::1")),
            patch("socket.socket") as create,
        ):
            with self.assertRaises(transport.DestinationRefused):
                transport.connect_checked(("api.test", 443))
            create.assert_not_called()

    def test_erreur_dns_ou_reponse_vide_ne_donne_aucun_repli(self):
        for result in ([], socket.gaierror(socket.EAI_NONAME, "fixture")):
            with (
                self.subTest(result=result),
                patch("socket.socket") as create,
                patch("socket.getaddrinfo") as resolve,
            ):
                if isinstance(result, Exception):
                    resolve.side_effect = result
                else:
                    resolve.return_value = result
                with self.assertRaises(socket.gaierror):
                    transport.connect_checked(("api.test", 443))
                create.assert_not_called()

    def test_repli_ipv6_ipv4_ferme_le_socket_en_echec_sans_nouveau_dns(self):
        first, second = MagicMock(), MagicMock()
        first.connect.side_effect = ConnectionRefusedError("fixture")
        with (
            patch("socket.getaddrinfo", return_value=addresses("2001:db8::1", "10.0.0.2")) as dns,
            patch("socket.socket", side_effect=[first, second]),
        ):
            self.assertIs(transport.connect_checked(("api.test", 443), 7), second)
        dns.assert_called_once()
        first.close.assert_called_once()
        second.connect.assert_called_once_with(("10.0.0.2", 443))
        second.settimeout.assert_called_once_with(7)

    def test_dernier_echec_ferme_son_socket(self):
        sock = MagicMock()
        sock.connect.side_effect = TimeoutError("fixture")
        with (
            patch("socket.getaddrinfo", return_value=addresses("192.0.2.1")),
            patch("socket.socket", return_value=sock),
        ):
            with self.assertRaises(TimeoutError):
                transport.connect_checked(("api.test", 443))
        sock.close.assert_called_once()


class HTTPSFlowTests(unittest.TestCase):
    def test_host_sni_et_proxy_ignorent_un_second_dns_non_valide(self):
        sock = fake_socket()
        tls = fake_tls(sock)
        with (
            patch.dict(
                "os.environ",
                {
                    "HTTPS_PROXY": "http://proxy.test:3128",
                    "https_proxy": "http://proxy.test:3128",
                    "NO_PROXY": "",
                },
            ),
            patch(
                "socket.getaddrinfo", side_effect=[addresses("10.0.0.2"), addresses("127.0.0.1")]
            ) as dns,
            patch("socket.socket", return_value=sock),
        ):
            opener = management.api_opener(tls)
            with opener.open("https://api.test/v1", timeout=2) as response:
                self.assertEqual(response.read(), b"{}")
        dns.assert_called_once_with("api.test", 443, 0, socket.SOCK_STREAM)
        sock.connect.assert_called_once_with(("10.0.0.2", 443))
        tls.wrap_socket.assert_called_once_with(sock, server_hostname="api.test")
        sent = b"".join(call.args[0] for call in sock.sendall.call_args_list)
        self.assertIn(b"Host: api.test\r\n", sent)
        self.assertNotIn(b"proxy.test", sent)
        self.assertTrue(tls.check_hostname)
        self.assertEqual(tls.verify_mode, ssl.CERT_REQUIRED)

    def test_changement_dns_apres_controle_bloque_authentification_wazuh(self):
        with (
            patch(
                "socket.getaddrinfo", side_effect=[addresses("10.0.0.2"), addresses("127.0.0.1")]
            ),
            patch("socket.socket") as create,
        ):
            self.assertIsNone(management.destination_refused("https://api.test"))
            with self.assertRaises(urllib.error.URLError) as error:
                management.wazuh_token("https://api.test", "fixture:fixture", fake_tls(None), 2)
            self.assertIsInstance(error.exception.reason, transport.DestinationRefused)
            create.assert_not_called()
        self.assertEqual(management.collection_error(error.exception)["error_kind"], "destination")

    def test_zabbix_live_utilise_le_meme_controle_a_la_connexion(self):
        connection = {
            "url": "https://api.test/api_jsonrpc.php",
            "provider": "Zabbix",
            "token_env": "INFRAOPS_ZABBIX_AUTH_FIXTURE",
        }
        with (
            patch.dict("os.environ", {"INFRAOPS_ZABBIX_AUTH_FIXTURE": "identifiant-simule"}),
            patch.object(management, "ACTIVE_BINDINGS", None),
            patch.object(management, "ssl_context_for", return_value=fake_tls(None)),
            patch(
                "socket.getaddrinfo", side_effect=[addresses("10.0.0.2"), addresses("127.0.0.1")]
            ),
            patch("socket.socket") as create,
        ):
            with self.assertRaises(urllib.error.URLError) as error:
                zabbix_live.fetch(connection, ["1"])
            self.assertIsInstance(error.exception.reason, transport.DestinationRefused)
            create.assert_not_called()

    def test_vulnerabilites_wazuh_utilisent_le_meme_transport(self):
        connection = {
            "url": "https://api.test/manager/status",
            "provider": "Wazuh",
            "token_env": "INFRAOPS_WAZUH_AUTH_FIXTURE",
        }
        with (
            patch.object(management, "ACTIVE_BINDINGS", None),
            patch.object(management, "ssl_context_for", return_value=fake_tls(None)),
            patch(
                "socket.getaddrinfo", side_effect=[addresses("10.0.0.2"), addresses("127.0.0.1")]
            ),
            patch("socket.socket") as create,
        ):
            with self.assertRaises(urllib.error.URLError) as error:
                security_cve.wazuh_get(
                    connection, "/vulnerability/001", bearer="identifiant-simule"
                )
            self.assertIsInstance(error.exception.reason, transport.DestinationRefused)
            create.assert_not_called()

    def test_echec_tls_interdit_envoi_du_jeton(self):
        sock = fake_socket()
        tls = fake_tls(sock)
        tls.wrap_socket.side_effect = ssl.SSLCertVerificationError("fixture")
        with (
            patch("socket.getaddrinfo", return_value=addresses("10.0.0.2")),
            patch("socket.socket", return_value=sock),
        ):
            with self.assertRaises(urllib.error.URLError):
                management.wazuh_token("https://api.test", "fixture:fixture", tls, 2)
        sock.sendall.assert_not_called()
        sock.close.assert_called()

    def test_proxy_connect_explicite_refuse(self):
        connection = transport.CheckedHTTPSConnection("proxy.test", context=fake_tls(None))
        connection.set_tunnel("api.test", 443)
        with patch("socket.getaddrinfo") as dns:
            with self.assertRaises(transport.DestinationRefused):
                connection.connect()
        dns.assert_not_called()

    def test_sonde_certificat_recontrole_la_destination(self):
        with (
            patch(
                "socket.getaddrinfo", side_effect=[addresses("10.0.0.2"), addresses("127.0.0.1")]
            ),
            patch("socket.socket") as create,
        ):
            self.assertIsNone(management.destination_refused("https://api.test"))
            with self.assertRaises(transport.DestinationRefused):
                management.probe_certificate("api.test", 443)
        create.assert_not_called()


class BaculaExceptionTests(unittest.TestCase):
    def test_seules_les_deux_lectures_locales_prevues_sont_autorisees(self):
        for url in sorted(transport.BACULA_READ_URLS):
            with (
                self.subTest(url=url),
                patch("urllib.request.HTTPHandler.http_open", return_value="fixture") as opened,
            ):
                request = urllib.request.Request(url)
                self.assertEqual(
                    transport.BaculaHTTPHandler(enabled=True).http_open(request), "fixture"
                )
                opened.assert_called_once_with(request)

    def test_exception_refusee_pour_autres_ports_chemins_et_methodes(self):
        for url, method in (
            (transport.BACULA_TUNNEL_URL, "POST"),
            ("http://127.0.0.1:19096/api/v2/config", "GET"),
            ("http://127.0.0.1:19097/api/v2/jobs", "GET"),
            ("http://localhost:19096/api/v2/jobs", "GET"),
            ("http://api.test/api/v2/jobs", "GET"),
        ):
            with self.subTest(url=url, method=method), patch("socket.socket") as create:
                with self.assertRaises(urllib.error.URLError):
                    management.api_opener(fake_tls(None), local_bacula=True).open(
                        urllib.request.Request(url, method=method)
                    )
                create.assert_not_called()

    def test_sans_exception_explicite_le_http_local_est_refuse(self):
        with patch("socket.socket") as create:
            with self.assertRaises(urllib.error.URLError):
                management.api_opener(fake_tls(None)).open(transport.BACULA_TUNNEL_URL)
        create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
