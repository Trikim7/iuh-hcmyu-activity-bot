import contextlib
import datetime
import hashlib
import io
import os
import ssl
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import iuh_telegram_bot as bot


class TLSVerificationTests(unittest.TestCase):
    def test_iuh_context_contains_official_intermediate_and_preserves_verification(self):
        with requests.Session() as session:
            telegram = session.get_adapter("https://api.telegram.org/")
            bot.configure_iuh_tls(session)
            adapter = session.get_adapter(bot.EVENT_URL)
            bot.configure_iuh_tls(session)
            self.assertIs(session.get_adapter(bot.LOGIN_URL), adapter)
            self.assertIs(session.get_adapter("https://api.telegram.org/"), telegram)
            self.assertIs(session.get_adapter("https://doantn.iuh.edu.vn.evil.example/"), telegram)
            request = requests.Request("GET", bot.EVENT_URL).prepare()
            _, pool = adapter.build_connection_pool_key_attributes(request, True)
            context = pool["ssl_context"]
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertFalse(context.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN)
            fingerprints = {hashlib.sha256(cert).hexdigest() for cert in context.get_ca_certs(binary_form=True)}
            self.assertIn("4422e963ee53cd58cc9f85cd40bf5ffec0095fdf1a154535661c1c06bcadc69b", fingerprints)

    def test_custom_ca_bundle_is_preserved(self):
        request = requests.Request("GET", bot.EVENT_URL).prepare()
        _, pool = bot.IUHTLSAdapter().build_connection_pool_key_attributes(request, "/custom/ca.pem")
        self.assertEqual(pool["ca_certs"], "/custom/ca.pem")
        self.assertNotIn("ssl_context", pool)

    def test_real_tls_rejects_untrusted_expired_and_wrong_hostname_certificates(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        for failure in ("untrusted", "expired", "hostname"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as folder:
                builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                           .public_key(key.public_key()).serial_number(x509.random_serial_number())
                           .not_valid_before(now - datetime.timedelta(days=2))
                           .not_valid_after(now + datetime.timedelta(days=-1 if failure == "expired" else 1))
                           .add_extension(x509.SubjectAlternativeName([
                               x509.DNSName("wrong.example" if failure == "hostname" else "localhost")]), critical=False))
                certificate = builder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)
                cert_path, key_path = Path(folder) / "cert.pem", Path(folder) / "key.pem"
                cert_path.write_bytes(certificate)
                key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                server_context.load_cert_chain(cert_path, key_path)
                server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
                server.socket = server_context.wrap_socket(server.socket, server_side=True)
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                try:
                    with requests.Session() as session:
                        session.trust_env = False
                        adapter = bot.IUHTLSAdapter()
                        if failure != "untrusted":
                            adapter.ssl_context.load_verify_locations(cadata=certificate.decode())
                        session.mount("https://localhost:", adapter)
                        with self.assertRaises(requests.exceptions.SSLError):
                            session.get(f"https://localhost:{server.server_port}/", timeout=3)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=3)

    def test_account_tls_error_is_not_reported_as_bad_password_or_saved(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
            "SUBSCRIBER_STATE_KEY": "k" * 48, "IUH_ACCOUNT_COLLECTION_ENABLED": "true",
        }, clear=True), patch.object(bot, "telegram_request", return_value=True) as api, \
                patch.object(bot, "get_events", side_effect=requests.exceptions.SSLError("private details")), \
                contextlib.redirect_stdout(io.StringIO()):
            path = Path(folder) / "state.json"
            listener = bot.TelegramCommandListener("token", path)
            for number, text in enumerate(("/account", "12345678", "test-password"), 1):
                listener.handle_update(Mock(), {"update_id": number, "message": {
                    "chat": {"id": 12345, "type": "private"}, "message_id": number, "text": text}})
            account = bot.read_subscribers(bot.read_state(path), "token")["subscribers"]["12345"]
            self.assertNotIn("password", account)
            self.assertNotIn("test-password", path.read_text())
            reply = api.call_args.kwargs["data"]["text"]
            self.assertIn("lỗi chứng chỉ", reply)
            self.assertNotIn("private details", reply)


if __name__ == "__main__":
    unittest.main()
