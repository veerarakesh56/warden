"""The traffic Lambda's calls to the internal ALB trust the ALB's own certificate and nothing else (Sonar terraform:S5332,
2026-10-17: the ALB answers HTTPS only, with a self-signed ECDSA P-256 certificate the dev stack makes and imports into
ACM). Runs in the apps lane, where neither WARDEN nor cryptography is installed: the test certificates come from the
openssl command, as terraform's tls provider would make them (server auth, CA:FALSE, the ALB's DNS name)."""

from __future__ import annotations

import http.server
import importlib.util
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import types

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOST = "internal-warden-test-alb-1234567890.example.elb.amazonaws.com"


def _traffic(monkeypatch):
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: None))
    spec = importlib.util.spec_from_file_location(
        "fs_traffic_tls", ROOT / "scenarios" / "fullstack" / "lambdas" / "traffic" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _self_signed(directory: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    directory.mkdir(parents=True, exist_ok=True)
    crt, key = directory / "alb.pem", directory / "alb.key"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
         "-subj", "/CN=warden-test-orders-alb", "-keyout", str(key), "-out", str(crt),
         "-addext", f"subjectAltName=DNS:{HOST}", "-addext", "basicConstraints=critical,CA:FALSE",
         "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth"],
        check=True, capture_output=True)
    return crt, key


def _serve(crt: pathlib.Path, key: pathlib.Path) -> http.server.HTTPServer:
    handler = type("H", (http.server.BaseHTTPRequestHandler,), {
        "do_GET": lambda s: (s.send_response(200), s.end_headers(), s.wfile.write(b"[]")),
        "log_message": lambda *a: None})
    server = http.server.HTTPServer(("127.0.0.1", 0), handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # as the ALB's policy, ELBSecurityPolicy-TLS13-1-2-2021-06
    ctx.load_cert_chain(crt, key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_the_alb_is_reached_over_tls_trusting_its_certificate_and_nothing_else(tmp_path, monkeypatch):
    """A real handshake: the call succeeds against the ALB's certificate; an impostor with the same name and another
    key gets no request, and neither does the ALB reached by its bare address."""
    crt, key = _self_signed(tmp_path / "alb")
    real, impostor = _serve(crt, key), _serve(*_self_signed(tmp_path / "impostor"))
    app = _traffic(monkeypatch)
    try:
        # The ALB's name resolves to the local servers: urllib connects by name, so the name check is real.
        resolve = socket.getaddrinfo
        monkeypatch.setattr(socket, "getaddrinfo", lambda h, *a, **k: resolve("127.0.0.1" if h == HOST else h, *a, **k))
        for proxy in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):  # as in Lambda: straight to the ALB
            monkeypatch.delenv(proxy, raising=False)
        monkeypatch.setenv("ALB_CA_PEM", crt.read_text(encoding="ascii"))
        for server, host, expected in ((real, HOST, 200), (impostor, HOST, 0), (real, "127.0.0.1", 0)):
            app._ALB_TLS.clear()
            base = f"https://{host}:{server.server_address[1]}"
            monkeypatch.setenv("ALB_URL", base)
            assert app._call("GET", base + "/orders") == expected, (host, expected)
    finally:
        real.shutdown()
        impostor.shutdown()


def test_an_alb_call_trusts_exactly_one_certificate_and_any_other_call_the_systems(tmp_path, monkeypatch):
    crt, _ = _self_signed(tmp_path)
    app = _traffic(monkeypatch)
    monkeypatch.setenv("ALB_URL", "https://internal-alb.example")
    monkeypatch.setenv("ALB_CA_PEM", crt.read_text(encoding="ascii"))
    ctx = app._tls_for("https://internal-alb.example/orders")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.cert_store_stats()["x509"] == 1  # not the system's trust store
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname
    assert app._tls_for("https://internal-alb.example/orders") is ctx  # built once per container
    # The API, and a host that only starts like the ALB's name, get the default context (None).
    for url in ("https://api.example/checkout", "https://internal-alb.example.evil/orders"):
        assert app._tls_for(url) is None, url
    # Without the certificate (the code deployed before the stack moved to HTTPS) nothing changes either.
    monkeypatch.delenv("ALB_CA_PEM")
    assert app._tls_for("https://internal-alb.example/orders") is None
