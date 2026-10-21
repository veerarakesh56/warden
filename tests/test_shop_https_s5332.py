"""The shop's containers serve HTTPS only (Sonar python:S5332 on scenarios/fullstack/app/app.py, owner row 25).

Each container makes its own self-signed certificate at start: nothing is stored, nothing costs, and the key never
leaves the container. That is safe only while no caller verifies the certificate, so these tests also pin down who
the callers are: the ALB (which does not validate a target's certificate) and the kubelet's probes (which skip
verification). A Service exposed beyond the cluster, or a new caller, has to come back here.
"""
from __future__ import annotations

import ast
import http.client
import importlib.util
import json
import pathlib
import socket
import ssl
import sys
import threading
import types

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP = ROOT / "scenarios" / "fullstack" / "app" / "app.py"
K8S = ROOT / "manifests" / "shop"


def _load_app(monkeypatch, role="orders-api"):
    # The shop image's clients, none reached here: the modules app.py imports, with the names it takes from them.
    stubs = {"psycopg": {}, "redis": {}, "redis.backoff": {"NoBackoff": object}, "redis.retry": {"Retry": object}}
    for name, names in stubs.items():
        monkeypatch.setitem(sys.modules, name, types.SimpleNamespace(**names))
    monkeypatch.setenv("APP_ROLE", role)
    spec = importlib.util.spec_from_file_location("shop_app_s5332", APP)
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)
    return app


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def running_app(monkeypatch):
    """app.main() as it runs in the container, on a free port; the server is shut down afterwards."""
    app = _load_app(monkeypatch)
    port = _free_port()
    monkeypatch.setenv("PORT", str(port))
    monkeypatch.setenv("ORDERS_FF_1", "0")
    servers = []

    class Recorded(app.ThreadingHTTPServer):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            servers.append(self)

    monkeypatch.setattr(app, "ThreadingHTTPServer", Recorded)
    monkeypatch.setattr(app.signal, "signal", lambda *_: None)  # only the main thread may install a handler
    thread = threading.Thread(target=app.main, daemon=True)
    thread.start()
    for _ in range(200):
        if servers and servers[0].socket.fileno() >= 0:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.1).close()
                break
            except OSError:
                pass
        threading.Event().wait(0.05)
    yield port
    app._stop.set()  # what SIGTERM does in the container
    thread.join(timeout=5)
    assert not thread.is_alive()  # the loop ends on its own and closes the socket


def _like_the_alb() -> ssl.SSLContext:
    """A client that does not verify the target's certificate - what the ALB and the kubelet's probes do."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # NOSONAR - the test plays the ALB, which does not verify targets
    return context


def test_the_app_answers_over_https_with_its_own_certificate(running_app):
    conn = http.client.HTTPSConnection("127.0.0.1", running_app, timeout=5, context=_like_the_alb())
    conn.connect()
    assert conn.sock.version() in ("TLSv1.2", "TLSv1.3")
    der = conn.sock.getpeercert(binary_form=True)
    conn.request("GET", "/health")
    reply = conn.getresponse()
    assert reply.status == 200
    assert json.loads(reply.read()) == {"status": "ok", "role": "orders-api"}
    conn.close()
    pem = ssl.DER_cert_to_PEM_cert(der)
    from cryptography import x509

    cert = x509.load_pem_x509_certificate(pem.encode())
    assert cert.subject == cert.issuer  # self-signed: made by this container, by nobody else
    assert cert.subject.rfc4514_string() == "CN=shop-orders-api"
    assert cert.public_key().curve.name == "secp256r1"


def test_the_app_refuses_plain_http(running_app):
    conn = http.client.HTTPConnection("127.0.0.1", running_app, timeout=5)
    conn.request("GET", "/health")
    # A TLS server answers a plain request with a TLS alert or a closed connection, never an HTTP response.
    with pytest.raises((http.client.HTTPException, ConnectionError, OSError)):
        conn.getresponse()
    conn.close()


def test_the_key_never_stays_on_disk(monkeypatch, tmp_path):
    """ssl loads a key only from a file: it is written encrypted, into a private folder that is gone afterwards."""
    app = _load_app(monkeypatch)
    monkeypatch.setattr(app.tempfile, "tempdir", str(tmp_path))
    seen = {}
    real = ssl.SSLContext.load_cert_chain

    class Spy(ssl.SSLContext):
        def load_cert_chain(self, certfile, keyfile=None, password=None):
            folder = pathlib.Path(certfile).parent
            seen["mode"] = folder.stat().st_mode & 0o777
            seen["files"] = {p.name: p.stat().st_mode & 0o777 for p in folder.iterdir()}
            seen["key"] = pathlib.Path(keyfile).read_text(encoding="ascii")
            return real(self, certfile, keyfile, password)

    app.self_signed_certificate(Spy(ssl.PROTOCOL_TLS_SERVER))
    assert seen["mode"] == 0o700
    assert seen["files"] == {"cert.pem": 0o600, "key.pem": 0o600}
    assert "BEGIN ENCRYPTED PRIVATE KEY" in seen["key"]
    assert list(tmp_path.iterdir()) == []  # nothing left behind


def test_main_wraps_the_server_socket_before_serving():
    """The order in main(): a TLS 1.2+ server context, the certificate, the socket wrapped, then serve_forever."""
    tree = ast.parse(APP.read_text(encoding="utf-8"))
    main = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main")
    src = [ast.unparse(s) for s in main.body]
    steps = ["ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)", "context.minimum_version = ssl.TLSVersion.TLSv1_2",
             "self_signed_certificate(context)", "server.socket = context.wrap_socket(server.socket, server_side=True)",
             "server.handle_request()"]
    where = [next(i for i, s in enumerate(src) if step in s) for step in steps]
    assert where == sorted(where), where
    # One server in the app, served only after the wrap.
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
    assert [ast.unparse(c) for c in calls if c.func.attr in ("serve_forever", "handle_request")] == [
        "server.handle_request()"]


def _docs() -> list[dict]:
    out = []
    for path in sorted(K8S.rglob("*.yaml")):
        out += [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    return out


def _containers(doc: dict) -> list[dict]:
    spec = (doc.get("spec") or {}).get("template", {}).get("spec", {})
    return spec.get("containers", []) + spec.get("initContainers", [])


def test_every_shop_probe_uses_https():
    probes = [(doc["metadata"]["name"], kind, c[kind]["httpGet"])
              for doc in _docs() for c in _containers(doc)
              for kind in ("readinessProbe", "livenessProbe", "startupProbe") if "httpGet" in c.get(kind, {})]
    assert len(probes) >= 3  # catalog-api ready + live, cart-worker live
    assert all(get.get("scheme") == "HTTPS" for _, _, get in probes), probes


def test_the_shop_services_stay_inside_the_cluster():
    """A self-made certificate is fine only while nothing outside verifies it: every shop Service is a ClusterIP with
    no external IPs, serving HTTPS."""
    services = [d for d in _docs() if d.get("kind") == "Service"]
    assert services
    for svc in services:
        spec = svc["spec"]
        assert spec.get("type", "ClusterIP") == "ClusterIP", svc["metadata"]["name"]
        for exposure in ("externalIPs", "externalName", "loadBalancerIP"):
            assert not spec.get(exposure), (svc["metadata"]["name"], exposure)
        for port in spec["ports"]:
            assert port["name"] == "https", port
            assert port.get("appProtocol") == "https", port
    assert not [d for d in _docs() if d.get("kind") in ("Ingress", "Gateway", "HTTPRoute")]


def test_nothing_in_the_repo_calls_a_shop_service_by_its_cluster_name():
    """The in-cluster callers are the kubelet's probes only. A caller by Service name would verify the certificate
    (or ought to), and would need a shared certificate instead of the per-container one."""
    names = ("catalog-api.shop", "cart-worker.shop", "//catalog-api", "//cart-worker")
    hits = []
    for top in ("src", "scripts", "scenarios", "manifests", "k8s", "terraform", "helm"):
        for path in (ROOT / top).rglob("*"):
            if path.is_file() and path.suffix in (".py", ".yaml", ".yml", ".tf", ".json", ".sh", ".tpl"):
                text = path.read_text(encoding="utf-8", errors="replace")
                hits += [f"{path.relative_to(ROOT)}: {n}" for n in names if n in text]
    assert hits == []
