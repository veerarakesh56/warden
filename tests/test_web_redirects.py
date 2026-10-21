"""A credentialed request never follows a redirect to another host (warden.web).

CPython's `urllib.request.HTTPRedirectHandler.redirect_request` copies every request header to the redirect's target
except Content-Length and Content-Type, so a bare `urllib.request.urlopen` sends an Authorization or DD-API-KEY header
to whatever host a 3xx names. `warden.web.urlopen` follows a redirect only to the same https host and port and refuses
any other as an HTTPError, which every caller reads as a failed read. Shown here with real TLS servers on this machine
(the finding itself, then the fix), with a fake https handler for each caller, and with a source check that no module
sends a credential header through bare urllib.
"""

from __future__ import annotations

import ast
import datetime as dt
import email.message
import functools
import http.server
import importlib.util
import io
import pathlib
import re
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import urllib.response

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from warden import changes, chatops, datadog, grafana, slack_login, timeline, web, webhooks

ROOT = pathlib.Path(__file__).resolve().parents[1]
HOME, ELSEWHERE = "api.warden.test", "elsewhere.test"  # .test is reserved (RFC 2606): both resolve to 127.0.0.1 here
CREDENTIAL = "Bearer " + "test" + "-credential-" + "0" * 16
PROXIES = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy")


# ------------------------------------------------------------------ local servers


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _certificates(directory: pathlib.Path) -> tuple[bytes, pathlib.Path, pathlib.Path]:
    """A throwaway CA and a server certificate for both test names: (the CA's PEM, the server's cert and key files)."""
    now = dt.datetime.now(dt.UTC)
    ca_key, key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca = (x509.CertificateBuilder().subject_name(_name("warden-test-ca")).issuer_name(_name("warden-test-ca"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          .add_extension(ca_ski, critical=False)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(_name(HOME)).issuer_name(ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOME), x509.DNSName(ELSEWHERE)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False)
            .sign(ca_key, hashes.SHA256()))
    directory.mkdir(parents=True, exist_ok=True)
    crt, pem_key = directory / "server.pem", directory / "server.key"
    crt.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    pem_key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    return ca.public_bytes(serialization.Encoding.PEM), crt, pem_key


class _Server:
    """A local server that records each request's path and headers and answers from `routes`: path -> (status,
    Location). A path it does not know is answered 200 with a small JSON body."""

    def __init__(self, tls: tuple[pathlib.Path, pathlib.Path] | None) -> None:
        self.seen: list[tuple[str, dict[str, str]]] = []
        self.routes: dict[str, tuple[int, str]] = {}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self) -> None:
                outer.seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
                status, location = outer.routes.get(self.path, (200, ""))
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                body = b"" if location else b'{"ok": true}'
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_HEAD = _answer

            def log_message(self, *args) -> None:
                pass

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            ctx.load_cert_chain(*tls)
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def url(self, host: str, path: str, scheme: str = "https") -> str:
        return f"{scheme}://{host}:{self.port}{path}"


@pytest.fixture
def servers(tmp_path, monkeypatch):
    """Two TLS servers (both answer for both names) and one plain-http server, all on this machine, reached by name and
    without any proxy, through a `web` opener and a plain urllib opener that trust the test CA."""
    ca, crt, key = _certificates(tmp_path / "tls")
    for name in PROXIES:
        monkeypatch.delenv(name, raising=False)
    resolve = socket.getaddrinfo
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda h, *a, **k: resolve("127.0.0.1" if str(h).lower() in (HOME, ELSEWHERE) else h, *a, **k))
    trust = ca.decode("ascii")
    monkeypatch.setattr(ssl, "_create_default_https_context", lambda: ssl.create_default_context(cadata=trust))
    monkeypatch.setattr(web, "_HTTPS", web._opener())  # built after the proxies are gone
    first, second, plain = _Server((crt, key)), _Server((crt, key)), _Server(None)
    yield first, second, plain
    for s in (first, second, plain):
        s.httpd.shutdown()
        s.httpd.server_close()


START, AUTH = "/start", "authorization"


def _request(url: str) -> urllib.request.Request:
    return urllib.request.Request(url, headers={"Authorization": CREDENTIAL, "DD-API-KEY": CREDENTIAL})


def _refused(first: _Server, status: int, location: str) -> urllib.error.HTTPError:
    """`first` answers START with a redirect to `location`; the HTTPError web.urlopen raises for it."""
    first.routes[START] = (status, location)
    req = _request(first.url(HOME, START))
    with pytest.raises(urllib.error.HTTPError) as refused:
        web.urlopen(req, timeout=5)
    refused.value.close()
    return refused.value


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
def test_a_redirect_to_another_host_is_refused_and_the_credential_never_reaches_it(servers, status):
    first, second, _ = servers
    first.routes[START] = (status, second.url(ELSEWHERE, "/steal"))
    # The finding, with real sockets: urllib's own opener carries both credential headers to the other host.
    with urllib.request.build_opener().open(_request(first.url(HOME, START)), timeout=5) as resp:
        assert resp.status == 200
    assert [p for p, _ in second.seen] == ["/steal"]
    assert second.seen[0][1][AUTH] == CREDENTIAL
    assert second.seen[0][1]["dd-api-key"] == CREDENTIAL
    second.seen.clear()
    # The fix: the same answer is a refused read, and the other host is never contacted.
    refused = _refused(first, status, second.url(ELSEWHERE, "/steal"))
    assert (refused.code, refused.reason) == (status, web.REFUSED)
    assert second.seen == []


def test_a_redirect_on_the_same_https_host_is_followed_with_its_credential(servers):
    first, _, _ = servers
    first.routes[START] = (302, "/next")  # relative: the same host and port
    first.routes["/next"] = (301, first.url(HOME.upper(), "/done"))  # absolute, the host in another case
    with web.urlopen(_request(first.url(HOME, START)), timeout=5) as resp:
        assert resp.status == 200
        assert resp.read() == b'{"ok": true}'
    assert [p for p, _ in first.seen] == [START, "/next", "/done"]
    assert all(headers[AUTH] == CREDENTIAL for _, headers in first.seen)


@pytest.mark.parametrize("same_port", [True, False])
def test_a_redirect_to_plain_http_on_the_same_host_is_refused(servers, same_port):
    first, _, plain = servers
    refused = _refused(first, 302, f"http://{HOME}:{first.port if same_port else plain.port}/clear")
    assert (refused.code, refused.reason) == (302, web.REFUSED)
    assert plain.seen == []


def test_a_redirect_to_another_port_on_the_same_host_is_refused(servers):
    first, second, _ = servers
    refused = _refused(first, 307, second.url(HOME, "/other-port"))
    assert (refused.code, refused.reason) == (307, web.REFUSED)
    assert second.seen == []


def test_an_address_that_is_not_https_is_refused_before_any_connection(servers):
    _, _, plain = servers
    for url in (plain.url(HOME, "/clear", scheme="http"), "file:///etc/hostname", "ftp://elsewhere.test/x"):
        req = _request(url)
        with pytest.raises(urllib.error.URLError, match="not an https address"):
            web.urlopen(req, timeout=5)
    assert plain.seen == []


GITHUB = "api.github.com"
_FROM = f"https://{GITHUB}/a"


@pytest.mark.parametrize(("first", "second", "same"), [
    (_FROM, f"https://{GITHUB}/b?c=d", True),
    (_FROM, "https://API.GitHub.com:443/b", True),
    ("https://grafana.example:3000/a", "https://grafana.example:3000/b", True),
    (_FROM, f"https://{GITHUB}.elsewhere.test/a", False),
    (_FROM, f"https://{GITHUB}@elsewhere.test/a", False),
    (_FROM, f"https://{GITHUB}:8443/a", False),
    (_FROM, f"http://{GITHUB}/a", False),
    (f"http://{GITHUB}/a", f"http://{GITHUB}/b", False),
    (_FROM, f"https://{GITHUB}:99999/a", False),
    (_FROM, f"https://{GITHUB}:0/a", False),  # an explicit port 0 is not the default port
    ("https:///a", "https:///b", False),
])
def test_same_origin(first, second, same):
    assert web.same_origin(first, second) is same


# ------------------------------------------------------------------ every credentialed caller


class _FakeHTTPS(urllib.request.BaseHandler):
    """Stands in for the network inside web's opener (before its HTTPSHandler): every request to `home` is answered
    302 to another host, with an HTML body as servers send; a request anywhere else is recorded and answered 200."""

    handler_order = 400

    def __init__(self, home: str) -> None:
        self.home, self.seen = home, []

    def https_open(self, req: urllib.request.Request):
        host = urllib.parse.urlsplit(req.full_url).hostname
        self.seen.append((host, {k.lower(): v for k, v in req.header_items()}))
        headers = email.message.Message()
        if host == self.home:
            headers["Location"] = f"https://{ELSEWHERE}/steal"
        body = b"<html>Moved</html>" if host == self.home else b"{}"
        resp = urllib.response.addinfourl(io.BytesIO(body), headers, req.full_url, 302 if host == self.home else 200)
        resp.msg = "Found" if host == self.home else "OK"
        return resp


def _script(name: str):
    spec = importlib.util.spec_from_file_location(f"rd_{name}", ROOT / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


REDIRECTED = "HTTPError 302"


def _raises(call) -> str:
    try:
        call()
    except urllib.error.HTTPError as exc:
        exc.close()
        return f"HTTPError {exc.code}"
    return "no error"


DD_SITE, DD_API, BODY_ONLY = "datadoghq.com", "api.datadoghq.com", "content-type"
_DD = {"WARDEN_DATADOG_SITE": DD_SITE, "WARDEN_DATADOG_API_KEY": CREDENTIAL, "WARDEN_DATADOG_APP_KEY": CREDENTIAL}
_GRAFANA = {"WARDEN_GRAFANA_READ_TOKEN": CREDENTIAL, "WARDEN_GRAFANA_LOGS_URL": "https://grafana.example",
            "WARDEN_GRAFANA_LOGS_USER": "1"}
_NOW = dt.datetime(2026, 10, 21, tzinfo=dt.UTC)
_NOT_READ = "HTTP 302 - not read (late, limited or refused)"
# caller -> (the host it calls, a header it must have sent there, the call, what the call returns for the redirect).
# slack_login and bench_approve carry their secret in a POST body, which no redirect forwards; they go through web
# all the same.
CALLERS = {
    "changes.GitHubIssues": (GITHUB, AUTH, lambda: changes.GitHubIssues("o/r", CREDENTIAL).open(
        "WARDEN change: x", "body"), (None, "HTTP 302")),
    "timeline.github_deployments": (GITHUB, AUTH, lambda: _raises(
        lambda: timeline.github_deployments("o/r", CREDENTIAL, "dev", _NOW, _NOW)), REDIRECTED),
    "timeline.CommitReader": (GITHUB, AUTH, lambda: _raises(
        lambda: timeline.CommitReader(None, repo="o/r", token=CREDENTIAL)._get("/repos/o/r/commits/abc")), REDIRECTED),
    "chatops._slack_call": ("slack.com", AUTH, lambda: chatops._slack_call(
        "chat.postMessage", {}, CREDENTIAL), (None, "HTTP 302")),
    "datadog.DatadogReader": (DD_API, "dd-api-key", lambda: datadog.DatadogReader(env=_DD)._ask(
        "logs", "GET", "/api/v2/x")[1], f"{datadog.PARTIAL}datadog logs: {_NOT_READ}"),
    "grafana.GrafanaReader": ("grafana.example", AUTH, lambda: grafana.GrafanaReader(env=_GRAFANA)._ask(
        "LOGS", "/x", {})[1], f"{grafana.PARTIAL}grafana logs: {_NOT_READ}"),
    "webhooks.datadog_alerting": (DD_API, "dd-application-key", lambda: webhooks.datadog_alerting(
        DD_SITE, CREDENTIAL, CREDENTIAL)("123"), False),
    "slack_login._post": ("slack.com", BODY_ONLY, lambda: _raises(
        lambda: slack_login._post(slack_login.TOKEN_ENDPOINT, {"client_secret": CREDENTIAL})), REDIRECTED),
    "scripts/datadog_setup.Datadog": (DD_API, "dd-api-key", lambda: _raises(
        lambda: _script("datadog_setup").Datadog(DD_SITE, CREDENTIAL, CREDENTIAL).call("GET", "/api/v1/x")), REDIRECTED),
    "scripts/bench_approve._post": ("approve.warden.test", BODY_ONLY, lambda: _script("bench_approve")._post(
        "approve.warden.test", "approve", {"signature": CREDENTIAL}), (302, {})),
}


@pytest.mark.parametrize("caller", sorted(CALLERS))
def test_every_credentialed_caller_reads_a_redirect_elsewhere_as_a_failed_read(caller, monkeypatch):
    home, header, call, failed = CALLERS[caller]
    fake = _FakeHTTPS(home)
    for name in PROXIES:
        monkeypatch.delenv(name, raising=False)
    opener = web._opener()
    opener.add_handler(fake)
    monkeypatch.setattr(web, "_HTTPS", opener)
    assert call() == failed
    assert [host for host, _ in fake.seen] == [home]  # it went through web, and nothing reached the other host
    assert header in fake.seen[0][1]


# ------------------------------------------------------------------ no credential through bare urllib

# A string that names a credential header: the bearer/basic header, a cookie, an API key or token header.
_CREDENTIAL_HEADER = re.compile(r"(?i)authorization|proxy-authorization|cookie|x-api-key|dd-[a-z-]*-key|x-[a-z-]*-(token|key)")
_BARE = {"urllib.request.urlopen", "urllib.request.build_opener", "urllib.request.OpenerDirector"}
SOURCES = [*sorted((ROOT / "src" / "warden").rglob("*.py")), *sorted((ROOT / "scripts").glob("*.py"))]


@functools.cache
def _tree(path: pathlib.Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"))


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return node.id if isinstance(node, ast.Name) else ""


def _bare_names(tree: ast.Module) -> set[str]:
    """What `from urllib.request import urlopen [as x]` binds, as names that are the bare opener too."""
    return {alias.asname or alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
            and node.module == "urllib.request" for alias in node.names if f"urllib.request.{alias.name}" in _BARE}


def credentialed_bare_calls(tree: ast.Module) -> list[str]:
    """Each top-level function or class that names a credential header and also reaches urllib's own opener (a call,
    or a default argument such as `opener=urllib.request.urlopen`): it would send the header to wherever a redirect
    points."""
    aliases = _bare_names(tree)
    found = []
    for unit in tree.body:
        if not isinstance(unit, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        nodes = list(ast.walk(unit))
        named = any(isinstance(n, ast.Constant) and isinstance(n.value, str) and _CREDENTIAL_HEADER.fullmatch(n.value)
                    for n in nodes)
        bare = any(_dotted(n) in _BARE or (isinstance(n, ast.Name) and n.id in aliases) for n in nodes)
        if named and bare:
            found.append(unit.name)
    return found


def test_no_module_sends_a_credential_header_through_bare_urllib():
    offenders = {f"{p.relative_to(ROOT)}:{name}" for p in SOURCES if p.name != "web.py"
                 for name in credentialed_bare_calls(_tree(p))}
    assert offenders == set(), f"send these through warden.web.urlopen: {sorted(offenders)}"


def test_the_source_check_sees_the_credentialed_units_and_catches_a_bare_call():
    named = set()
    for p in SOURCES:
        named |= {f"{p.name}:{u.name}" for u in _tree(p).body if any(
            isinstance(n, ast.Constant) and isinstance(n.value, str) and _CREDENTIAL_HEADER.fullmatch(n.value)
            for n in ast.walk(u))}
    assert {"changes.py:GitHubIssues", "timeline.py:github_deployments", "timeline.py:CommitReader",
            "chatops.py:_slack_call", "datadog.py:DatadogReader", "grafana.py:GrafanaReader",
            "webhooks.py:datadog_alerting", "datadog_setup.py:Datadog"} <= named
    old = ('import urllib.request\n'
           'def get(url, token, opener=urllib.request.urlopen):\n'
           '    return opener(urllib.request.Request(url, headers={"Authorization": token}), timeout=1)\n'
           'class Reader:\n'
           '    def _http(self, url):\n'
           '        req = urllib.request.Request(url, headers={"DD-API-KEY": self.key})\n'
           '        return urllib.request.urlopen(req, timeout=1)\n'
           'def built(url):\n'
           '    return urllib.request.build_opener().open(urllib.request.Request(url, headers={"Cookie": "a"}))\n'
           'from urllib.request import urlopen as fetch\n'
           'def aliased(url):\n'
           '    return fetch(urllib.request.Request(url, headers={"X-Slack-Token": "a"}))\n'
           'def clean(url):\n'
           '    return urllib.request.urlopen(url, timeout=1)\n')
    assert credentialed_bare_calls(ast.parse(old)) == ["get", "Reader", "built", "aliased"]
