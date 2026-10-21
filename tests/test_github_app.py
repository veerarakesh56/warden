"""WARDEN's GitHub App identity (register B4, phase 2): a narrow token, signed commits, its own branches only."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from warden import github_app
from warden.github_app import (
    Api,
    AppCredentials,
    GitHubApp,
    GitHubAppError,
    InstallationToken,
    RepoWriter,
    app_jwt,
)

REPO = "example-owner/example-repo"
SHA = "a" * 40
NEW = "b" * 40
NOW = 1_800_000_000


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def creds(rsa_key) -> AppCredentials:
    pem = rsa_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    return AppCredentials(app_id="123456", private_key=pem)


def _part(text: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)))


class FakeConn:
    def __init__(self, replies, log, host):
        self.replies, self.log, self.host = replies, log, host

    def request(self, method, path, body=None, headers=None):
        self.log.append({"host": self.host, "method": method, "path": path, "headers": headers,
                         "body": json.loads(body) if body else None})

    def getresponse(self):
        status, data = self.replies.pop(0)
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()

        class Resp:
            def read(self, n):
                return raw[:n]

        resp = Resp()
        resp.status = status
        return resp

    def close(self):
        pass


def fake_api(*replies):
    log: list[dict] = []
    queue = list(replies)
    return Api(connect=lambda host: FakeConn(queue, log, host)), log


TOKEN_REPLY = {"token": "ghs_" + "x" * 36, "expires_at": "2027-01-15T10:00:00Z",
               "permissions": {"contents": "write", "pull_requests": "write", "metadata": "read"},
               "repository_selection": "selected", "repositories": [{"full_name": REPO}]}


def token() -> InstallationToken:
    return InstallationToken(token="ghs_" + "y" * 36, expires_at="", repository=REPO)


# ----------------------------------------------------------------------------------------------------- the JWT

def test_the_jwt_is_rs256_backdated_and_under_ten_minutes(creds, rsa_key):
    jwt = app_jwt(creds, now=NOW)
    header, claims, signature = jwt.split(".")
    assert _part(header) == {"alg": "RS256", "typ": "JWT"}
    body = _part(claims)
    assert body == {"iat": NOW - 60, "exp": NOW - 60 + 540, "iss": "123456"}
    assert body["exp"] - NOW <= 600
    rsa_key.public_key().verify(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
                                f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())


def test_a_key_that_is_not_rsa_or_not_pem_is_refused():
    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    ec_creds, junk = AppCredentials("1", ec_pem), AppCredentials("1", "not a key")
    with pytest.raises(GitHubAppError, match="not an RSA key"):
        app_jwt(ec_creds, now=NOW)
    with pytest.raises(GitHubAppError, match="not an unencrypted PEM"):
        app_jwt(junk, now=NOW)


def test_credentials_come_from_the_environment_and_never_show_the_key(creds):
    env = {"WARDEN_CODEFIX_APP_ID": "123456", "WARDEN_CODEFIX_APP_KEY": creds.private_key}
    got = AppCredentials.from_environment(env)
    assert got == creds
    assert "PRIVATE" not in repr(got)
    assert "withheld" in repr(got)
    assert AppCredentials.from_environment({}) is None
    assert AppCredentials.from_environment({"WARDEN_CODEFIX_APP_ID": "1"}) is None
    assert AppCredentials.from_environment({"WARDEN_CODEFIX_APP_ID": "Iv23liExample", "WARDEN_CODEFIX_APP_KEY": "k"})


@pytest.mark.parametrize("app_id", ["abc", "12 34", "1" * 13, "Iv", "-1"])
def test_an_app_id_of_the_wrong_shape_is_refused(app_id):
    with pytest.raises(GitHubAppError, match="not a GitHub App id"):
        AppCredentials.from_environment({"WARDEN_CODEFIX_APP_ID": app_id, "WARDEN_CODEFIX_APP_KEY": "k"})


# ------------------------------------------------------------------------------------------ the installation token

def test_the_token_is_asked_for_one_repository_and_two_permissions(creds):
    api, log = fake_api((200, {"id": 42}), (201, TOKEN_REPLY))
    got = GitHubApp(creds, api=api, clock=lambda: NOW).installation_token(REPO)
    assert got.repository == REPO
    assert got.token == TOKEN_REPLY["token"]
    assert [(c["method"], c["path"]) for c in log] == [("GET", f"/repos/{REPO}/installation"),
                                                       ("POST", "/app/installations/42/access_tokens")]
    assert log[1]["body"] == {"repositories": ["example-repo"],
                              "permissions": {"contents": "write", "pull_requests": "write"}}
    assert {c["host"] for c in log} == {"api.github.com"}
    assert log[0]["headers"]["Authorization"].startswith("Bearer ey")
    assert TOKEN_REPLY["token"] not in repr(got)


@pytest.mark.parametrize("change", [
    {"permissions": {"contents": "write", "pull_requests": "write", "workflows": "write"}},
    {"permissions": {"contents": "write", "pull_requests": "write", "administration": "write", "metadata": "read"}},
    {"permissions": {"contents": "write", "pull_requests": "write", "metadata": "write"}},
    {"permissions": {"contents": "write"}},
    {"permissions": None},
    {"repository_selection": "all"},
    {"repositories": [{"full_name": REPO}, {"full_name": "example-owner/other"}]},
    {"repositories": None},
    {"token": ""},
])
def test_a_token_broader_or_other_than_asked_is_refused(creds, change):
    api, _ = fake_api((200, {"id": 42}), (201, {**TOKEN_REPLY, **change}))
    app = GitHubApp(creds, api=api, clock=lambda: NOW)
    with pytest.raises(GitHubAppError):
        app.installation_token(REPO)


@pytest.mark.parametrize("replies", [
    [(404, {"message": "Not Found"})],
    [(200, {"id": "42"})],
    [(200, {"id": True})],
    [(200, {"id": 42}), (422, {"message": "nope"})],
])
def test_a_failed_token_request_raises_with_no_reply_text(creds, replies):
    api, _ = fake_api(*replies)
    app = GitHubApp(creds, api=api, clock=lambda: NOW)
    with pytest.raises(GitHubAppError) as err:
        app.installation_token(REPO)
    assert "nope" not in str(err.value)
    assert "Not Found" not in str(err.value)


@pytest.mark.parametrize("repo", ["", "owner", "owner/../x", "a/b/c", "https://github.com/a/b", "/a/b"])
def test_only_an_owner_slash_name_repository(creds, repo):
    app = GitHubApp(creds, api=fake_api()[0], clock=lambda: NOW)
    with pytest.raises(GitHubAppError, match="owner/name"):
        app.installation_token(repo)


# --------------------------------------------------------------------------------------------- the wire

def test_the_reply_size_is_capped(monkeypatch):
    monkeypatch.setattr(github_app, "MAX_REPLY", 10)
    api, _ = fake_api((200, b"x" * 11))
    with pytest.raises(GitHubAppError, match="over 10 bytes"):
        api.call("GET", "/x", token="t")


def test_a_reply_that_is_not_json_is_an_error():
    api, _ = fake_api((200, b"<html>"))
    with pytest.raises(GitHubAppError, match="not JSON"):
        api.call("GET", "/x", token="t")


def test_a_network_failure_names_the_call_not_the_token():
    class Down:
        def request(self, *a, **k):
            raise ConnectionResetError("secret-token-here")

        def close(self):
            pass

    api = Api(connect=lambda host: Down())
    with pytest.raises(GitHubAppError) as err:
        api.call("GET", "/x", token="secret-token-here")
    assert "secret-token-here" not in str(err.value)
    assert "ConnectionResetError" in str(err.value)


@pytest.mark.parametrize("path", ["x", "//evil.example/x", "/a\\b"])
def test_only_paths_on_the_fixed_host(path):
    api = fake_api()[0]
    with pytest.raises(GitHubAppError, match="not a path"):
        api.call("GET", path, token="t")


def test_the_default_connection_is_https_with_certificate_checks():
    conn = github_app._connect(github_app.API_HOST)
    assert conn.host == "api.github.com"
    assert conn.port == 443
    assert conn._context.verify_mode.name == "CERT_REQUIRED"
    assert conn._context.check_hostname
    assert conn._context.minimum_version >= __import__("ssl").TLSVersion.TLSv1_2
    assert conn.timeout == github_app.TIMEOUT_S


# --------------------------------------------------------------------------------------------- the repository

def test_head_reads_a_branch():
    api, log = fake_api((200, {"object": {"sha": SHA}}))
    assert RepoWriter(token(), api=api).head("dev") == SHA
    assert log[0]["path"] == f"/repos/{REPO}/git/ref/heads/dev"
    assert log[0]["headers"]["Authorization"] == f"Bearer {token().token}"


def test_read_file_decodes_and_checks_size():
    content = base64.b64encode(b"x = 1\n").decode()
    api, log = fake_api((200, {"type": "file", "encoding": "base64", "content": content, "size": 6}), (404, {}))
    writer = RepoWriter(token(), api=api)
    assert writer.read_file("apps/orders/app.py", SHA) == b"x = 1\n"
    assert writer.read_file("apps/orders/gone.py", SHA) is None
    assert log[0]["path"] == f"/repos/{REPO}/contents/apps/orders/app.py?ref={SHA}"


@pytest.mark.parametrize("reply", [{"type": "dir"}, {"type": "file", "encoding": "none", "content": ""},
                                   {"type": "file", "encoding": "base64", "content": "eA==", "size": 2}])
def test_read_file_refuses_what_is_not_an_inline_file(reply):
    writer = RepoWriter(token(), api=fake_api((200, reply))[0])
    with pytest.raises(GitHubAppError):
        writer.read_file("a.py", SHA)


def test_create_branch_only_under_warden():
    api, log = fake_api((201, {}))
    RepoWriter(token(), api=api).create_branch("warden/fix/inc-1", SHA)
    assert log[0]["body"] == {"ref": "refs/heads/warden/fix/inc-1", "sha": SHA}


@pytest.mark.parametrize("branch", ["dev", "prod", "main", "warden", "warden/", "warden/../dev", "warden/x.lock",
                                    "warden/UPPER", "refs/heads/warden/x", "feature/warden/x"])
def test_warden_never_writes_another_branch(branch):
    writer = RepoWriter(token(), api=fake_api((201, {}), (200, {}))[0])
    with pytest.raises(GitHubAppError, match="its own branches"):
        writer.create_branch(branch, SHA)
    with pytest.raises(GitHubAppError, match="its own branches"):
        writer.commit(branch, expected_head=SHA, headline="Revert x", additions={"a.py": b"x"})


COMMIT_OK = {"data": {"createCommitOnBranch": {"commit": {"oid": NEW, "url": "u"}}}}


def test_commit_goes_through_create_commit_on_branch():
    api, log = fake_api((200, COMMIT_OK))
    oid = RepoWriter(token(), api=api).commit("warden/fix/inc-1", expected_head=SHA, headline="Revert abc: x",
                                               body="why", additions={"b.py": b"b", "a.py": b"a"},
                                               deletions=("c.py",))
    assert oid == NEW
    call = log[0]
    assert call["path"] == "/graphql"
    assert "createCommitOnBranch" in call["body"]["query"]
    assert call["body"]["variables"]["input"] == {
        "branch": {"repositoryNameWithOwner": REPO, "branchName": "warden/fix/inc-1"},
        "expectedHeadOid": SHA, "message": {"headline": "Revert abc: x", "body": "why"},
        "fileChanges": {"additions": [{"path": "a.py", "contents": "YQ=="}, {"path": "b.py", "contents": "Yg=="}],
                        "deletions": [{"path": "c.py"}]}}


@pytest.mark.parametrize("reply", [(200, {"errors": [{"message": "Expected branch to point to x"}]}),
                                   (200, {**COMMIT_OK, "errors": [{"message": "partial"}]}),
                                   (200, {"data": {"createCommitOnBranch": None}}), (502, {})])
def test_a_refused_commit_raises(reply):
    writer = RepoWriter(token(), api=fake_api(reply)[0])
    with pytest.raises(GitHubAppError):
        writer.commit("warden/x", expected_head=SHA, headline="h", additions={"a.py": b"a"})


@pytest.mark.parametrize("kw, match", [
    ({"additions": {}}, "no change"),
    ({"additions": {"../x.py": b"x"}}, "plain relative path"),
    ({"deletions": ("/etc/x",)}, "plain relative path"),
    ({"additions": {"a.py": b"a"}, "headline": "line\nbreak"}, "one plain line"),
    ({"additions": {"a.py": b"a"}, "headline": "tab\there"}, "one plain line"),
    ({"additions": {"a.py": b"a"}, "headline": "x" * 201}, "one plain line"),
    ({"additions": {"a.py": b"a"}, "expected_head": "abc"}, "full commit id"),
])
def test_commit_input_is_checked(kw, match):
    args = {"expected_head": SHA, "headline": "h", **kw}
    writer = RepoWriter(token(), api=fake_api((200, COMMIT_OK))[0])
    with pytest.raises(GitHubAppError, match=match):
        writer.commit("warden/x", **args)


DEFAULT = (200, {"default_branch": "main"})


def test_a_pull_request_from_warden_into_the_default_branch():
    api, log = fake_api(DEFAULT, (201, {"number": 7, "html_url": "https://github.com/x/y/pull/7"}))
    got = RepoWriter(token(), api=api).open_pull_request(head="warden/fix/inc-1", base="main",
                                                         title='Revert "Fix the cart (#123)"', body="b")
    assert got == (7, "https://github.com/x/y/pull/7")
    assert log[1]["body"] == {"head": "warden/fix/inc-1", "base": "main", "title": 'Revert "Fix the cart (#123)"',
                              "body": "b", "maintainer_can_modify": False}


@pytest.mark.parametrize("base", ["dev", "prod"])
def test_a_pull_request_into_any_branch_but_the_default_is_refused(base):
    api, log = fake_api(DEFAULT, (201, {"number": 1}))
    with pytest.raises(GitHubAppError, match="default branch"):
        RepoWriter(token(), api=api).open_pull_request(head="warden/x", base=base, title="t", body="")
    assert [entry["method"] for entry in log] == ["GET"]  # nothing was opened


def test_default_branch_is_read_and_checked():
    api, _log = fake_api((200, {"default_branch": "main"}), (200, {"default_branch": "warden/x"}), (200, {}))
    writer = RepoWriter(token(), api=api)
    assert writer.default_branch() == "main"
    for _ in range(2):
        with pytest.raises(GitHubAppError, match="default branch"):
            writer.default_branch()


@pytest.mark.parametrize("base", ["warden/fix/x", "warden", "", "dev/x", "../dev"])
def test_a_pull_request_base_is_never_a_warden_branch(base):
    writer = RepoWriter(token(), api=fake_api((201, {"number": 1}))[0])
    with pytest.raises(GitHubAppError, match="never WARDEN's"):
        writer.open_pull_request(head="warden/x", base=base, title="t", body="")


def test_a_pull_request_reply_without_a_number_raises():
    writer = RepoWriter(token(), api=fake_api(DEFAULT, (201, {}))[0])
    with pytest.raises(GitHubAppError, match="no number"):
        writer.open_pull_request(head="warden/x", base="main", title="t", body="")


# ------------------------------------------------------------------------------------------------ who holds the key

def test_only_the_act_zones_worker_loads_the_apps_secrets():
    from warden import settings

    names = {"WARDEN_CODEFIX_APP_ID", "WARDEN_CODEFIX_APP_KEY"}
    assert names <= settings.SECRETS
    assert names <= settings.loadable_for("worker", "act")
    for zone in set(settings.ZONE_SECRETS) - {"act"}:
        assert not names & settings.loadable_for("worker", zone), zone
    for command in ("incident", "mcp", "approve", "status", "run", "lambda-approval", "lambda-alarm"):
        assert not names & settings.loadable_for(command), command
