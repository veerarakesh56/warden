"""The approval site's gate at the gateway (owner, 2026-10-21; Sonar terraform:S6333 on frontdoor.tf): a Lambda REQUEST
authorizer (src/warden/edge_auth.py, terraform edgeauth.tf) in front of the records, WARDEN's own pages and the signed
links. It checks with the page's own code, only ever refuses what the function behind it refuses too, and the routes it
leaves open are exactly the documented ones.
"""
from __future__ import annotations

import pathlib
import re
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_enrol_passkey_g10h import _pem
from test_slack_login_g10q import MEMBER, OTHER, Slack, _login
from warden import approval_page, approvals, edge_auth, slack_login
from warden.approval_page import RESET_INVITE, STOP_INVITE, ApprovalPage, invite

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "terraform" / "modules" / "warden-runtime"
SECRET = "s3cret-not-real"  # test_slack_login_g10q._login's
NOW = datetime(2026, 10, 21, 9, 0, tzinfo=UTC)
# The approval site's routes left open on purpose; each is named, with its reason, in edge_auth's docstring and in
# docs/DESIGN-DECISIONS.md.
OPEN = {"GET /a/{token}", "POST /a/{token}/{step}", "GET /s/callback", "GET /s/{kind}/{token}", "POST /s/interact",
        "GET /s/r", "GET /s/p"}
SIGNED_IN_ROUTES = ("GET /r", "GET /r/{incident}", "GET /p", "POST /p/{step}")
PURPOSES = {"e": approval_page.INVITE, "k": RESET_INVITE, "x": STOP_INVITE}
INC = "50ac32d0fe243384-20261014T071413Z"


def _policy(key):
    return approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=_pem(key), tiers=["T1"],
                                                                          slack=MEMBER)})


def _who(member=MEMBER, at=NOW):
    return "warden_who=" + slack_login.remember(_login(clock=lambda: at.timestamp()), member)


def _forged():
    """The sign-in's cookie with the last character of its seal changed."""
    who = _who()
    return who[:-1] + ("1" if who.endswith("0") else "0")


def _event(route, token="", cookies=()):
    return {"routeKey": route, "pathParameters": {"token": token} if token else {}, "cookies": list(cookies)}


def _decide(event, policy=None, secret=SECRET, at=NOW):
    return edge_auth.decide(event, client_secret=secret, policy=policy, now=at.timestamp())


def _page(key, at=NOW):
    return ApprovalPage(rp_id="approve.example.test", policy=_policy(key), plan_of=lambda _: None,
                        signal=lambda *_: None, clock=lambda: at, slack=_login(Slack(), clock=lambda: at.timestamp()))


# ------------------------------------------------------------------ what it checks


@pytest.mark.parametrize("route", SIGNED_IN_ROUTES)
def test_the_records_and_pages_pass_only_with_the_sign_ins_own_sealed_cookie_in_its_time(route):
    assert _decide(_event(route, cookies=[_who()]))
    assert _decide(_event(route, cookies=["other=1", _who()]))
    assert not _decide(_event(route))  # signed out: the gateway refuses; a link lands on /s/r or /s/p instead
    assert not _decide(_event(route, cookies=["other=1"]))
    assert not _decide(_event(route, cookies=["warden_who="]))
    assert not _decide(_event(route, cookies=[_who().replace(MEMBER, OTHER)]))  # another member under the same seal
    assert not _decide(_event(route, cookies=[_forged()]))  # forged seal
    assert not _decide(_event(route, cookies=[_who()]), at=NOW + timedelta(seconds=slack_login.REMEMBER_S + 1))
    assert not _decide(_event(route, cookies=[_who()]), secret="")  # no Slack app: nobody reads them
    sealed_elsewhere = "warden_who=" + slack_login.remember(
        slack_login.SlackLogin("x", "another-apps-secret", clock=lambda: NOW.timestamp()), MEMBER)
    assert not _decide(_event(route, cookies=[sealed_elsewhere]))


@pytest.mark.parametrize(("kind", "purpose"), sorted(PURPOSES.items()))
def test_a_signed_link_passes_only_signed_by_its_approver_for_its_purpose_and_in_its_time(kind, purpose):
    key = Ed25519PrivateKey.generate()
    policy = _policy(key)
    good = invite(key, "owner", now=NOW, purpose=purpose)
    other = next(p for p in PURPOSES.values() if p != purpose)
    refused = {
        "expired": (good, NOW + approval_page.LINK_TTL),
        "made to last longer than a link": (invite(key, "owner", now=NOW + timedelta(hours=1), purpose=purpose), NOW),
        "not the approver's key": (invite(Ed25519PrivateKey.generate(), "owner", now=NOW, purpose=purpose), NOW),
        "nobody on the list": (invite(key, "nobody", now=NOW, purpose=purpose), NOW),
        "another purpose": (invite(key, "owner", now=NOW, purpose=other), NOW),
    }
    for bad in ("", "x", "a.b.c", good + "x", "../" + good, "é." + good.split(".")[1], good.replace(".", "..")):
        refused[f"malformed {bad!r}"] = (bad, NOW)
    for route in (f"GET /{kind}/{{token}}", f"POST /{kind}/{{token}}/{{step}}"):
        assert _decide(_event(route, good), policy)
        assert _decide(_event(route, good), lambda: policy)  # the Lambda reads the list for each link
        assert not _decide(_event(route, good))  # no approver list: nothing is signed by anyone on it
        for why, (token, at) in refused.items():
            assert not _decide(_event(route, token), policy, at=at), why


def test_a_cookie_opens_no_signed_link_and_a_signed_link_opens_no_record():
    key = Ed25519PrivateKey.generate()
    good = invite(key, "owner", now=NOW)
    assert not _decide(_event("GET /e/{token}", "t.s", cookies=[_who()]), _policy(key))
    assert not _decide(_event("GET /r", good), _policy(key))


def test_it_refuses_every_route_it_does_not_gate():
    for route in sorted(OPEN) + ["POST /alertmanager", "GET /unknown", "get /r", "GET /r ", ""]:
        assert not _decide(_event(route, "t.s", cookies=[_who()])), route  # never wired there; if it were, no


# ------------------------------------------------------------------ the Lambda


def test_the_handler_reads_the_app_secret_once_and_the_approver_list_for_each_link(monkeypatch):
    from warden import runtime_base, settings

    key = Ed25519PrivateKey.generate()
    loads, reads = [], []
    monkeypatch.setattr(edge_auth, "_LOADED", set())
    monkeypatch.setattr(settings, "load", lambda **kw: loads.append(kw["only"]))
    monkeypatch.setattr(runtime_base, "approver_policy", lambda: reads.append(1) or _policy(key))
    monkeypatch.setenv("WARDEN_SLACK_CLIENT_SECRET", SECRET)
    token = invite(key, "owner", now=datetime.now(UTC))
    assert edge_auth.handler(_event("GET /e/{token}", token)) == {"isAuthorized": True}
    assert edge_auth.handler(_event("GET /k/{token}", token)) == {"isAuthorized": False}  # an enrolment's, not a reset's
    assert edge_auth.handler(_event("GET /r", cookies=["warden_who=forged.1.x"])) == {"isAuthorized": False}
    assert len(loads) == 1
    assert len(reads) == 2  # a cookie's check reads no approver list
    assert loads[0] == settings.loadable_for("lambda-edge-auth")
    assert loads[0] & settings.SECRETS == {"WARDEN_SLACK_CLIENT_SECRET"}  # no Temporal key, no webhook secret
    assert "WARDEN_SLACK_CLIENT_ID" not in loads[0]  # the app's id is the page's; the gate needs only the seal's key


def test_a_gate_that_cannot_read_its_settings_or_the_list_raises_so_the_gateway_refuses_and_a_person_is_paged(
        monkeypatch):
    """A raised error is a 500 from the gateway (the route's function never runs) and counts in the Lambda's Errors,
    which page (paging.tf paged_functions). Nothing is remembered from a failed load: the next request tries again."""
    from warden import runtime_base, settings

    def down(**_):
        raise RuntimeError("Secrets Manager is unreachable")

    monkeypatch.setattr(edge_auth, "_LOADED", set())
    monkeypatch.setattr(settings, "load", down)
    with pytest.raises(RuntimeError):
        edge_auth.handler(_event("GET /r", cookies=[_who()]))
    assert edge_auth._LOADED == set()
    monkeypatch.setattr(settings, "load", lambda **_: None)

    def no_list():
        raise RuntimeError("SSM is unreachable")

    monkeypatch.setattr(runtime_base, "approver_policy", no_list)
    key = Ed25519PrivateKey.generate()
    with pytest.raises(RuntimeError):
        edge_auth.handler(_event("GET /e/{token}", invite(key, "owner", now=datetime.now(UTC))))


# ------------------------------------------------------------------ the same checks as the page


def test_the_gate_uses_the_pages_own_checks_and_never_refuses_what_the_page_accepts():
    key = Ed25519PrivateKey.generate()
    page = _page(key)
    for kind, purpose in PURPOSES.items():
        token = invite(key, "owner", now=NOW, purpose=purpose)
        assert page._invited(token, purpose) == "owner"
        assert _decide(_event(f"GET /{kind}/{{token}}", token), page.policy)
    # The cookie the page's own sign-in sets (approval_page._slack: remember(self.slack, ...)) passes the gate.
    assert _decide(_event("GET /p", cookies=[f"warden_who={slack_login.remember(page.slack, MEMBER)}"]))
    assert edge_auth._WHO == approval_page._WHO
    assert {getattr(approval_page, name) for name in edge_auth.SIGNED_LINKS.values()} == set(PURPOSES.values())


def test_a_used_link_still_passes_the_gate_and_the_page_refuses_it():
    """The gate does not read the audit: a link already used is the page's to refuse, as it does."""
    key = Ed25519PrivateKey.generate()
    page = _page(key)
    token = invite(key, "owner", now=NOW)
    page.store.use_link(token)
    assert _decide(_event("GET /e/{token}", token), page.policy)
    assert page._invited(token) is None


# ------------------------------------------------------------------ where a records or pages link lands


@pytest.mark.parametrize(("path", "back"), [("/s/r", "/r"), (f"/s/r/{INC}", f"/r/{INC}"), ("/s/p", "/p")])
def test_a_link_lands_on_the_sign_in_which_goes_straight_on_for_a_reader_already_named(path, back, monkeypatch):
    monkeypatch.delenv("WARDEN_RECORD_VIEWERS", raising=False)
    page = _page(Ed25519PrivateKey.generate())
    named = page.handle("GET", path, cookies=[_who()])
    assert named.status == 302
    assert named.headers["Location"] == back
    assert "Set-Cookie" not in named.headers
    for cookies in ((), [_who(OTHER)], [_forged()],
                    [_who(at=NOW - timedelta(seconds=slack_login.REMEMBER_S + 1))]):
        out = page.handle("GET", path, cookies=cookies)  # nobody, not a reader, a forged seal, an old sign-in
        assert out.status == 302
        assert out.headers["Location"].startswith(slack_login.AUTHORIZE_ENDPOINT)


def test_the_links_wardens_messages_carry_land_on_the_sign_in(monkeypatch):
    from warden import activities

    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", "approve.example.test")
    links = activities.IncidentActivities._record_link(INC)
    assert [link for _, link in links] == [f"https://approve.example.test/s/r/{INC}", "https://approve.example.test/s/r"]
    paging = (MODULE / "paging.tf").read_text(encoding="utf-8")
    assert 'ack_url = var.approval_domain == "" ? "" : "https://${var.approval_domain}/s/p"' in paging


# ------------------------------------------------------------------ the gateway


def _flat(text):
    return " ".join(re.sub(r"(?m)\s#.*$", "", text).split())


def _approval_routes():
    front = (MODULE / "frontdoor.tf").read_text(encoding="utf-8")
    approval = front[front.index('resource "aws_apigatewayv2_route" "approval" {'):]
    approval = approval[:approval.index("\n}\n")]
    return approval, set(re.findall(r'"((?:GET|POST) [^"]+)"', approval[:approval.index("api_id")]))


def test_the_gated_routes_are_the_python_lists_and_every_other_approval_route_is_a_documented_open_one():
    edge = (MODULE / "edgeauth.tf").read_text(encoding="utf-8")
    block = edge[edge.index("edge_gated = toset(["):edge.index("])", edge.index("edge_gated = toset(["))]
    assert set(re.findall(r'"([^"]+)"', block)) == set(edge_auth.GATED)
    approval, routes = _approval_routes()
    assert edge_auth.GATED <= routes
    assert routes - edge_auth.GATED == OPEN
    decisions = (ROOT / "docs" / "DESIGN-DECISIONS.md").read_text(encoding="utf-8")
    for route in OPEN:
        path = route.split(" ", 1)[1].split("/{")[0]
        assert path in edge_auth.__doc__, route
        assert f"`{route}`" in decisions, route
    flat = _flat(approval)
    assert 'authorization_type = contains(local.edge_gated, each.key) ? "CUSTOM" : "NONE"' in flat
    assert "authorizer_id = contains(local.edge_gated, each.key) ? aws_apigatewayv2_authorizer.edge.id : null" in flat


def test_no_route_of_the_module_is_left_without_an_authorizer_unintentionally():
    """Every route resource in the runtime module either names an authorizer outright or is the approval site's, whose
    only NONE routes are the documented open ones (the test above)."""
    found = {}
    for tf in sorted(MODULE.glob("*.tf")):
        text = tf.read_text(encoding="utf-8")
        for m in re.finditer(r'^resource "aws_apigatewayv2_route" "(\w+)" \{\n(.*?)^\}', text, re.MULTILINE | re.DOTALL):
            found[m.group(1)] = _flat(m.group(2))
    assert sorted(found) == ["alertmanager", "approval", "datadog"]
    for name in ("alertmanager", "datadog"):
        assert 'authorization_type = "CUSTOM" authorizer_id = aws_apigatewayv2_authorizer.webhook.id' in found[name]
    assert found["approval"].count("authorization_type") == 1
    assert '"NONE"' in found["approval"]  # only through the documented list: contains(local.edge_gated, ...)
    _, routes = _approval_routes()
    assert len(routes - OPEN) == len(edge_auth.GATED)


def test_the_authorizer_is_uncached_outside_the_vpc_and_reads_only_the_app_secret_and_the_approver_list():
    edge = _flat((MODULE / "edgeauth.tf").read_text(encoding="utf-8"))
    for setting in ('authorizer_type = "REQUEST"', "authorizer_uri = aws_lambda_function.edge_auth.invoke_arn",
                    'authorizer_payload_format_version = "2.0"', "enable_simple_responses = true",
                    "identity_sources = []", "authorizer_result_ttl_in_seconds = 0"):
        assert setting in edge, setting
    fn = edge[edge.index('resource "aws_lambda_function" "edge_auth"'):edge.index('resource "aws_lambda_permission"')]
    assert 'command = ["warden.edge_auth.handler"]' in fn
    assert "vpc_config" not in fn
    assert "variables = { WARDEN_ENV = var.environment }" in fn
    policy = edge[edge.index('resource "aws_iam_role_policy" "edge_auth"'):edge.index('resource "aws_cloudwatch_log_group"')]
    assert "local.audit_and_settings[0], local.who_may_approve," in policy
    assert policy.count('Effect = "Allow"') == 2
    assert 'Resource = ["${local.secret_arn}/slack-client-secret-??????"] }' in policy  # that secret alone
    assert policy.count("secret_arn") == 1
    assert '"${aws_cloudwatch_log_group.edge_auth.arn}:*"' in policy
    iam = _flat((MODULE / "iam.tf").read_text(encoding="utf-8"))
    assert 'Sid = "ItsOwnSettings"' in iam.split("audit_and_settings = [")[1].split("}")[0]  # [0] is the settings read
    assert 'Action = ["ssm:GetParametersByPath"]' in iam.split("audit_and_settings = [")[1].split("}")[0]
    assert "permissions_boundary = var.permissions_boundary_arn" in edge
    assert "/authorizers/${aws_apigatewayv2_authorizer.edge.id}" in edge
    assert "retention_in_days = 90" in edge


def test_the_stage_throttles_and_logs_every_route_with_the_authorizers_refusals():
    front = _flat((MODULE / "frontdoor.tf").read_text(encoding="utf-8"))
    stage = front[front.index('resource "aws_apigatewayv2_stage" "front"'):front.index('resource "aws_apigatewayv2_integration"')]
    assert "default_route_settings { throttling_rate_limit = var.api_rate_limit" in stage
    assert "throttling_burst_limit = var.api_burst_limit" in stage
    assert "destination_arn = aws_cloudwatch_log_group.api_access.arn" in stage
    assert 'authError = "$context.authorizer.error"' in stage
    assert 'status = "$context.status"' in stage
    assert "route_settings" not in stage.replace("default_route_settings", "")  # no route given looser limits


def test_an_erroring_gate_pages_a_person():
    paging = _flat((MODULE / "paging.tf").read_text(encoding="utf-8"))
    functions = paging[paging.index("paged_functions = "):paging.index("audit_db_dimensions")]
    assert "edge-auth = aws_lambda_function.edge_auth.function_name" in functions
