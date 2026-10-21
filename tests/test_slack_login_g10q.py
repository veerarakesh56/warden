"""Sign in with Slack binds WHO is at the approval page to the approver the link was made for (register G10-37).

Owner, 2026-10-12: "it should automatically be linked to the Slack user id plus this passkey, so the tracking, the
authentication and the authorisation are all in place" - and, of a typed name or id: "if they wanted to, they would
write a different one". With a Slack app configured, a link opens only for the Slack member its approver is, said by
Slack itself, before the passkey; an enrolment writes the member Slack named into the list it hands back."""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import pathlib
import urllib.parse

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_approval_page import PLAN, T0, _show
from test_enrol_passkey_g10h import _pem
from test_passkeys_h6 import RP, SoftAuthenticator
from warden import approvals, audit, settings, slack_login
from warden.approval_page import ApprovalPage, AuditLinkStore, invite

ROOT = pathlib.Path(__file__).resolve().parents[1]
CLIENT = "1234.5678"
MEMBER = "U" + "0" * 3 + "ABCDEFG"  # placeholder ids, built from parts
TEAM = "T" + "0" * 3 + "TEAM1"
OTHER = "U" + "0" * 3 + "ZZZZZZZ"


def _id_token(**over):
    claims = {"iss": slack_login.ISSUER, "aud": CLIENT, "exp": 2_000_000_000, "nonce": "n",
              slack_login.USER_CLAIM: MEMBER, slack_login.TEAM_CLAIM: TEAM, **over}
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return f"header.{body}.signature"


class Slack:
    """Slack's token endpoint, as the client sees it: answers the code it was given with an ID token."""

    def __init__(self, **claims):
        self.claims, self.asked = claims, []

    def __call__(self, url, form):
        self.asked.append((url, dict(form)))
        return {"ok": True, "id_token": _id_token(nonce=self.nonce, **self.claims)}

    nonce = "n"


def _login(slack=None, clock=lambda: 1_900_000_000.0):
    return slack_login.SlackLogin(CLIENT, "s3cret-not-real", post=slack or Slack(), clock=clock)


# ------------------------------------------------------------------ the client


def test_the_member_is_whoever_slack_says_and_every_other_answer_is_refused():
    slack = Slack()
    login = _login(slack)
    assert login.member("the-code", redirect_uri="https://x.test/s/callback", nonce="n") == {
        "user": MEMBER, "team": TEAM}
    (url, form), = slack.asked
    assert url == slack_login.TOKEN_ENDPOINT
    assert form["code"] == "the-code"
    assert form["client_id"] == CLIENT
    assert form["redirect_uri"] == "https://x.test/s/callback"
    assert form["grant_type"] == "authorization_code"
    for wrong, needle in (({"iss": "https://evil.test"}, "not issued by Slack"), ({"aud": "another-app"}, "not issued"),
                          ({"exp": 1}, "expired"), ({slack_login.USER_CLAIM: "", "sub": ""}, "named no member")):
        wrong_token = _login(Slack(**wrong))
        with pytest.raises(slack_login.SlackLoginError, match=needle):
            wrong_token.member("c", redirect_uri="r", nonce="n")
    with pytest.raises(slack_login.SlackLoginError, match="does not belong to this page"):
        login.member("c", redirect_uri="r", nonce="another-pages-nonce")
    for answer in ({"ok": False, "error": "invalid_code"}, {"ok": True}, "not json", {"ok": True, "id_token": "x"}):
        bad_answer = _login(lambda url, form, a=answer: a)
        with pytest.raises(slack_login.SlackLoginError):
            bad_answer.member("c", redirect_uri="r", nonce="n")

    def down(url, form):
        raise TimeoutError("no route to Slack")
    unreachable = _login(down)
    with pytest.raises(slack_login.SlackLoginError, match="could not be reached"):
        unreachable.member("c", redirect_uri="r", nonce="n")


def test_the_authorize_address_is_slacks_with_state_and_nonce_and_the_feature_is_off_without_both_settings(monkeypatch):
    url = urllib.parse.urlparse(_login().authorize_url(redirect_uri="https://x.test/s/callback", state="st", nonce="no"))
    asked = urllib.parse.parse_qs(url.query)
    sent_to = f"{url.scheme}://{url.netloc}{url.path}"
    assert sent_to == slack_login.AUTHORIZE_ENDPOINT
    assert asked == {"response_type": ["code"], "scope": ["openid profile"], "client_id": [CLIENT], "state": ["st"],
                     "nonce": ["no"], "redirect_uri": ["https://x.test/s/callback"]}
    for name in ("WARDEN_SLACK_CLIENT_ID", "WARDEN_SLACK_CLIENT_SECRET"):
        monkeypatch.delenv(name, raising=False)
    assert slack_login.from_environment() is None
    monkeypatch.setenv("WARDEN_SLACK_CLIENT_ID", CLIENT)
    assert slack_login.from_environment() is None  # the id alone: no sign-in to offer
    monkeypatch.setenv("WARDEN_SLACK_CLIENT_SECRET", "x")
    assert slack_login.from_environment().client_id == CLIENT


# ------------------------------------------------------------------ the page


def _with_slack(page, member=MEMBER, **claims):
    slack = Slack(**claims)
    policy = page.policy.model_copy(deep=True)
    policy.approvers["owner"].slack = member
    return dataclasses.replace(page, policy=policy, slack=_login(slack)), slack


def _sign_in(page, slack, kind, token):
    """Follow the two redirects a browser would: to Slack, and back with its code."""
    out = page.handle("GET", f"/s/{kind}/{token}")
    assert out.status == 302, out.body
    assert out.headers["Location"].startswith(slack_login.AUTHORIZE_ENDPOINT), out.body
    cookie = out.headers["Set-Cookie"].split(";")[0]
    asked = urllib.parse.parse_qs(urllib.parse.urlparse(out.headers["Location"]).query)
    assert token not in out.headers["Location"]  # the link never goes to Slack
    assert asked["state"] == [hashlib.sha256(cookie.split("=", 1)[1].encode()).hexdigest()]
    slack.nonce = asked["nonce"][0]
    return page.handle("GET", "/s/callback", query=f"code=c1&state={asked['state'][0]}", cookies=[cookie])


def test_a_link_opens_only_after_slack_says_it_is_the_approver_it_was_made_for(page_setup):
    page, device, _, _ = page_setup
    page, slack = _with_slack(page)
    token = page.new_link("rem-dev-1", "owner")
    shell = page.handle("GET", f"/a/{token}")
    assert shell.status == 200
    assert 'data-slack="1"' in shell.body
    for step in ("login-options", "approve-options", "deny-options"):
        blocked = page.handle("POST", f"/a/{token}/{step}")
        assert blocked.status == 403
        assert json.loads(blocked.body) == {"error": "sign in with Slack first"}
    back = _sign_in(page, slack, "a", token)
    assert back.status == 302
    assert back.headers["Location"] == f"/a/{token}"
    assert 'data-slack="0"' in page.handle("GET", f"/a/{token}").body
    assert _show(page, device, token).status == 200  # and now the passkey shows the plan
    # Without a Slack app the page is as it was: the passkey alone.
    plain = page_setup[0]
    assert 'data-slack="0"' in plain.handle("GET", f"/a/{plain.new_link('rem-dev-1', 'owner')}").body
    assert plain.handle("GET", f"/s/a/{token}").status == 404


def test_another_slack_member_or_a_sign_in_begun_elsewhere_opens_nothing(page_setup):
    page, slack = _with_slack(page_setup[0], member=OTHER)  # the approver is another member than Slack will name
    token = page.new_link("rem-dev-1", "owner")
    refused = _sign_in(page, slack, "a", token)
    assert refused.status == 403
    assert "not the approver this link was made for" in refused.body
    assert "owner" not in refused.body
    assert page.handle("POST", f"/a/{token}/login-options").status == 403
    page, slack = _with_slack(page_setup[0])
    token = page.new_link("rem-dev-1", "owner")
    start = page.handle("GET", f"/s/a/{token}")
    cookie = start.headers["Set-Cookie"].split(";")[0]
    state = urllib.parse.parse_qs(urllib.parse.urlparse(start.headers["Location"]).query)["state"][0]
    for query, cookies in ((f"code=c&state={state}", []), ("code=c&state=forged", [cookie]),
                           (f"state={state}", [cookie]), (f"code=c&state={state}", ["warden_s=a/other.n"])):
        assert page.handle("GET", "/s/callback", query=query, cookies=cookies).status == 400
    assert page.handle("GET", "/s/a/not-a-link").status == 404
    assert page.handle("POST", f"/s/a/{token}").status == 404
    # An approver with no Slack member in the list cannot approve where sign-in is on: enrolment links one.
    page, slack = _with_slack(page_setup[0], member="")
    token = page.new_link("rem-dev-1", "owner")
    assert "has no Slack identity in the approver list yet" in _sign_in(page, slack, "a", token).body


def test_an_enrolment_links_the_member_slack_named_and_never_another_than_the_lists(tmp_path):
    key = Ed25519PrivateKey.generate()
    policy = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(public_key=_pem(key), tiers=["T1", "T2"])})
    slack = Slack()
    log = audit.AuditLog(tmp_path / "a.db")
    page = ApprovalPage(rp_id=RP, policy=policy, plan_of=lambda wf: PLAN, signal=lambda wf, a: None,
                        clock=lambda: T0, slack=_login(slack), store=AuditLinkStore(log, clock=lambda: T0))
    token = invite(key, "owner", now=T0)
    assert 'data-slack="1"' in page.handle("GET", f"/e/{token}").body
    assert page.handle("POST", f"/e/{token}/options").status == 403
    assert _sign_in(page, slack, "e", token).headers["Location"] == f"/e/{token}"
    options = page.handle("POST", f"/e/{token}/options")
    done = page.handle("POST", f"/e/{token}/finish", json.dumps({"response": SoftAuthenticator().register(
        json.dumps(json.loads(options.body)["options"]))}))
    listed = approvals.ApproverPolicy.loads(json.loads(done.body)["approvers"])
    assert listed.approvers["owner"].slack == MEMBER
    assert len(listed.approvers["owner"].passkeys) == 1
    [row] = [e["body"] for e in log.entries(kinds=("approval.slack_verified",))]
    assert row["approver"] == "owner"
    assert row["slack_user"] == MEMBER
    assert token not in json.dumps(row)
    # Once the list names a member, an enrolment by any other Slack account is refused.
    named = listed.model_copy(deep=True)
    named.approvers["owner"].slack = OTHER
    again, token2 = dataclasses.replace(page, policy=named), invite(key, "owner", now=T0)
    assert "not the approver this link was made for" in _sign_in(again, slack, "e", token2).body


def test_the_runtime_gives_the_secret_to_the_approval_lambda_alone_and_routes_the_two_steps():
    assert "WARDEN_SLACK_CLIENT_SECRET" in settings.SECRETS
    assert {n for n, names in settings.LAMBDA_SECRETS.items() if "WARDEN_SLACK_CLIENT_SECRET" in names} == {"approval"}
    assert settings.RESTRICTED["WARDEN_SLACK_CLIENT_SECRET"] == frozenset({"lambda-approval"})
    assert "WARDEN_SLACK_CLIENT_ID" not in settings.SECRETS  # an id, not a secret: plain configuration
    for zone in settings.ZONE_SECRETS:
        assert "WARDEN_SLACK_CLIENT_SECRET" not in settings.loadable_for("worker", zone)
    assert "WARDEN_SLACK_CLIENT_SECRET" not in settings.loadable_for("lambda-alarm")
    assert settings.secret_id("ops", "WARDEN_SLACK_CLIENT_SECRET") == "warden/ops/slack-client-secret"
    iam = (ROOT / "terraform" / "modules" / "warden-runtime" / "iam.tf").read_text(encoding="utf-8")
    approval = next(line for line in iam.splitlines() if line.strip().startswith("approval "))
    assert '"slack-client-secret"' in approval
    assert iam.count('"slack-client-secret"') == 1
    tf = (ROOT / "terraform" / "modules" / "warden-runtime" / "frontdoor.tf").read_text(encoding="utf-8")
    assert '"GET /s/callback", "GET /s/{kind}/{token}"' in tf
    lambdas = (ROOT / "src" / "warden" / "lambdas.py").read_text(encoding="utf-8")
    assert 'query=str(event.get("rawQueryString") or ""), cookies=event.get("cookies") or []' in lambdas
    src = (ROOT / "src" / "warden").rglob("*.py")
    assert not any(CLIENT in p.read_text(encoding="utf-8") for p in src)  # no app's id is written into the code


def test_the_kill_switch_reset_asks_slack_who_is_there_first_too(tmp_path):
    from test_killswitch_reset_g10m import World
    from warden import bounds
    from warden.approval_page import INVITE

    world = World(tmp_path)
    stranger, slack = _with_slack(world.page, member=OTHER)
    refused = _sign_in(stranger, slack, "k", world.link())
    assert refused.status == 403
    assert "not the approver this link was made for" in refused.body
    world.page, slack = _with_slack(world.page)
    token = world.link()
    assert 'data-slack="1"' in world.page.handle("GET", f"/k/{token}").body
    for step in ("trips", "reset"):
        assert world.page.handle("POST", f"/k/{token}/{step}").status == 403
    assert world.page.handle("GET", f"/s/k/{world.link(INVITE)}").status == 404  # an enrolment's link is no reset's
    assert world.page.handle("GET", f"/s/x/{token}").status == 404
    assert _sign_in(world.page, slack, "k", token).headers["Location"] == f"/k/{token}"
    _, done = world.reset(token)
    assert done.status == 200
    assert bounds.killswitch(world.log) is None


def test_a_browser_slack_named_is_remembered_for_the_next_links_and_the_passkey_is_still_asked(page_setup, tmp_path):
    """Owner, 2026-10-12: "why do I see that Slack thing again and again ... it should be only the first time".
    Slack is asked once in thirty days per browser, not once per link; every decision still takes the passkey; the
    record says how the member was known."""
    page, device, _, _ = page_setup
    log = audit.AuditLog(tmp_path / "a.db")
    now = [1_900_000_000.0]
    page = dataclasses.replace(_with_slack(page)[0], store=AuditLinkStore(log, clock=page.clock))
    slack = Slack()
    page = dataclasses.replace(page, slack=_login(slack, clock=lambda: now[0]))
    first = page.new_link("rem-dev-1", "owner")
    kept = _sign_in(page, slack, "a", first).headers["Set-Cookie"]
    assert kept.startswith("warden_who=" + MEMBER + ".")
    assert (kept.endswith(
        "; Max-Age=2592000; Path=/; Secure; HttpOnly; SameSite=Lax"))
    who = kept.split(";")[0]
    second = page.new_link("rem-dev-1", "owner")
    assert 'data-slack="1"' in page.handle("GET", f"/a/{second}").body               # another browser: Slack first
    assert 'data-slack="0"' in page.handle("GET", f"/a/{second}", cookies=[who]).body  # this one: straight to the passkey
    assert len(slack.asked) == 1
    assert _show(page, device, second).status == 200
    rows = [e["body"] for e in log.entries(kinds=("approval.slack_verified",))]
    assert [(r["slack_user"], r["via"]) for r in rows] == [(MEMBER, "sign-in"), (MEMBER, "remembered")]
    # Forged, cut, another member's, or past its thirty days: Slack is asked again.
    third = page.new_link("rem-dev-1", "owner")
    member, until, mac = who.split("=", 1)[1].split(".")
    other = slack_login.remember(page.slack, OTHER)
    for bad in (f"warden_who={OTHER}.{until}.{mac}", f"warden_who={member}.{int(until) + 9}.{mac}",
                f"warden_who={member}.{until}", "warden_who=", f"warden_who={other}", f"other={who.split('=', 1)[1]}"):
        assert 'data-slack="1"' in page.handle("GET", f"/a/{third}", cookies=[bad]).body, bad
    now[0] += slack_login.REMEMBER_S + 1
    assert 'data-slack="1"' in page.handle("GET", f"/a/{third}", cookies=[who]).body
    assert slack_login.remembered(page.slack, who.split("=", 1)[1]) == ""
    assert slack_login.REMEMBER_S == 30 * 24 * 3600
    # Sealed with the app's own secret: a value another secret made is nobody.
    stranger = slack_login.SlackLogin(CLIENT, "another-secret", clock=lambda: 1_900_000_000.0)
    assert slack_login.remembered(stranger, slack_login.remember(_login(), MEMBER)) == ""
    # An approver with no Slack member yet is linked at a real sign-in, never from a remembered browser.
    now[0] = 1_900_000_000.0
    unlinked = dataclasses.replace(page, policy=page_setup[0].policy)
    assert 'data-slack="1"' in unlinked.handle("GET", f"/a/{unlinked.new_link('rem-dev-1', 'owner')}", cookies=[who]).body
