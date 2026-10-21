"""The Slack sign-in for WARDEN's own pages (`/s/p`) brings the reader back to `/p`, remembered - the branch of
ApprovalPage._reader_signed_in that no other test pinned."""

from __future__ import annotations

import hashlib
import urllib.parse

from test_slack_login_g10q import MEMBER, Slack, _login
from warden import slack_login
from warden.approval_page import ApprovalPage
from warden.approvals import ApproverPolicy


def test_the_pages_sign_in_comes_back_to_the_pages(monkeypatch):
    monkeypatch.setenv("WARDEN_RECORD_VIEWERS", MEMBER)
    slack = Slack()
    page = ApprovalPage(rp_id="warden.example", policy=ApproverPolicy(approvers={}), plan_of=lambda _: None,
                        signal=lambda *_: None, slack=_login(slack))
    out = page.handle("GET", "/s/p")
    cookie = out.headers["Set-Cookie"].split(";")[0]
    asked = urllib.parse.parse_qs(urllib.parse.urlparse(out.headers["Location"]).query)
    assert asked["state"] == [hashlib.sha256(cookie.split("=", 1)[1].encode()).hexdigest()]
    slack.nonce = asked["nonce"][0]
    back = page.handle("GET", "/s/callback", query=f"code=c1&state={asked['state'][0]}", cookies=[cookie])
    assert back.headers["Location"] == "/p"
    assert back.headers["Set-Cookie"].startswith("warden_who=")
    assert out.headers["Location"].startswith(slack_login.AUTHORIZE_ENDPOINT)
