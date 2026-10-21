"""A plan voided because WARDEN's own code was deployed after it was made reached the channel as
"`dev/lambda:warden-dev-checkout` changed after the plan ..." and the record said "Target changed" - the target had
not changed. The words for a voided plan no longer name a cause; the reason that follows says what changed."""

from __future__ import annotations

from warden import records
from warden.activities import OUTCOME


def test_a_voided_plan_is_not_said_to_be_a_changed_target():
    said = OUTCOME["drifted"].format(entry="lambda_move_alias", target="dev/lambda:warden-dev-checkout")
    assert "changed after the plan" not in said
    assert "the reason is below" in said
    assert "nothing was changed" in said
    assert records.ENDED["drifted"][0] == "Changed since planned - not applied"
    assert records.TOLD["drifted"] == "Changed since planned"
    for words in (records.ENDED["drifted"][0], records.TOLD["drifted"]):
        assert "Target" not in words
