"""Owner, 2026-10-15: WARDEN's answers in the discussion channel should be immediate - "within 1 or 2 seconds" - and
compare with similar past incidents. Its record (this incident and the ones like it) is posted first, from the
signed record with no model, and the model's answer follows in the same thread."""

from __future__ import annotations

import asyncio
import json
import os
from concurrent.futures import ThreadPoolExecutor

from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from test_discuss_g10v import INCIDENT, _turn, world  # noqa: F401
from warden import codec, discuss
from warden.cli import DEMO_ALERTS
from warden.models import Alert
from warden.workflows import DiscussWorkflow


def test_the_record_is_posted_first_and_the_answer_after_it(world):  # noqa: F811
    acts = world["acts"]
    pack = world["inc"].prepare(Alert(**{**DEMO_ALERTS["inc-002"], "alert_id": INCIDENT}))
    world["inc"].verify(pack, world["inc"].diagnose(pack))

    async def main():
        env = await WorkflowEnvironment.start_time_skipping(data_converter=codec.data_converter(os.urandom(32)))
        async with env, Worker(env.client, task_queue="facts-test", workflows=[DiscussWorkflow],
                               activities=[acts.discuss_thread, acts.discuss_facts, acts.discuss_evidence,
                                           acts.discuss_answer, acts.discuss_reply],
                               activity_executor=ThreadPoolExecutor(2)):
            return await env.client.execute_workflow(DiscussWorkflow.run, _turn("<@UWARDEN> why did it fire?"),
                                                     id="discuss-facts", task_queue="facts-test")

    said = asyncio.run(main())
    posts = [p for p in world["posted"] if p[0] == "chat.postMessage"]
    texts = [json.dumps(p[1]) + json.dumps(p[2]) for p in posts]
    assert len(posts) >= 2
    assert f"WARDEN's record of `{INCIDENT}`" in texts[0]
    assert "Seen before" in texts[0]
    assert "(a test answer)" in texts[-1]
    assert said.startswith("(a test answer)")
    assert "WARDEN answers in this thread" in discuss.HEARD
    assert "comes first, within seconds" in discuss.HEARD
