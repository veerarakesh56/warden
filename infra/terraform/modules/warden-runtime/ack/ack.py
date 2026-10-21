"""Slack's note of a button click, answered - and nothing else.

Slack tells an app of every button click, a link button's too, and shows "Operation timed out" beside the button
unless the app answers within three seconds. WARDEN's approval link is such a button: the click opens the approval
page, where Slack sign-in and the passkey decide. This function reads nothing, calls nothing and holds no
permission; it exists so that the answer never waits for the approval function to start.
"""


def handler(event, context):
    return {"statusCode": 200, "headers": {"Content-Type": "text/plain", "Cache-Control": "no-store"}, "body": ""}
