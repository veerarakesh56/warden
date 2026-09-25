"""warden-pg-fs-notifier - SQS warden-pg-fs-notifications (fed by the SNS topic) -> "send" a notification."""
import json
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)


def handler(event, context):
    for record in event.get("Records", []):
        try:
            order = json.loads(record["body"])
            log.info("notification sent order_id=%s cart_id=%s", order["order_id"], order["cart_id"])
        except (ValueError, KeyError, TypeError):
            log.exception("unreadable order event id=%s", record.get("messageId"))
            raise
