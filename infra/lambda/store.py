"""DynamoDB storage for per-session canaries and leak alerts (issue #2)."""
import os
import secrets
import time
import uuid

import boto3
from botocore.exceptions import ClientError

_ddb = boto3.resource("dynamodb")
_sessions = _ddb.Table(os.environ["SESSIONS_TABLE"])
_alerts = _ddb.Table(os.environ["ALERTS_TABLE"])

SESSION_TTL_SECONDS = 24 * 3600      # sessions auto-delete after 1 day
ALERT_TTL_SECONDS = 7 * 24 * 3600    # alerts auto-delete after 7 days


def get_or_create_canary(session_id):
    """Return this session's canary, creating and saving one if it's new."""
    item = _sessions.get_item(
        Key={"session_id": session_id}, ConsistentRead=True
    ).get("Item")
    if item:
        return item["canary"]

    canary = "CANARY-" + secrets.token_hex(8)
    now = int(time.time())
    try:
        # Only create if no other request created it first
        _sessions.put_item(
            Item={
                "session_id": session_id,
                "canary": canary,
                "blocked": False,
                "created_at": now,
                "expires_at": now + SESSION_TTL_SECONDS,
            },
            ConditionExpression="attribute_not_exists(session_id)",
        )
        return canary
    except ClientError as e:
        if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
            # Another request won the race; use its canary
            return _sessions.get_item(
                Key={"session_id": session_id}, ConsistentRead=True
            )["Item"]["canary"]
        raise


def write_alert(session_id, reason, details=None):
    """Save a leak alert for a session. Returns the alert_id.

    details: optional dict of short strings. Never put the canary
    or the leaked reply text in here.
    """
    now = time.time()
    alert_id = (
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
        + "#" + uuid.uuid4().hex[:8]
    )
    item = {
        "session_id": session_id,
        "alert_id": alert_id,
        "reason": reason,
        "created_at": int(now),
        "expires_at": int(now) + ALERT_TTL_SECONDS,
    }
    if details:
        item["details"] = {k: str(v) for k, v in details.items()}
    _alerts.put_item(Item=item)
    return alert_id