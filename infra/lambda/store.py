"""DynamoDB storage for per-session canaries and leak alerts (issue #2)."""
import os
import secrets
import time
import uuid
import json
import logging
import boto3

from botocore.exceptions import ClientError
from decimal import Decimal
from boto3.dynamodb.conditions import Key

logger = logging.getLogger()
_events = boto3.client("events")
EVENT_SOURCE = os.environ.get("EVENT_SOURCE", "canary-gateway")

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

def is_session_blocked(session_id):
    """True if this session was blocked after a leak (issue #4)."""
    item = _sessions.get_item(
        Key={"session_id": session_id},
        ProjectionExpression="blocked",
        ConsistentRead=True,
    ).get("Item")
    return bool(item and item.get("blocked"))


def block_session(session_id):
    """Mark the session as blocked so its next request is refused (issue #4)."""
    _sessions.update_item(
        Key={"session_id": session_id},
        UpdateExpression="SET blocked = :t, blocked_at = :now",
        ExpressionAttributeValues={":t": True, ":now": int(time.time())},
    )


def _publish_leak_event(session_id, alert_id, reason):
    """Send a LeakDetected event; EventBridge forwards it to SNS email (issue #4)."""
    _events.put_events(Entries=[{
        "Source": EVENT_SOURCE,
        "DetailType": "LeakDetected",
        "Detail": json.dumps({
            "session_id": session_id,
            "alert_id": alert_id,
            "reason": reason,
        }),
    }])

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
    
    # Issue #4: block the session and send the email alert.
    # If these fail, the leaked reply is still withheld; we only log the error.
    try:
        block_session(session_id)
    except ClientError as e:
        logger.error("block_session failed: %s (session %s)",
                     e.response["Error"]["Code"], session_id)
    try:
        _publish_leak_event(session_id, alert_id, reason)
    except ClientError as e:
        logger.error("publish leak event failed: %s (session %s)",
                     e.response["Error"]["Code"], session_id)

    return alert_id
def _plain(value):
    """Turn DynamoDB Decimals into normal numbers so they can be sent as JSON."""
    if isinstance(value, Decimal):
        return int(value)
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    return value


def list_alerts(session_id=None, limit=50):
    """Newest alerts first. With session_id, only that session's alerts."""
    if session_id:
        items = _alerts.query(
            KeyConditionExpression=Key("session_id").eq(session_id),
            ScanIndexForward=False,
            Limit=limit,
        )["Items"]
    else:
        items = _alerts.scan(Limit=limit)["Items"]
        items.sort(key=lambda a: a["alert_id"], reverse=True)
    fields = ("session_id", "alert_id", "reason", "created_at", "details")
    return [_plain({k: a[k] for k in fields if k in a}) for a in items]