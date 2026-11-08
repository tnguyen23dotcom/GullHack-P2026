"""Gateway Lambda: chat via Bedrock, with a hook for egress checks.

Request:  POST /chat  {"session_id": "...", "message": "..."}
Response: 200 {"session_id": "...", "reply": "...", "blocked": true/false}
"""

import json
import logging
import os
import uuid

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from checks.link_allowlist import LinkAllowlistCheck
from checks.check_interface import SecurityContext
from checks.layer_checks import ExactMatchCheck, FuzzyMatchCheck, NormalizedMatchCheck
from checks.opaque_output import OpaqueOutputCheck
from checks.policy_facts import PolicyFactCheck
from checks.prompt import PROTECTED_POLICIES, build_system_prompt, get_static_secret_values
from store import get_or_create_canary, write_alert, is_session_blocked, list_alerts

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

MODEL_ID = os.environ["MODEL_ID"]
MAX_MESSAGE_CHARS = 4000
MAX_SESSION_ID_CHARS = 128
MAX_REPLY_TOKENS = 512

# Created once per container, reused across invocations.
bedrock = boto3.client("bedrock-runtime")

# Egress checks (#3), cheapest first. Built once per container.
# The semantic layer (Person C) is not here: its model is too big for this zip. Its results are
# measured offline in eval/. Add it here only if the Lambda is moved to a container image.
CHECKS = [ExactMatchCheck(), NormalizedMatchCheck(), PolicyFactCheck(), OpaqueOutputCheck(),LinkAllowlistCheck(), FuzzyMatchCheck()]
WITHHELD_REPLY = "This reply was withheld by the security gateway because it may contain protected information."


def run_checks(reply: str, session_id: str, canary: str):
    """Run every check on the model's reply before the user sees it (#3).

    Returns (reply_to_send, blocked_by): the original reply and None if it is clean, or
    WITHHELD_REPLY and the name of the layer that flagged it. Fails closed: if a check
    crashes, the reply is withheld. Never logs or stores the reply, the canary or the
    matched secret (CheckResult.matched_fragment).
    """
    context = SecurityContext(
        session_id=session_id,
        session_canary=canary,
        static_secrets=get_static_secret_values(),
        protected_chunks=list(PROTECTED_POLICIES),
    )
    for check in CHECKS:
        try:
            result = check.evaluate(reply, context)
        except Exception as err:  # fail closed: a broken check must not let a leak through
            logger.error("check %s failed: %s (session %s)", check.name, type(err).__name__, session_id)
            _save_alert(session_id, f"Check {check.name} failed; reply withheld", {"layer": check.name})
            return WITHHELD_REPLY, check.name
        if result.is_violation:
            logger.warning("leak blocked by %s (session %s)", result.layer_name, session_id)
            _save_alert(session_id, result.reason or "Leak detected", {
                "layer": result.layer_name,
                "confidence": f"{result.confidence:.2f}",
                "latency_ms": f"{result.latency_ms:.1f}",
            })
            return WITHHELD_REPLY, result.layer_name
    return reply, None


def _save_alert(session_id, reason, details):
    """Write the alert to DynamoDB. The reply is withheld even if this write fails."""
    try:
        write_alert(session_id, reason, details)
    except (ClientError, BotoCoreError) as err:
        code = getattr(err, "response", {}).get("Error", {}).get("Code", type(err).__name__)
        logger.error("alert write failed: %s (session %s)", code, session_id)


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }

def _alerts_endpoint(event):
    """GET /alerts (optionally ?session_id=...) for Person D's dashboard."""
    params = event.get("queryStringParameters") or {}
    session_id = params.get("session_id")
    try:
        alerts = list_alerts(session_id)
    except (ClientError, BotoCoreError) as err:
        code = getattr(err, "response", {}).get("Error", {}).get("Code", type(err).__name__)
        logger.error("list_alerts failed: %s", code)
        return _response(503, {"error": "alert store unavailable"})
    return _response(200, {"alerts": alerts})

def lambda_handler(event, context):
    if event.get("routeKey") == "GET /alerts":
        return _alerts_endpoint(event)
    try:
        body = json.loads(event.get("body") or "{}")
    except (json.JSONDecodeError, TypeError):
        return _response(400, {"error": "body must be JSON"})
    if not isinstance(body, dict):
        return _response(400, {"error": "body must be a JSON object"})

    message = body.get("message")
    if not isinstance(message, str) or not message.strip():
        return _response(400, {"error": "message is required"})
    if len(message) > MAX_MESSAGE_CHARS:
        return _response(400, {"error": f"message is longer than {MAX_MESSAGE_CHARS} characters"})

    # 1. Work out the session ID first (make a new one if none was sent)
    session_id = body.get("session_id")
    if not isinstance(session_id, str) or not session_id.strip():
        session_id = str(uuid.uuid4())
    session_id = session_id.strip()
    if len(session_id) > MAX_SESSION_ID_CHARS:
        return _response(400, {"error": "session_id is too long"})

    # 2. Look up or create this session's canary in DynamoDB (#2)
    try:
        canary = get_or_create_canary(session_id)
    except (ClientError, BotoCoreError) as err:
        code = getattr(err, "response", {}).get("Error", {}).get("Code", type(err).__name__)
        logger.error("session store failed: %s (session %s)", code, session_id)
        return _response(503, {"error": "session store unavailable"})
    # Issue #4: refuse sessions that were blocked after a leak
    try:
        if is_session_blocked(session_id):
            logger.warning("request from blocked session %s refused", session_id)
            return _response(200, {
                "session_id": session_id,
                "reply": "This session has been blocked for security reasons. Please start a new session.",
                "blocked": True,
            })
    except (ClientError, BotoCoreError) as err:
        code = getattr(err, "response", {}).get("Error", {}).get("Code", type(err).__name__)
        logger.error("blocked check failed: %s (session %s)", code, session_id)
        return _response(503, {"error": "session store unavailable"})
    # 3. Build Person B's protected prompt with this session's canary.
    #    Never log the canary or the prompt.
    system_prompt = build_system_prompt(canary)

    try:
        result = bedrock.converse(
            modelId=MODEL_ID,
            system=[{"text": system_prompt}],
            messages=[{"role": "user", "content": [{"text": message}]}],
            inferenceConfig={"maxTokens": MAX_REPLY_TOKENS},
        )
    except (ClientError, BotoCoreError) as err:
        # Log the error type and code only, never the prompt or the message.
        code = getattr(err, "response", {}).get("Error", {}).get("Code", type(err).__name__)
        logger.error("bedrock converse failed: %s (session %s)", code, session_id)
        return _response(502, {"error": "upstream model error"})

    blocks = result["output"]["message"]["content"]
    reply = "".join(b.get("text", "") for b in blocks)

    reply, blocked_by = run_checks(reply, session_id, canary)

    return _response(200, {"session_id": session_id, "reply": reply, "blocked": blocked_by is not None})