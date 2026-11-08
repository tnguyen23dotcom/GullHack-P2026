"""Gateway Lambda: chat via Bedrock, with a hook for egress checks.

Request:  POST /chat  {"session_id": "...", "message": "..."}
Response: 200 {"session_id": "...", "reply": "..."}
"""

import json
import logging
import os
import uuid

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from checks.prompt import build_system_prompt
from store import get_or_create_canary

logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

MODEL_ID = os.environ["MODEL_ID"]
MAX_MESSAGE_CHARS = 4000
MAX_SESSION_ID_CHARS = 128
MAX_REPLY_TOKENS = 512

# Created once per container, reused across invocations.
bedrock = boto3.client("bedrock-runtime")


def run_checks(reply: str, session_id: str) -> str:
    """TODO(#3): run the exact, normalized and semantic checks here.

    Should return the reply if it is clean, or withhold it if a leak is flagged.
    Currently passes everything through unchanged.
    """
    return reply


def _response(status: int, body: dict) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def lambda_handler(event, context):
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

    reply = run_checks(reply, session_id)

    return _response(200, {"session_id": session_id, "reply": reply})