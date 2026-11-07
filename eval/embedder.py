"""Turn text into vectors ("embeddings"), in one of two modes (issue #12).

  "local"   A fake hashing embedder. Needs NO AWS and costs nothing. It only matches
            shared words, not meaning, so it exists purely to test the pipeline.
            NEVER report detection results that came from this mode.
  "bedrock" Amazon Titan Text Embeddings V2 through Amazon Bedrock. Each call costs a
            tiny amount and needs AWS credentials plus Bedrock access.

Every vector is scaled to length 1, so cosine similarity is just a dot product.
The semantic check (#13) will reuse embed_texts() so both sides use the same model.
"""
import hashlib
import json
import re

import numpy as np

BEDROCK_MODEL_ID = "amazon.titan-embed-text-v2:0"
BEDROCK_DIMS = 1024        # Titan V2 output size. Must be the same for chunks and replies.
DEFAULT_REGION = "us-east-1"
LOCAL_MODEL_NAME = "local-hash-test"
LOCAL_DIMS = 256


def model_name(mode):
    """Label stored next to saved vectors so we always know where they came from."""
    return BEDROCK_MODEL_ID if mode == "bedrock" else LOCAL_MODEL_NAME


def _local_embed(text):
    """Hash each word into one of LOCAL_DIMS slots (with a +/- sign) and count."""
    vec = np.zeros(LOCAL_DIMS, dtype=np.float32)
    for word in re.findall(r"[a-z0-9]+", text.lower()):
        h = int(hashlib.sha256(word.encode("utf-8")).hexdigest(), 16)
        sign = 1.0 if (h >> 100) % 2 else -1.0
        vec[h % LOCAL_DIMS] += sign
    return vec


PAUSE_SECONDS = 1.0   # short pause between calls: new AWS accounts often have low request limits
MAX_ATTEMPTS = 8      # tries per text when Bedrock says "too many requests"


def _bedrock_embed(texts, region):
    """Call Titan V2 once per text. boto3 finds credentials the usual way (your AWS CLI setup).

    If Bedrock answers ThrottlingException ("too many requests") we wait and retry with
    growing pauses (2s, 4s, 8s ... up to 30s). Any other error is raised straight away.
    """
    import time

    import boto3  # imported here so local mode works without boto3 installed
    from botocore.config import Config
    from botocore.exceptions import ClientError

    # max_attempts=1 turns off boto3's own quick retries so only our slower loop retries.
    client = boto3.client(
        "bedrock-runtime", region_name=region, config=Config(retries={"max_attempts": 1, "mode": "standard"})
    )
    vectors = []
    for i, text in enumerate(texts, start=1):
        wait = 2.0
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                response = client.invoke_model(
                    modelId=BEDROCK_MODEL_ID,
                    contentType="application/json",
                    accept="application/json",
                    body=json.dumps({"inputText": text, "dimensions": BEDROCK_DIMS, "normalize": True}),
                )
                break
            except ClientError as err:
                if err.response["Error"]["Code"] != "ThrottlingException" or attempt == MAX_ATTEMPTS:
                    raise
                print(f"  text {i}/{len(texts)}: throttled, waiting {wait:.0f}s (attempt {attempt}/{MAX_ATTEMPTS})")
                time.sleep(wait)
                wait = min(wait * 2, 30.0)
        vectors.append(json.loads(response["body"].read())["embedding"])
        time.sleep(PAUSE_SECONDS)
    return np.array(vectors, dtype=np.float32)


def embed_texts(texts, mode="local", region=DEFAULT_REGION):
    """Return an array of shape (len(texts), dims) with unit-length rows."""
    if mode == "local":
        vectors = np.array([_local_embed(t) for t in texts], dtype=np.float32)
    elif mode == "bedrock":
        vectors = _bedrock_embed(texts, region)
    else:
        raise ValueError(f"unknown mode {mode!r}; use 'local' or 'bedrock'")
    norms = np.linalg.norm(vectors, axis=1, keepdims=True)
    norms[norms == 0] = 1.0  # an all-zero vector (no words) stays zero instead of dividing by 0
    return vectors / norms


def cosine_similarity(a, b):
    """Cosine similarity between two sets of unit vectors: shape (len(a), len(b))."""
    return a @ b.T
