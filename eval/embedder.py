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


def _bedrock_embed(texts, region):
    """Call Titan V2 once per text. boto3 finds credentials the usual way (your AWS CLI setup)."""
    import boto3  # imported here so local mode works without boto3 installed

    client = boto3.client("bedrock-runtime", region_name=region)
    vectors = []
    for text in texts:
        response = client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            contentType="application/json",
            accept="application/json",
            body=json.dumps({"inputText": text, "dimensions": BEDROCK_DIMS, "normalize": True}),
        )
        vectors.append(json.loads(response["body"].read())["embedding"])
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
