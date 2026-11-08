"""Layer 4 of the gateway: the semantic check, built on Person B's BaseCheck interface (issue #13).

What it does for one chatbot reply:
  1. Embed every protected policy in context.protected_chunks (done once, then cached).
  2. Split the reply into sentences and embed each one.
  3. Find the highest cosine similarity between any sentence and any policy.
  4. Flag the reply when that score reaches the threshold.

Why it exists: exact and normalized checks look for the same characters. A leak that has been
translated or reworded shares the meaning but not the characters, so only a meaning-based
comparison can catch it.

Usage (the gateway loops over checks without knowing what is inside each one):
  check = SemanticCheck(threshold=0.85, mode="local-model")   # or mode="bedrock" once quotas allow
  result = check.evaluate(reply_text, security_context)        # returns a CheckResult

The result never copies policy text into metadata or reasons, so logs and the dashboard do not
re-leak the secrets. matched_fragment holds the reply sentence that triggered the alert.
"""
import time

import numpy as np

from b_contract import BaseCheck, CheckResult
from embedder import DEFAULT_REGION, embed_texts, model_name
from semantic_check import split_reply


class SemanticCheck(BaseCheck):
    def __init__(self, threshold, mode="local-model", region=DEFAULT_REGION, name="layer_4_semantic"):
        super().__init__(name=name)
        self.threshold = threshold
        self.mode = mode
        self.region = region
        self._chunk_cache = {}  # tuple of policy texts -> their vectors (policies rarely change)

    def _chunk_vectors(self, chunks):
        """Embed the protected policies once and reuse the vectors on later calls."""
        key = tuple(chunks)
        cache_hit = key in self._chunk_cache
        if not cache_hit:
            self._chunk_cache[key] = embed_texts(list(chunks), mode=self.mode, region=self.region)
        return self._chunk_cache[key], cache_hit

    def evaluate(self, model_output, context):
        start = time.perf_counter()
        chunks = [c for c in context.protected_chunks if c and c.strip()]
        sentences = split_reply(model_output or "")
        base_meta = {"model": model_name(self.mode), "threshold": self.threshold, "sentences": len(sentences)}

        # Nothing to compare: no protected policies, or a reply with no real sentences.
        if not chunks or not sentences:
            return CheckResult(
                is_violation=False,
                layer_name=self.name,
                confidence=0.0,
                latency_ms=(time.perf_counter() - start) * 1000.0,
                metadata={**base_meta, "score": 0.0, "chunk_index": None, "chunk_cache_hit": None},
            )

        chunk_vectors, cache_hit = self._chunk_vectors(chunks)
        sentence_vectors = embed_texts(sentences, mode=self.mode, region=self.region)
        similarity = sentence_vectors @ chunk_vectors.T  # rows: reply sentences, columns: policies
        row, col = np.unravel_index(np.argmax(similarity), similarity.shape)
        score = float(similarity[row, col])
        flagged = score >= self.threshold

        return CheckResult(
            is_violation=flagged,
            layer_name=self.name,
            confidence=min(max(score, 0.0), 1.0),
            matched_fragment=sentences[row] if flagged else None,
            reason=(
                f"Reply sentence is semantically similar to protected policy #{col + 1} "
                f"(cosine {score:.3f} >= threshold {self.threshold:.3f})."
                if flagged
                else None
            ),
            latency_ms=(time.perf_counter() - start) * 1000.0,
            metadata={**base_meta, "score": score, "chunk_index": int(col), "chunk_cache_hit": cache_hit},
        )
