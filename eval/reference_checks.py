"""Reference checks used ONLY by the evaluation (issue #14).

ReferenceExactCheck is the BASELINE the project compares against: a plain exact-match canary,
i.e. "does the reply contain the canary or a decoy secret, character for character?". It is
written here so the baseline can be measured before Person B's checks (#7) are pushed. When
B's exact check lands, evaluate.py should use it instead, so the numbers describe the real gateway.
"""
import time

from b_contract import BaseCheck, CheckResult


class ReferenceExactCheck(BaseCheck):
    def __init__(self, name="exact_reference"):
        super().__init__(name=name)

    def evaluate(self, model_output, context):
        start = time.perf_counter()
        text = model_output or ""
        hits = sum(1 for target in context.exact_targets if target and target in text)
        flagged = hits > 0
        return CheckResult(
            is_violation=flagged,
            layer_name=self.name,
            confidence=1.0 if flagged else 0.0,
            matched_fragment=None,  # never copy the secret itself into logs
            reason=f"Reply contains {hits} protected value(s) verbatim." if flagged else None,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            metadata={"hits": hits},
        )
