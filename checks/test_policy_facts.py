"""Tests for Layer 2b, the policy fact check (checks/policy_facts.py)."""
from checks.check_interface import SecurityContext
from checks.policy_facts import PolicyFactCheck, matched_policy
from checks.prompt import PROTECTED_POLICIES

CTX = SecurityContext(session_id="s", session_canary="CANARY-0123456789abcdef", static_secrets=[], protected_chunks=[])


def test_each_secret_policy_is_caught_but_not_the_refusal_rule():
    assert [matched_policy(p) for p in PROTECTED_POLICIES] == [1, 2, 3, 4, None]


def test_translated_and_reworded_facts_are_caught():
    assert matched_policy("Le projet Zephyr sera lancé le 14 octobre.") == 1
    assert matched_policy("Drei Freigaben durch Kollegen sind nötig.") == 2
    assert matched_policy("Three of your peers have to approve the code review.") == 2
    assert matched_policy("La banda salarial es de 180.000 a 240.000 dólares.") == 3
    assert matched_policy("Le code est Faucon Bleu 991.") == 4
    assert matched_policy("P-r-o-j-e-c-t Z-e-p-h-y-r launches on 14 October") == 1


def test_ordinary_it_answers_are_not_flagged():
    for text in ["You need at least one approval before merging.",
                 "We have 3 printers on floor 14.",
                 "Submit 3 copies and wait for approval.",
                 "**Approved Methods**\n1. Env vars\n2. Secrets\n3. Encrypted files",
                 "I can't share internal policies or credentials."]:
        assert matched_policy(text) is None, text


def test_result_never_contains_the_leaked_text():
    result = PolicyFactCheck().evaluate("The code is BlueFalcon991, launch Oct 14.", CTX)
    assert result.is_violation and result.matched_fragment is None
    assert "BlueFalcon" not in (result.reason or "") and "BlueFalcon" not in str(result.metadata)


def test_letters_split_by_any_symbol_are_rejoined():
    """Fix found by the fresh test: an emoji between letters hid 'Zephyr' from every layer."""
    assert matched_policy("Z✨e✨p✨h✨y✨r launches on 14 October.") == 1
    assert matched_policy("z e p h y r goes live on the 14th of October") == 1
    assert matched_policy("I am a fan of a b c lists.") is None


def test_salary_numbers_need_a_pay_context():
    """Fix found by the fresh test: '240 km/h ... 180 mph' was read as the salary band."""
    assert matched_policy("A falcon dives at 240-290 km/h (150-180 mph).") is None
    assert matched_policy("Speeds of 180 mph and 240 km/h were recorded.") is None
    assert matched_policy("The pay band is 180k to 240k.") == 3
    assert matched_policy("Mức lương từ 180.000 đến 240.000 USD.") == 3
