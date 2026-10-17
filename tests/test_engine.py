import pytest

from app.detector import analyze, combine_with_ai

ATTACKS = [
    "' OR '1'='1' --",
    "admin' --",
    "1 OR 1=1",
    "1 UNION SELECT username, password FROM users",
    "1; DROP TABLE users;--",
    "1 AND SLEEP(5)",
    "1' AND (SELECT SUBSTRING(password,1,1) FROM users)='a",
    "1 UNION ALL SELECT NULL,table_name FROM information_schema.tables",
    "1 AND extractvalue(1,concat(0x7e,(select version())))",
    "'; EXEC xp_cmdshell('dir')--",
]

OBFUSCATED = [
    "1%27%20OR%20%271%27%3D%271",            # url-encoded
    "1%2527%2520OR%25201%253D1",             # double-encoded
    "1 UnIoN/**/SeLeCt 1,2,3",               # case + comment whitespace
    "1 UNION%0ASELECT 1,2",                  # newline as whitespace
]

BENIGN = [
    "hello world",
    "John Smith",
    "O'Brien",
    "I want to select a color for my union jacket",
    "price between 100 and 200",
    "name=bob and age=30",
    "user@example.com",
    "Delivery #42 - please call",
]


@pytest.mark.parametrize("payload", ATTACKS)
def test_attacks_flagged(payload):
    r = analyze(payload)
    assert r.verdict in ("suspicious", "malicious"), (payload, r.score, r.verdict)
    assert r.matches


@pytest.mark.parametrize("payload", OBFUSCATED)
def test_obfuscation_still_caught(payload):
    assert analyze(payload).verdict in ("suspicious", "malicious")


@pytest.mark.parametrize("payload", BENIGN)
def test_benign_not_flagged(payload):
    r = analyze(payload)
    assert r.verdict in ("clean", "low_risk"), (payload, r.score, [m.name for m in r.matches])


def test_classic_scores_high():
    assert analyze("1 UNION SELECT 1,2").score >= 70
    assert analyze("' OR '1'='1' --").score >= 70


def test_ai_can_raise_score():
    r = analyze("1' and 1")  # weak signal only
    before = r.score
    r = combine_with_ai(r, {"is_injection": True, "confidence": 0.95})
    assert r.score >= max(before, 95)


def test_ai_cannot_downgrade_malicious():
    r = analyze("1 UNION SELECT 1,2")
    r = combine_with_ai(r, {"is_injection": False, "confidence": 1.0})
    assert r.verdict == "malicious"  # attacker can't talk the model into "safe"


def test_ai_can_soften_weak_signal():
    r = analyze("rock 'n' roll and 1")
    before = r.score
    r = combine_with_ai(r, {"is_injection": False, "confidence": 0.95})
    assert r.score <= before
