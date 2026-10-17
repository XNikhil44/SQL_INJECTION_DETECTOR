from dataclasses import dataclass, field

from .normalize import normalize
from .rules import RULES

MALICIOUS_AT = 70
SUSPICIOUS_AT = 40
LOW_AT = 15


@dataclass
class Match:
    rule_id: str
    name: str
    category: str
    weight: int
    evidence: str


@dataclass
class DetectionResult:
    original: str
    normalized: str
    score: int
    verdict: str
    matches: list[Match] = field(default_factory=list)
    ambiguous: bool = False  # True -> worth asking the AI for a second opinion


def verdict_for(score: int) -> str:
    if score >= MALICIOUS_AT:
        return "malicious"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    if score >= LOW_AT:
        return "low_risk"
    return "clean"


def analyze(payload: str) -> DetectionResult:
    norm = normalize(payload)
    matches: list[Match] = []
    # check both views: normalised text catches obfuscation, raw catches odd encodings
    for rule in RULES:
        m = rule.pattern.search(norm) or rule.pattern.search(payload)
        if m:
            matches.append(Match(rule.id, rule.name, rule.category, rule.weight, m.group(0)[:80]))

    # noisy-OR: independent weak signals accumulate, one strong signal is enough
    p_clean = 1.0
    for m in matches:
        p_clean *= 1 - m.weight / 100
    score = round((1 - p_clean) * 100)
    verdict = verdict_for(score)
    return DetectionResult(
        original=payload,
        normalized=norm,
        score=score,
        verdict=verdict,
        matches=matches,
        ambiguous=LOW_AT <= score < MALICIOUS_AT,
    )


def combine_with_ai(result: DetectionResult, ai: dict | None) -> DetectionResult:
    """Merge the LLM opinion into the rule result.

    Safety rule: the payload is attacker-controlled and may try to talk the model
    into saying "safe". So the AI can RAISE the score freely, but can only LOWER it
    modestly, and never when the rules already say malicious.
    """
    if not ai:
        return result
    conf = float(ai.get("confidence", 0))
    if ai.get("is_injection"):
        result.score = max(result.score, round(conf * 100))
    elif conf >= 0.85 and result.score < MALICIOUS_AT:
        result.score = round(result.score * 0.5)
    result.verdict = verdict_for(result.score)
    return result
