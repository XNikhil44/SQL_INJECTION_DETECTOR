"""Analyse web-server access logs (Apache/Nginx common + combined format) for SQLi attempts."""
import re
from collections import Counter

from .detector import analyze

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)(?: HTTP/[\d.]+)?" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

MAX_LINES = 5000


def parse_line(line: str) -> dict:
    m = LOG_RE.match(line)
    if m:
        return {
            "ip": m["ip"],
            "method": m["method"],
            "path": m["path"],
            "status": int(m["status"]),
        }
    return {"ip": None, "method": None, "path": line, "status": None}


def analyze_log(text: str) -> dict:
    lines = [ln for ln in text.splitlines() if ln.strip()][:MAX_LINES]
    by_ip: Counter = Counter()
    by_rule: Counter = Counter()
    flagged = []

    for ln in lines:
        entry = parse_line(ln)
        res = analyze(entry["path"])
        if res.score < 40:  # suspicious or worse
            continue
        by_ip[entry["ip"] or "unknown"] += 1
        for m in res.matches:
            by_rule[m.name] += 1
        flagged.append(
            {
                "ip": entry["ip"],
                "method": entry["method"],
                "status": entry["status"],
                "score": res.score,
                "verdict": res.verdict,
                "request": entry["path"][:300],
                "rules": [m.rule_id for m in res.matches],
                # 5xx on an injection-looking request = the payload may have reached the DB layer
                "investigate": bool(entry["status"] and entry["status"] >= 500),
            }
        )

    return {
        "lines_analyzed": len(lines),
        "flagged": len(flagged),
        "top_ips": by_ip.most_common(10),
        "top_rules": by_rule.most_common(10),
        "investigate_first": [f for f in flagged if f["investigate"]][:20],
        "samples": sorted(flagged, key=lambda f: -f["score"])[:50],
        "note": "Logs only contain the URL; POST bodies are not visible here.",
    }
