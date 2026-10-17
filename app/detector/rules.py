"""Signature rules. Each rule has a weight (0-100) = how strongly a single hit suggests SQLi.

Scores from multiple hits are combined in engine.py (noisy-OR), so weak signals
add up while a single strong signal (UNION SELECT, stacked DROP, SLEEP()) is enough alone.
"""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    weight: int
    pattern: re.Pattern
    description: str


def _r(id_, name, category, weight, pattern, description):
    return Rule(id_, name, category, weight, re.compile(pattern, re.I), description)


RULES = [
    _r("SQLI-001", "Tautology (OR 1=1)", "auth-bypass", 70,
       r"\b(?:or|and)\b\s*\(?\s*(['\"]?)(\w+)\1\s*=\s*\(?\s*\1\2\1?",
       "Always-true condition such as OR 1=1 or OR 'a'='a' used to bypass filters/logins."),
    _r("SQLI-002", "Always-true keyword", "auth-bypass", 55,
       r"\bor\b\s+(?:true|not\s+false)\b",
       "Boolean keyword tautology."),
    _r("SQLI-003", "Quote break followed by logic", "syntax-break", 35,
       r"['\"`)]\s*(?:or|and|union|;)\b",
       "A quote/bracket is closed and SQL logic is appended."),
    _r("SQLI-004", "UNION SELECT", "union-based", 80,
       r"\bunion\b(?:\s+(?:all|distinct))?\s*(?:\(\s*)?select\b",
       "UNION-based data extraction."),
    _r("SQLI-005", "Stacked query", "stacked", 75,
       r";\s*(?:drop|insert|update|delete|create|alter|truncate|exec|execute|select|shutdown|declare)\b",
       "A second statement is chained after the first."),
    _r("SQLI-006", "Time-based blind function", "blind-time", 80,
       r"\b(?:sleep|pg_sleep|benchmark|dbms_pipe\.receive_message|randomblob)\s*\(|\bwaitfor\s+delay\b",
       "Delay functions used to infer data from response time."),
    _r("SQLI-007", "Error-based extraction", "error-based", 70,
       r"\b(?:extractvalue|updatexml|xmltype|exp\s*\(\s*~|geometrycollection|polygon)\s*\(|convert\s*\(\s*int\s*,|cast\s*\(.+?\bas\s+(?:int|numeric)\b",
       "Functions abused to leak data via database error messages."),
    _r("SQLI-008", "Schema enumeration", "recon", 60,
       r"\b(?:information_schema|sqlite_master|sqlite_schema|pg_catalog|pg_tables|sysobjects|syscolumns|all_tables|mysql\.user)\b",
       "Reading database metadata."),
    _r("SQLI-009", "DB fingerprinting function", "recon", 35,
       r"@@version|\bversion\s*\(\s*\)|\bdatabase\s*\(\s*\)|\bcurrent_user\b|\bsession_user\b|\buser\s*\(\s*\)|@@hostname",
       "Functions used to identify DB type/version/user."),
    _r("SQLI-010", "Boolean-blind probing", "blind-boolean", 55,
       r"\b(?:and|or)\b\s*\(?\s*(?:select\b|(?:ascii|substring|substr|mid|length|ord|hex)\s*\()",
       "Character-by-character extraction using conditional logic."),
    _r("SQLI-011", "Command / file access", "rce-file", 85,
       r"\b(?:xp_cmdshell|sp_oacreate|load_file|utl_http|utl_file|copy\s+\w+\s+to\s+program)\b|into\s+(?:out|dump)file",
       "File read/write or OS command execution from SQL."),
    _r("SQLI-012", "Trailing comment terminator", "syntax-break", 25,
       r"(?:--\s?|#|/\*)\s*$|;\s*--",
       "Comment used to cut off the rest of the original query."),
    _r("SQLI-017", "Quote followed by comment", "syntax-break", 55,
       r"['\"`]\s*(?:--|#|/\*)",
       "A quote is closed and the rest of the query is commented out (e.g. admin' --)."),
    _r("SQLI-013", "Column-count probing", "recon", 40,
       r"\border\s+by\s+\d+\b|\bgroup\s+by\b.+\bhaving\b\s+\d",
       "ORDER BY n / HAVING probes used to learn column count."),
    _r("SQLI-014", "Encoded string building", "obfuscation", 30,
       r"\b(?:char|chr|nchar)\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\)|0x[0-9a-f]{8,}|\bconcat(?:_ws)?\s*\(.*?(?:select|char)",
       "CHAR()/hex literals used to evade string filters."),
    _r("SQLI-015", "Subquery injection", "union-based", 45,
       r"[=<>(,]\s*\(\s*select\b",
       "Inline SELECT inside an expression."),
    _r("SQLI-016", "Numeric tautology comparison", "auth-bypass", 40,
       r"\b(?:or|and)\b\s+\d+\s*(?:<|>|<=|>=|<>|!=|like)\s*\d+",
       "Numeric comparison that is trivially true/false."),
]
