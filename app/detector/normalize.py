"""Canonicalise input before matching so simple obfuscation doesn't hide a payload.

Handles: repeated URL-encoding, HTML entities, unicode look-alikes (NFKC),
inline /* comments */ used as whitespace, and whitespace runs.
"""
import html
import re
import unicodedata
import urllib.parse

_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_SPACES = re.compile(r"\s+")


def normalize(text: str) -> str:
    out = text
    # decode up to 3 layers (e.g. %2527 -> %27 -> ')
    for _ in range(3):
        prev = out
        out = urllib.parse.unquote_plus(out)
        out = html.unescape(out)
        if out == prev:
            break
    out = unicodedata.normalize("NFKC", out)
    out = out.replace("\x00", "")
    out = _COMMENT.sub(" ", out)  # UNION/**/SELECT -> UNION SELECT
    out = _SPACES.sub(" ", out)
    return out.strip()
