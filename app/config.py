import os
import tempfile
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    gemini_api_key: str
    gemini_model: str
    gemini_timeout: float
    db_path: str
    api_key: str  # optional: if set, clients must send X-API-Key
    allow_public_scan: bool
    rate_limit_per_min: int


def _default_db_path() -> str:
    """Local: ./sqli_detector.db. On Vercel / read-only hosts only the temp dir is writable
    (temporary and per instance, so history resets on cold start)."""
    if os.getenv("VERCEL") or not os.access(os.getcwd(), os.W_OK):
        return os.path.join(tempfile.gettempdir(), "sqli_detector.db")
    return "sqli_detector.db"


def get_settings() -> Settings:
    # read env on every call so tests can override it
    return Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        gemini_timeout=float(os.getenv("GEMINI_TIMEOUT", "15")),
        db_path=os.getenv("DB_PATH") or _default_db_path(),
        api_key=os.getenv("API_KEY", ""),
        allow_public_scan=os.getenv("ALLOW_PUBLIC_SCAN", "false").lower() == "true",
        rate_limit_per_min=int(os.getenv("RATE_LIMIT_PER_MIN", "60")),
    )