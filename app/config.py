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


def _resolve_db_path() -> str:
    """Local: ./sqli_detector.db (or DB_PATH). On Vercel / read-only hosts only the temp dir
    is writable, so any path outside it is moved there (temporary, per instance: history
    resets on cold start). This also fixes a DB_PATH copied from .env.example."""
    path = os.getenv("DB_PATH") or "sqli_detector.db"
    absolute = os.path.abspath(path)
    tmp = os.path.realpath(tempfile.gettempdir())
    in_tmp = os.path.realpath(absolute).startswith(tmp + os.sep)
    unwritable = not os.access(os.path.dirname(absolute), os.W_OK)
    if unwritable or (os.getenv("VERCEL") and not in_tmp):
        return os.path.join(tmp, os.path.basename(path))
    return path


def get_settings() -> Settings:
    # read env on every call so tests can override it
    return Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        gemini_timeout=float(os.getenv("GEMINI_TIMEOUT", "15")),
        db_path=_resolve_db_path(),
        api_key=os.getenv("API_KEY", ""),
        allow_public_scan=os.getenv("ALLOW_PUBLIC_SCAN", "false").lower() == "true",
        rate_limit_per_min=int(os.getenv("RATE_LIMIT_PER_MIN", "60")),
    )