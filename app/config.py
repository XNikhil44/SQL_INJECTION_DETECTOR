import os
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


def get_settings() -> Settings:
    # read env on every call so tests can override it
    return Settings(
        gemini_api_key=os.getenv("GEMINI_API_KEY", ""),
        gemini_model=os.getenv("GEMINI_MODEL", "gemini-2.5-flash"),
        gemini_timeout=float(os.getenv("GEMINI_TIMEOUT", "15")),
        db_path=os.getenv("DB_PATH", "sqli_detector.db"),
        api_key=os.getenv("API_KEY", ""),
        allow_public_scan=os.getenv("ALLOW_PUBLIC_SCAN", "false").lower() == "true",
        rate_limit_per_min=int(os.getenv("RATE_LIMIT_PER_MIN", "60")),
    )
