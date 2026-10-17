import json
import sqlite3
import threading
from datetime import datetime, timezone

from .config import get_settings

_lock = threading.Lock()


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(get_settings().db_path, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c


def init_db() -> None:
    with _lock, _conn() as c:
        c.execute(
            """CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                source TEXT NOT NULL,
                payload TEXT NOT NULL,
                score INTEGER NOT NULL,
                verdict TEXT NOT NULL,
                rules TEXT NOT NULL,
                ai_used INTEGER NOT NULL DEFAULT 0
            )"""
        )
        c.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL
            )"""
        )


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def save_detection(source: str, payload: str, score: int, verdict: str, rule_ids: list[str], ai_used: bool) -> int:
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO detections (ts, source, payload, score, verdict, rules, ai_used) VALUES (?,?,?,?,?,?,?)",
            (_now(), source, payload[:500], score, verdict, json.dumps(rule_ids), int(ai_used)),
        )
        return cur.lastrowid


def save_scan(target: str, result: dict) -> int:
    with _lock, _conn() as c:
        cur = c.execute(
            "INSERT INTO scans (ts, target, result) VALUES (?,?,?)",
            (_now(), target, json.dumps(result)),
        )
        return cur.lastrowid


def history(limit: int = 50) -> list[dict]:
    with _lock, _conn() as c:
        rows = c.execute("SELECT * FROM detections ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["rules"] = json.loads(d["rules"])
        d["ai_used"] = bool(d["ai_used"])
        out.append(d)
    return out


def stats() -> dict:
    with _lock, _conn() as c:
        total = c.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        by_verdict = {
            r["verdict"]: r["n"]
            for r in c.execute("SELECT verdict, COUNT(*) AS n FROM detections GROUP BY verdict")
        }
        scans = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    return {"total_checks": total, "by_verdict": by_verdict, "scans_run": scans}
