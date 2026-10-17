import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

try:
    from . import ai, db, scanner
    from .config import get_settings
    from .detector import DetectionResult, analyze, combine_with_ai
    from .logparser import analyze_log
    from .schemas import (
        AnalyzeRequest,
        AnalyzeResponse,
        BatchRequest,
        LogRequest,
        ScanRequest,
    )
except ImportError:
    # Some serverless runtimes (e.g. Vercel) load this file by path, not as the "app.main"
    # package module, so relative imports fail. Absolute imports work from the project root.
    from app import ai, db, scanner
    from app.config import get_settings
    from app.detector import DetectionResult, analyze, combine_with_ai
    from app.logparser import analyze_log
    from app.schemas import (
        AnalyzeRequest,
        AnalyzeResponse,
        BatchRequest,
        LogRequest,
        ScanRequest,
    )

STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        db.init_db()
    except Exception as e:  # history is optional: never stop detection because of the DB
        print(f"[warn] database unavailable, history disabled: {type(e).__name__}: {e}")
    yield


app = FastAPI(title="SQLi Detector", version="1.0.0", lifespan=lifespan)

_hits: dict[str, deque] = defaultdict(deque)


async def guard(request: Request):
    """Optional API-key auth + per-IP rate limit (protects your free Gemini quota)."""
    s = get_settings()
    if s.api_key and request.headers.get("x-api-key") != s.api_key:
        raise HTTPException(401, "Invalid or missing X-API-Key")
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    q = _hits[ip]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= s.rate_limit_per_min:
        raise HTTPException(429, "Too many requests, slow down")
    q.append(now)


def _to_response(res: DetectionResult, ai_verdict, ai_error, ai_used, row_id=None) -> AnalyzeResponse:
    return AnalyzeResponse(
        id=row_id,
        score=res.score,
        verdict=res.verdict,
        normalized=res.normalized,
        matches=[m.__dict__ for m in res.matches],
        ai_used=ai_used,
        ai=ai_verdict,
        ai_error=ai_error,
    )


async def _run(payload: str, mode: str, source: str) -> AnalyzeResponse:
    res = analyze(payload)
    ai_verdict, ai_error, ai_used = None, None, False
    if mode == "always" or (mode == "auto" and res.ambiguous):
        ai_verdict, ai_error = await ai.classify(payload, [m.rule_id for m in res.matches])
        ai_used = ai_verdict is not None
        res = combine_with_ai(res, ai_verdict)
    try:
        row_id = db.save_detection(
            source, payload, res.score, res.verdict, [m.rule_id for m in res.matches], ai_used
        )
    except Exception:
        row_id = None
    return _to_response(res, ai_verdict, ai_error, ai_used, row_id)


@app.get("/api/health")
async def health():
    s = get_settings()
    return {
        "status": "ok",
        "gemini_configured": bool(s.gemini_api_key),
        "nmap_installed": scanner.shutil.which("nmap") is not None,
    }


@app.post("/api/analyze", response_model=AnalyzeResponse, dependencies=[Depends(guard)])
async def analyze_one(req: AnalyzeRequest):
    return await _run(req.payload, req.ai, "api")


@app.post("/api/analyze/batch", dependencies=[Depends(guard)])
async def analyze_batch(req: BatchRequest):
    results = []
    for p in req.payloads:
        r = await _run(p[:10_000], req.ai, "batch")
        results.append({"payload": p[:200], **r.model_dump(exclude={"normalized", "ai"})})
    flagged = sum(1 for r in results if r["verdict"] in ("suspicious", "malicious"))
    return {"total": len(results), "flagged": flagged, "results": results}


@app.post("/api/logs/analyze", dependencies=[Depends(guard)])
async def logs(req: LogRequest):
    return analyze_log(req.log_text)


@app.post("/api/scan", dependencies=[Depends(guard)])
async def scan(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(400, "Set authorized=true to confirm you own or may test this target")
    s = get_settings()
    try:
        target = scanner.validate_target(req.target, s.allow_public_scan)
        ports = scanner.validate_ports(req.ports)
        hosts = await scanner.run_scan(target, ports)
    except scanner.ScanError as e:
        raise HTTPException(400, str(e))
    except scanner.NmapNotInstalled as e:
        raise HTTPException(503, str(e))
    except Exception as e:  # keep the real reason visible in the UI instead of a bare 500
        raise HTTPException(500, f"Scan failed: {type(e).__name__}: {e}")
    result = {"target": target, "ports": ports, "hosts": hosts}
    try:
        db.save_scan(target, result)
    except Exception:
        pass
    return result


@app.get("/api/history", dependencies=[Depends(guard)])
async def get_history(limit: int = 50):
    try:
        return db.history(max(1, min(limit, 200)))
    except Exception:
        return []


@app.get("/api/stats", dependencies=[Depends(guard)])
async def get_stats():
    try:
        return db.stats()
    except Exception:
        return {"total_checks": 0, "by_verdict": {}, "scans_run": 0}


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")