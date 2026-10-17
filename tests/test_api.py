import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("API_KEY", "")
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "1000")
    from app.main import _hits, app

    _hits.clear()
    with TestClient(app) as c:
        yield c


def test_health(client):
    r = client.get("/api/health").json()
    assert r["status"] == "ok" and r["gemini_configured"] is False


def test_analyze_malicious_and_clean(client):
    bad = client.post("/api/analyze", json={"payload": "1 UNION SELECT 1,2", "ai": "never"}).json()
    assert bad["verdict"] == "malicious" and bad["matches"]
    ok = client.post("/api/analyze", json={"payload": "hello world", "ai": "never"}).json()
    assert ok["verdict"] == "clean"


def test_ai_missing_key_falls_back_to_rules(client):
    r = client.post("/api/analyze", json={"payload": "1 UNION SELECT 1,2", "ai": "always"}).json()
    assert r["verdict"] == "malicious"
    assert r["ai_used"] is False and "GEMINI_API_KEY" in r["ai_error"]


def test_ai_result_is_merged(client, monkeypatch):
    async def fake(payload, hits):
        return {"is_injection": True, "confidence": 0.9, "attack_type": "boolean-blind",
                "explanation": "x", "safe_fix": "use parameterised queries"}, None

    monkeypatch.setattr("app.ai.classify", fake)
    r = client.post("/api/analyze", json={"payload": "1' and 1", "ai": "always"}).json()
    assert r["ai_used"] and r["score"] >= 90


def test_batch_and_history_and_stats(client):
    r = client.post("/api/analyze/batch", json={"payloads": ["hello", "' OR 1=1 --"]}).json()
    assert r["total"] == 2 and r["flagged"] == 1
    hist = client.get("/api/history").json()
    assert len(hist) == 2
    assert client.get("/api/stats").json()["total_checks"] == 2


def test_log_analysis(client):
    log = (
        '10.0.0.5 - - [10/Oct/2026:13:55:36 +0530] "GET /item?id=1%20UNION%20SELECT%201,2 HTTP/1.1" 500 100\n'
        '10.0.0.6 - - [10/Oct/2026:13:55:37 +0530] "GET /home HTTP/1.1" 200 500\n'
    )
    r = client.post("/api/logs/analyze", json={"log_text": log}).json()
    assert r["flagged"] == 1 and r["top_ips"][0][0] == "10.0.0.5"
    assert len(r["investigate_first"]) == 1  # 5xx on an attack-looking request


def test_scan_requires_authorization_and_blocks_public(client):
    assert client.post("/api/scan", json={"target": "192.168.1.1"}).status_code == 400
    r = client.post("/api/scan", json={"target": "8.8.8.8", "authorized": True})
    assert r.status_code == 400


def test_api_key_enforced(client, monkeypatch):
    monkeypatch.setenv("API_KEY", "secret")
    assert client.post("/api/analyze", json={"payload": "x"}).status_code == 401
    ok = client.post("/api/analyze", json={"payload": "x", "ai": "never"}, headers={"X-API-Key": "secret"})
    assert ok.status_code == 200


def test_rate_limit(client, monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_PER_MIN", "2")
    codes = [client.post("/api/analyze", json={"payload": "x", "ai": "never"}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]


def test_ui_served(client):
    assert "SQLi Detector" in client.get("/").text
