import asyncio

import pytest

from app import scanner
from app.scanner import ScanError, parse_nmap_xml, validate_ports, validate_target

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <hostnames><hostname name="dev.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="8000">
        <state state="open"/>
        <service name="http" product="uvicorn" version="0.30"/>
        <script id="http-title" output="My App"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
      <port protocol="tcp" portid="81">
        <state state="closed"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
  <host><address addr="192.168.1.11" addrtype="ipv4"/><ports/></host>
</nmaprun>"""


def test_parse_nmap_xml():
    hosts = parse_nmap_xml(SAMPLE_XML)
    assert len(hosts) == 1  # host with no open ports dropped
    h = hosts[0]
    assert h["address"] == "192.168.1.10" and h["hostname"] == "dev.local"
    assert h["web_services"] == 1
    web = [p for p in h["ports"] if p["is_web"]][0]
    assert web["port"] == 8000 and web["http_title"] == "My App"
    assert all(p["port"] != 81 for p in h["ports"])  # closed ports ignored


def test_private_targets_allowed():
    assert validate_target("127.0.0.1") == "127.0.0.1"
    assert validate_target("192.168.1.0/24") == "192.168.1.0/24"


@pytest.mark.parametrize("bad", ["8.8.8.8", "1.1.1.0/24", "10.0.0.0/8", "-oX /tmp/x", "a b", "evil;rm -rf /", "$(id)"])
def test_bad_targets_rejected(bad):
    with pytest.raises(ScanError):
        validate_target(bad)


def test_public_allowed_only_with_flag():
    assert validate_target("8.8.8.8", allow_public=True) == "8.8.8.8"


def test_ports():
    assert validate_ports(None).startswith("80")
    assert validate_ports("80, 443,8000-8100") == "80,443,8000-8100"
    for bad in ("0", "70000", "80;id", "abc", "1-2-3"):
        with pytest.raises(ScanError):
            validate_ports(bad)


class _FakeProc:
    def __init__(self, stdout, returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def _patch_nmap(monkeypatch, proc):
    monkeypatch.setattr(scanner.shutil, "which", lambda _: "nmap")
    monkeypatch.setattr(scanner.subprocess, "run", lambda *a, **k: proc)


def test_run_scan_success(monkeypatch):
    _patch_nmap(monkeypatch, _FakeProc(SAMPLE_XML))
    hosts = asyncio.run(scanner.run_scan("192.168.1.10", "8000"))
    assert hosts[0]["web_services"] == 1


def test_run_scan_garbage_output_is_scan_error(monkeypatch):
    _patch_nmap(monkeypatch, _FakeProc("not xml"))
    with pytest.raises(ScanError):
        asyncio.run(scanner.run_scan("192.168.1.10", "8000"))


def test_run_scan_nmap_failure_is_scan_error(monkeypatch):
    _patch_nmap(monkeypatch, _FakeProc("", returncode=1, stderr="boom"))
    with pytest.raises(ScanError):
        asyncio.run(scanner.run_scan("192.168.1.10", "8000"))