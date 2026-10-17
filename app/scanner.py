"""Nmap-based discovery of web services on hosts you own / are authorised to test.

This only does service discovery (open ports, banners, page titles) using safe NSE
scripts. It deliberately does not fire injection payloads at targets.
"""
import asyncio
import ipaddress
import re
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

WEB_PORTS = "80,443,3000,5000,8000,8080,8443,8888"
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
MAX_HOSTS = 256


class ScanError(ValueError):
    pass


class NmapNotInstalled(RuntimeError):
    pass


def _is_internal(ip) -> bool:
    return ip.is_private or ip.is_loopback or ip.is_link_local


def validate_target(target: str, allow_public: bool = False) -> str:
    t = target.strip()
    if "/" in t:
        try:
            net = ipaddress.ip_network(t, strict=False)
        except ValueError:
            raise ScanError("Invalid CIDR range")
        if net.num_addresses > MAX_HOSTS:
            raise ScanError(f"Range too large (max {MAX_HOSTS} addresses, e.g. /24)")
        if not allow_public and not _is_internal(net):
            raise ScanError("Public ranges are blocked. Scan only your own private network.")
        return str(net)
    try:
        ip = ipaddress.ip_address(t)
    except ValueError:
        ip = None
    if ip is not None:
        if not allow_public and not _is_internal(ip):
            raise ScanError("Public IPs are blocked. Scan only your own private network.")
        return str(ip)

    # hostname: must start alphanumeric (blocks '-oX' style option injection)
    if not HOSTNAME_RE.match(t):
        raise ScanError("Invalid hostname")
    try:
        infos = socket.getaddrinfo(t, None)
    except socket.gaierror:
        raise ScanError("Hostname does not resolve")
    for info in infos:
        if not allow_public and not _is_internal(ipaddress.ip_address(info[4][0])):
            raise ScanError("Hostname resolves to a public IP. Public scanning is disabled.")
    return t


def validate_ports(ports: str | None) -> str:
    if not ports:
        return WEB_PORTS
    p = ports.strip().replace(" ", "")
    if not PORTS_RE.match(p):
        raise ScanError("Ports must look like 80,443,8000-8100")
    for part in p.split(","):
        for n in part.split("-"):
            if not 1 <= int(n) <= 65535:
                raise ScanError("Port out of range (1-65535)")
    return p


def parse_nmap_xml(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    hosts = []
    for h in root.findall("host"):
        addr_el = h.find("address[@addrtype='ipv4']")
        if addr_el is None:  # note: childless XML elements are falsy, so no `or` here
            addr_el = h.find("address")
        addr = addr_el.get("addr") if addr_el is not None else "unknown"
        hn = h.find("hostnames/hostname")
        ports = []
        for p in h.findall("ports/port"):
            if p.find("state").get("state") != "open":
                continue
            svc = p.find("service")
            name = svc.get("name", "") if svc is not None else ""
            scripts = {s.get("id"): s.get("output", "").strip() for s in p.findall("script")}
            port_no = int(p.get("portid"))
            is_web = name.startswith("http") or str(port_no) in WEB_PORTS.split(",")
            ports.append(
                {
                    "port": port_no,
                    "protocol": p.get("protocol"),
                    "service": name,
                    "product": " ".join(
                        x for x in (svc.get("product"), svc.get("version")) if x
                    ) if svc is not None else "",
                    "is_web": is_web,
                    "http_title": scripts.get("http-title"),
                    "server_header": scripts.get("http-server-header"),
                }
            )
        if ports:
            hosts.append(
                {
                    "address": addr,
                    "hostname": hn.get("name") if hn is not None else None,
                    "ports": ports,
                    "web_services": sum(1 for x in ports if x["is_web"]),
                }
            )
    return hosts


async def run_scan(target: str, ports: str, timeout: int = 180) -> list[dict]:
    if not shutil.which("nmap"):
        raise NmapNotInstalled("nmap is not installed on the server (apt install nmap / brew install nmap)")
    cmd = [
        "nmap", "-Pn", "-sV", "--version-light", "-T3",
        "-p", ports,
        "--script", "http-title,http-server-header",
        "--host-timeout", "60s",
        "-oX", "-",
        target,
    ]
    # Blocking subprocess in a worker thread: works on every event loop. (asyncio's own
    # subprocess support raises NotImplementedError on Windows under uvicorn --reload.)
    out = await asyncio.to_thread(_run_nmap_blocking, cmd, timeout)
    try:
        return parse_nmap_xml(out)
    except (ET.ParseError, AttributeError, ValueError):
        raise ScanError("Could not read nmap output: " + out[:150].strip())


def _run_nmap_blocking(cmd: list[str], timeout: int) -> str:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="ignore", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise ScanError("Scan timed out. Try a smaller range or fewer ports.")
    except FileNotFoundError:
        raise NmapNotInstalled("nmap executable not found on PATH")
    if p.returncode != 0:
        raise ScanError("nmap failed: " + (p.stderr or p.stdout or "")[:300].strip())
    return p.stdout