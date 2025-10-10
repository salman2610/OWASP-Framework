#!/usr/bin/env python3
"""
scanners/dast/nmap_scan.py

Fast nmap wrapper: runs a quick service scan and returns structured findings:
{ "vulnerabilities": [...], "summary": "..." }
"""

import subprocess
import os
import xml.etree.ElementTree as ET
from shutil import which
from datetime import datetime

NMAP_BIN = "nmap"

PORT_SEVERITY = {
    22: "High",   # SSH
    23: "Critical",
    21: "High",
    3389: "Critical",
    445: "High",
    1433: "High",
    3306: "High",
    80: "Low",
    443: "Low",
    8080: "Low",
}

def _is_installed():
    return which(NMAP_BIN) is not None

def _sanitize_target(t):
    # Nmap expects host or ip, remove scheme if present
    if t.startswith("http://"):
        return t.split("://",1)[1].split("/",1)[0]
    if t.startswith("https://"):
        return t.split("://",1)[1].split("/",1)[0]
    return t

def run(target, output_dir="reports"):
    target_host = _sanitize_target(target)
    print(f"[DAST][Nmap] Running fast nmap scan on {target_host}...")
    out_items = []
    summary = ""

    if not _is_installed():
        summary = f"nmap binary not found in PATH (expected '{NMAP_BIN}')."
        print(f"[DAST][Nmap] {summary}")
        return {"vulnerabilities": [], "summary": summary}

    os.makedirs(output_dir, exist_ok=True)
    xml_out = os.path.join(output_dir, f"nmap_{target_host.replace(':','_')}.xml")

    # Fast but reliable: -T4 timing, -Pn skip host discovery, -p 1-1000 (common ports), -sV service detect
    cmd = [NMAP_BIN, "-T4", "-Pn", "-p", "1-1000", "-sV", "-oX", xml_out, target_host]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=300)
    except subprocess.TimeoutExpired:
        summary = "Nmap scan timed out."
        print(f"[DAST][Nmap] {summary}")
        return {"vulnerabilities": [], "summary": summary}
    except Exception as e:
        summary = f"Nmap execution failed: {e}"
        print(f"[DAST][Nmap] {summary}")
        return {"vulnerabilities": [], "summary": summary}

    if os.path.exists(xml_out) and os.path.getsize(xml_out) > 0:
        try:
            tree = ET.parse(xml_out)
            root = tree.getroot()
            for host in root.findall("host"):
                addr_el = host.find("address")
                ip = addr_el.get("addr") if addr_el is not None else target_host
                ports = host.find("ports")
                if ports is None:
                    continue
                for port in ports.findall("port"):
                    portid = int(port.get("portid")) if port.get("portid") else None
                    state_el = port.find("state")
                    state = state_el.get("state") if state_el is not None else "unknown"
                    service_el = port.find("service")
                    svcname = service_el.get("name") if service_el is not None and service_el.get("name") else ""
                    product = service_el.get("product") if service_el is not None and service_el.get("product") else ""
                    version = service_el.get("version") if service_el is not None and service_el.get("version") else ""
                    if state and state.lower() == "open":
                        sev = PORT_SEVERITY.get(portid, "Low")
                        out_items.append({
                            "id": f"nmap-{ip}-{portid}",
                            "title": f"Open port {portid}/{svcname}",
                            "description": f"{svcname} {product} {version}".strip(),
                            "severity": sev,
                            "port": portid,
                            "service": svcname,
                            "host": ip,
                            "raw": {}
                        })
            summary = f"Nmap discovered {len(out_items)} open ports of interest."
            print(f"[DAST][Nmap] {summary}")
        except Exception as e:
            summary = f"Failed parsing nmap XML: {e}"
            print(f"[DAST][Nmap] {summary}")
            return {"vulnerabilities": [], "summary": summary}
    else:
        stderr_preview = (proc.stderr or "").splitlines()[0] if proc.stderr else ""
        summary = "Nmap did not produce XML output."
        if stderr_preview:
            summary += f" Stderr: {stderr_preview}"
        print(f"[DAST][Nmap] {summary}")

    return {"vulnerabilities": out_items, "summary": summary}
