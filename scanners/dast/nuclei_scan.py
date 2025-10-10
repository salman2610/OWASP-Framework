#!/usr/bin/env python3
"""
scanners/dast/nuclei_scan.py

Runs nuclei against a target and returns structured results:
{ "vulnerabilities": [ ... ], "summary": "..." }
Handles multiple nuclei output flag variants (jsonl-export, jsonl, json-export).
"""

import subprocess
import json
import os
from shutil import which
from datetime import datetime

NUCLEI_BIN = "nuclei"

def _is_installed():
    return which(NUCLEI_BIN) is not None

def _sanitize_target(target):
    # ensure http scheme if no scheme provided (nuclei accepts http/https)
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"

def _try_run(cmd, timeout=600):
    """Run subprocess command and return (returncode, stdout, stderr)"""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=timeout)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"

def _find_supported_export_flag():
    """
    Determine which export flag to use for this nuclei binary.
    Preference order:
      - -jsonl-export <file>
      - -jsonl (with -o file)
      - -json-export <file>
      - -je / -jle aliases (less common)
    Return tuple (flag_name, needs_value) where needs_value True => use as flag value file.
    """
    # Quick check: call nuclei -h and inspect
    try:
        out = subprocess.run([NUCLEI_BIN, "-h"], capture_output=True, text=True, check=False, timeout=5).stdout.lower()
    except Exception:
        out = ""
    # prefer jsonl-export
    if "-jsonl-export" in out:
        return ("-jsonl-export", True)
    if "-jsonl" in out:
        # -jsonl writes to stdout; we'll use -o to redirect to file
        return ("-jsonl", False)
    if "-json-export" in out:
        return ("-json-export", True)
    if "-je" in out and "-jsonl-export" not in out:
        return ("-je", True)
    # fallback to none
    return (None, False)

def run(target, output_dir="reports", templates=None):
    """
    Run nuclei and return {'vulnerabilities': [...], 'summary': str}
    Each vulnerability is a normalized dict: title, description, severity, template, url, raw
    """
    target = _sanitize_target(target)
    print(f"[DAST][Nuclei] Running nuclei scan on {target}...")
    results = []
    summary = ""

    if not _is_installed():
        summary = f"nuclei binary not found in PATH (expected '{NUCLEI_BIN}')."
        print(f"[DAST][Nuclei] {summary}")
        return {"vulnerabilities": [], "summary": summary}

    os.makedirs(output_dir, exist_ok=True)
    filename_base = f"nuclei_{target.replace('://','_').replace('/','_')}"
    outfile = os.path.join(output_dir, f"{filename_base}.jsonl")
    # remove leftover file if present
    try:
        if os.path.exists(outfile):
            os.remove(outfile)
    except Exception:
        pass

    flag, needs_value = _find_supported_export_flag()

    cmd = [NUCLEI_BIN, "-u", target, "-silent"]
    if templates:
        # templates can be a list or comma-separated path
        if isinstance(templates, (list, tuple)):
            for t in templates:
                cmd.extend(["-t", t])
        else:
            cmd.extend(["-t", str(templates)])

    # build final command using detected flag
    if flag == "-jsonl-export" or flag == "-json-export" or flag == "-je":
        cmd.extend([flag, outfile])
        rc, out, err = _try_run(cmd)
    elif flag == "-jsonl":
        # use -jsonl (stdout JSONL) and redirect to file with -o (nuclei supports -o)
        cmd.extend(["-jsonl", "-o", outfile])
        rc, out, err = _try_run(cmd)
    else:
        # fallback: use -o plain text and parse lines (less structured)
        cmd.extend(["-o", outfile])
        rc, out, err = _try_run(cmd)

    # If file not created, try a simple fallback to stdout capture
    if not os.path.exists(outfile) or os.path.getsize(outfile) == 0:
        # try running without -silent to capture possible CLI output
        try:
            rc2 = subprocess.run([NUCLEI_BIN, "-u", target, "-t", "cves/"], capture_output=True, text=True, check=False, timeout=300)
            # write stdout to outfile for inspection
            if rc2.stdout:
                with open(outfile, "w") as fh:
                    fh.write(rc2.stdout)
        except Exception:
            pass

    # parse the output file if exists
    if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
        try:
            with open(outfile, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        j = json.loads(line)
                    except Exception:
                        # lines might be human readable output; attempt to skip
                        continue
                    info = j.get("info", {}) if isinstance(j.get("info", {}), dict) else {}
                    vuln = {
                        "title": info.get("name") or j.get("template") or info.get("title") or "",
                        "description": info.get("description") or info.get("reference") or "",
                        "severity": (info.get("severity") or "").capitalize() or "Info",
                        "template": j.get("template") or j.get("templateID") or "",
                        "url": j.get("host") or j.get("matched-at") or j.get("target") or target,
                        "raw": j
                    }
                    results.append(vuln)
            summary = f"Nuclei found {len(results)} findings."
        except Exception as e:
            summary = f"Nuclei output parse failed: {e}"
            print(f"[DAST][Nuclei] {summary}")
    else:
        # no output file produced
        stderr_preview = ""
        try:
            stderr_preview = err.splitlines()[0] if err else ""
        except Exception:
            stderr_preview = ""
        summary = "Nuclei did not produce output file (no findings or nuclei error)."
        if stderr_preview:
            summary += f" Stderr: {stderr_preview}"
        print(f"[DAST][Nuclei] {summary}")

    return {"vulnerabilities": results, "summary": summary}
