#!/usr/bin/env python3
"""
Parse nuclei JSONL output and merge into reports/latest_report.json
Usage:
  python3 scripts/parse_nuclei_and_merge.py reports/nuclei_test_http.jsonl
"""
import sys, json, os

def normalize_nuclei_line(j):
    info = j.get("info", {}) if isinstance(j.get("info"), dict) else {}
    title = info.get("name") or j.get("template") or info.get("title") or ""
    description = info.get("description") or info.get("reference") or j.get("matcher-name") or ""
    severity = (info.get("severity") or "").capitalize() or "Info"
    template = j.get("template") or j.get("templateID") or ""
    url = j.get("host") or j.get("matched-at") or j.get("target") or j.get("matched") or ""
    return {
        "title": title,
        "description": description,
        "severity": severity,
        "template": template,
        "url": url,
        "raw": j
    }

def parse_jsonl(path):
    finds = []
    if not os.path.exists(path):
        print("[!] input file not found:", path)
        return finds
    with open(path, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except Exception:
                # skip non-json lines
                continue
            finds.append(normalize_nuclei_line(j))
    return finds

def merge_into_latest(finds, out_reports_json="reports/latest_report.json"):
    # create reports dir if needed
    os.makedirs(os.path.dirname(out_reports_json) or ".", exist_ok=True)
    report = {}
    if os.path.exists(out_reports_json):
        try:
            with open(out_reports_json, "r") as fh:
                report = json.load(fh)
        except Exception:
            report = {}
    # Ensure structure
    scanners = report.get("scanners", {})
    # put nuclei normalized results under scanners.nuclei => {"summary","details"}
    scanners["nuclei"] = {
        "summary": f"Nuclei parsed {len(finds)} findings",
        "details": finds
    }
    report["scanners"] = scanners
    # update generated_at
    report["generated_at"] = report.get("generated_at") or ""
    # write file
    with open(out_reports_json, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"[+] Merged {len(finds)} nuclei findings into {out_reports_json}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: parse_nuclei_and_merge.py <nuclei-jsonl-file> [output-json]")
        sys.exit(1)
    infile = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "reports/latest_report.json"
    findings = parse_jsonl(infile)
    print(f"[+] Parsed {len(findings)} lines from {infile}")
    merge_into_latest(findings, out_reports_json=out)
