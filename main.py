from scanners.dast import zap_scan, api_fuzzer
from scanners.sast import bandit_scan
from scanners.dependency import dependency_check
from session_analysis import session_checker
from reports.generate_report import generate_report
from dashboard import dashboard_advanced as dashboard
import yaml


# Load config
with open("config/settings.yaml") as f:
    config = yaml.safe_load(f)


def run_scans():
    results = {}

    if "sast" in config["scan_types"]:
        results["sast"] = bandit_scan.run(config["target_url"])

    if "dast" in config["scan_types"]:
        results["dast"] = zap_scan.run(config["target_url"])
        results["api_fuzz"] = api_fuzzer.run(config["target_url"])

    if "dependency" in config["scan_types"]:
        results["dependency"] = dependency_check.run(config["target_url"])

    if config.get("session", {}).get("check_jwt"):
        results["session"] = session_checker.run(config["target_url"])

    # Generate report
    generate_report(results, config["report"]["format"])

    return results


if __name__ == "__main__":
    # Run all scans
    results = run_scans()

    # Save scan to dashboard history
    dashboard.add_scan(results)

    # Generate HTML dashboard
    dashboard.generate_dashboard()

