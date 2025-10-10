# scanners/dast/__init__.py
from . import zap_scan, api_fuzzer

# optional imports - set to None if missing
try:
    from . import nuclei_scan
except Exception:
    nuclei_scan = None

try:
    from . import nmap_scan
except Exception:
    nmap_scan = None
