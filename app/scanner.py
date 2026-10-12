import hashlib
import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
SIG_FILE = BASE / "data" / "signatures.json"
RULES_DIR = BASE / "rules"

try:
    import yara
except ImportError:
    yara = None


def load_signatures():
    try:
        return json.loads(SIG_FILE.read_text())
    except (OSError, ValueError):
        return {}


def load_rules():
    if yara is None:
        return None
    files = {p.stem: str(p) for p in RULES_DIR.glob("*.yar")}
    return yara.compile(filepaths=files) if files else None


SIGNATURES = load_signatures()
RULES = load_rules()


def clam_scan(data: bytes):
    """Returns (state, detail). state: clean | infected | unavailable"""
    try:
        import pyclamd

        cd = pyclamd.ClamdNetworkSocket(
            host=os.getenv("CLAMD_HOST", "127.0.0.1"),
            port=int(os.getenv("CLAMD_PORT", "3310")),
        )
        if not cd.ping():
            return "unavailable", ""
        result = cd.scan_stream(data)
    except Exception:
        return "unavailable", ""
    if result is None:
        return "clean", ""
    return "infected", list(result.values())[0][1]


def scan_bytes(filename: str, data: bytes) -> dict:
    sha256 = hashlib.sha256(data).hexdigest()
    findings = []
    engines = []
    malicious = False

    # Engine 1: known-hash list
    engines.append({"name": "Hash signatures", "state": "active"})
    if sha256 in SIGNATURES:
        findings.append(f"Known bad file: {SIGNATURES[sha256]}")
        malicious = True

    # Engine 2: YARA
    if RULES is not None:
        engines.append({"name": "YARA rules", "state": "active"})
        try:
            for m in RULES.match(data=data, timeout=30):
                findings.append(f"Rule match: {m.rule}")
        except Exception:
            engines[-1]["state"] = "error"
    else:
        engines.append({"name": "YARA rules", "state": "not installed"})

    # Engine 3: ClamAV
    state, detail = clam_scan(data)
    engines.append({"name": "ClamAV", "state": "active" if state != "unavailable" else "not available"})
    if state == "infected":
        findings.append(f"ClamAV: {detail}")
        malicious = True

    if malicious:
        verdict = "malicious"
    elif findings:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "filename": filename,
        "size": len(data),
        "sha256": sha256,
        "verdict": verdict,
        "findings": findings,
        "engines": engines,
    }