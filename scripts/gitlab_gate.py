"""Return the scanner's preserved outcome; fail closed on absent/stale artifacts."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ci_integration

if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: gitlab_gate.py REPORT_DIRECTORY')
    raise SystemExit(ci_integration.gate(sys.argv[1]))
