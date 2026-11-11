#!/usr/bin/env bash
# Review 2 E6 kit: run on a DIFFERENT computer (not the development Mac).
# Creates a fresh environment from the lock file, runs the test suite, the performance
# suite and the Argon2id record, and writes results/review2/hosts/<host-id>/.
# Uses only random fictional data; never opens a real vault. Takes about 10 minutes.
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"
"$PY" -m venv .venv-host
.venv-host/bin/python -m pip install --quiet -r requirements-lock.txt
HOST_ID=$(.venv-host/bin/python -c "import hashlib,platform,uuid;print(hashlib.sha256((platform.platform()+str(uuid.getnode())).encode()).hexdigest()[:10])")
OUT="results/review2/hosts/$HOST_ID"
mkdir -p "$OUT"
.venv-host/bin/python - "$OUT/host.json" <<'PY'
import json, os, platform, sys
info = dict(platform=platform.platform(), machine=platform.machine(), processor=platform.processor(),
            python=sys.version.split()[0], cpu_count=os.cpu_count())
open(sys.argv[1], 'w').write(json.dumps(info, indent=2))
print(info)
PY
.venv-host/bin/python -m pytest -q > "$OUT/test_results.txt" 2>&1 || true
tail -1 "$OUT/test_results.txt"
.venv-host/bin/python scripts/review2_performance.py --out "$OUT/performance.json"
.venv-host/bin/python scripts/argon2_calibration_report.py --out "$OUT/argon2_calibration.json"
echo "Done. Send back the folder: $OUT"
