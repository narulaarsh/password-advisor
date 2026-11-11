"""Records Argon2id calibration outcomes and fixed-parameter timings on this host (Review 2 E5)."""
import json
import platform
import secrets
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from vault.crypto import calibrate_argon2_parameters, derive_k_pw


def timed(m, t, p, repeats=5):
    salt = secrets.token_bytes(16)
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        derive_k_pw('timing-only-not-a-secret', salt, m, t, p)
        samples.append((time.perf_counter() - start) * 1000)
    return dict(m_mib=m // 1024, t=t, p=p, median_ms=round(statistics.median(samples), 1),
                min_ms=round(min(samples), 1), max_ms=round(max(samples), 1), repeats=repeats)


def main(out=ROOT / 'results/review2/argon2_calibration.json'):
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    fixed = [timed(65536, 3, 4), timed(262144, 3, 4), timed(262144, 9, 4)]
    runs = [calibrate_argon2_parameters() for _ in range(5)]
    report = dict(platform=platform.platform(), python=sys.version.split()[0], fixed_parameters=fixed,
                  calibration_runs=runs, note='Host timings only; not adversary guessing throughput.')
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'results/review2/argon2_calibration.json')
    main(parser.parse_args().out)
