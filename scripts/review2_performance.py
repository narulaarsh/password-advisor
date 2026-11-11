"""Review 2 E6: local latency, CPU time, peak resident memory and emulated breach-check network faults.

Each (size, component) memory measurement runs in a fresh subprocess so peak RSS
includes native allocations. Network conditions are emulated by replacing
`requests.get` inside modules.syntactic; no real network traffic is generated.
One host only; repeat on other hardware before generalising.
"""
import argparse
import json
import platform
import random
import resource
import statistics
import string
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'tests'))
import numpy as np
import requests

from modules import syntactic
from modules.syntactic import BreachStatus
from vault.audit import audit_vault, detect_derivative_families
from vault.gate import evaluate_save_gate
from vault.models import Entry, Profile

PROFILE = Profile('Maya', 'Carter', 'Denver', 1998)
CANDIDATE = 'Candidate-Passphrase-For-Study!'


def vault(n, seed=42):
    rng = random.Random(seed + n)
    return [Entry(str(i), f'site{i}', '', 'fictional', ''.join(rng.choices(string.ascii_letters + string.digits, k=16)))
            for i in range(n)]


def operations(entries):
    from test_review2_derivatives import reference_families
    return {
        'full_local_audit': lambda: audit_vault(entries, PROFILE),
        'save_gate': lambda: evaluate_save_gate(CANDIDATE, 'test', entries, PROFILE),
        'derivative_indexed': lambda: detect_derivative_families(entries),
        'derivative_reference_quadratic': lambda: reference_families(entries),
        'audit_without_derivatives': lambda: _patched(lambda: audit_vault(entries, PROFILE),
                                                      'vault.audit.detect_derivative_families', ({}, {})),
        'audit_without_syntax': lambda: _patched(lambda: audit_vault(entries, PROFILE),
                                                 'vault.audit.evaluate_syntactic_strength', {'score': 4}),
    }


def _patched(fn, target, value):
    with patch(target, return_value=value):
        return fn()


def summarise(wall, cpu):
    return dict(repeats=len(wall), median_ms=statistics.median(wall), p95_ms=float(np.percentile(wall, 95)),
                p99_ms=float(np.percentile(wall, 99)), min_ms=min(wall), max_ms=max(wall),
                median_cpu_ms=statistics.median(cpu), raw_ms=wall)


def time_it(fn, repeats):
    fn()  # warm-up (imports, caches); not recorded
    wall, cpu = [], []
    for _ in range(repeats):
        w, c = time.perf_counter(), time.process_time()
        fn()
        wall.append((time.perf_counter() - w) * 1000)
        cpu.append((time.process_time() - c) * 1000)
    return summarise(wall, cpu)


def child(size, component):
    """Runs one operation once in this fresh process and prints peak RSS (bytes)."""
    with patch('vault.audit.check_hibp_k_anonymity', return_value=0), \
         patch('vault.gate.check_hibp_status', return_value=(BreachStatus.NOT_BREACHED, 0)):
        entries = vault(size)
        baseline = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if component != 'baseline':
            operations(entries)[component]()
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    scale = 1 if sys.platform == 'darwin' else 1024  # macOS reports bytes, Linux kilobytes
    print(json.dumps(dict(baseline_rss_bytes=baseline * scale, peak_rss_bytes=peak * scale)))


def peak_rss(size, component):
    out = subprocess.run([sys.executable, __file__, '--child', str(size), component], capture_output=True,
                         text=True, cwd=ROOT, check=True).stdout.strip().splitlines()[-1]
    return json.loads(out)


class FakeResponse:
    def __init__(self, status=200, text=''):
        self.status_code, self.text = status, text

    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.HTTPError(str(self.status_code))


def padded_body(n_lines=800):
    rng = random.Random(7)
    return '\n'.join(''.join(rng.choices('0123456789ABCDEF', k=35)) + f':{rng.randrange(0, 3)}' for _ in range(n_lines))


def network_conditions():
    body = padded_body()
    def latency(seconds):
        def get(*args, **kwargs):
            time.sleep(seconds)
            return FakeResponse(200, body)
        return get
    def error(exc, after=0.0):
        def get(*args, **kwargs):
            time.sleep(after)
            raise exc
        return get
    return {
        'latency_50ms': latency(0.05), 'latency_200ms': latency(0.2), 'latency_1000ms': latency(1.0),
        'connection_refused': error(requests.ConnectionError('emulated refusal')),
        'timeout_after_10s_each_attempt': error(requests.Timeout('emulated timeout'), after=10.0),
        'http_503': lambda *a, **k: FakeResponse(503, ''),
        'malformed_body': lambda *a, **k: FakeResponse(200, 'not-a-range-response'),
    }


def network_runs(sizes_for_audit=(100,)):
    results = []
    for name, get in network_conditions().items():
        slow = name.startswith('timeout')
        with patch.object(syntactic.requests, 'get', get):
            for op in ('save_gate', 'full_local_audit'):
                for n in ((100,) if op == 'save_gate' else sizes_for_audit):
                    entries = vault(n)
                    repeats = 1 if slow else 5
                    if slow and op == 'full_local_audit':
                        continue  # 100 entries x 20 s / 8 workers would take minutes; gate shows the bound
                    wall = []
                    status = None
                    for _ in range(repeats):
                        syntactic.clear_hibp_cache()
                        start = time.perf_counter()
                        res = (evaluate_save_gate(CANDIDATE, 'test', entries, PROFILE) if op == 'save_gate'
                               else audit_vault(entries, PROFILE))
                        wall.append((time.perf_counter() - start) * 1000)
                        status = (res.breach_status.value if op == 'save_gate'
                                  else f'unknown={res.unknown_breach_count}/{res.total_entries}')
                    results.append(dict(condition=name, operation=op, entries=n, repeats=repeats,
                                        median_ms=statistics.median(wall), max_ms=max(wall), breach_status=status))
                    print(results[-1], flush=True)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--child', nargs=2, metavar=('SIZE', 'COMPONENT'))
    parser.add_argument('--sizes', nargs='+', type=int, default=[10, 100, 500, 1000, 5000])
    parser.add_argument('--repeats', type=int, default=20)
    parser.add_argument('--repeats-large', type=int, default=5)
    parser.add_argument('--out', type=Path, default=ROOT / 'results/review2/performance.json')
    args = parser.parse_args()
    if args.child:
        child(int(args.child[0]), args.child[1])
        return
    records = []
    with patch('vault.audit.check_hibp_k_anonymity', return_value=0), \
         patch('vault.gate.check_hibp_status', return_value=(BreachStatus.NOT_BREACHED, 0)):
        for n in args.sizes:
            entries = vault(n)
            for name, fn in operations(entries).items():
                repeats = args.repeats if n <= 1000 else args.repeats_large
                if name == 'derivative_reference_quadratic' and n >= 5000:
                    repeats = 3
                rec = dict(size=n, component=name, **time_it(fn, repeats))
                records.append(rec)
                print(n, name, round(rec['median_ms'], 2), flush=True)
    memory = []
    for n in args.sizes:
        base = peak_rss(n, 'baseline')
        for name in ('full_local_audit', 'save_gate', 'derivative_indexed'):
            m = peak_rss(n, name)
            memory.append(dict(size=n, component=name, baseline_rss_mib=base['peak_rss_bytes'] / 2**20,
                               peak_rss_mib=m['peak_rss_bytes'] / 2**20,
                               increase_over_baseline_mib=(m['peak_rss_bytes'] - base['peak_rss_bytes']) / 2**20))
            print(memory[-1], flush=True)
    network = network_runs()
    cpu = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], capture_output=True, text=True).stdout.strip() \
        if sys.platform == 'darwin' else platform.processor()
    ram = subprocess.run(['sysctl', '-n', 'hw.memsize'], capture_output=True, text=True).stdout.strip() \
        if sys.platform == 'darwin' else ''
    report = dict(platform=platform.platform(), cpu=cpu, ram_bytes=int(ram) if ram else None,
                  python=sys.version.split()[0], timer='time.perf_counter (wall) and time.process_time (CPU)',
                  caveats=['One host only', 'Random fictional 16-character vaults',
                           'HIBP stubbed in local timings; network conditions emulated, not live',
                           'Peak RSS from a fresh subprocess per measurement (includes interpreter baseline)'],
                  timing=records, peak_rss=memory, emulated_network=network)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
