"""Tabulates E6 results from every host folder in results/review2/hosts/ next to the development host."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def summarise(perf):
    t = {(r['size'], r['component']): r for r in perf['timing']}
    return {n: dict(full_audit_ms=round(t[(n, 'full_local_audit')]['median_ms'], 1),
                    save_gate_ms=round(t[(n, 'save_gate')]['median_ms'], 2),
                    derivative_ms=round(t[(n, 'derivative_indexed')]['median_ms'], 1))
            for n in sorted({k[0] for k in t})}


def main():
    hosts = {'development': ROOT / 'results/review2/performance.json'}
    for folder in sorted((ROOT / 'results/review2/hosts').glob('*/performance.json')):
        hosts[folder.parent.name] = folder
    if len(hosts) == 1:
        print('No second-host results yet. Run scripts/run_second_machine.sh on another computer.')
    for name, path in hosts.items():
        perf = json.loads(path.read_text())
        print(name, perf.get('platform'), perf.get('cpu'))
        for n, row in summarise(perf).items():
            print(f'  {n:>5}: {row}')


if __name__ == '__main__':
    sys.exit(main())
