"""Writes a concealed permuted-block allocation schedule for the G1-G4 study.

Keep the output private (mode 0600) and give participants slot IDs in enrollment order.
Example: .venv/bin/python scripts/make_allocation_schedule.py --seed <secret> --slots 200 --out data/private/allocation.csv
"""
import argparse
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vault.study import make_allocation_schedule, write_allocation_schedule


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', required=True)
    parser.add_argument('--slots', type=int, required=True)
    parser.add_argument('--out', type=Path, default=Path('data/private/allocation.csv'))
    args = parser.parse_args()
    rows = make_allocation_schedule(args.seed, args.slots)
    write_allocation_schedule(rows, args.out)
    print(f'Wrote {len(rows)} slots to {args.out}')


if __name__ == '__main__':
    main()
