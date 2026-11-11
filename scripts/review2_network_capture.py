"""Review 2 E5: application-layer capture of real HIBP range requests for fictional passwords.

Records the host, port, method, path and headers of every outbound HTTP request made
by `check_hibp_k_anonymity`, plus response size and line count, by wrapping urllib3's
connection methods. It then checks that neither the password, its full SHA-1 digest
nor the 35-character suffix appears in any outbound request. This is not a packet
capture: DNS, TLS handshakes and TCP metadata are not recorded (that needs root).
Only fictional or well-known public test passwords are used.
"""
import argparse
import hashlib
import json
import random
import string
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import urllib3.connection

from modules import syntactic

CAPTURED = []


def install_hooks():
    original_request = urllib3.connection.HTTPConnection.request

    def request(self, method, url, body=None, headers=None, *args, **kwargs):
        CAPTURED.append(dict(host=self.host, port=self.port, scheme='https' if self.port == 443 else 'http',
                             method=method, path=url, headers=dict(headers or {}),
                             body_bytes=len(body) if body else 0))
        return original_request(self, method, url, body=body, headers=headers, *args, **kwargs)

    urllib3.connection.HTTPConnection.request = request


def fictional_passwords(n, seed=2026):
    rng = random.Random(seed)
    made_up = [''.join(rng.choices(string.ascii_letters + string.digits + '!#', k=rng.randrange(10, 20)))
               for _ in range(n)]
    return ['password123', 'Summer2024!'] + made_up  # two widely published test strings, then random ones


def run(n):
    install_hooks()
    observations = []
    for pw in fictional_passwords(n):
        syntactic.clear_hibp_cache()
        digest = hashlib.sha1(pw.encode()).hexdigest().upper()
        before = len(CAPTURED)
        start = time.perf_counter()
        count = syntactic.check_hibp_k_anonymity(pw)
        elapsed = (time.perf_counter() - start) * 1000
        sent = CAPTURED[before:]
        outbound_text = json.dumps(sent).upper()
        observations.append(dict(
            requests=len(sent), elapsed_ms=round(elapsed, 1), result=('unknown' if count < 0 else
                                                                      'breached' if count > 0 else 'not_found'),
            prefix_matches_digest=all(r['path'].endswith('/' + digest[:5]) for r in sent),
            full_digest_sent=digest in outbound_text, suffix_sent=digest[5:] in outbound_text,
            password_sent=pw.upper() in outbound_text,
            destinations=sorted({f"{r['method']} {r['scheme']}://{r['host']}:{r['port']}{r['path'][:7]}…" for r in sent})))
    # Response-size observation for padding: fetch a few prefixes directly through the same path.
    sizes = []
    import requests
    for prefix in ('00000', '5BAA6', 'FFFFF', 'ABCDE', '12345'):
        r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', headers={
            'User-Agent': 'PasswordAdvisor-ResearchPilot/1.0', 'Add-Padding': 'true'}, timeout=10,
            allow_redirects=False)
        lines = r.text.splitlines()
        sizes.append(dict(prefix=prefix, status=r.status_code, bytes=len(r.content), lines=len(lines),
                          zero_count_padding_lines=sum(l.endswith(':0') for l in lines)))
    headers_seen = sorted({k for r in CAPTURED for k in r['headers']})
    summary = dict(
        provenance='application-layer capture (urllib3 hooks) of live requests; not a packet capture',
        passwords_tested=len(observations), requests_captured=len(CAPTURED),
        distinct_destinations=sorted({f"{r['method']} {r['host']}:{r['port']}" for r in CAPTURED}),
        request_headers_seen=headers_seen,
        user_agent=sorted({r['headers'].get('User-Agent', '') for r in CAPTURED}),
        add_padding_on_every_request=all(r['headers'].get('Add-Padding') == 'true' for r in CAPTURED),
        any_request_body=any(r['body_bytes'] for r in CAPTURED),
        any_full_digest_sent=any(o['full_digest_sent'] for o in observations),
        any_suffix_sent=any(o['suffix_sent'] for o in observations),
        any_password_sent=any(o['password_sent'] for o in observations),
        all_prefixes_match=all(o['prefix_matches_digest'] for o in observations),
        results=dict((k, sum(o['result'] == k for o in observations)) for k in ('breached', 'not_found', 'unknown')),
        median_elapsed_ms=sorted(o['elapsed_ms'] for o in observations)[len(observations) // 2],
        padded_response_sizes=sizes, observations=observations,
        limitations=['DNS queries, TLS SNI and TCP/IP metadata were not captured',
                     'Timing and request frequency remain visible to a network observer',
                     'One network, one host, one run'])
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--n', type=int, default=18)
    parser.add_argument('--out', type=Path, default=ROOT / 'results/review2/network_capture.json')
    args = parser.parse_args()
    summary = run(args.n)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != 'observations'}, indent=2))


if __name__ == '__main__':
    main()
