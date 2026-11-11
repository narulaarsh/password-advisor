"""Review 2 E5: packet-level view of breach checks, as a network observer would see them.

Captures only DNS and HTTPS traffic to the HIBP range API addresses with tcpdump
(requires membership of the access_bpf group or root), while the application checks
fictional passwords. Only HIBP-related findings are kept: DNS names containing
'pwnedpasswords', TLS server names, per-connection sizes and timing, and whether
any hash prefix or path is visible in plaintext. Local IP/MAC addresses and other
DNS queries are never stored, and the raw capture file is deleted after parsing.
"""
import argparse
import hashlib
import json
import os
import platform
import random
import signal
import socket
import string
import struct
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from modules import syntactic

HOST = 'api.pwnedpasswords.com'


def default_interface():
    out = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if 'interface:' in line:
            return line.split(':', 1)[1].strip()
    return 'en0'


def resolve(host):
    return sorted({info[4][0] for info in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})


def read_pcap(path):
    data = Path(path).read_bytes()
    magic = data[:4]
    endian = '<' if magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1') else '>'
    nano = magic in (b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d')
    linktype = struct.unpack(endian + 'I', data[20:24])[0]
    offset, packets = 24, []
    while offset + 16 <= len(data):
        sec, frac, incl, _ = struct.unpack(endian + 'IIII', data[offset:offset + 16])
        packets.append((sec + frac / (1e9 if nano else 1e6), data[offset + 16:offset + 16 + incl]))
        offset += 16 + incl
    return linktype, packets


def parse_ip(linktype, frame):
    if linktype == 1:  # Ethernet
        ethertype, payload = struct.unpack('!H', frame[12:14])[0], frame[14:]
        if ethertype == 0x8100:
            ethertype, payload = struct.unpack('!H', frame[16:18])[0], frame[18:]
    elif linktype in (0, 108):  # BSD loopback / null
        family = struct.unpack('<I', frame[:4])[0]
        ethertype, payload = (0x0800 if family == 2 else 0x86DD), frame[4:]
    else:
        return None
    if ethertype == 0x0800:
        ihl = (payload[0] & 0x0F) * 4
        proto = payload[9]
        return proto, socket.inet_ntop(socket.AF_INET, payload[12:16]), socket.inet_ntop(socket.AF_INET, payload[16:20]), payload[ihl:]
    if ethertype == 0x86DD:
        return payload[6], socket.inet_ntop(socket.AF_INET6, payload[8:24]), socket.inet_ntop(socket.AF_INET6, payload[24:40]), payload[40:]
    return None


def dns_question(udp_payload):
    try:
        offset, labels = 12, []
        while udp_payload[offset]:
            n = udp_payload[offset]
            labels.append(udp_payload[offset + 1:offset + 1 + n].decode('ascii', 'replace'))
            offset += n + 1
        qtype = struct.unpack('!H', udp_payload[offset + 1:offset + 3])[0]
        return '.'.join(labels), {1: 'A', 28: 'AAAA', 65: 'HTTPS'}.get(qtype, str(qtype))
    except (IndexError, struct.error):
        return None, None


def tls_sni(payload):
    try:
        if payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 9 + 2 + 32  # record(5) + handshake header(4) + version + random
        p += 1 + payload[p]  # session id
        p += 2 + struct.unpack('!H', payload[p:p + 2])[0]  # cipher suites
        p += 1 + payload[p]  # compression
        end = p + 2 + struct.unpack('!H', payload[p:p + 2])[0]
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack('!HH', payload[p:p + 4])
            if etype == 0:
                name_len = struct.unpack('!H', payload[p + 7:p + 9])[0]
                return payload[p + 9:p + 9 + name_len].decode('ascii', 'replace')
            p += 4 + elen
    except (IndexError, struct.error):
        return None
    return None


def run(n):
    rng = random.Random(4242)
    passwords = [''.join(rng.choices(string.ascii_letters + string.digits + '!#', k=16)) for _ in range(n)]
    digests = [hashlib.sha1(p.encode()).hexdigest().upper() for p in passwords]
    addresses = resolve(HOST)
    iface = default_interface()
    hosts = ' or '.join(f'host {a}' for a in addresses)
    capture_filter = f'port 53 or (tcp port 443 and ({hosts}))'
    tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
    tmp.close()
    proc = subprocess.Popen(['tcpdump', '-i', iface, '-n', '-U', '-s', '0', '-w', tmp.name, capture_filter],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(2.0)
    if proc.poll() is not None:
        raise SystemExit('tcpdump failed to start: ' + proc.stderr.read().decode(errors='replace'))
    started = time.time()
    outcomes = []
    for pw in passwords:
        syntactic.clear_hibp_cache()
        outcomes.append(syntactic.check_hibp_k_anonymity(pw))
        time.sleep(0.3)
    elapsed = time.time() - started
    time.sleep(1.5)
    proc.send_signal(signal.SIGINT)
    proc.wait(timeout=10)
    try:
        linktype, packets = read_pcap(tmp.name)
    finally:
        os.unlink(tmp.name)  # raw capture may contain unrelated DNS queries; never kept

    remote = set(addresses)
    dns_names, flows, sni, other_dns = defaultdict(int), {}, defaultdict(int), 0
    plaintext = b''
    for ts, frame in packets:
        ip = parse_ip(linktype, frame)
        if not ip:
            continue
        proto, src, dst, l4 = ip
        if proto == 17 and len(l4) >= 8 and 53 in struct.unpack('!HH', l4[:4]):
            name, qtype = dns_question(l4[8:])
            if name and 'pwnedpasswords' in name:
                dns_names[f'{name} ({qtype})'] += 1
            elif name:
                other_dns += 1
        elif proto == 6 and len(l4) >= 20:
            sport, dport = struct.unpack('!HH', l4[:4])
            payload = l4[(l4[12] >> 4) * 4:]
            outbound = dst in remote and dport == 443
            key = sport if outbound else dport
            flow = flows.setdefault(key, dict(first=ts, last=ts, up_bytes=0, down_bytes=0, up_packets=0, down_packets=0))
            flow['last'] = ts
            if outbound:
                flow['up_bytes'] += len(payload); flow['up_packets'] += 1
                name = tls_sni(payload) if payload else None
                if name:
                    sni[name] += 1
            else:
                flow['down_bytes'] += len(payload); flow['down_packets'] += 1
            plaintext += payload
    visible = dict(
        range_path=b'/range/' in plaintext,
        any_prefix=any(d[:5].encode() in plaintext for d in digests),
        any_suffix=any(d[5:].encode() in plaintext for d in digests),
        any_password=any(p.encode() in plaintext for p in passwords),
        user_agent=b'PasswordAdvisor' in plaintext)
    flow_list = sorted(flows.values(), key=lambda f: f['first'])
    report = dict(
        provenance='tcpdump capture on the default interface; only HIBP-related findings retained; raw capture deleted',
        platform=platform.platform(), interface_type='default route interface', checks=n,
        check_results=dict(breached=sum(c > 0 for c in outcomes), not_found=sum(c == 0 for c in outcomes),
                           unknown=sum(c < 0 for c in outcomes)),
        seconds=round(elapsed, 1), packets_captured=len(packets), hibp_addresses_resolved=len(addresses),
        dns_queries_for_hibp=dict(dns_names), other_dns_queries_seen_not_recorded=other_dns,
        tls_server_names=dict(sni), tls_connections=len(flow_list),
        connection_sizes=[dict(up_bytes=f['up_bytes'], down_bytes=f['down_bytes'], up_packets=f['up_packets'],
                               down_packets=f['down_packets'], duration_ms=round((f['last'] - f['first']) * 1000, 1))
                          for f in flow_list],
        visible_in_plaintext=visible,
        limitations=['DNS answers may come from cache, so absent queries do not mean no lookup occurs in general',
                     'One network, one host, one run', 'Encrypted DNS configurations would hide the DNS name'])
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--n', type=int, default=10)
    parser.add_argument('--out', type=Path, default=ROOT / 'results/review2/packet_capture.json')
    args = parser.parse_args()
    report = run(args.n)
    args.out.write_text(json.dumps(report, indent=2))
    print(json.dumps({k: v for k, v in report.items() if k != 'connection_sizes'}, indent=2))
    sizes = report['connection_sizes']
    if sizes:
        print('connections:', len(sizes), 'up bytes', min(s['up_bytes'] for s in sizes), '-', max(s['up_bytes'] for s in sizes),
              'down bytes', min(s['down_bytes'] for s in sizes), '-', max(s['down_bytes'] for s in sizes))


if __name__ == '__main__':
    main()
