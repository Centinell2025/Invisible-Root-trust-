#!/usr/bin/env python3
"""High-fidelity but entirely simulated enterprise Linux incident evidence.

No production events, enterprise identifiers, firmware acquisitions, executable
malware, credentials, or real victim data.  Python standard library only.
Generated content is deterministic for exact cold-solve answer contracts.
"""
import csv
import hashlib
import ipaddress
import json
import random
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts"
OUT.mkdir(parents=True, exist_ok=True)
DAY = datetime(2026, 9, 17, 2, 48, tzinfo=timezone.utc)
RAND = random.Random(20260917)
HOST = "nrg-gw-07"
GATEWAY = "192.0.2.17"
DEST = "198.51.100.73"
OTHER = "198.51.100.91"
SOC = "192.0.2.80"
LOCAL_ACCOUNT = "svc-maint"

def stamp(minutes=0, seconds=0):
    return (DAY + timedelta(minutes=minutes, seconds=seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")

def write_csv(name, columns, records):
    with (OUT / name).open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(records)

def write_jsonl(name, records):
    (OUT / name).write_text("".join(json.dumps(x, sort_keys=True, separators=(",", ":")) + "\n"
                                     for x in records), encoding="utf-8")

def digest(x):
    return hashlib.sha256(x).hexdigest()

# A local *software* configuration and check are not shim, PK/KEK/db UEFI
# measurements or TPM quotes. Make the source-to-measurement derivation explicit.
policy_old = (OUT / "policy_baseline.bin").read_bytes()
policy_new = (OUT / "policy_observed.bin").read_bytes()
kernel_sample = b"NRG-LAB-REFERENCE-KERNEL:6.8.0-simulated:metadata-only"
old_hash, new_hash, kernel_hash = map(digest, (policy_old, policy_new, kernel_sample))
write_csv("secure_boot_attestation.csv",
          ["utc", "host", "component", "expected_digest", "observed_digest", "status",
           "measurement_method", "trust_anchor", "collector"],
          [
            dict(utc="2026-09-17T02:55:00Z", host=HOST, component="shim-policy",
                 expected_digest=old_hash, observed_digest=old_hash, status="match",
                 measurement_method="software-sha256-policy-specimen", trust_anchor="none", collector="attestationd"),
            dict(utc="2026-09-17T03:18:00Z", host=HOST, component="shim-policy",
                 expected_digest=old_hash, observed_digest=new_hash, status="mismatch",
                 measurement_method="software-sha256-policy-specimen", trust_anchor="none", collector="attestationd"),
            dict(utc="2026-09-17T03:19:00Z", host=HOST, component="kernel-image",
                 expected_digest=kernel_hash, observed_digest=kernel_hash, status="match",
                 measurement_method="software-reference-metadata", trust_anchor="none", collector="attestationd")
          ])
write_csv("measurement_derivation.csv",
          ["utc", "component", "observation", "source_specimen", "algorithm", "sha256",
           "collection_type", "trust_anchor"],
          [
            dict(utc="2026-09-17T02:55:00Z", component="shim-policy",
                 observation="approved-reference", source_specimen="policy_baseline.bin",
                 algorithm="SHA-256", sha256=old_hash,
                 collection_type="offline-simulated-specimen", trust_anchor="none"),
            dict(utc="2026-09-17T03:18:00Z", component="shim-policy",
                 observation="observed-local-software-check", source_specimen="policy_observed.bin",
                 algorithm="SHA-256", sha256=new_hash,
                 collection_type="simulated-local-software-check", trust_anchor="none"),
          ])
write_csv("trust_anchor_inventory.csv",
          ["utc", "host", "mechanism", "collection_status", "reference", "verified_by"],
          [
            dict(utc="2026-09-17T03:25:00Z", host=HOST, mechanism="TPM2-quote",
                 collection_status="not-acquired", reference="missing-TPM-nonce-PCR-signature", verified_by=""),
            dict(utc="2026-09-17T03:25:00Z", host=HOST, mechanism="EFI-variable-export",
                 collection_status="not-acquired", reference="missing-PK-KEK-db-dbX", verified_by=""),
            dict(utc="2026-09-17T03:25:00Z", host=HOST, mechanism="offline-firmware-image",
                 collection_status="not-acquired", reference="missing-spi-firmware-dump", verified_by=""),
          ])

# Snapshot of an installed unit is a file artifact, not proof of execution
# or persistence across reboot.
unit_text = """# synthetic offline unit specimen, not captured from a real machine
[Unit]
Description=Local boot health telemetry
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/local/libexec/boot-health-agent --check /etc/secureboot/policy.conf
StandardOutput=journal

[Install]
WantedBy=multi-user.target
"""
(OUT / "boot-health-agent.service").write_text(unit_text, encoding="utf-8")
service_inventory = [
    ("2026-09-17T02:53:20Z", "ssh.service", "/usr/lib/systemd/system/ssh.service", "enabled", "active", "openssh-server", "stock"),
    ("2026-09-17T02:53:21Z", "systemd-timesyncd.service", "/usr/lib/systemd/system/systemd-timesyncd.service", "enabled", "active", "systemd", "stock"),
    ("2026-09-17T02:53:22Z", "apt-daily.service", "/usr/lib/systemd/system/apt-daily.service", "static", "inactive", "apt", "stock"),
    ("2026-09-17T03:16:40Z", "boot-health-agent.service", "/etc/systemd/system/boot-health-agent.service", "enabled", "active", "unverified-local", "investigate"),
    ("2026-09-17T03:16:55Z", "node-exporter.service", "/usr/lib/systemd/system/node-exporter.service", "enabled", "active", "prometheus-node-exporter", "stock"),
]
write_csv("systemd_unit_inventory.csv",
          ["utc", "unit", "fragment_path", "unit_file_state", "active_state", "package_owner", "triage"],
          [dict(zip(("utc", "unit", "fragment_path", "unit_file_state", "active_state", "package_owner", "triage"), r))
           for r in service_inventory])

# File and process observations have distinct acquisition provenance. Events
# labeled from a local source remain host assertions, not external attestation.
file_rows = [
    ("2026-09-17T02:55:00Z", "/etc/secureboot/policy.conf", old_hash, "root", "root", "0644", "FIM-0001", "local-fim", "baseline"),
    ("2026-09-17T03:10:03Z", "/etc/apt/apt.conf.d/20auto-upgrades", digest(b"APT::Periodic::Update-Package-Lists"), "root", "root", "0644", "FIM-0002", "local-fim", "routine"),
    ("2026-09-17T03:12:28Z", "/etc/secureboot/policy.conf", new_hash, "root", "root", "0644", "FIM-0003", "local-fim", "altered"),
    ("2026-09-17T03:16:39Z", "/etc/systemd/system/boot-health-agent.service", digest(unit_text.encode()), "root", "root", "0644", "FIM-0004", "local-fim", "new-unit-specimen"),
    ("2026-09-17T03:17:44Z", "/var/log/apt/history.log", digest(b"routine update history"), "root", "adm", "0640", "FIM-0005", "local-fim", "routine"),
]
write_csv("file_integrity_timeline.csv",
          ["utc", "path", "sha256", "owner", "group", "mode", "event_id", "collector", "label"],
          [dict(zip(("utc", "path", "sha256", "owner", "group", "mode", "event_id", "collector", "label"), r))
           for r in file_rows])

process_rows = [
    ("2026-09-17T03:02:10Z", "1772", "902", "svc-maint", "/usr/sbin/sshd -D", "AUTH-701", "gateway-proc", "local-snapshot"),
    ("2026-09-17T03:06:12Z", "2417", "1772", "root", "/usr/bin/sudo -n /usr/local/sbin/nrg-policy-sync", "AUTH-702", "gateway-proc", "local-snapshot"),
    ("2026-09-17T03:12:27Z", "2421", "2417", "root", "/usr/bin/python3 /usr/local/sbin/nrg-policy-sync", "AUTH-702", "gateway-audit", "audit-join"),
    ("2026-09-17T03:16:40Z", "2741", "1", "root", "/usr/local/libexec/boot-health-agent --check /etc/secureboot/policy.conf", "PRC-2741", "gateway-proc", "local-snapshot"),
    ("2026-09-17T03:17:07Z", "2904", "2741", "root", "/usr/bin/curl --silent --retry 0 https://telemetry.example.invalid/api/health", "PRC-2904", "gateway-proc", "local-snapshot"),
    ("2026-09-17T03:18:02Z", "2917", "1", "root", "/usr/local/sbin/attestationd --local-policy", "PRC-2917", "gateway-proc", "local-snapshot"),
]
write_csv("process_lineage.csv",
          ["utc", "pid", "ppid", "account", "command_line", "reference", "collector", "confidence_scope"],
          [dict(zip(("utc", "pid", "ppid", "account", "command_line", "reference", "collector", "confidence_scope"), r))
           for r in process_rows])

# A high signal-to-noise ratio was the principal earlier design flaw.  Create
# background events with reproducible intervals and a few common operational
# lookalikes, using domain/documentation IPs only.
auth_lines = []
for i in range(80):
    t = DAY + timedelta(seconds=RAND.randrange(0, 41 * 60))
    ts = t.strftime("%b %d %H:%M:%S")
    account = ["backup", "metrics", "buildbot", "svc-maint", "deploy"][i % 5]
    ip = ["192.0.2.31", "192.0.2.32", "192.0.2.64"][i % 3]
    if i % 9 == 0:
        msg = f"sshd[{4100+i}]: Invalid user {account} from {ip} port {44000+i}"
    elif i % 3 == 0:
        msg = f"CRON[{4100+i}]: pam_unix(cron:session): session opened for user root(uid=0)"
    else:
        msg = f"sshd[{4100+i}]: Connection closed by authenticating user {account} {ip} port {44000+i} [preauth]"
    auth_lines.append((t, f"{ts} {HOST} {msg}"))
special = [
    ("2026-09-17T03:02:10Z", "sshd[1772]: Accepted publickey for svc-maint from 192.0.2.44 port 49212 ssh2: ED25519 SHA256:simulated-key-fingerprint"),
    ("2026-09-17T03:06:12Z", "sudo[2417]: svc-maint : TTY=pts/1 ; PWD=/home/svc-maint ; USER=root ; COMMAND=/usr/local/sbin/nrg-policy-sync"),
    ("2026-09-17T03:12:27Z", "sudo[2417]: pam_unix(sudo:session): session opened for user root(uid=0) by svc-maint(uid=1102)"),
]
for dt, message in special:
    t = datetime.fromisoformat(dt.replace("Z", "+00:00"))
    auth_lines.append((t, t.strftime("%b %d %H:%M:%S") + f" {HOST} " + message))
auth_lines.sort(key=lambda x: (x[0], x[1]))
(OUT / "auth_syslog.log").write_text("\n".join(x[1] for x in auth_lines) + "\n", encoding="utf-8")

# auditd-style messages: real Linux audit syntax shape, simulated IDs. Preserve
# the same local event identifier in a key; audit record seq numbers 8102/8103
# are intentionally absent from the simplified CSV, not proof of deletion.
# Preserve auditd timestamp ordering and monotonically increasing serial IDs.
# The simplified export intentionally omits 8102/8103; no fake claim of tampering.
audit_records = []
for moment, serial, pid, syscall, item in [
    ("2026-09-17T03:06:15Z", 8101, 2417, "openat", "/etc/secureboot/policy.conf"),
    ("2026-09-17T03:12:27Z", 8104, 2421, "write", "/etc/secureboot/policy.conf"),
    ("2026-09-17T03:13:01Z", 8105, 2421, "close", "/etc/secureboot/policy.conf"),
]:
    t = datetime.fromisoformat(moment.replace("Z", "+00:00"))
    epoch = t.timestamp()
    audit_records.extend([
        (t, serial, 0, f'type=SYSCALL msg=audit({epoch:.3f}:{serial}): arch=c000003e syscall={syscall} success=yes pid={pid} auid=1102 uid=0 key="AUTH-702"'),
        (t, serial, 1, f'type=PATH msg=audit({epoch:.3f}:{serial}): item=0 name="{item}" inode=440221 nametype=NORMAL'),
    ])
# Background activity occurs entirely before 8101 or after 8105.
# Synthetic serial numbers increase with time. None impersonate 8102/8103.
for i in range(35):
    if i < 20:
        t = datetime(2026, 9, 17, 2, 50, tzinfo=timezone.utc) + timedelta(seconds=38 * i)
        serial = 8070 + i
    else:
        t = datetime(2026, 9, 17, 3, 13, 20, tzinfo=timezone.utc) + timedelta(seconds=40 * (i - 20))
        serial = 8110 + (i - 20)
    epoch = t.timestamp()
    audit_records.append(
        (t, serial, 0, f'type=SYSCALL msg=audit({epoch:.3f}:{serial}): arch=c000003e syscall=openat success=yes pid={4800+i} auid=0 uid=0 key="routine-maintenance"')
    )
audit_records.sort(key=lambda r:(r[0],r[1],r[2]))
(OUT / "auditd_extract.log").write_text(
    "\n".join(row[3] for row in audit_records) + "\n", encoding="utf-8"
)

# Sensor capture: valid Ethernet/IPv4 TCP + UDP frames with checksums. TCP
# handshake plus short application-like data is not a complete exfil session.
def checksum(b):
    if len(b) & 1:
        b += b"\x00"
    words = struct.unpack("!" + "H" * (len(b) // 2), b)
    s = sum(words)
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def ipbytes(addr):
    return ipaddress.IPv4Address(addr).packed

def frame(src, dst, sport, dport, protocol, payload, *, seq=0, ack=0, flags=0x10, packet_id=100):
    # All MAC addresses are locally administered.
    ethernet = b"\x02\x42\xac\x11\x00\x02\x02\x42\xac\x11\x00\x01\x08\x00"
    src_b, dst_b = ipbytes(src), ipbytes(dst)
    if protocol == 6:
        header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, (5 << 12) | flags, 65535, 0, 0)
        pseudo = src_b + dst_b + struct.pack("!BBH", 0, protocol, len(header) + len(payload))
        transport = header[:16] + struct.pack("!H", checksum(pseudo + header + payload)) + header[18:]
    else:
        transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
        pseudo = src_b + dst_b + struct.pack("!BBH", 0, protocol, len(transport) + len(payload))
        transport = transport[:6] + struct.pack("!H", checksum(pseudo + transport + payload))
    length = 20 + len(transport) + len(payload)
    ipv4 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, length, packet_id, 0, 64, protocol, 0, src_b, dst_b)
    ipv4 = ipv4[:10] + struct.pack("!H", checksum(ipv4)) + ipv4[12:]
    return ethernet + ipv4 + transport + payload

packets = []
def packet(when, *args, **kwargs):
    packets.append((when, frame(*args, **kwargs)))
base = datetime(2026, 9, 17, 3, 17, 7, tzinfo=timezone.utc)
packet(base, GATEWAY, DEST, 50544, 443, 6, b"", seq=330000, flags=0x02, packet_id=301)
packet(base + timedelta(milliseconds=33), DEST, GATEWAY, 443, 50544, 6, b"", seq=710000, ack=330001, flags=0x12, packet_id=302)
packet(base + timedelta(milliseconds=38), GATEWAY, DEST, 50544, 443, 6, b"", seq=330001, ack=710001, flags=0x10, packet_id=303)
# Deterministic TLS-record-like bytes, intentionally NOT an authenticated TLS
# session or complete reconstruction of the claimed 9821 outbound bytes.
hello = b"\x16\x03\x03" + struct.pack("!H", 48) + bytes(range(48))
packet(base + timedelta(milliseconds=94), GATEWAY, DEST, 50544, 443, 6, hello,
       seq=330001, ack=710001, flags=0x18, packet_id=304)
packet(base + timedelta(milliseconds=125), DEST, GATEWAY, 443, 50544, 6, b"",
       seq=710001, ack=330001 + len(hello), flags=0x10, packet_id=305)
# A separate UDP observation shares the destination but is not this TCP tuple.
packet(base + timedelta(milliseconds=250), GATEWAY, DEST, 52118, 443, 17, b"status=probe",
       packet_id=306)
# A benign background TCP connection is intentionally present.
packet(base + timedelta(seconds=4), GATEWAY, OTHER, 50545, 443, 6, b"", seq=1100, flags=0x02,
       packet_id=307)
packet(base + timedelta(seconds=4, milliseconds=39), OTHER, GATEWAY, 443, 50545, 6, b"",
       seq=2200, ack=1101, flags=0x12, packet_id=308)
packets.sort(key=lambda x: x[0])
pcap = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
for instant, raw in packets:
    pcap += struct.pack("<IIII", int(instant.timestamp()), instant.microsecond, len(raw), len(raw)) + raw
(OUT / "edge_sensor_capture.pcap").write_bytes(pcap)

write_csv("socket_observations.csv",
          ["utc", "host", "pid", "process", "src_ip", "src_port", "dst_ip", "dst_port",
           "protocol", "state", "collector"],
          [
            dict(utc="2026-09-17T03:17:07Z", host=HOST, pid="2904", process="curl",
                 src_ip=GATEWAY, src_port="50544", dst_ip=DEST, dst_port="443",
                 protocol="TCP", state="ESTABLISHED", collector="gateway-local-ss"),
            dict(utc="2026-09-17T03:17:11Z", host=HOST, pid="3007", process="apt-helper",
                 src_ip=GATEWAY, src_port="50545", dst_ip=OTHER, dst_port="443",
                 protocol="TCP", state="SYN-SENT", collector="gateway-local-ss"),
          ])
write_csv("sensor_capture_scope.csv",
          ["utc", "sensor", "capture", "method", "start_utc", "end_utc",
           "packet_count", "selection", "coverage_note"],
          [dict(utc="2026-09-17T03:17:12Z", sensor="nrg-sensor-04",
                capture="edge_sensor_capture.pcap", method="simulated-off-host-pcap",
                start_utc="2026-09-17T03:17:07Z", end_utc="2026-09-17T03:17:11Z",
                packet_count=str(len(packets)), selection="short-window-synthetic-sample",
                coverage_note="partial capture; not representative of flow byte counters")])
# Zero-copy collection manifest by source: synthetic provenance, not true
# chain-of-custody signing.
write_csv("acquisition_register.csv",
          ["utc", "source_id", "artifact", "source_host", "method", "completeness", "verified_origin"],
          [
            dict(utc="2026-09-17T03:26:00Z", source_id="COL-01",
                 artifact="auth_syslog.log", source_host=HOST, method="simulated-log-export",
                 completeness="window-selection", verified_origin="no"),
            dict(utc="2026-09-17T03:26:10Z", source_id="COL-02",
                 artifact="auditd_extract.log", source_host=HOST, method="simulated-audit-export",
                 completeness="selected-events", verified_origin="no"),
            dict(utc="2026-09-17T03:26:20Z", source_id="COL-03",
                 artifact="edge_sensor_capture.pcap", source_host="nrg-sensor-04",
                 method="synthetic-off-host-pcap", completeness="short-window", verified_origin="no"),
            dict(utc="2026-09-17T03:26:30Z", source_id="COL-04",
                 artifact="file_integrity_timeline.csv", source_host=HOST,
                 method="local-agent-export", completeness="selected-paths", verified_origin="no"),
            dict(utc="2026-09-17T03:26:40Z", source_id="COL-05",
                 artifact="measurement_derivation.csv", source_host=HOST,
                 method="local-software-mock", completeness="limited", verified_origin="no"),
          ])

write_jsonl("journal_extended.jsonl", [
    {
        "utc": stamp(minutes=i // 3, seconds=(i * 17) % 59),
        "_HOSTNAME": HOST,
        "_PID": str(4800 + i),
        "_SYSTEMD_UNIT": ["ssh.service", "apt-daily.service", "node-exporter.service"][i % 3],
        "PRIORITY": str([5, 6, 6][i % 3]),
        "MESSAGE": ["session activity observed", "periodic package metadata refresh",
                    "node metrics collection completed"][i % 3],
        "collector": "synthetic-journal-export",
    }
    for i in range(65)
] + [
    dict(utc="2026-09-17T03:12:29Z", _HOSTNAME=HOST, _PID="2421",
         _SYSTEMD_UNIT="nrg-update.service", PRIORITY="6",
         MESSAGE="Routine signed update completed", collector="synthetic-journal-export"),
    dict(utc="2026-09-17T03:16:40Z", _HOSTNAME=HOST, _PID="2741",
         _SYSTEMD_UNIT="boot-health-agent.service", PRIORITY="6",
         MESSAGE="Started Local boot health telemetry", collector="synthetic-journal-export"),
    dict(utc="2026-09-17T03:18:02Z", _HOSTNAME=HOST, _PID="2917",
         _SYSTEMD_UNIT="attestationd.service", PRIORITY="4",
         MESSAGE="Local software measurement mismatch", collector="synthetic-journal-export"),
])
print("Generated realistic synthetic host, file, identity, measurement and sensor evidence.")
