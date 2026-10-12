#!/usr/bin/env python3
"""Verify high-fidelity *synthetic* Linux/DFIR evidence.

Checks on-wire packet layout/checksums, a partial TCP conversation, evidence
content hashes, process/identity correlation, acquisition boundaries, and
non-trivial background noise. No claim of real data acquisition or UEFI trust.
"""
import csv
import hashlib
import ipaddress
import json
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "artifacts"

def require(ok, why):
    if not ok:
        raise ValueError(why)

def table(name):
    with (OUT / name).open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    require(len(rows) > 0, "Empty " + name)
    return rows

def sha(data):
    return hashlib.sha256(data).hexdigest()

def sum16(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff

def packets_from_pcap(raw):
    require(len(raw) >= 40, "PCAP too short")
    require(struct.unpack_from("<I", raw, 0)[0] == 0xa1b2c3d4, "PCAP magic")
    require(struct.unpack_from("<I", raw, 20)[0] == 1, "Not Ethernet")
    result = []
    i = 24
    while i < len(raw):
        require(i + 16 <= len(raw), "Truncated PCAP header")
        seconds, micros, captured, original = struct.unpack_from("<IIII", raw, i)
        i += 16
        require(0 <= micros < 1_000_000 and 0 < captured <= original <= 65535, "Invalid packet sizes")
        require(i + captured <= len(raw), "Truncated PCAP packet")
        eth = raw[i:i+captured]
        i += captured
        require(len(eth) >= 14 + 20 and eth[12:14] == b"\x08\x00", "Invalid Ethernet IPv4")
        ip = eth[14:]
        ihl = (ip[0] & 0xf) * 4
        require(ip[0] >> 4 == 4 and ihl >= 20 and len(ip) >= ihl, "Invalid IPv4 header")
        size = struct.unpack_from("!H", ip, 2)[0]
        require(size >= ihl and len(ip) >= size, "IPv4 total length mismatch")
        require(sum16(ip[:ihl]) == 0, "IPv4 header checksum invalid")
        protocol = ip[9]
        require(protocol in (6, 17), "Unexpected transport")
        src = str(ipaddress.IPv4Address(ip[12:16]))
        dst = str(ipaddress.IPv4Address(ip[16:20]))
        data = ip[ihl:size]
        require(len(data) >= (20 if protocol == 6 else 8), "Truncated transport header")
        sport, dport = struct.unpack_from("!HH", data, 0)
        pseudo = ip[12:20] + struct.pack("!BBH", 0, protocol, len(data))
        require(sum16(pseudo + data) == 0, "Invalid transport checksum")
        flags, seq, ack = 0, None, None
        if protocol == 6:
            hdrlen = (data[12] >> 4) * 4
            require(hdrlen >= 20 and hdrlen <= len(data), "Invalid TCP data offset")
            flags = data[13]
            seq, ack = struct.unpack_from("!II", data, 4)
        else:
            require(struct.unpack_from("!H", data, 4)[0] == len(data), "UDP length mismatch")
            hdrlen = 8
        instant = datetime.fromtimestamp(seconds, timezone.utc)
        result.append(dict(utc=instant.isoformat().replace("+00:00", "Z"),
                           epoch=seconds, micros=micros, src=src, dst=dst,
                           protocol=protocol, sport=sport, dport=dport,
                           seq=seq, ack=ack, flags=flags,
                           payload=data[hdrlen:]))
    require(i == len(raw), "Extra PCAP bytes")
    return result

def verify():
    att = table("secure_boot_attestation.csv")
    measurements = table("measurement_derivation.csv")
    ledger = {r["specimen"]:r["sha256"] for r in table("policy_digest_crosscheck.csv")}
    pold = (OUT / "policy_baseline.bin").read_bytes()
    pnew = (OUT / "policy_observed.bin").read_bytes()
    old_hash, new_hash = sha(pold), sha(pnew)
    require(old_hash != new_hash, "Identical baseline and observed specimens")
    require(ledger["policy_baseline.bin"] == old_hash and ledger["policy_observed.bin"] == new_hash,
            "Policy hash ledger mismatch")
    rows = {r["observation"]:r for r in measurements}
    require(rows["approved-reference"]["sha256"] == old_hash, "Baseline derivation mismatch")
    require(rows["observed-local-software-check"]["sha256"] == new_hash, "Observed derivation mismatch")
    require(all(r["trust_anchor"] == "none" for r in measurements), "False hardware trust claim")
    match = [r for r in att if r["component"] == "shim-policy" and r["status"] == "match"]
    mismatch = [r for r in att if r["component"] == "shim-policy" and r["status"] == "mismatch"]
    require(len(match) == 1 and len(mismatch) == 1, "Ambiguous software policy measurements")
    require(match[0]["expected_digest"] == old_hash == match[0]["observed_digest"], "Wrong baseline hashes")
    require(mismatch[0]["expected_digest"] == old_hash and mismatch[0]["observed_digest"] == new_hash,
            "Local policy measurement not linked to specimen bytes")
    require(all(x["measurement_method"] == "software-sha256-policy-specimen" and x["trust_anchor"] == "none"
                for x in match + mismatch), "Local software check misrepresented as TPM-backed")
    anchors = table("trust_anchor_inventory.csv")
    require({"TPM2-quote", "EFI-variable-export", "offline-firmware-image"}
            <= {x["mechanism"] for x in anchors}, "Missing trust boundary inventory")
    require(all(x["collection_status"] == "not-acquired" for x in anchors),
            "Unexpected verified trust anchor without re-assessment")

    file_changes = table("file_integrity_timeline.csv")
    policy = [r for r in file_changes if r["path"] == "/etc/secureboot/policy.conf"]
    require([r["sha256"] for r in policy] == [old_hash, new_hash], "File integrity no longer linked to specimens")
    unit = (OUT / "boot-health-agent.service").read_bytes()
    units = table("systemd_unit_inventory.csv")
    require(any(r["unit"] == "boot-health-agent.service" and r["unit_file_state"] == "enabled"
                and r["fragment_path"] == "/etc/systemd/system/boot-health-agent.service"
                for r in units), "Unit metadata is absent")
    require(any(r["path"].endswith("/boot-health-agent.service") and r["sha256"] == sha(unit)
                for r in file_changes), "Unit byte hash disagrees with FIM")
    require(b"[Unit]" in unit and b"[Service]" in unit and b"ExecStart=" in unit,
            "Unit specimen not systemd shaped")

    processes = table("process_lineage.csv")
    by_pid = {r["pid"]:r for r in processes}
    require(len(by_pid) == len(processes), "Duplicate PID in process snapshot")
    require(by_pid["2417"]["reference"] == "AUTH-702" and
            by_pid["2421"]["ppid"] == "2417", "Privilege-to-write process chain broken")
    require(by_pid["2904"]["ppid"] == "2741" and
            "boot-health-agent" in by_pid["2741"]["command_line"], "Service-to-egress process chain broken")
    sockets = table("socket_observations.csv")
    outbound = [r for r in sockets if r["pid"] == "2904" and r["protocol"] == "TCP"]
    require(len(outbound) == 1, "Ambiguous socket attribution")
    flow = table("network_flows.csv")
    require(any(r["dst_ip"] == outbound[0]["dst_ip"] and r["dst_port"] == outbound[0]["dst_port"]
                and r["protocol"] == "TCP" for r in flow), "Flow and socket disagree")

    evidence = packets_from_pcap((OUT / "edge_sensor_capture.pcap").read_bytes())
    require(len(evidence) >= 8, "Packet capture needs nontrivial multi-frame evidence")
    require(all(datetime.fromtimestamp(p["epoch"], timezone.utc).year == 2026 for p in evidence),
            "Packet dates outside incident year")
    own = [p for p in evidence if p["src"] == "192.0.2.17" and p["dst"] == "198.51.100.73"
           and p["sport"] == 50544 and p["dport"] == 443 and p["protocol"] == 6]
    reverse = [p for p in evidence if p["src"] == "198.51.100.73" and p["dst"] == "192.0.2.17"
               and p["sport"] == 443 and p["dport"] == 50544 and p["protocol"] == 6]
    require(any(p["flags"] & 0x12 == 0x02 for p in own), "TCP SYN missing")
    require(any(p["flags"] & 0x12 == 0x12 for p in reverse), "TCP SYN/ACK missing")
    require(any((p["flags"] & 0x10) and not (p["flags"] & 0x02) for p in own), "TCP ACK missing")
    require(any(p["payload"] for p in own), "No captured TCP application bytes")
    captured_out = sum(len(p["payload"]) for p in own)
    require(captured_out < int(flow[0]["bytes_out"]), "Capture no longer partial vs flow export")
    require(any(p["protocol"] == 17 and p["dst"] == "198.51.100.73" for p in evidence),
            "Missing UDP protocol decoy")
    require(any(p["dst"] == "198.51.100.91" for p in evidence), "Missing independent benign traffic")
    scope = table("sensor_capture_scope.csv")
    require(int(scope[0]["packet_count"]) == len(evidence), "Capture count metadata wrong")
    require(scope[0]["coverage_note"].startswith("partial"), "Capture limitation undocumented")

    syslog = (OUT / "auth_syslog.log").read_text(encoding="utf-8").splitlines()
    audit = (OUT / "auditd_extract.log").read_text(encoding="utf-8").splitlines()
    journal = [json.loads(x) for x in (OUT / "journal_extended.jsonl").read_text(encoding="utf-8").splitlines()]
    require(len(syslog) >= 75 and len(audit) >= 35 and len(journal) >= 60,
            "Insufficient benign background noise")
    require(any("Accepted publickey for svc-maint" in s for s in syslog), "No accepted authentication")
    require(any('key="AUTH-702"' in s and "syscall=write" in s for s in audit),
            "Auditd detail no longer joins privileged write")
    require(any(j["_SYSTEMD_UNIT"] == "boot-health-agent.service" for j in journal),
            "New unit absent from journal")
    acquisition = table("acquisition_register.csv")
    require(all(r["verified_origin"] == "no" for r in acquisition),
            "Synthetic provenance improperly described as independently authenticated")
    require({"edge_sensor_capture.pcap", "measurement_derivation.csv"} <=
            {x["artifact"] for x in acquisition}, "Missing custody acquisition register entries")
    return dict(software_measurements=2, tcp_packets=len(own)+len(reverse),
                packet_total=len(evidence), captured_outbound_tcp_bytes=captured_out,
                auth_log_lines=len(syslog), audit_log_lines=len(audit),
                journal_records=len(journal), acquired_sources=len(acquisition))

if __name__ == "__main__":
    try:
        print("PASS high-fidelity synthetic evidence:", verify())
    except (OSError, ValueError, KeyError, IndexError, struct.error, json.JSONDecodeError) as e:
        print("FAIL high-fidelity synthetic evidence:", e, file=sys.stderr)
        sys.exit(1)
