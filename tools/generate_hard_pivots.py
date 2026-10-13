#!/usr/bin/env python3
"""Hard-tier multi-source pivots for the fictional Invisible Root of Trust case.

All streams are entirely synthetic, deterministically generated, and NOT
independently authenticated. Background events are plausible decoys; they
must not be interpreted as undisclosed attacks against real organizations.
"""
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ART = Path(__file__).resolve().parents[1] / "artifacts"
ART.mkdir(parents=True, exist_ok=True)
RNG = random.Random(2026091726)
BASE = datetime(2026, 9, 17, 2, 48, tzinfo=timezone.utc)
HOSTS = ["nrg-gw-07","nrg-bastion-02","nrg-idp-01","nrg-build-03","nrg-sensor-04"]
ACCOUNTS = ["backup","metrics","svc-maint","buildbot","deploy","root"]

def clock(seconds):
    return (BASE + timedelta(seconds=seconds)).isoformat(timespec="seconds").replace("+00:00", "Z")

def save(name, rows):
    rows.sort(key=lambda r: (r["utc"],r["event_id"]))
    with (ART / name).open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True, separators=(",",":")) + "\n")

# Identity records contain unlinked lookalike tokens. An accepted service token
# does NOT bind it to an actual human or a trusted source device.
idp = []
for i in range(56):
    ref = "BG-AUTH-" + str(2500+i)
    idp.append(dict(
        utc=clock(22 * i),event_id=f"IDP-BG-{i:04d}",
        source_host="nrg-idp-01",event=["token-refresh","token-issued","token-expired"][i%3],
        account=ACCOUNTS[i%len(ACCOUNTS)],reference=ref,
        session_id=f"SES-BG-{i:04d}",
        token_scope=["metrics:read","backup:write","deploy:read"][i%3],
        assertion_type="simulated-service-assertion",
        human_binding="unknown",origin_verified="no"))
idp.extend([
    dict(utc="2026-09-17T03:01:55Z",event_id="IDP-4701",
         source_host="nrg-idp-01",event="token-refresh",account="svc-maint",
         reference="AUTH-701",session_id="SES-901",token_scope="maintenance:read",
         assertion_type="simulated-service-assertion",human_binding="unknown",origin_verified="no"),
    dict(utc="2026-09-17T03:05:50Z",event_id="IDP-4702",
         source_host="nrg-idp-01",event="token-issued",account="svc-maint",
         reference="AUTH-702",session_id="SES-903",token_scope="gateway:maintenance",
         assertion_type="simulated-service-assertion",human_binding="unknown",origin_verified="no"),
    dict(utc="2026-09-17T03:20:31Z",event_id="IDP-4703",
         source_host="nrg-idp-01",event="token-expired",account="svc-maint",
         reference="AUTH-702",session_id="SES-903",token_scope="gateway:maintenance",
         assertion_type="simulated-service-assertion",human_binding="unknown",origin_verified="no"),
])
save("idp_session_audit.jsonl",idp)

# An authorization denial is distinguishable from an approved maintenance
# assertion written by a less trustworthy gateway-local service.
control=[]
for i in range(68):
    control.append(dict(
        utc=clock(12*i),event_id=f"CTRL-BG-{i:04d}",
        source_host="nrg-build-03",ticket=f"CHG-{500+i}",
        action=["requested","approval-check","reviewed","closed"][i%4],
        approval=["pending","approved","rejected"][i%3],
        package_id=f"PKG-BG-{i:04d}",
        target=HOSTS[i%len(HOSTS)],origin_verified="no"))
control.extend([
    dict(utc="2026-09-17T03:00:00Z",event_id="CTRL-2101",
         source_host="nrg-build-03",ticket="CHG-421",action="requested",
         approval="pending",package_id="PKG-202",target="nrg-gw-07",origin_verified="no"),
    dict(utc="2026-09-17T03:08:00Z",event_id="CTRL-2102",
         source_host="nrg-build-03",ticket="CHG-421",action="approval-check",
         approval="pending",package_id="PKG-202",target="nrg-gw-07",origin_verified="no"),
    dict(utc="2026-09-17T03:12:05Z",event_id="CTRL-2103",
         source_host="nrg-build-03",ticket="CHG-421",action="security-rejected",
         approval="rejected",package_id="PKG-204",target="nrg-gw-07",origin_verified="no"),
    dict(utc="2026-09-17T03:12:10Z",event_id="CTRL-2104",
         source_host="nrg-build-03",ticket="CHG-421",action="package-quarantined",
         approval="rejected",package_id="PKG-204",target="nrg-gw-07",origin_verified="no"),
    dict(utc="2026-09-17T03:10:00Z",event_id="CTRL-2105",
         source_host="nrg-build-03",ticket="CHG-418",action="approval-check",
         approval="approved",package_id="PKG-203",target="nrg-gw-07",origin_verified="no"),
])
save("change_approval_audit.jsonl",control)

# The firewall log is a simulated edge decision stream, independent as a
# modeled collector but not a verified production witness. An ALLOW decision
# supports only the rule decision for the tuple, NOT exfiltration or byte count.
firewall=[]
for i in range(88):
    host=HOSTS[i%len(HOSTS)]
    firewall.append(dict(
        utc=clock(5*i),event_id=f"FW-BG-{i:04d}",source_host="nrg-sensor-04",
        sensor="gw-edge-firewall",src_host=host,
        src_ip=f"192.0.2.{20+i%55}",src_port=41000+i,
        dst_ip=f"198.51.100.{30+i%60}",dst_port=[80,443,8443,53][i%4],
        protocol="UDP" if i%4==3 else "TCP",
        decision=["allow","deny","allow"][i%3],
        flow_ref=f"FLOW-{i:05d}",byte_scope="not-recorded",
        origin_verified="no"))
firewall.extend([
    dict(utc="2026-09-17T03:17:07Z",event_id="FW-5031",source_host="nrg-sensor-04",
         sensor="gw-edge-firewall",src_host="nrg-gw-07",
         src_ip="192.0.2.17",src_port=50544,
         dst_ip="198.51.100.73",dst_port=443,protocol="TCP",
         decision="allow",flow_ref="FLOW-99999",byte_scope="not-recorded",origin_verified="no"),
    dict(utc="2026-09-17T03:17:11Z",event_id="FW-5032",source_host="nrg-sensor-04",
         sensor="gw-edge-firewall",src_host="nrg-gw-07",
         src_ip="192.0.2.17",src_port=50545,
         dst_ip="198.51.100.91",dst_port=443,protocol="TCP",
         decision="deny",flow_ref="FLOW-99998",byte_scope="not-recorded",origin_verified="no"),
    dict(utc="2026-09-17T03:17:08Z",event_id="FW-5033",source_host="nrg-sensor-04",
         sensor="gw-edge-firewall",src_host="nrg-gw-07",
         src_ip="192.0.2.17",src_port=53053,
         dst_ip="198.51.100.73",dst_port=443,protocol="UDP",
         decision="allow",flow_ref="unresolved-udp-packet",byte_scope="not-recorded",origin_verified="no"),
])
save("firewall_edge_decisions.jsonl",firewall)

# A modeled file-level systemd installation is distinguishable from claims
# about post-reboot persistence. No independently observed reboot exists.
unit=[]
for i in range(64):
    unit.append(dict(utc=clock(17*i),event_id=f"UNIT-BG-{i:04d}",
        source_host="nrg-gw-07",unit=["ssh.service","apt-daily.service","node-exporter.service"][i%3],
        event=["unit-inventory","service-health-check","unit-file-read"][i%3],
        path=["/usr/lib/systemd/system/ssh.service",
              "/usr/lib/systemd/system/apt-daily.service",
              "/usr/lib/systemd/system/node-exporter.service"][i%3],
        boot_marker="synthetic-boot-6e21a",collection="simulated-gateway-local-export",
        reboot_verified="no"))
unit.extend([
    dict(utc="2026-09-17T03:16:39Z",event_id="UNIT-3117",source_host="nrg-gw-07",
         unit="boot-health-agent.service",event="enablement-symlink-observed",
         path="/etc/systemd/system/multi-user.target.wants/boot-health-agent.service",
         boot_marker="synthetic-boot-6e21a",collection="simulated-gateway-file-inventory",
         reboot_verified="no"),
    dict(utc="2026-09-17T03:16:40Z",event_id="UNIT-3118",source_host="nrg-gw-07",
         unit="boot-health-agent.service",event="unit-start-asserted",
         path="/etc/systemd/system/boot-health-agent.service",
         boot_marker="synthetic-boot-6e21a",collection="simulated-gateway-local-journal",
         reboot_verified="no"),
    dict(utc="2026-09-17T03:23:12Z",event_id="UNIT-3119",source_host="nrg-gw-07",
         unit="boot-health-agent.service",event="post-incident-inventory",
         path="/etc/systemd/system/boot-health-agent.service",
         boot_marker="synthetic-boot-6e21a",collection="simulated-gateway-file-inventory",
         reboot_verified="no"),
])
save("systemd_lifecycle.jsonl",unit)
# Document collection provenance for every additional source. These
# registers are exercise metadata, not original chain-of-custody proof.
import csv
register=ART/"acquisition_register.csv"
with register.open("r",encoding="utf-8",newline="") as f:
    current=list(csv.DictReader(f))
    headers=list(current[0].keys())
existing={r["artifact"] for r in current}
for i,(name,host,method) in enumerate([
    ("idp_session_audit.jsonl","nrg-idp-01","simulated-identity-export"),
    ("change_approval_audit.jsonl","nrg-build-03","simulated-approval-ledger"),
    ("firewall_edge_decisions.jsonl","nrg-sensor-04","simulated-firewall-decision-export"),
    ("systemd_lifecycle.jsonl","nrg-gw-07","simulated-local-service-events"),
],start=6):
    if name not in existing:
        current.append(dict(utc=f"2026-09-17T03:27:{i:02d}Z",
            source_id=f"COL-{i:02d}",artifact=name,source_host=host,
            method=method,completeness="selected-training-window",
            verified_origin="no"))
with register.open("w",encoding="utf-8",newline="") as f:
    writer=csv.DictWriter(f,fieldnames=headers)
    writer.writeheader()
    writer.writerows(current)

print("Generated 4 Hard investigative streams with 56/68/88/64 background events and exact cross-source pivots")
