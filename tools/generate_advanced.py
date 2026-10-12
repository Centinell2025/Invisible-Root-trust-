#!/usr/bin/env python3
"""Add deterministic, safe synthetic binary and multi-host evidence."""
from pathlib import Path
import hashlib,struct,csv,json
from datetime import datetime, timezone
ROOT=Path(__file__).resolve().parents[1];OUT=ROOT/"artifacts";OUT.mkdir(exist_ok=True)
def write_csv(name,fields,rows):
 with (OUT/name).open("w",newline="",encoding="utf8") as f:
  w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)
def digest(b):return hashlib.sha256(b).hexdigest()
# Binary specimens are illustrative data, not actual firmware or memory dumps.
baseline=b"NRG-BOOT-POLICY\x00signed=approved\x00version=2.4\x00"
changed=b"NRG-BOOT-POLICY\x00signed=unverified\x00version=2.4\x00"
(OUT/"policy_baseline.bin").write_bytes(baseline)
(OUT/"policy_observed.bin").write_bytes(changed)
(OUT/"memory_excerpt.bin").write_bytes(b"NRG-SYNTHETIC-MEMORY\x00session=AUTH-702\x00service=boot-health-agent\x00" + bytes(range(256))*16)
write_csv("policy_digest_crosscheck.csv",["specimen","sha256","role"],[
 {"specimen":"policy_baseline.bin","sha256":digest(baseline),"role":"reference"},
 {"specimen":"policy_observed.bin","sha256":digest(changed),"role":"observed"}])
write_csv("multi_host_events.csv",["utc","host","source","event","principal","reference"],[
 {"utc":"2026-09-17T03:01:55Z","host":"nrg-bastion-02","source":"vpn","event":"session-accepted","principal":"svc-maint","reference":"AUTH-701"},
 {"utc":"2026-09-17T03:05:50Z","host":"nrg-idp-01","source":"identity","event":"token-issued","principal":"svc-maint","reference":"AUTH-702"},
 {"utc":"2026-09-17T03:12:31Z","host":"nrg-bastion-02","source":"session-record","event":"configuration-write-observed","principal":"svc-maint","reference":"AUTH-702"},
 {"utc":"2026-09-17T03:14:05Z","host":"nrg-build-03","source":"change-ledger","event":"approved-deployment-not-found","principal":"system","reference":"CHG-421"}])
write_csv("clock_calibration.csv",["host","source","offset_seconds","confidence"],[
 {"host":"nrg-gw-07","source":"journal","offset_seconds":"2","confidence":"medium"},
 {"host":"nrg-bastion-02","source":"vpn","offset_seconds":"-3","confidence":"high"},
 {"host":"nrg-idp-01","source":"identity","offset_seconds":"1","confidence":"high"}])
write_csv("benign_decoys.csv",["utc","host","event","ticket","assessment"],[
 {"utc":"2026-09-17T03:09:10Z","host":"nrg-build-03","event":"signed-package-staged","ticket":"CHG-419","assessment":"approved unrelated build"},
 {"utc":"2026-09-17T03:11:03Z","host":"nrg-gw-07","event":"security-scanner-read","ticket":"CHG-418","assessment":"scheduled inspection"}])
# Valid minimal Ethernet/IPv4/UDP PCAP containing reserved documentation IPs and benign payload.
def pkt(src,dst,sport,dport,payload):
 def ip(a):return bytes(map(int,a.split(".")))
 eth=b"\x02\x00\x00\x00\x00\x02\x02\x00\x00\x00\x00\x01\x08\x00"
 udp=struct.pack("!HHHH",sport,dport,8+len(payload),0)
 hdr=struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp)+len(payload),0x1701,0,64,17,0,ip(src),ip(dst))
 def checksum(b):
  if len(b)%2:b+=b"\x00"
  s=sum(struct.unpack("!%dH"%(len(b)//2),b))
  while s>>16:s=(s&65535)+(s>>16)
  return (~s)&65535
 hdr=hdr[:10]+struct.pack("!H",checksum(hdr))+hdr[12:]
 return eth+hdr+udp+payload
payload=b"NRG synthetic telemetry; investigation only"
frame=pkt("192.0.2.17","198.51.100.73",52118,443,payload)
pcap=struct.pack("<IHHIIII",0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack("<IIII",int(datetime(2026,9,17,3,17,7,tzinfo=timezone.utc).timestamp()),0,len(frame),len(frame))+frame
(OUT/"synthetic_telemetry.pcap").write_bytes(pcap)
manifest=[]
for p in sorted(OUT.iterdir()):
 if p.is_file() and p.name!="custody_manifest.sha256":manifest.append(f"{digest(p.read_bytes())}  {p.name}")
(OUT/"custody_manifest.sha256").write_text("\n".join(manifest)+"\n")
print("Advanced synthetic evidence generated; PCAP uses UDP telemetry, not encrypted TCP.")
