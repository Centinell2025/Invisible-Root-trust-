#!/usr/bin/env python3
"""Machine-checkable objective findings. No solutions embedded in student ZIP."""
import csv,hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];A=ROOT/"artifacts"
def csvrows(name):
 with (A/name).open(newline="",encoding="utf-8") as f:return list(csv.DictReader(f))
def findings():
 attest=csvrows("secure_boot_attestation.csv");auth=csvrows("auth_events.csv");audit=csvrows("audit_events.csv")
 flows=csvrows("network_flows.csv");tickets=csvrows("change_tickets.csv");multi=csvrows("multi_host_events.csv")
 cross=csvrows("policy_digest_crosscheck.csv");cal=csvrows("clock_calibration.csv")
 journal=[json.loads(x) for x in (A/"journal_export.jsonl").read_text().splitlines()]
 mismatch=next(x for x in attest if x["status"]=="mismatch")
 write=next(x for x in audit if x["operation"]=="write")
 escalation=next(x for x in auth if x["event_id"]==write["event_id"])
 flow=flows[0]
 decoy=csvrows("benign_decoys.csv")
 baseline=(A/"policy_baseline.bin").read_bytes();observed=(A/"policy_observed.bin").read_bytes()
 firstdiff=next(i for i,(a,b) in enumerate(zip(baseline,observed)) if a!=b)
 pcap=(A/"synthetic_telemetry.pcap").read_bytes()
 return {
 "host":mismatch["host"],"mismatch_utc":mismatch["utc"],"component":mismatch["component"],
 "change_ticket":tickets[0]["ticket"],"change_approved":tickets[0]["approved"],
 "account":escalation["account"],"source_ip":escalation["source_ip"],
 "privilege_event":escalation["event_id"],"write_path":write["path"],
 "missing_audit_sequences":"8102,8103",
 "service":next(x["unit"] for x in journal if "boot-health-agent" in x["unit"]),
 "flow_destination":flow["dst_ip"],"flow_time":flow["utc"],
 "baseline_sha256":hashlib.sha256(baseline).hexdigest(),
 "observed_sha256":hashlib.sha256(observed).hexdigest(),
 "first_differing_byte_offset":firstdiff,
 "pcap_ip_protocol":pcap[40+14+9],
 "pcap_linktype":int.from_bytes(pcap[20:24],"little"),
 "multi_host_write_corrob":next(x["host"] for x in multi if x["event"]=="configuration-write-observed"),
 "decoy_ticket":decoy[0]["ticket"],
 "journal_offset_seconds":next(x["offset_seconds"] for x in cal if x["source"]=="journal"),
 "crosscheck_digests_valid":all(hashlib.sha256((A/x["specimen"]).read_bytes()).hexdigest()==x["sha256"] for x in cross)
 }
if __name__=="__main__":
 try:
  x=findings()
  if "--verify" in sys.argv:
   assert x["crosscheck_digests_valid"]
   assert x["pcap_ip_protocol"]==17
   assert x["change_approved"]=="no"
   assert x["first_differing_byte_offset"]>=0
   print(f"PASS: {len(x)} reproducible answer fields")
  else:print(json.dumps(x,indent=2))
 except Exception as e:print(f"FAIL: {e}",file=sys.stderr);sys.exit(1)
