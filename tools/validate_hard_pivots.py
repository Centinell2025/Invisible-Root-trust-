#!/usr/bin/env python3
"""Cross-validate Hard-tier simulated identity/change/firewall/systemd witnesses.

No stream is independently verified production data. Passing proves internal
consistency and answerability of this synthetic exercise, not incident truth.
"""
import csv
import json
import sqlite3
import sys
import tarfile
from datetime import datetime, timezone
from pathlib import Path

ART = Path(__file__).resolve().parents[1] / "artifacts"
FILES = (
    "idp_session_audit.jsonl",
    "change_approval_audit.jsonl",
    "firewall_edge_decisions.jsonl",
    "systemd_lifecycle.jsonl",
)
MIN_ROWS = {FILES[0]:59,FILES[1]:73,FILES[2]:91,FILES[3]:67}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def csvrows(name):
    with (ART/name).open(encoding="utf-8",newline="") as f:
        return list(csv.DictReader(f))

def read_stream(name):
    with (ART/name).open(encoding="utf-8") as f:
        return [json.loads(x) for x in f if x.strip()]

def utc(iso):
    t = datetime.fromisoformat(iso.replace("Z","+00:00"))
    require(iso.endswith("Z") and t.utcoffset().total_seconds()==0,"Invalid timezone "+iso)
    return t

def validate_records(streams):
    for name in FILES:
        rows=streams[name]
        require(len(rows)>=MIN_ROWS[name],"Insufficient Hard background/decoy events in "+name)
        ids=[r["event_id"] for r in rows]
        require(len(ids)==len(set(ids)), "Duplicate Hard evidence identifiers in "+name)
        require(all(r["origin_verified"]=="no" if "origin_verified" in r
                    else r.get("reboot_verified")=="no" for r in rows),
                "A synthetic source falsely asserts verified origin or reboot: "+name)
        keys=[(utc(r["utc"]),r["event_id"]) for r in rows]
        require(keys==sorted(keys),"Disordered Hard source stream "+name)

    identity=streams[FILES[0]]
    sess=csvrows("session_lineage.csv")
    auth=csvrows("auth_events.csv")
    pivotal=[r for r in identity if r["event"]=="token-issued"
             and r["reference"]=="AUTH-702"
             and r["session_id"]=="SES-903" and r["account"]=="svc-maint"]
    require(len(pivotal)==1,"Identity/session pivotal correlation ambiguous")
    require(pivotal[0]["human_binding"]=="unknown" and
            pivotal[0]["assertion_type"]=="simulated-service-assertion",
            "Service token incorrectly implies human attribution")
    require(any(r["session_id"]==pivotal[0]["session_id"] and r["reference"]=="AUTH-702"
                for r in sess),"Identity token lacks session-lineage witness")
    require(any(r["event_id"]=="AUTH-702" and r["action"]=="sudo-session" for r in auth),
            "Privileged account context inconsistent with IdP pivot")

    approvals=streams[FILES[1]]
    packages=csvrows("deployment_provenance.csv")
    tickets=csvrows("change_tickets.csv")
    denial=[r for r in approvals if r["ticket"]=="CHG-421" and r["approval"]=="rejected"
            and r["action"]=="security-rejected" and r["package_id"]=="PKG-204"]
    require(len(denial)==1,"Unique rejected change gate missing")
    require(any(r["ticket"]=="CHG-421" and r["approved"]=="no" for r in tickets),
            "Change register contradicts denied authorization")
    require(any(r["package_id"]=="PKG-204" and r["approval"]=="rejected"
                and r["signature"]=="unsigned" for r in packages),
            "Rejected unsigned package not corroborated")
    require(utc(denial[0]["utc"]) < min(utc(r["utc"]) for r in packages if r["package_id"]=="PKG-204"),
            "Security denial must precede rejected package ledger event")
    require(not any(r["ticket"]=="CHG-421" and r["approval"]=="approved" for r in packages),
            "Rejected ticket has contradictory approved deployment")

    firewall=streams[FILES[2]]
    sockets=csvrows("socket_observations.csv")
    with sqlite3.connect(f"file:{(ART/'endpoint_telemetry.sqlite3').as_posix()}?mode=ro",uri=True) as db:
        flow=db.execute("""SELECT source_host,source_ip,source_port,dest_ip,dest_port,protocol,bytes_out,pid_claim
                           FROM netflow_sessions WHERE session_id='FLOW-99999'""").fetchone()
        boot=db.execute("SELECT sample_id,boot_id,independently_verified FROM boot_inventory ORDER BY timestamp_utc").fetchall()
    require(flow is not None, "Relevant SQLite netflow absent")
    host,source,port,dest,dport,protocol,bytes_out,pid=flow
    matches=[r for r in firewall if r["src_host"]==host and r["src_ip"]==source
             and r["src_port"]==port and r["dst_ip"]==dest and
             r["dst_port"]==dport and r["protocol"]==protocol and
             r["decision"]=="allow" and r["flow_ref"]=="FLOW-99999"]
    require(len(matches)==1,"Ambiguous firewall/netflow five-tuple correlation")
    require(matches[0]["byte_scope"]=="not-recorded" and bytes_out==9821,
            "FW decision falsely asserts measured network byte coverage")
    require(any(r["pid"]==str(pid) and r["src_port"]==str(port)
                and r["dst_ip"]==dest and r["protocol"]==protocol for r in sockets),
            "Socket process and edge firewall five-tuple inconsistent")
    require(any(r["protocol"]=="UDP" and r["dst_ip"]==dest and r["dst_port"]==dport
                for r in firewall),"Missing lookalike UDP negative control")

    unit=streams[FILES[3]]
    enables=[r for r in unit if r["event"]=="enablement-symlink-observed"
             and r["unit"]=="boot-health-agent.service"]
    require(len(enables)==1,"Ambiguous service enablement trace")
    s=enables[0]
    with tarfile.open(ART/"offline_gateway_triage.tar", "r:") as tar:
        member=tar.getmember(s["path"].lstrip("/"))
        require(member.issym() and member.linkname=="../boot-health-agent.service",
                "Service lifecycle does not match offline file-level symlink")
    fim=csvrows("file_integrity_timeline.csv")
    require(any(r["path"]=="/etc/systemd/system/boot-health-agent.service"
                and r["label"]=="new-unit-specimen" for r in fim),
            "Service unit installation not linked to FIM")
    require(len(boot)==2 and boot[0][1]==boot[1][1]
            and all(r[2]==0 for r in boot)
            and s["boot_marker"]==boot[0][1],
            "False independently verified reboot or synthetic boot ID mismatch")
    require(any(r["event"]=="unit-start-asserted" and r["unit"]==s["unit"]
                and r["reboot_verified"]=="no" for r in unit),
            "No limited start assertion corresponding to enabled unit")
    return dict(identity_events=len(identity),change_events=len(approvals),
                firewall_events=len(firewall),service_events=len(unit),
                critical_correlations=4,independently_verified_sources=0)

def verify():
    return validate_records({name:read_stream(name) for name in FILES})

if __name__=="__main__":
    try: print("PASS Hard-tier synthetic multihost correlation:",verify())
    except (OSError,ValueError,KeyError,IndexError,TypeError,sqlite3.Error,tarfile.TarError,json.JSONDecodeError) as e:
        print("FAIL Hard-tier correlation:",e,file=sys.stderr)
        sys.exit(1)
