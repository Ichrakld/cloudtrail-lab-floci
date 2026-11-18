#!/usr/bin/env python3
"""Analyse de journaux CloudTrail natifs ou synthétiques du laboratoire."""
from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

TRUSTED_CIDRS = ("10.0.0.0/8", "172.16.0.0/12")
SENSITIVE_BUCKET = re.compile(r"(prod|backup|finance|secret|payroll|log)", re.I)
ADMIN_POLICY = "arn:aws:iam::aws:policy/AdministratorAccess"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def load_records(paths: list[str]) -> list[dict]:
    records: list[dict] = []
    for item in paths:
        path = Path(item)
        files = [path] if path.is_file() else sorted(
            p for p in path.rglob("*") if p.is_file() and (p.suffix == ".json" or p.name.endswith(".json.gz"))
        )
        for file in files:
            opener = gzip.open if file.name.endswith(".gz") else open
            with opener(file, "rt", encoding="utf-8") as stream:
                payload = json.load(stream)
            if isinstance(payload, dict):
                records.extend(payload.get("Records", []))
            elif isinstance(payload, list):
                records.extend(payload)
    unique = {}
    for record in records:
        event_id = record.get("eventID")
        if event_id:
            unique.setdefault(event_id, record)
    return sorted(unique.values(), key=lambda r: r.get("eventTime", ""))


def actor(event: dict) -> str:
    identity = event.get("userIdentity") or {}
    return identity.get("userName") or identity.get("arn", "unknown").rsplit("/", 1)[-1]


def emit(findings: list[dict], rule: str, severity: str, event: dict,
         message: str, related: list[dict] | None = None) -> None:
    findings.append({
        "rule": rule,
        "severity": severity,
        "eventTime": event.get("eventTime", ""),
        "eventName": event.get("eventName", ""),
        "user": actor(event),
        "sourceIPAddress": event.get("sourceIPAddress", ""),
        "eventID": event.get("eventID", ""),
        "related_eventIDs": [e.get("eventID", "") for e in (related or [event])],
        "message": message,
    })


def is_success(event: dict) -> bool:
    if event.get("errorCode"):
        return False
    response = event.get("responseElements") or {}
    return response.get("ConsoleLogin", "Success") == "Success"


def is_trusted_ip(value: str, networks: tuple) -> bool:
    try:
        address = ipaddress.ip_address(value)
        return any(address in network for network in networks)
    except ValueError:
        return True


def detect(records: list[dict], trusted_cidrs: tuple[str, ...] = TRUSTED_CIDRS) -> list[dict]:
    findings: list[dict] = []
    trusted_networks = tuple(ipaddress.ip_network(cidr) for cidr in trusted_cidrs)

    # R01 — connexion console réussie sans MFA.
    for event in records:
        if event.get("eventName") != "ConsoleLogin" or not is_success(event):
            continue
        additional = event.get("additionalEventData") or {}
        attrs = (((event.get("userIdentity") or {}).get("sessionContext") or {}).get("attributes") or {})
        no_mfa = additional.get("MFAUsed", "").lower() == "no" or attrs.get("mfaAuthenticated", "").lower() == "false"
        if no_mfa:
            emit(findings, "R01", "CRITICAL", event,
                 f"Connexion console réussie de {actor(event)} sans MFA.")

    # R02 — attribution d'une policy administrateur.
    for event in records:
        params = event.get("requestParameters") or {}
        if event.get("eventName") == "AttachUserPolicy" and params.get("policyArn") == ADMIN_POLICY:
            emit(findings, "R02", "CRITICAL", event,
                 f"AdministratorAccess attribuée à {params.get('userName', actor(event))}.")

    # R03 — création d'une clé d'accès pour un autre utilisateur.
    for event in records:
        params = event.get("requestParameters") or {}
        target = params.get("userName")
        if event.get("eventName") == "CreateAccessKey" and target and target != actor(event):
            emit(findings, "R03", "CRITICAL", event,
                 f"{actor(event)} crée une clé pour une autre identité : {target}.")

    # R04 — suppression d'un bucket sensible.
    for event in records:
        bucket = (event.get("requestParameters") or {}).get("bucketName", "")
        if event.get("eventName") == "DeleteBucket" and SENSITIVE_BUCKET.search(bucket):
            emit(findings, "R04", "CRITICAL", event,
                 f"Suppression du bucket sensible {bucket}.")

    # R05 — actions de désactivation ou de suppression du trail. StartLogging est la reprise.
    for event in records:
        name = event.get("eventName")
        if name in {"StopLogging", "DeleteTrail"}:
            result = event.get("errorCode") or "succès"
            emit(findings, "R05", "CRITICAL", event,
                 f"Action {name} sur le trail ({result}).")

    # R06 — au moins trois refus par identité dans une fenêtre de dix minutes.
    denied = defaultdict(list)
    for event in records:
        if event.get("errorCode") in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}:
            denied[(actor(event), event.get("sourceIPAddress", ""))].append(event)
    for (user, ip), events in denied.items():
        events.sort(key=lambda e: e.get("eventTime", ""))
        for index, first in enumerate(events):
            start = parse_time(first["eventTime"])
            window = [e for e in events[index:] if parse_time(e["eventTime"]) <= start + timedelta(minutes=10)]
            if len(window) >= 3:
                names = ", ".join(sorted({e.get("eventName", "") for e in window}))
                emit(findings, "R06", "HIGH", first,
                     f"{len(window)} accès refusés pour {user} en moins de 10 minutes depuis {ip} ({names}).", window)
                break

    # R07 — au moins trois échecs de connexion suivis d'un succès dans les dix minutes.
    logins = defaultdict(list)
    for event in records:
        if event.get("eventName") == "ConsoleLogin":
            logins[(actor(event), event.get("sourceIPAddress", ""))].append(event)
    for (user, ip), events in logins.items():
        events.sort(key=lambda e: e.get("eventTime", ""))
        failures = [e for e in events if not is_success(e)]
        successes = [e for e in events if is_success(e)]
        for success in successes:
            success_time = parse_time(success["eventTime"])
            recent = [e for e in failures if timedelta(0) <= success_time - parse_time(e["eventTime"]) <= timedelta(minutes=10)]
            if len(recent) >= 3:
                emit(findings, "R07", "CRITICAL", recent[0],
                     f"{len(recent)} échecs de connexion suivis d'un succès pour {user} depuis {ip}.", recent + [success])
                break

    # R08 — trou uniquement lorsqu'un StopLogging est suivi d'un StartLogging tardif.
    stops = [e for e in records if e.get("eventName") == "StopLogging"]
    starts = [e for e in records if e.get("eventName") == "StartLogging"]
    for stop in stops:
        later = [e for e in starts if parse_time(e["eventTime"]) > parse_time(stop["eventTime"])]
        if later:
            start = min(later, key=lambda e: e["eventTime"])
            gap = parse_time(start["eventTime"]) - parse_time(stop["eventTime"])
            if gap >= timedelta(minutes=30):
                minutes = int(gap.total_seconds() // 60)
                emit(findings, "R08", "CRITICAL", stop,
                     f"Journalisation interrompue pendant {minutes} minutes entre StopLogging et StartLogging.", [stop, start])

    # R09 — activité par adresse hors plages internes. Une alerte par utilisateur et IP.
    external = defaultdict(list)
    for event in records:
        ip = event.get("sourceIPAddress", "")
        if ip and not is_trusted_ip(ip, trusted_networks):
            external[(actor(event), ip)].append(event)
    for (user, ip), events in external.items():
        events.sort(key=lambda e: e.get("eventTime", ""))
        emit(findings, "R09", "MEDIUM", events[0],
             f"{len(events)} événement(s) pour {user} depuis l'IP hors périmètre {ip}.", events)

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (order[f["severity"]], f["eventTime"], f["rule"]))
    return findings


def write_reports(findings: list[dict], out_dir: Path, event_count: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "findings.json").write_text(json.dumps(findings, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    fields = ["rule", "severity", "eventTime", "user", "sourceIPAddress", "eventName", "eventID", "message"]
    with (out_dir / "findings.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows({key: finding.get(key, "") for key in fields} for finding in findings)
    counts = defaultdict(int)
    for finding in findings:
        counts[finding["severity"]] += 1
    lines = ["# Rapport d’analyse CloudTrail", "", f"- Événements uniques analysés : {event_count}",
             f"- Alertes détectées : {len(findings)}", f"- Gravités : {dict(counts)}", "", "## Alertes", ""]
    lines.extend(f"- **[{f['severity']}] {f['rule']}** — {f['eventTime']} — {f['user']} — {f['message']} (eventID: `{f['eventID']}`)" for f in findings)
    lines += ["", "## Limites", "", "Les résultats dépendent des règles et du périmètre réseau configurés. Les événements synthétiques ne sont pas des journaux émis par AWS ou Floci. Une absence d'alerte ne démontre pas l'absence d'activité suspecte.", ""]
    (out_dir / "analysis_report.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyse des journaux JSON/JSON.GZ au format CloudTrail.")
    parser.add_argument("paths", nargs="+", help="fichiers ou dossiers à analyser")
    parser.add_argument("--out-dir", help="dossier de rapport (par défaut reports/<nom de la source>)")
    parser.add_argument("--trusted-cidrs", default=",".join(TRUSTED_CIDRS), help="CIDR internes séparés par des virgules")
    args = parser.parse_args()
    records = load_records(args.paths)
    if not records:
        print("Aucun événement CloudTrail trouvé.", file=sys.stderr)
        return 2
    trusted = tuple(item.strip() for item in args.trusted_cidrs.split(",") if item.strip())
    findings = detect(records, trusted)
    default_name = Path(args.paths[0]).stem.removesuffix(".json")
    out_dir = Path(args.out_dir or "reports") / ("" if args.out_dir else default_name)
    write_reports(findings, out_dir, len(records))
    print(f"Événements uniques analysés : {len(records)}")
    print(f"Alertes détectées : {len(findings)}")
    print(f"Rapports écrits dans : {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
