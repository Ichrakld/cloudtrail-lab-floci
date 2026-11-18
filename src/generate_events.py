#!/usr/bin/env python3
"""Génère un jeu CloudTrail synthétique pour le laboratoire, sans appel AWS/Floci."""
import json
import uuid
from collections import defaultdict
from pathlib import Path

NOTICE = "SYNTHETIC LAB DATA - not produced by AWS CloudTrail or Floci"
ACCOUNT = "000000000000"
ATTACKER_IP = "203.0.113.66"
BENIGN_IP = "198.51.100.31"
INTERNAL_IP = "10.10.0.24"
USERS = {
    "alice": ("AIDALABALICE00000001", "ASIALABALICE00001"),
    "bob": ("AIDALABBOB00000000000", "ASIALABBOB00000001"),
    "carol": ("AIDALABCAROL00000001", "ASIALABCAROL00001"),
    "svc-backup": ("AIDALABSVCBACKUP0001", "AKIALABSVCBACKUP0001"),
}
DATA_EVENTS = {"PutObject", "GetObject", "HeadObject", "DeleteObject"}
groups = defaultdict(list)


def add(group, time, user, event_source, event_name, ip, params=None,
        error=None, response=None, additional=None, access_key=None):
    principal, default_key = USERS[user]
    region = "us-east-1" if event_source in {
        "iam.amazonaws.com", "signin.amazonaws.com", "sts.amazonaws.com",
        "cloudtrail.amazonaws.com"
    } else "eu-west-3"
    is_data = event_source == "s3.amazonaws.com" and event_name in DATA_EVENTS
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser", "principalId": principal,
            "arn": f"arn:aws:iam::{ACCOUNT}:user/{user}",
            "accountId": ACCOUNT, "accessKeyId": access_key or default_key,
            "userName": user,
            "sessionContext": {"attributes": {
                "creationDate": time, "mfaAuthenticated": "false"
            }}
        },
        "eventTime": time, "eventSource": event_source,
        "eventName": event_name, "awsRegion": region,
        "sourceIPAddress": ip, "userAgent": "aws-cli/2.x synthetic-lab",
        "requestParameters": params or {}, "responseElements": response,
        "eventID": str(uuid.uuid5(uuid.NAMESPACE_URL,
                                  f"{group}|{time}|{event_name}|{user}")),
        "readOnly": event_name.startswith(("Get", "List", "Describe", "Head")),
        "eventType": "AwsConsoleSignIn" if event_name == "ConsoleLogin" else "AwsApiCall",
        "managementEvent": not is_data, "recipientAccountId": ACCOUNT,
        "eventCategory": "Data" if is_data else "Management"
    }
    if error:
        event["errorCode"] = error
        event["errorMessage"] = error
    if additional:
        event["additionalEventData"] = additional
    groups[group].append(event)


# S5 : échecs de connexion, puis succès sans MFA.
for t in ("02:11:07", "02:11:31", "02:11:52"):
    add("S5", f"2026-10-29T{t}Z", "bob", "signin.amazonaws.com", "ConsoleLogin",
        ATTACKER_IP, {"userName": "bob"}, "Failed authentication",
        {"ConsoleLogin": "Failure"}, {"MFAUsed": "No"})
add("S5", "2026-10-29T02:14:30Z", "bob", "signin.amazonaws.com", "ConsoleLogin",
    ATTACKER_IP, {"userName": "bob"}, response={"ConsoleLogin": "Success"},
    additional={"MFAUsed": "No"})

# S6 : quatre accès refusés en moins de dix minutes.
for t, name, source, params in [
    ("02:16:02", "ListUsers", "iam.amazonaws.com", {}),
    ("02:16:40", "ListRoles", "iam.amazonaws.com", {}),
    ("02:17:25", "GetBucketPolicy", "s3.amazonaws.com", {"bucketName": "corp-finance-secrets"}),
    ("02:18:03", "GetObject", "s3.amazonaws.com", {"bucketName": "corp-finance-secrets", "key": "2026/payroll.csv"}),
]:
    add("S6", f"2026-10-29T{t}Z", "bob", source, name, ATTACKER_IP,
        params=params, error="AccessDenied")

# S2 : auto-attribution d'AdministratorAccess.
add("S2", "2026-10-29T02:21:40Z", "bob", "iam.amazonaws.com", "AttachUserPolicy",
    ATTACKER_IP, {"userName": "bob", "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}, response={})

# S1 : création d'une clé pour svc-backup, puis utilisation de cette clé.
rogue_key = "AKIALABROGUE00000001"
add("S1", "2026-10-29T02:23:15Z", "bob", "iam.amazonaws.com", "CreateAccessKey",
    ATTACKER_IP, {"userName": "svc-backup"}, response={"accessKey": {
        "userName": "svc-backup", "accessKeyId": rogue_key, "status": "Active"}})
add("S1", "2026-10-29T02:26:48Z", "svc-backup", "sts.amazonaws.com", "GetCallerIdentity",
    ATTACKER_IP, response={}, access_key=rogue_key)

# S3 : suppression d'un bucket de sauvegarde critique.
add("S3", "2026-10-29T02:33:05Z", "bob", "s3.amazonaws.com", "DeleteBucket",
    ATTACKER_IP, {"bucketName": "corp-backups-prod"}, response={})

# S4 : altération de la journalisation et trou de 71 minutes.
add("S4", "2026-10-29T02:39:20Z", "bob", "cloudtrail.amazonaws.com", "DeleteTrail",
    ATTACKER_IP, {"name": "corp-trail"}, error="AccessDeniedException")
add("S4", "2026-10-29T02:41:03Z", "bob", "cloudtrail.amazonaws.com", "StopLogging",
    ATTACKER_IP, {"name": "corp-trail"}, response={})
add("S4", "2026-10-29T03:52:10Z", "alice", "cloudtrail.amazonaws.com", "StartLogging",
    INTERNAL_IP, {"name": "corp-trail"}, response={})

# Activité bénigne pour mesurer les faux positifs.
add("BENIGN", "2026-10-28T14:20:09Z", "alice", "signin.amazonaws.com", "ConsoleLogin",
    BENIGN_IP, {"userName": "alice"}, "Failed authentication", {"ConsoleLogin": "Failure"}, {"MFAUsed": "No"})
add("BENIGN", "2026-10-28T14:30:00Z", "alice", "iam.amazonaws.com", "CreateAccessKey",
    INTERNAL_IP, {"userName": "alice"}, response={})
add("BENIGN", "2026-10-28T15:20:00Z", "alice", "iam.amazonaws.com", "AttachUserPolicy",
    INTERNAL_IP, {"userName": "carol", "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}, response={})
add("BENIGN", "2026-10-28T16:00:00Z", "alice", "s3.amazonaws.com", "DeleteBucket",
    INTERNAL_IP, {"bucketName": "corp-test-bucket"}, response={})
add("BENIGN", "2026-10-28T17:00:00Z", "carol", "iam.amazonaws.com", "ListUsers",
    INTERNAL_IP, error="AccessDenied")


def main():
    out = Path("data/synthetic")
    scenarios = out / "scenarios"
    scenarios.mkdir(parents=True, exist_ok=True)
    all_records = []
    for name, records in groups.items():
        records.sort(key=lambda r: r["eventTime"])
        all_records.extend(records)
        (scenarios / f"{name}.json").write_text(json.dumps(
            {"_lab_notice": NOTICE, "Records": records}, indent=2) + "\n", encoding="utf-8")
    all_records.sort(key=lambda r: r["eventTime"])
    (out / "dataset_synthetic.json").write_text(json.dumps(
        {"_lab_notice": NOTICE, "Records": all_records}, indent=2) + "\n", encoding="utf-8")
    print(f"Événements synthétiques générés : {len(all_records)}")
    print(f"Scénarios : {', '.join(sorted(groups))}")
    print(f"Jeu complet : {out / 'dataset_synthetic.json'}")


if __name__ == "__main__":
    main()
