#!/usr/bin/env python3
"""Répartit les événements synthétiques en fichiers gzip au format de chemin CloudTrail."""
import gzip
import hashlib
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

ACCOUNT = "000000000000"
NOTICE = "SYNTHETIC LAB DATA - not produced by AWS CloudTrail or Floci"
SOURCE = Path("data/synthetic/dataset_synthetic.json")
DESTINATION = Path("data/synthetic-layout")


def main():
    dataset = json.loads(SOURCE.read_text(encoding="utf-8"))
    groups = defaultdict(list)
    for event in dataset["Records"]:
        timestamp = datetime.fromisoformat(event["eventTime"].replace("Z", "+00:00"))
        region = event.get("awsRegion", "eu-west-3")
        minute = (timestamp.minute // 5) * 5
        groups[(region, timestamp.date(), timestamp.hour, minute)].append(event)
    count = 0
    for (region, day, hour, minute), records in sorted(groups.items()):
        stamp = f"{day:%Y%m%d}T{hour:02d}{minute:02d}Z"
        digest = hashlib.sha256("".join(r["eventID"] for r in records).encode()).hexdigest()[:12]
        relative = Path("AWSLogs") / ACCOUNT / "CloudTrail" / region / f"{day:%Y}" / f"{day:%m}" / f"{day:%d}"
        target = DESTINATION / relative / f"{ACCOUNT}_CloudTrail_{region}_{stamp}_{digest}.json.gz"
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"_lab_notice": NOTICE, "Records": records}, indent=2).encode("utf-8")
        with gzip.open(target, "wb") as stream:
            stream.write(payload)
        count += 1
    print(f"Fichiers synthétiques CloudTrail créés : {count}")
    print(f"Dossier de sortie : {DESTINATION}")


if __name__ == "__main__":
    main()
