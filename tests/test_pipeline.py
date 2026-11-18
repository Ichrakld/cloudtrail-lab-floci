"""Tests de cohérence du générateur, de l'export gzip et de l'analyse."""
import gzip
import json
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PipelineTest(unittest.TestCase):
    def test_synthetic_pipeline_and_cloudtrail_layout(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            subprocess.run([sys.executable, str(ROOT / "src/generate_events.py")],
                           cwd=work, check=True, capture_output=True, text=True)
            dataset_path = work / "data/synthetic/dataset_synthetic.json"
            dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
            records = dataset["Records"]
            self.assertEqual(len(records), 20)
            self.assertEqual(len({event["eventID"] for event in records}), 20)
            self.assertIn("SYNTHETIC LAB DATA", dataset["_lab_notice"])
            self.assertEqual({p.stem for p in (work / "data/synthetic/scenarios").glob("*.json")},
                             {"BENIGN", "S1", "S2", "S3", "S4", "S5", "S6"})
            categories = {event["eventName"]: event["eventCategory"] for event in records
                          if event["eventSource"] == "s3.amazonaws.com"}
            self.assertEqual(categories["GetObject"], "Data")
            self.assertEqual(categories["DeleteBucket"], "Management")

            subprocess.run([sys.executable, str(ROOT / "src/analyze_logs.py"),
                            str(dataset_path), "--out-dir", str(work / "reports/direct")],
                           cwd=work, check=True, capture_output=True, text=True)
            direct = json.loads((work / "reports/direct/findings.json").read_text(encoding="utf-8"))
            self.assertEqual(len(direct), 12)
            self.assertEqual(Counter(f["rule"] for f in direct), Counter({
                "R01": 1, "R02": 1, "R03": 1, "R04": 1, "R05": 2,
                "R06": 1, "R07": 1, "R08": 1, "R09": 3,
            }))
            self.assertEqual({f["severity"] for f in direct if f["rule"] == "R09"}, {"MEDIUM"})

            subprocess.run([sys.executable, str(ROOT / "src/export_s3_layout.py")],
                           cwd=work, check=True, capture_output=True, text=True)
            gzip_files = list((work / "data/synthetic-layout").rglob("*.json.gz"))
            self.assertEqual(len(gzip_files), 14)
            exported = []
            for file in gzip_files:
                with gzip.open(file, "rt", encoding="utf-8") as stream:
                    payload = json.load(stream)
                self.assertIn("SYNTHETIC LAB DATA", payload["_lab_notice"])
                exported.extend(payload["Records"])
            self.assertEqual({event["eventID"] for event in exported},
                             {event["eventID"] for event in records})

            subprocess.run([sys.executable, str(ROOT / "src/analyze_logs.py"),
                            str(work / "data/synthetic-layout"), "--out-dir",
                            str(work / "reports/exported")], cwd=work, check=True,
                           capture_output=True, text=True)
            restored = json.loads((work / "reports/exported/findings.json").read_text(encoding="utf-8"))
            self.assertEqual(Counter(f["rule"] for f in direct), Counter(f["rule"] for f in restored))


if __name__ == "__main__":
    unittest.main()
