"""Is AWS Config recording what WARDEN's undo reads? (owner, 2026-10-15: "make them perfect").

revert_change sets a value back to what AWS Config recorded just before the change (platforms/aws.py). The recorder is
made once per account and Region by an administrator (docs/SETUP.md, "AWS Config"), not by a stack that is
destroyed after a test. This read-only check compares it with the code:

    AWS_PROFILE=warden python scripts/check_live_config.py

Exit 0 when the recorder is on, records continuously, delivers, and records every resource type the code reads;
1 with each difference named otherwise. Only names and states are printed.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def needed_types() -> set[str]:
    """Every AWS Config resource type the undo code reads (platforms/aws.py), from the code itself."""
    text = (ROOT / "src" / "warden" / "platforms" / "aws.py").read_text(encoding="utf-8")
    return set(re.findall(r'"(AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)"', text))


def documented_types() -> set[str]:
    """The types the setup guide says to record."""
    text = (ROOT / "docs" / "SETUP.md").read_text(encoding="utf-8")
    section = text.split("### AWS Config, so WARDEN can undo a recorded change", 1)[1].split("\n## ", 1)[0]
    return set(re.findall(r"`(AWS::[A-Za-z0-9]+::[A-Za-z0-9]+)`", section))


def problems(config, region: str) -> list[str]:
    out = []
    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders") or []
    if not recorders:
        return [f"no configuration recorder in {region}: revert_change plans are refused"]
    rec = recorders[0]
    status = (config.describe_configuration_recorder_status().get("ConfigurationRecordersStatus") or [{}])[0]
    if not status.get("recording"):
        out.append("the recorder is not recording")
    if str(status.get("lastStatus", "")).upper() not in ("SUCCESS", "PENDING"):
        out.append(f"the recorder's last status is {status.get('lastStatus')}")
    if (rec.get("recordingMode") or {}).get("recordingFrequency", "CONTINUOUS") != "CONTINUOUS":
        out.append("the recorder does not record continuously: a change between two daily snapshots is lost")
    group = rec.get("recordingGroup") or {}
    recorded = set(group.get("resourceTypes") or [])
    if not group.get("allSupported"):
        missing = sorted(needed_types() - recorded)
        if missing:
            out.append("not recorded, but read by the undo: " + ", ".join(missing))
    if not (config.describe_delivery_channels().get("DeliveryChannels") or []):
        out.append("no delivery channel: nothing is recorded")
    return out


def main() -> int:
    import boto3

    from warden.environments import region

    found = problems(boto3.client("config", region_name=region()), region())
    for p in found:
        print(f"DIFFERS  {p}")
    if not found:
        print(f"MATCHES  the recorder records the {len(needed_types())} types the undo reads, continuously")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
