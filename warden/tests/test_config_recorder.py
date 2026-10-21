"""AWS Config records what WARDEN's undo reads (owner, 2026-10-15: "make them perfect"): the owner's console steps
name every type the code reads, and the live check finds what is missing."""

from __future__ import annotations

import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("check_live_config", ROOT / "infra" / "scripts" / "check_live_config.py")
check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(check)


def test_the_owners_steps_record_every_type_the_undo_reads():
    needed = check.needed_types()
    assert len(needed) >= 8, "the scan found too few types - the test itself has rotted"
    assert needed <= check.documented_types(), sorted(needed - check.documented_types())


class _Config:
    def __init__(self, types, recording=True, frequency="CONTINUOUS", channels=1):
        self.types, self.recording, self.frequency, self.channels = types, recording, frequency, channels

    def describe_configuration_recorders(self):
        return {"ConfigurationRecorders": [{"recordingGroup": {"allSupported": False, "resourceTypes": self.types},
                                            "recordingMode": {"recordingFrequency": self.frequency}}]}

    def describe_configuration_recorder_status(self):
        return {"ConfigurationRecordersStatus": [{"recording": self.recording, "lastStatus": "SUCCESS"}]}

    def describe_delivery_channels(self):
        return {"DeliveryChannels": [{"name": "default"}] * self.channels}


def test_the_live_check_names_each_gap():
    full = sorted(check.needed_types())
    assert check.problems(_Config(full), "r") == []
    gaps = check.problems(_Config(full[1:], recording=False, frequency="DAILY", channels=0), "r")
    assert any(full[0] in g for g in gaps)
    assert any("not recording" in g for g in gaps)
    assert any("continuously" in g for g in gaps)
    assert any("delivery" in g for g in gaps)
