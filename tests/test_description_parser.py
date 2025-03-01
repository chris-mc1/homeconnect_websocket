from __future__ import annotations

import json
from pathlib import Path

import pytest
from homeconnect_websocket.description_parser import (
    convert_bool,
    parse_device_description,
)

REFERENCE_DISCRIPTION = {
    "info": {
        "brand": "Fake_Brand",
        "type": "HomeAppliance",
        "model": "Fake_Model",
        "version": 2,
        "revision": 0,
    },
    "status": [
        {
            "uid": 5,
            "name": "Status.1",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "read",
        },
        {
            "uid": 527,
            "name": "Status.2",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Open", "1": "Closed"},
            "available": True,
            "access": "read",
        },
    ],
    "setting": [
        {
            "uid": 3,
            "name": "Setting.1",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "readwrite",
            "min": "0",
            "max": "10",
            "stepSize": "1",
            "initValue": "1",
            "default": "0",
            "passwordProtected": False,
            "notifyOnChange": False,
        },
        {
            "uid": 4,
            "name": "Setting.2",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "readwrite",
        },
    ],
    "event": [
        {
            "uid": 21,
            "name": "Event.1",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
            "handling": "acknowledge",
            "level": "hint",
        },
        {
            "uid": 22,
            "name": "Event.2",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
            "handling": "acknowledge",
            "level": "hint",
        },
    ],
    "command": [
        {
            "uid": 1,
            "name": "Command.1",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "writeonly",
        },
        {
            "uid": 2,
            "name": "Command.2",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "writeonly",
        },
    ],
    "option": [
        {
            "uid": 542,
            "name": "Option.1",
            "contentType": "percent",
            "protocolType": "Float",
            "available": True,
            "access": "read",
            "liveUpdate": True,
        },
        {
            "uid": 544,
            "name": "Option.2",
            "contentType": "timeSpan",
            "protocolType": "Integer",
            "available": True,
            "access": "read",
        },
    ],
    "program": [
        {
            "uid": 8192,
            "name": "Program.1",
            "available": True,
            "execution": "selectonly",
            "options": [
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": False,
                    "refUID": 542,
                    "default": "true",
                },
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": True,
                    "refUID": 544,
                },
            ],
        },
        {
            "uid": 8193,
            "name": "Program.2",
            "available": True,
            "options": [
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": False,
                    "refUID": 542,
                },
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": True,
                    "refUID": 544,
                },
            ],
        },
    ],
    "activeProgram": {
        "uid": 256,
        "name": "ActiveProgram",
        "access": "readwrite",
        "validate": True,
    },
    "selectedProgram": {
        "uid": 257,
        "name": "SelectedProgram",
        "access": "readwrite",
        "fullOptionSet": False,
    },
    "protectionPort": {
        "uid": 258,
        "name": "ProtectionPort",
        "access": "readwrite",
        "available": True,
    },
}


def test_convert_bool() -> None:
    """Test str to bool."""
    assert convert_bool("True") is True
    assert convert_bool("true") is True
    assert convert_bool("False") is False
    assert convert_bool("false") is False

    assert convert_bool(True) is True  # noqa: FBT003
    assert convert_bool(False) is False  # noqa: FBT003

    with pytest.raises(TypeError):
        convert_bool({})
    with pytest.raises(TypeError):
        convert_bool("not bool")


def test_parse_device_description() -> None:
    """Test Description Parser."""
    with Path("tests/DeviceDescription.xml").open() as file:
        description_file = file.read()
    with Path("tests/FeatureMapping.xml").open() as file:
        feature_file = file.read()

    paresd_description = parse_device_description(description_file, feature_file)
    paresd_description = json.loads(json.dumps(paresd_description))

    assert paresd_description == REFERENCE_DISCRIPTION
