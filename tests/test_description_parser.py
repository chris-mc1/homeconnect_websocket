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
            "uid": 4097,
            "name": "Status.1",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "read",
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4098,
            "name": "Status.2",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Open", "1": "Closed"},
            "available": True,
            "access": "read",
            "refCID": 3,
            "refDID": 128,
        },
        {
            "uid": 4099,
            "name": "Status.3",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "read",
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4100,
            "name": "Status.4",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Open", "1": "Closed"},
            "available": True,
            "access": "read",
            "refCID": 3,
            "refDID": 128,
        },
    ],
    "setting": [
        {
            "uid": 4101,
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
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4102,
            "name": "Setting.2",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "readwrite",
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4103,
            "name": "Setting.3",
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
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4104,
            "name": "Setting.4",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "readwrite",
            "refCID": 1,
            "refDID": 0,
        },
    ],
    "event": [
        {
            "uid": 4105,
            "name": "Event.1",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
            "handling": "acknowledge",
            "level": "hint",
            "refCID": 3,
            "refDID": 128,
        },
        {
            "uid": 4106,
            "name": "Event.2",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
            "handling": "acknowledge",
            "level": "hint",
            "refCID": 3,
            "refDID": 128,
        },
        {
            "uid": 4107,
            "name": "Event.3",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
            "handling": "acknowledge",
            "level": "hint",
            "refCID": 3,
            "refDID": 128,
        },
        {
            "uid": 4108,
            "name": "Event.4",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
            "handling": "acknowledge",
            "level": "hint",
            "refCID": 3,
            "refDID": 128,
        },
    ],
    "command": [
        {
            "uid": 4109,
            "name": "Command.1",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "writeonly",
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4110,
            "name": "Command.2",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "writeonly",
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4111,
            "name": "Command.3",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "writeonly",
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4112,
            "name": "Command.4",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "writeonly",
            "refCID": 1,
            "refDID": 0,
        },
    ],
    "option": [
        {
            "uid": 4113,
            "name": "Option.1",
            "contentType": "percent",
            "protocolType": "Float",
            "available": True,
            "access": "read",
            "liveUpdate": True,
            "refCID": 17,
            "refDID": 160,
        },
        {
            "uid": 4114,
            "name": "Option.2",
            "contentType": "timeSpan",
            "protocolType": "Integer",
            "available": True,
            "access": "read",
            "refCID": 16,
            "refDID": 130,
        },
        {
            "uid": 4115,
            "name": "Option.3",
            "contentType": "percent",
            "protocolType": "Float",
            "available": True,
            "access": "read",
            "liveUpdate": True,
            "refCID": 17,
            "refDID": 160,
        },
        {
            "uid": 4116,
            "name": "Option.4",
            "contentType": "timeSpan",
            "protocolType": "Integer",
            "available": True,
            "access": "read",
            "refCID": 16,
            "refDID": 130,
        },
    ],
    "program": [
        {
            "uid": 4117,
            "name": "Program.1",
            "available": True,
            "execution": "selectonly",
            "options": [
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": False,
                    "refUID": 4113,
                    "default": "true",
                },
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": True,
                    "refUID": 4114,
                },
            ],
        },
        {
            "uid": 4118,
            "name": "Program.2",
            "available": True,
            "options": [
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": False,
                    "refUID": 4113,
                    "default": "true",
                },
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": True,
                    "refUID": 4114,
                },
            ],
        },
        {
            "uid": 4119,
            "name": "Program.3",
            "available": True,
            "execution": "selectonly",
            "options": [
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": False,
                    "refUID": 4113,
                    "default": "true",
                },
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": True,
                    "refUID": 4114,
                },
            ],
        },
        {
            "uid": 4120,
            "name": "Program.4",
            "available": True,
            "options": [
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": False,
                    "refUID": 4113,
                    "default": "true",
                },
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": True,
                    "refUID": 4114,
                },
            ],
        },
    ],
    "activeProgram": {
        "uid": 4121,
        "name": "ActiveProgram",
        "access": "readwrite",
        "validate": True,
    },
    "selectedProgram": {
        "uid": 4122,
        "name": "SelectedProgram",
        "access": "readwrite",
        "fullOptionSet": False,
    },
    "protectionPort": {
        "uid": 4123,
        "name": "ProtectionPort",
        "access": "readwrite",
        "available": True,
    },
}

REFERENCE_DISCRIPTION_SHORT = {
    "info": {
        "brand": "Fake_Brand",
        "type": "HomeAppliance",
        "model": "Fake_Model",
        "version": 2,
        "revision": 0,
    },
    "status": [
        {
            "uid": 4097,
            "name": "Status.1",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "read",
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4098,
            "name": "Status.2",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Open", "1": "Closed"},
            "available": True,
            "access": "read",
            "refCID": 3,
            "refDID": 0,
        },
    ],
    "setting": [
        {
            "uid": 4101,
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
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4102,
            "name": "Setting.2",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "readwrite",
            "refCID": 1,
            "refDID": 0,
        },
    ],
    "event": [
        {
            "uid": 4105,
            "name": "Event.1",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
            "handling": "acknowledge",
            "level": "hint",
            "refCID": 3,
            "refDID": 128,
        },
        {
            "uid": 4106,
            "name": "Event.2",
            "contentType": "enumeration",
            "protocolType": "Integer",
            "enumeration": {"0": "Off", "1": "Present", "2": "Confirmed"},
            "handling": "acknowledge",
            "level": "hint",
            "refCID": 3,
            "refDID": 128,
        },
    ],
    "command": [
        {
            "uid": 4109,
            "name": "Command.1",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "writeonly",
            "refCID": 1,
            "refDID": 0,
        },
        {
            "uid": 4110,
            "name": "Command.2",
            "contentType": "boolean",
            "protocolType": "Boolean",
            "available": True,
            "access": "writeonly",
            "refCID": 1,
            "refDID": 0,
        },
    ],
    "option": [
        {
            "uid": 4113,
            "name": "Option.1",
            "contentType": "percent",
            "protocolType": "Float",
            "available": True,
            "access": "read",
            "liveUpdate": True,
            "refCID": 17,
            "refDID": 160,
        },
        {
            "uid": 4114,
            "name": "Option.2",
            "contentType": "timeSpan",
            "protocolType": "Integer",
            "available": True,
            "access": "read",
            "refCID": 16,
            "refDID": 160,
        },
    ],
    "program": [
        {
            "uid": 4117,
            "name": "Program.1",
            "available": True,
            "execution": "selectonly",
            "options": [
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": False,
                    "refUID": 4113,
                    "default": "true",
                },
            ],
        },
        {
            "uid": 4118,
            "name": "Program.2",
            "available": True,
            "execution": "selectonly",
            "options": [
                {
                    "access": "readwrite",
                    "available": True,
                    "liveUpdate": False,
                    "refUID": 4113,
                    "default": "true",
                },
            ],
        },
    ],
    "activeProgram": {
        "uid": 4121,
        "name": "ActiveProgram",
        "access": "readwrite",
        "validate": True,
    },
    "selectedProgram": {
        "uid": 4122,
        "name": "SelectedProgram",
        "access": "readwrite",
        "fullOptionSet": False,
    },
    "protectionPort": {
        "uid": 4123,
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

    assert convert_bool(0) is False
    assert convert_bool(1) is True
    assert convert_bool(1.5) is True

    assert convert_bool("0") is False
    assert convert_bool("1") is True
    assert convert_bool("1.5") is True

    with pytest.raises(TypeError):
        convert_bool({})
    with pytest.raises(TypeError):
        convert_bool("not bool")


@pytest.mark.parametrize(
    ("description_path", "feature_path", "expected"),
    [
        (
            Path("tests/DeviceDescription.xml"),
            Path("tests/FeatureMapping.xml"),
            REFERENCE_DISCRIPTION,
        ),
        (
            Path("tests/DeviceDescription_short.xml"),
            Path("tests/FeatureMapping_short.xml"),
            REFERENCE_DISCRIPTION_SHORT,
        ),
    ],
)
def test_parse_device_description(
    description_path: Path, feature_path: Path, expected: dict
) -> None:
    """Test Description Parser."""
    with description_path.open() as file:
        description_file = file.read()
    with feature_path.open() as file:
        feature_file = file.read()

    paresd_description = parse_device_description(description_file, feature_file)
    paresd_description = json.loads(json.dumps(paresd_description))

    assert paresd_description == expected
