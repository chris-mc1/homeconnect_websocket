"""Parser to parse device description from XML-Files."""

from __future__ import annotations

from typing import Any, TextIO
from xml.parsers.expat import ExpatError

import xmltodict

from .const import DESCRIPTION_PROTOCOL_TYPES, DESCRIPTION_TYPES
from .entities import (
    DeviceDescription,
    DeviceInfo,
    EntityDescription,
    OptionDescription,
)
from .errors import ParserError


def convert_bool(obj: str | bool) -> bool:
    """Convert a string to as bool."""
    if isinstance(obj, str):
        if obj.lower() == "true":
            return True
        if obj.lower() == "false":
            return False
        msg = "Can't convert %s to bool"
        raise TypeError(msg, obj)
    if isinstance(obj, bool):
        return obj
    msg = "Can't convert %s to bool"
    raise TypeError(msg, obj)


def parse_feature_mapping(feature_mapping: dict) -> dict:
    """Parse Feature mapping."""
    features = {"feature": {}, "error": {}, "enumeration": {}}

    try:
        for feature in feature_mapping["featureDescription"]["feature"]:
            features["feature"][int(feature["@refUID"], base=16)] = feature["#text"]
    except (KeyError, ValueError, TypeError) as exc:
        msg = "Error while parsing on 'featureDescription'"
        raise ParserError(msg) from exc

    try:
        for error in feature_mapping["errorDescription"]["error"]:
            features["error"][int(error["@refEID"], base=16)] = error["#text"]
    except (KeyError, ValueError, TypeError) as exc:
        msg = "Error while parsing on 'errorDescription'"
        raise ParserError(msg) from exc

    try:
        for enum in feature_mapping["enumDescriptionList"]["enumDescription"]:
            temp_enum = {}
            for key in enum["enumMember"]:
                temp_enum[int(key["@refValue"])] = key["#text"]
            features["enumeration"][int(enum["@refENID"], base=16)] = temp_enum
    except (KeyError, ValueError, TypeError) as exc:
        msg = "Error while parsing on 'enumDescriptionList'"
        raise ParserError(msg) from exc

    return features


def parse_options(element: list[dict] | dict) -> list[OptionDescription]:
    """Parse Programs Options."""
    options = []
    for option in element:
        option_out = {}
        if "@access" in option:
            option_out["access"] = option["@access"].lower()
        if "@available" in option:
            option_out["available"] = convert_bool(option["@available"])
        if "@liveUpdate" in option:
            option_out["liveUpdate"] = convert_bool(option["@liveUpdate"])
        if "@refUID" in option:
            option_out["refUID"] = int(option["@refUID"], base=16)
        if "@default" in option:
            option_out["default"] = option["@default"]
        options.append(option_out)
    return options


def parse_element(element: dict[str, Any], features: dict) -> EntityDescription:
    """Parse Element."""
    element_out = EntityDescription()
    for attr_name, attr_value in element.items():
        if attr_name == "@uid":
            element_out["uid"] = int(attr_value, base=16)
            element_out["name"] = features["feature"][int(element["@uid"], base=16)]
        elif attr_name == "@refCID":
            element_out["contentType"] = DESCRIPTION_TYPES[int(attr_value, base=16)]
            element_out["protocolType"] = DESCRIPTION_PROTOCOL_TYPES[
                int(attr_value, base=16)
            ]
        elif attr_name == "@enumerationType":
            element_out["enumeration"] = features["enumeration"][
                int(attr_value, base=16)
            ]
        elif attr_name in (
            "@available",
            "@notifyOnChange",
            "@passwordProtected",
            "@liveUpdate",
            "@fullOptionSet",
            "@validate",
        ):
            element_out[attr_name.strip("@")] = convert_bool(attr_value)
        elif attr_name in ("@access", "@execution"):
            element_out[attr_name.strip("@")] = attr_value.lower()
        elif attr_name == "option":
            element_out["options"] = parse_options(element["option"])
        elif attr_name == "@refDID":
            continue
        else:
            element_out[attr_name.strip("@")] = attr_value
    return element_out


def parse_elements(description_list: dict, features: dict) -> list[EntityDescription]:
    """Parse list of Element."""
    return [parse_element(element, features) for element in description_list]


def parse_info(device_description: dict) -> DeviceInfo:
    """Parse Device Info."""
    return {
        "brand": device_description["description"]["brand"],
        "type": device_description["description"]["type"],
        "model": device_description["description"]["model"],
        "version": int(device_description["description"]["version"]),
        "revision": int(device_description["description"]["revision"]),
    }


def parse_device_description(
    device_description_xml: str | TextIO, feature_mapping_xml: str | TextIO
) -> DeviceDescription:
    """
    Parse device description from XML-Files.

    Args:
    ----
        device_description_xml (str | TextIO): Device description XML-File
        feature_mapping_xml (str | TextIO): Feature mapping XML-File

    """
    try:
        device_description = xmltodict.parse(
            device_description_xml,
            force_list=(
                "option",
                "status",
                "setting",
                "event",
                "command",
                "option",
                "program",
            ),
        )["device"]
    except ExpatError as exc:
        msg = "Error while parsing Device Description XML-File"
        raise ParserError(msg) from exc

    try:
        feature_mapping = xmltodict.parse(
            feature_mapping_xml,
            force_list=("feature", "error", "enumDescription", "enumMember"),
        )["featureMappingFile"]
    except ExpatError as exc:
        msg = "Error while parsing Feature Mapping XML-File"
        raise ParserError(msg) from exc

    features = parse_feature_mapping(feature_mapping)

    description = DeviceDescription()
    if "description" in device_description:
        try:
            description["info"] = parse_info(device_description)
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'description'"
            raise ParserError(msg) from exc

    if "statusList" in device_description:
        try:
            description["status"] = parse_elements(
                device_description["statusList"]["status"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'statusList'"
            raise ParserError(msg) from exc

    if "settingList" in device_description:
        try:
            description["setting"] = parse_elements(
                device_description["settingList"]["setting"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'settingList'"
            raise ParserError(msg) from exc

    if "eventList" in device_description:
        try:
            description["event"] = parse_elements(
                device_description["eventList"]["event"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'eventList'"
            raise ParserError(msg) from exc

    if "commandList" in device_description:
        try:
            description["command"] = parse_elements(
                device_description["commandList"]["command"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'commandList'"
            raise ParserError(msg) from exc

    if "optionList" in device_description:
        try:
            description["option"] = parse_elements(
                device_description["optionList"]["option"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'optionList'"
            raise ParserError(msg) from exc

    if "programGroup" in device_description:
        try:
            description["program"] = parse_elements(
                device_description["programGroup"]["program"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'programGroup'"
            raise ParserError(msg) from exc

    if "activeProgram" in device_description:
        try:
            description["activeProgram"] = parse_element(
                device_description["activeProgram"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'activeProgram'"
            raise ParserError(msg) from exc

    if "selectedProgram" in device_description:
        try:
            description["selectedProgram"] = parse_element(
                device_description["selectedProgram"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'selectedProgram'"
            raise ParserError(msg) from exc

    if "protectionPort" in device_description:
        try:
            description["protectionPort"] = parse_element(
                device_description["protectionPort"], features
            )
        except (KeyError, ValueError, TypeError) as exc:
            msg = "Error while parsing on 'protectionPort'"
            raise ParserError(msg) from exc

    return description
