"""Parser to parse device description from XML-Files."""

from __future__ import annotations

from functools import partial
from typing import TextIO, TypedDict
from xml.parsers.expat import ExpatError

import xmltodict

from .const import DESCRIPTION_PROTOCOL_TYPES, DESCRIPTION_TYPES
from .entities import (
    DeviceDescription,
    EntityDescription,
    OptionDescription,
)
from .errors import ParserError
from .helpers import convert_bool


class FeatureMap(TypedDict):
    """Typing for Feature mapping."""

    feature: dict[int, str]
    error: dict[int, str]
    enumeration: dict[int, dict[int, str]]


def parse_feature_mapping(feature_mapping: dict) -> FeatureMap:
    """Parse Feature mapping."""
    features = FeatureMap(feature={}, error={}, enumeration={})

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


def add_enum_subsets(features: FeatureMap, description: list[dict]) -> None:
    """Add Enum subsets to FeatureMap."""
    if "enumerationTypeList" in description:
        for enum in description["enumerationTypeList"]["enumerationType"]:
            if (
                "@subsetOf" in enum
                and int(enum["@enid"], base=16) not in features["enumeration"]
            ):
                super_enum = features["enumeration"][int(enum["@subsetOf"], base=16)]
                subset_enum = {}
                for value in enum["enumeration"]:
                    subset_enum[int(value["@value"])] = super_enum[int(value["@value"])]
                features["enumeration"][int(enum["@enid"], base=16)] = subset_enum


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


def parse_element(
    description: DeviceDescription,
    xml_description: dict,
    features: FeatureMap,
    key: str,
    *,
    is_list: bool = True,
) -> None:
    """Parse Element."""
    element_out = EntityDescription()

    for attr_name, attr_value in xml_description.items():
        try:
            if attr_name == "@uid":
                element_out["uid"] = int(attr_value, base=16)
                element_out["name"] = features["feature"][
                    int(xml_description["@uid"], base=16)
                ]
            elif attr_name == "@refCID":
                element_out["contentType"] = DESCRIPTION_TYPES[int(attr_value, base=16)]
                element_out["protocolType"] = DESCRIPTION_PROTOCOL_TYPES[
                    int(attr_value, base=16)
                ]
                element_out["refCID"] = int(attr_value, base=16)
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
                element_out["options"] = parse_options(xml_description["option"])
            elif attr_name == "@refDID":
                element_out["refDID"] = int(attr_value, base=16)
            else:
                element_out[attr_name.strip("@")] = attr_value
        except (KeyError, ValueError, TypeError) as exc:
            msg = f"Error while parsing '{attr_name}' in '{key}'"
            raise ParserError(msg) from exc

    if is_list:
        description[key].append(element_out)
    else:
        description[key] = element_out


def parse_elements(
    description: DeviceDescription, xml_description: list[dict], features: FeatureMap
) -> None:
    """Parse list of Element."""
    for element, parser in PARSERS.items():
        if element in xml_description:
            description_elements = xml_description[element]
            if not isinstance(description_elements, list):
                description_elements = [description_elements]
            for description_element in description_elements:
                parser["parser"](description, description_element, features)


def parse_info(
    description: DeviceDescription,
    xml_description: dict,
    features: FeatureMap,  # noqa: ARG001
    key: str,
) -> None:
    """Parse Device Info."""
    try:
        description[key] = {
            "brand": xml_description["brand"],
            "type": xml_description["type"],
            "model": xml_description["model"],
            "version": int(xml_description["version"]),
            "revision": int(xml_description["revision"]),
        }
    except (KeyError, ValueError, TypeError) as exc:
        msg = "Error while parsing 'Device Info'"
        raise ParserError(msg) from exc


PARSERS = {
    "description": {"parser": partial(parse_info, key="info")},
    "option": {"parser": partial(parse_element, key="option")},
    "optionList": {"parser": parse_elements},
    "status": {"parser": partial(parse_element, key="status")},
    "statusList": {"parser": parse_elements, "key": "status"},
    "setting": {"parser": partial(parse_element, key="setting")},
    "settingList": {"parser": parse_elements, "key": "setting"},
    "event": {"parser": partial(parse_element, key="event")},
    "eventList": {"parser": parse_elements},
    "command": {"parser": partial(parse_element, key="command")},
    "commandList": {"parser": parse_elements},
    "program": {"parser": partial(parse_element, key="program")},
    "programGroup": {"parser": parse_elements},
    "activeProgram": {
        "parser": partial(parse_element, key="activeProgram", is_list=False)
    },
    "selectedProgram": {
        "parser": partial(parse_element, key="selectedProgram", is_list=False)
    },
    "protectionPort": {
        "parser": partial(parse_element, key="protectionPort", is_list=False)
    },
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
        xml_description = xmltodict.parse(
            device_description_xml,
            force_list=(
                "option",
                "optionList",
                "status",
                "statusList",
                "setting",
                "settingList",
                "event",
                "eventList",
                "command",
                "commandList",
                "program",
                "programGroup",
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
    add_enum_subsets(features, xml_description)
    description = DeviceDescription(
        status=[], option=[], setting=[], event=[], command=[], program=[]
    )
    parse_elements(description, xml_description, features)

    return description


def main() -> None:
    """For CLI Parser."""
    import json  # noqa: PLC0415
    from argparse import ArgumentParser  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    arg_parser = ArgumentParser(
        description="HomeConnect Websocket Description Parser",
        usage="%(prog)s -d DeviceDescription.xml -f FeatureMapping.xml -o output.json",
    )
    arg_parser.add_argument(
        "-d",
        type=Path,
        required=True,
        dest="description_path",
        help="Device description files",
    )
    arg_parser.add_argument(
        "-f",
        type=Path,
        required=True,
        dest="feature_path",
        help="Feature mapping files",
    )
    arg_parser.add_argument(
        "-o", type=Path, required=True, dest="output_file", help="Output file"
    )
    args = arg_parser.parse_args()

    with Path(args.description_path).open() as file:
        description_file = file.read()

    with Path(args.feature_path).open() as file:
        feature_file = file.read()

    description = parse_device_description(description_file, feature_file)

    with Path(args.output_file).open("w") as file:
        json.dump(description, file, indent=4)


if __name__ == "__main__":
    main()
