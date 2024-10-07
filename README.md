# HomeConnect Websocket

Control HomeConnect Appliances through a local Websocket connection.

## Authentication and Device Description

To connect to an Appliance you need its encryption keys and the description of its features and options. The Appliance uses either TLS PSK or AES encryption, AES requires an additional Initialization Vector (IV). Both Key and IV are send to HomeConnects cloud servers on setup. To get the keys and description from the cloud use the `hc-login.py` script from the hcpy project (https://github.com/hcpy2-0/hcpy/)

From the script output you need the following:
* `devices.json`: The PSK ("key") and the IV ("iv") if the Appliance uses AES
* `[serialNumber].zip`: The two files named `*_DeviceDescription.xml` and `*_FeatureMapping.xml` containing the Device Description

## Parsing Device Description

```python

import json
from pathlib import Path

from homeconnect_websocket import parse_device_description

# Load Description from File
with Path("DeviceDescription.xml").open() as file:
    DeviceDescription = file.read()

with Path("FeatureMapping.xml").open() as file:
    FeatureMapping = file.read()

description = parse_device_description(DeviceDescription, FeatureMapping)

# Save Description to File for later use
with Path("DeviceDescription.json", "w").open() as file:
    json.dump(description, file)

```

Its best to save the parsed description as a json File to reuse later.

## Connecting

```python

import asyncio
import json

from homeconnect_websocket import DeviceDescription, HomeAppliance


async def main(description: DeviceDescription) -> None:
    app_name = "Example App"  # Name of your App
    app_id = "d50661eca7e45a"  # ID of your App
    psk64 = "whZJhkPa3a1hkuDdI3twHdqi1qhTxjnKE8954_zyY_E="  # PSK Key
    # iv64 = "ofi7M1WB98sJeM2H1Ew3XA==" # IV for Devices with AES Encryption

    appliance = HomeAppliance(
        description,
        "192.168.1.2",
        app_name,
        app_id,
        psk64=psk64,
        # iv64=iv64
    )
    await appliance.connect()

    # Set PowerState to On
    await appliance.settings["BSH.Common.Setting.PowerState"].set_value("On")


if __name__ == "__main__":
    # Load DeviceDescription from File
    with open("DeviceDescription.json", "r") as f:
        description = json.load(f)

    asyncio.run(main(description))

```