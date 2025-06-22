# Home Connect Protocol

## Services

### ei Version 1

* POST /ei/initialValues

Initial Message from device, contains "edMsgID"
Respond with:

```json
[
    {
      "deviceType" : 2,
      "deviceName" : "[Device Name]",
      "deviceID" : "[Device ID]"
    }
]
```

### ei Version 2

* POST /ei/initialValues

Initial Message from device, contains "edMsgID"
Respond with:

```json
[
    {
    "deviceType" : "Application",
    "deviceName" : "[Device Name]",
    "deviceID" : "[Device ID]"
    }
]
```

### ci Version 1

* GET /ci/services
Returns list of available services and there version. Version 1 is always possible

* GET /ci/authentication
Authenticate with device using a 32 Byte nonce. Device will respond with own nonce.

```json
[
    {
    "nonce": "[32 bytes hex encoded, padding removed]"
    }
]
```

* GET /ci/info
Device HW info

Response:

```json
[
    {
    "deviceID": "SIEMENS-SN8S3647TE-68E05997A408",
    "eNumber": "SN8S3647TE/33",
    "brand": "SIEMENS",
    "vib": "SN8S3647TE",
    "mac": "68-99-A4-0E-05-78",
    "haVersion": "1.0",
    "swVersion": "1.4.9",
    "hwVersion": "5056177560",
    "deviceType": 32,
    "deviceInfo": "DISHWASHER",
    "customerIndex": 33,
    "serialNumber": "017376983004000136",
    "fdString": "8949",
    "shipSki": "55DE2924BB42B2AAB8E783911C912AF6B6B953B1"
    }
]
```

* GET /ci/tzinfo
Time zone info? Only seen as empty string

Response:

```json
[
    {
        "tz": ""
    }
]
```

* GET /ci/networkdetails
Current? Network address

Response:

```json
[
    {
        "ipv4": {
            "ipaddress": "192.168.1.10",
            "prefixsize": 24,
            "gateway": "192.168.1.1",
            "dnsserver": "192.168.1.1"
        },
        "ipv6": {
            "ipaddress": "2a0a:a540:6aa4:eff:a0c7:0:9978:fe05",
            "prefixsize": 64,
            "gateway": "0:0:0:0:0:0:0:0",
            "dnsserver": "0:0:0:0:0:0:0:0"
        }
    }
]
```

* GET /ci/wifiSetting
Wi-Fi settings

Response:

```json
[
    {
        "SSID": "[Wi-Fi SSID]",
        "AutomaticIPv4": true,
        "AutomaticIPv6": true
    }
]
```

### ci Version 2

### ci Version 3

* GET /ci/registeredDevices

Response:

```json
[
    {
        "endDeviceID": 0,
        "deviceType": "Application",
        "deviceName": "[Device Name]",
        "deviceID": "[Device ID]",
        "connected": false,
        "protected": false
    }
]
```

* GET /ci/pairableDevices
Unknown

Response:

```json
[
    {
        "deviceTypeList": []
    }
]
```

### iz Version 1

* GET /iz/info
Device HW info

Response:

```json
[
   {
        "deviceID": "402618500510038612",
        "eNumber": "SREX2863KE/11",
        "brand": "SIEMENS",
        "vib": "SREX2863KE",
        "mac": "C8-78-43-F2-D7-23",
        "haVersion": "5.4",
        "swVersion": "3.11.4.1",
        "hwVersion": "2.2.0.5",
        "deviceType": "Dishwasher",
        "deviceInfo": "",
        "customerIndex": "11",
        "serialNumber": "402618500510038612",
        "fdString": "0210",
        "shipSki": "E63852441AFACDD53806393E797CBB26249499C0"
    }
]
```

### ni Version 1

* GET /ni/info
Network interface info
Optionally specify interface with:

```json
[
    {
        "interfaceID": 0
    }
]
```

Response:

```json
[
    {
        "interfaceID": 0,
        "type": "WiFi",
        "ssid": "[Wifi SSID]",
        "rssi": -73,
        "primary": true,
        "status": "CONNECTED",
        "configured": true,
        "euiAddress": "C8:43:F2:23:D7:78",
        "ipV4": {
            "ipAddress": "192.168.1.50",
            "prefixSize": 24,
            "gateway": "192.168.1.1",
            "dnsServer": "192.168.1.1"
        },
        "ipV6": {
            "ipAddress": "2001:7201:cad7:78ff:a62:fe43:f223:19ea",
            "prefixSize": 64,
            "gateway": "fe80::9ec7:a6ff:fefc:6da",
            "dnsServer": "fd00::9ec7:a6ff:fefc:6da"
        }
    }
]
```

* GET /ni/config
Network interface config

Response:

```json
[
    {
        "interfaceID": 0,
        "ssid": "[Wifi SSID]",
        "automaticIPv4": false,
        "automaticIPv6": false,
        "manualIPv4": {
            "ipAddress": "192.168.1.50",
            "prefixSize": 24,
            "gateway": "192.168.1.1",
            "dnsServer": "192.168.1.1"
        },
        "manualIPv6": {
            "ipAddress": "2001:7201:cad7:78ff:a62:fe43:f223:19ea",
            "prefixSize": 64,
            "gateway": "fe80::9ec7:a6ff:fefc:6da",
            "dnsServer": "fd00::9ec7:a6ff:fefc:6da"
        }
    }
]
```

### ro Version 1
