from homeconnect_websocket.message import Action, Message

SESSION_ID = 10
SERVER_MESSAGE_ID = 20
CLIENT_MESSAGE_ID = 30

MOCK_APPLIANCE_INFO = {
    "brand": "Fake_Brand",
    "type": "HomeAppliance",
    "deviceID": "Fake_deviceID",
    "vib": "Fake_vib",
    "haVersion": "1.1",
    "hwVersion": "2.2",
    "swVersion": "3.3",
    "mac": "C8-D7-78-43-F2-23",
    "serialNumber": "Fake_serialNumber",
}

DEVICE_MESSAGE_SET_1 = {
    "init": Message(
        sid=SESSION_ID,
        resource="/ei/initialValues",
        version=2,
        action=Action.POST,
        data=[{"edMsgID": CLIENT_MESSAGE_ID}],
    ),
    "services": [
        {"service": "ci", "version": 3},
        {"service": "ei", "version": 2},
        {"service": "iz", "version": 1},
        {"service": "ni", "version": 1},
        {"service": "ro", "version": 1},
    ],
    "responses": {
        "/iz/info": [
            {
                "deviceID": "240210038618500561",
                "eNumber": "FFAA1234/11",
                "brand": "HomeConnectWS",
                "vib": "FFAA1234",
                "mac": "23-43-F2-78-D7-23",
                "haVersion": "1.1",
                "swVersion": "1.2.12.20211004153146",
                "hwVersion": "1.1.0.5",
                "deviceType": "Dishwasher",
                "deviceInfo": "",
                "customerIndex": "11",
                "serialNumber": "240210038618500561",
                "fdString": "0686",
                "shipSki": "FBD7EDDF6A5BB504533D5397532FF21C1AFEF706",
            }
        ],
        "/ei/deviceReady": None,
        "/ci/registeredDevices": [
            {
                "endDeviceID": 0,
                "deviceType": "Application",
                "deviceName": "MockDevice",
                "deviceID": "000000",
                "connected": False,
                "protected": False,
            },
        ],
        "/ci/pairableDevices": [{"deviceTypeList": []}],
        "/ni/info": [
            {
                "interfaceID": 0,
                "type": "WiFi",
                "ssid": "ssid",
                "rssi": -73,
                "primary": True,
                "status": "CONNECTED",
                "configured": True,
                "euiAddress": "00:11:22:33:44:55",
                "ipV4": {
                    "ipAddress": "192.168.1.50",
                    "prefixSize": 24,
                    "gateway": "192.168.1.1",
                    "dnsServer": "192.168.1.1",
                },
                "ipV6": {
                    "ipAddress": "0011:2233:4455:6677:8899:AABB:CCDD:EEFF",
                    "prefixSize": 64,
                    "gateway": "fe80::0011:2233:4455:6677",
                    "dnsServer": "fe80::0011:2233:4455:6677",
                },
            }
        ],
        "/ni/config": [
            {
                "interfaceID": 0,
                "ssid": "ssid",
                "automaticIPv4": True,
                "automaticIPv6": True,
            }
        ],
        "/ro/allDescriptionChanges": [
            {"uid": 555, "parentUID": 261, "access": "NONE"},
        ],
        "/ro/allMandatoryValues": [
            {"uid": 3, "value": True},
        ],
    },
}
