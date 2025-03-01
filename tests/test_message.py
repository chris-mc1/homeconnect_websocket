from __future__ import annotations

from homeconnect_websocket.message import Action, Message, load_message


def test_message_load() -> None:
    """Test load_message()."""
    message_str = '{"sID":3609751529,"msgID":3294751923,"resource":"/ei/initialValues","version":2,"action":"POST","data":[{"edMsgID":2974143846}]}'  # noqa: E501

    message = load_message(message_str)
    assert message.sid == 3609751529
    assert message.msg_id == 3294751923
    assert message.resource == "/ei/initialValues"
    assert message.version == 2
    assert message.action == Action.POST
    assert message.data == [{"edMsgID": 2974143846}]
    assert message.code is None

    message_str = '{"sID":3609751529,"msgID":3294751923,"resource":"/ro/values","version":1,"action":"RESPONSE","code":400}'  # noqa: E501
    message = load_message(message_str)
    assert message.resource == "/ro/values"
    assert message.version == 1
    assert message.action == Action.RESPONSE
    assert message.data is None
    assert message.code == 400


def test_message_dump() -> None:
    """Test Message.dump()."""
    message = Message(
        sid=3609751529,
        msg_id=3294751923,
        resource="/ei/initialValues",
        version=2,
        action=Action.POST,
        data={"edMsgID": 2974143846},
    )
    assert (
        message.dump()
        == '{"sID":3609751529,"msgID":3294751923,"resource":"/ei/initialValues","version":2,"action":"POST","data":[{"edMsgID":2974143846}]}'  # noqa: E501
    )


def test_message_response() -> None:
    """Test Message.responde()."""
    message = Message(
        sid=3609751529,
        msg_id=3294751923,
        resource="/ei/initialValues",
        version=2,
        action=Action.POST,
        data={"edMsgID": 2974143846},
    )
    response_message = message.responde({"deviceType": "Application"})

    assert response_message.sid == 3609751529
    assert response_message.msg_id == 3294751923
    assert response_message.resource == "/ei/initialValues"
    assert response_message.version == 2
    assert response_message.action == Action.RESPONSE
    assert response_message.data == {"deviceType": "Application"}
    assert response_message.code is None
