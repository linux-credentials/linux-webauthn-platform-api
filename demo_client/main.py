#!/usr/bin/env python3

import asyncio
import json
from pprint import pprint
import secrets
import sys
from typing import Optional
import unittest

from dbus_next.aio import MessageBus
from dbus_next import Variant

import util
import webauthn

async def run(cmd):
    bus = await MessageBus().connect()

    with open('xyz.iinuwa.credentials.CredentialManager.xml', 'r') as f:
        introspection = f.read()

    proxy_object = bus.get_proxy_object('xyz.iinuwa.credentials.CredentialManagerUi',
                                        '/xyz/iinuwa/credentials/CredentialManagerUi',
                                        introspection)

    interface = proxy_object.get_interface(
        'xyz.iinuwa.credentials.CredentialManagerUi1')

    rp_id = "example.com"
    origin = "https://example.com"
    is_same_origin = False
    user_handle = b"123abdsacddw"
    username = "user@example.com"

    if cmd == 'create':
        auth_data = await create_passkey(interface, origin, is_same_origin, rp_id, user_handle, username)
        user_data = {
            "id": 1,
            "name": username,
            "user_handle": user_handle,
            "cred_id": util.b64_encode(auth_data.cred_id),
            "pub_key": util.b64_encode(auth_data.pub_key_bytes),
            "sign_count": auth_data.sign_count,
            "backup_eligible": auth_data.has_flag('BE'),
            "backup_state": auth_data.has_flag('BS'),
            "uv_initialized": auth_data.has_flag('UV'),
        }
        print("New credential data:")
        print(json.dumps(user_data))
        json.dump(user_data, open('./user.json', 'w'))
    elif cmd == 'get':
        user_data = json.load(open('./user.json', 'r'))
        cred_id = util.b64_decode(user_data['cred_id'])
        auth_data = await get_passkey(interface, origin, is_same_origin, rp_id, cred_id, user_data)
        print(auth_data)
    else:
        print(f"unknown cmd: {cmd}")
        exit()
    # rsp = await create_password(interface)
    # print(rsp)
    # rsp = await get_password(interface)
    # print(rsp)
    # await bus.wait_for_disconnect()


async def create_password(interface):
    password_req = {
        "type": Variant('s', "password"),
        "password": Variant("a{sv}", {
            "origin": Variant('s', "xyz.iinuwa.credentials.CredentialManager:local"),
            "id": Variant('s', "test@example.com"),
            "password": Variant('s', "abc123"),
        })
    }
    rsp = await interface.call_create_credential(password_req)
    return rsp


async def get_password(interface):
    password_req = {
        "origin": Variant("s", "xyz.iinuwa.credentials.CredentialManager:local"),
        "options": Variant("aa{sv}", [
            {
                "type": Variant("s", "password"),
                "password": Variant("a{sv}", {}),
            }
        ])
    }
    rsp = await interface.call_get_credential(password_req)
    if rsp['type'].value == 'password':
        cred = rsp['password'].value
        id = cred['id'].value
        password = cred['password'].value
        return (id, password)
    return None


async def create_passkey(interface, origin, is_same_origin, rp_id, user_handle, username):
    options = {
        "challenge": util.b64_encode(secrets.token_bytes(16)),
        "rp": {
            "name": "Example Org",
            "id": rp_id,
        },
        "user": {
            "id": util.b64_encode(user_handle),
            "name": username,
            "displayName": "User 1",
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7},
            {"type": "public-key", "alg": -257},
            {"type": "public-key", "alg": -8},
        ],
    }

    print(f"Sending {'same' if is_same_origin else 'cross'}-origin request for {origin} using options:")
    pprint(options)
    print()

    req_json = json.dumps(options)
    req = {
        "type": Variant('s', "publicKey"),
        "origin": Variant('s', origin),
        "is_same_origin": Variant('b', is_same_origin),
        "publicKey": Variant('a{sv}', {
            "request_json": Variant('s', req_json)
        })
    }

    rsp = await interface.call_create_credential(req)
    print("Received response")
    pprint(rsp)
    if rsp['type'].value != 'public-key':
        raise Exception(f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}")

    response_json = json.loads(rsp['public_key'].value['registration_response_json'].value)
    return webauthn.verify_create_response(response_json, options, origin)


async def get_passkey(interface, origin, is_same_origin, rp_id, cred_id, user: Optional[dict]):
    options = {
        "challenge": util.b64_encode(secrets.token_bytes(16)),
        "rpId": rp_id,
        "allowCredentials": [
            {"type": "public-key", "id": util.b64_encode(cred_id)},
        ],
    }

    print(f"Sending {'same' if is_same_origin else 'cross'}-origin request for {origin} using options:")
    pprint(options)
    print()

    req_json = json.dumps(options)
    req = {
        "type": Variant('s', "publicKey"),
        "origin": Variant('s', origin),
        "is_same_origin": Variant('b', is_same_origin),
        "publicKey": Variant('a{sv}', {
            "request_json": Variant('s', req_json)
        })
    }

    rsp = await interface.call_get_credential(req)
    print("Received response")
    pprint(rsp)
    if rsp['type'].value != 'public-key':
        raise Exception(f"Invalid credential type received: expected 'public-key', received {rsp['type'.value]}")

    response_json = json.loads(rsp['public_key'].value['registration_response_json'].value)
    print(user)
    return webauthn.verify_get_response(response_json, options, origin, user, None)


def main():
    args = sys.argv[1:]
    if not args:
        print("No cmd given. Use 'get' or 'create'")
        exit()
    cmd = args[0]
    loop = asyncio.get_event_loop()
    loop.run_until_complete(run(cmd))


if __name__ == "__main__":
    main()

class VerificationTests(unittest.TestCase):
    def test_1(self):
        response = {
            'id': 'owBYoufBWYDUOeNB9dZs9x6GlEPiS8ziKnI_9YVq9RpkwwYsxelm66HOP2usfy-SaV8NE5nJVWDIMvS0W-x9BYtN4AmHZVY33GW2rdfLpeBruuh4jDXgYdnHtZC0IyDIKZiOTzSzyoQih8F-VLcTmqQl7SVHgf-xAh-6TxAJMccROZyIsili1OOnv3WSE7374c2Sw9At0ILaSiTmvC7MtZfnj9hhnAFMFobCJvainepVBn3HAlDo22486wkPqW2D5N00XYXK',
            'rawId': 'owBYoufBWYDUOeNB9dZs9x6GlEPiS8ziKnI_9YVq9RpkwwYsxelm66HOP2usfy-SaV8NE5nJVWDIMvS0W-x9BYtN4AmHZVY33GW2rdfLpeBruuh4jDXgYdnHtZC0IyDIKZiOTzSzyoQih8F-VLcTmqQl7SVHgf-xAh-6TxAJMccROZyIsili1OOnv3WSE7374c2Sw9At0ILaSiTmvC7MtZfnj9hhnAFMFobCJvainepVBn3HAlDo22486wkPqW2D5N00XYXK',
            'response': {
                'attestationObject': 'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgIQ1ReuY8bt2QPrmsZGqphT3hwTJ4Ar2zd3RevRXelHYCIQDiSKGGo5mUqsWP43B6TgxcWby0M1ucBkwOQTS4E6Dt-mN4NWOBWQKqMIICpjCCAkygAwIBAgIUfWe3F4mJfmOVopPF8mmAKxBb0igwCgYIKoZIzj0EAwIwLTERMA8GA1UECgwIU29sb0tleXMxCzAJBgNVBAYTAkNIMQswCQYDVQQDDAJGMTAgFw0yMTA1MjMwMDUyMDBaGA8yMDcxMDUxMTAwNTIwMFowgYMxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhTb2xvS2V5czEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjE9MDsGA1UEAww0U29sbyAyIE5GQytVU0ItQSA4NjUyQUJFOUZCRDg0ODEwQTg0MEQ2RkM0NDJBOEMyQyBCMTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABArSyTVT7sDxX0rom6XoIcg8qwMStGV3SjoGRNMqHBSAh2sr4EllUzA1F8yEX5XvUPN_M6DQlqEFGw18UodOjBqjgfAwge0wHQYDVR0OBBYEFBiTdxTWyNCRuzSieBflmHPSJbS1MB8GA1UdIwQYMBaAFEFrtkvvohkN5GJf_SkElrmCKbT4MAkGA1UdEwQCMAAwCwYDVR0PBAQDAgTwMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcwAoYWaHR0cDovL2kuczJwa2kubmV0L2YxLzAnBgNVHR8EIDAeMBygGqAYhhZodHRwOi8vYy5zMnBraS5uZXQvcjEvMCEGCysGAQQBguUcAQEEBBIEEIZSq-n72EgQqEDW_EQqjCwwEwYLKwYBBAGC5RwCAQEEBAMCBDAwCgYIKoZIzj0EAwIDSAAwRQIgMsLnUg5Px2FehxIUNiaey8qeT1FGtlJ1s3LEUGOks-8CIQDNEv5aupDvYxn2iqWSNysv4qpdoqSMytRQ7ctfuJDWN2hhdXRoRGF0YVkBJ6N5pvbur7mlXjeMEYA04nUeaC-rny0wqxPSElWGzhlHRQAAADmGUqvp-9hIEKhA1vxEKowsAMajAFii58FZgNQ540H11mz3HoaUQ-JLzOIqcj_1hWr1GmTDBizF6Wbroc4_a6x_L5JpXw0TmclVYMgy9LRb7H0Fi03gCYdlVjfcZbat18ul4Gu66HiMNeBh2ce1kLQjIMgpmI5PNLPKhCKHwX5UtxOapCXtJUeB_7ECH7pPEAkxxxE5nIiyKWLU46e_dZITvfvhzZLD0C3QgtpKJOa8Lsy1l-eP2GGcAUwWhsIm9qKd6lUGfccCUOjbbjzrCQ-pbYPk3TRdhcqkAQEDJyAGIVggzFQIxv1GYCb7CZXbKR8VRTWiRCbceHYcsBNx-lOg9Xk',
                'clientDataJSON': '{"type":"webauthn.create","challenge":"j-dyF8Xcw5lY2YFJ260ywg","origin":"xyz.iinuwa.credentials.CredentialManager:local","crossOrigin":true}',
                'transports': ['usb']
            }
        }
        challenge = 'j-dyF8Xcw5lY2YFJ260ywg'
        create_options = {
            'challenge': challenge,
            'rp': {
                'id': 'example.com'
            },
            'authenticatorSelection': {
                'userVerification': 'required'
            },
            'pubKeyCredParams': [
                {
                    "type": "public-key",
                    "alg": -8
                },
                {
                    "type": "public-key",
                    "alg": -7
                },
                {
                    "type": "public-key",
                    "alg": -257
                }
            ]
        }
        origin =  "xyz.iinuwa.credentials.CredentialManager:local"

        auth_data = webauthn.verify_create_response(response, create_options, origin)
        self.assertEqual(response['id'], util.b64_encode(auth_data.cred_id))

    def test_get_credential(self):
        response = {
            "authenticatorAttachment":"cross-platform",
            "id":"owBYojOVzZU-pjscj82gQAHvhUDTMgzQtTcQjyBpzHT-bqLwtLF2OOJDoskE18lOn2-1-SV-b7nCvn5s5Uq2KhBt1Q9kFVBUsb8jBl959BY3KWTg2rgjpN9nB5uIWTEFXfAWo0qIYGGVhXLyEbvu72Lq_W0wlccoKlxWrP349qN9OG2RTaGrgNjxTo1LqnSVc9S6D1zD7mop5KQ_9FZEjA5jABAquwFMAuO4ongyujnpoAfyAlB6UZ_JDmDFCkuN598q_LAu",
            "rawId":"owBYojOVzZU-pjscj82gQAHvhUDTMgzQtTcQjyBpzHT-bqLwtLF2OOJDoskE18lOn2-1-SV-b7nCvn5s5Uq2KhBt1Q9kFVBUsb8jBl959BY3KWTg2rgjpN9nB5uIWTEFXfAWo0qIYGGVhXLyEbvu72Lq_W0wlccoKlxWrP349qN9OG2RTaGrgNjxTo1LqnSVc9S6D1zD7mop5KQ_9FZEjA5jABAquwFMAuO4ongyujnpoAfyAlB6UZ_JDmDFCkuN598q_LAu",
            "response": {
                "authenticatorData":"o3mm9u6vuaVeN4wRgDTidR5oL6ufLTCrE9ISVYbOGUcFAAAAXA",
                "clientDataJSON":"{\"type\":\"webauthn.get\",\"challenge\":\"Z16OhkVPywn9276J6wtGfg\",\"origin\":\"https://example.com\",\"crossOrigin\":true}",
                "signature":"9frQigpe0p8NGwWc9Ikve9RlOZbcmz6S-JVDaPde-dxS-sPRFLGDA3ekh0j294MqaejRudzTw5uggh1IU2lJCQ",
                "userHandle": None
            }
        }

        user = {
            "id": 1,
            "name": "user@example.com",
            "user_handle": "MTIzYWJkc2FjZGR3",
            "cred_id": "owBYojOVzZU-pjscj82gQAHvhUDTMgzQtTcQjyBpzHT-bqLwtLF2OOJDoskE18lOn2-1-SV-b7nCvn5s5Uq2KhBt1Q9kFVBUsb8jBl959BY3KWTg2rgjpN9nB5uIWTEFXfAWo0qIYGGVhXLyEbvu72Lq_W0wlccoKlxWrP349qN9OG2RTaGrgNjxTo1LqnSVc9S6D1zD7mop5KQ_9FZEjA5jABAquwFMAuO4ongyujnpoAfyAlB6UZ_JDmDFCkuN598q_LAu",
            "pub_key": "pAEBAycgBiFYIE1iZTi4KhfSBhYRWMiP0_wD2cdkJ5sHoQG1zBgxfMaJ",
            "sign_count": 85,
            "backup_eligible": False,
            "backup_state": False,
            "uv_initialized": True,
        }
        options = {
            'challenge': "Z16OhkVPywn9276J6wtGfg",
            'rpId': 'example.com',
            "allowCredentials": [
                {
                    "type": "public-key",
                    "id": ("owBYojOVzZU-pjscj82gQAHvhUDTMgzQtTcQjyBpzHT-bqLwtLF2OOJDoskE18lO"
                          "n2-1-SV-b7nCvn5s5Uq2KhBt1Q9kFVBUsb8jBl959BY3KWTg2rgjpN9nB5uIWTEF"
                          "XfAWo0qIYGGVhXLyEbvu72Lq_W0wlccoKlxWrP349qN9OG2RTaGrgNjxTo1LqnSV"
                          "c9S6D1zD7mop5KQ_9FZEjA5jABAquwFMAuO4ongyujnpoAfyAlB6UZ_JDmDFCkuN"
                          "598q_LAu")
                },
            ],
        }
        expected_origin = 'https://example.com'

        auth_data = webauthn.verify_get_response(response, options, "https://example.com", user, None)
        self.assertTrue(auth_data.has_flag('UV'))
        self.assertFalse(auth_data.has_flag('BS'))
        self.assertTrue(auth_data.sign_count > user['sign_count'])

