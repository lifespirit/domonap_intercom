import base64
import importlib.util
import json
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "custom_components" / "domonap"

custom_components = types.ModuleType("custom_components")
custom_components.__path__ = [str(ROOT / "custom_components")]
sys.modules.setdefault("custom_components", custom_components)

domonap_pkg = types.ModuleType("custom_components.domonap")
domonap_pkg.__path__ = [str(PKG)]
sys.modules.setdefault("custom_components.domonap", domonap_pkg)


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, PKG / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


load_module("custom_components.domonap.api", "api.py")
panel_api = load_module("custom_components.domonap.panel_api", "panel_api.py")
RubetekPanelIntercomAPI = panel_api.RubetekPanelIntercomAPI

ROLE_CLAIM = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"


def fake_jwt(role="Panel", user_id="panel-user"):
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {ROLE_CLAIM: role, NAME_CLAIM: user_id}

    def enc(value):
        raw = json.dumps(value, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    return f"{enc(header)}.{enc(payload)}.signature"


class RubetekPanelApiTests(unittest.IsolatedAsyncioTestCase):
    def test_panel_identity_matches_captured_aosp_contract(self):
        api = RubetekPanelIntercomAPI(instance_id="0123456789abcdef")
        self.assertEqual(api.headers["dom-app"], "panel;")
        self.assertEqual(api.headers["dom-platform"], "panel;")
        self.assertEqual(api.headers["instanceId"], "0123456789abcdef")
        self.assertIsNone(api.device_token)

        info = json.loads(api.headers["device-info"])
        self.assertEqual(info["InstanceId"], "0123456789abcdef")
        self.assertEqual(info["versionCode"], "9845")
        self.assertEqual(info["versionName"], "9845")
        self.assertIn("Brand", info)
        self.assertNotIn("brand", info)

        signalr = api.signalr_headers()
        self.assertIn("User-Agent", signalr)
        self.assertNotIn("dom-app", signalr)
        self.assertNotIn("dom-platform", signalr)
        self.assertNotIn("instanceId", signalr)
        self.assertNotIn("device-info", signalr)

    async def test_activation_code_uses_panel_endpoint_and_stores_session(self):
        api = RubetekPanelIntercomAPI(instance_id="0123456789abcdef")
        calls = []

        async def fake_post(path, payload=None, **kwargs):
            calls.append((path, payload, kwargs))
            return {
                "panel": {"userId": "panel-user", "name": "Test Panel"},
                "completeToken": {
                    "accessToken": fake_jwt(),
                    "refreshToken": "refresh-token",
                    "expirationDate": "2098-01-01T00:00:00Z",
                    "refreshExpirationDate": "2099-01-01T00:00:00Z",
                },
            }

        api._post = fake_post
        result = await api.confirm_panel_authorization("12345678")

        self.assertIn("completeToken", result)
        self.assertEqual(calls[0][0], "/sso-api/Authorization/ConfirmAuthorizationCode")
        self.assertEqual(calls[0][1], {"confirmCode": "12345678"})
        self.assertFalse(calls[0][2]["need_auth"])
        self.assertEqual(api.panel["userId"], "panel-user")
        self.assertEqual(api.refresh_token, "refresh-token")

    def test_existing_session_import_restores_exact_identity(self):
        session = {
            "instanceId": "0123456789abcdef",
            "deviceInfo": {
                "Brand": "Android",
                "Device": "emulator64_x86_64",
                "ID": "SE1B.240122.005",
                "InstanceId": "0123456789abcdef",
                "Manufacturer": "unknown",
                "Model": "Android SDK built for x86_64",
                "OsVersion": "kernel",
                "Product": "sdk_phone64_x86_64",
                "Release": "12",
                "versionCode": "9845",
                "versionName": "9845",
            },
            "panel": {"userId": "panel-user", "name": "Test Panel"},
            "completeToken": {
                "accessToken": fake_jwt(),
                "refreshToken": "refresh-token",
                "refreshExpirationDate": "2099-01-01T00:00:00Z",
            },
        }

        api = RubetekPanelIntercomAPI.from_session_payload(json.dumps(session))
        self.assertEqual(api.instance_id, "0123456789abcdef")
        self.assertEqual(json.loads(api.device_info)["OsVersion"], "kernel")
        self.assertEqual(api.panel["name"], "Test Panel")
        self.assertEqual(api.access_token, session["completeToken"]["accessToken"])

    def test_existing_session_rejects_non_panel_jwt(self):
        session = {
            "instanceId": "0123456789abcdef",
            "completeToken": {
                "accessToken": fake_jwt(role="User"),
                "refreshToken": "refresh-token",
                "refreshExpirationDate": "2099-01-01T00:00:00Z",
            },
        }
        with self.assertRaises(ValueError):
            RubetekPanelIntercomAPI.from_session_payload(session)


if __name__ == "__main__":
    unittest.main()
