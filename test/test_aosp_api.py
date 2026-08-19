import importlib.util
import re
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "custom_components" / "domonap"

# Load protocol modules without importing custom_components.domonap.__init__,
# so these contract tests don't require a full Home Assistant installation.
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
aosp_api = load_module("custom_components.domonap.aosp_api", "aosp_api.py")
AospIntercomAPI = aosp_api.AospIntercomAPI


class AospApiContractTests(unittest.IsolatedAsyncioTestCase):
    def test_new_instance_id_matches_android_id_shape(self):
        api = AospIntercomAPI()
        self.assertRegex(api.instance_id, re.compile(r"^[0-9a-f]{16}$"))
        self.assertEqual(api.headers["dom-app"], "panel;")
        self.assertEqual(api.headers["dom-platform"], "panel;")
        self.assertIsNone(api.device_token)

    def test_existing_instance_id_is_reused(self):
        api = AospIntercomAPI(instance_id="0123456789abcdef")
        self.assertEqual(api.instance_id, "0123456789abcdef")

    def test_signalr_headers_do_not_include_rest_device_identity(self):
        api = AospIntercomAPI(instance_id="0123456789abcdef")
        headers = api.signalr_headers()
        self.assertEqual(headers["dom-app"], "panel;")
        self.assertEqual(headers["dom-platform"], "panel;")
        self.assertNotIn("instanceId", headers)
        self.assertNotIn("device-info", headers)
        self.assertNotIn("Authorization", headers)

    def test_device_info_uses_analyzed_aosp_release(self):
        api = AospIntercomAPI(instance_id="0123456789abcdef")
        self.assertIn('"InstanceId":"0123456789abcdef"', api.headers["device-info"])
        self.assertIn('"versionCode":"9845"', api.headers["device-info"])
        self.assertIn('"versionName":"9845"', api.headers["device-info"])

    async def test_sms_confirm_omits_push_device_token_and_stores_auth(self):
        api = AospIntercomAPI(instance_id="0123456789abcdef")
        calls = []

        async def fake_post(path, payload=None, **kwargs):
            calls.append((path, payload, kwargs))
            return {
                "completeToken": {
                    "accessToken": "access",
                    "refreshToken": "refresh",
                    "refreshExpirationDate": "2099-01-01T00:00:00Z",
                }
            }

        api._post = fake_post
        result = await api.confirm_authorization("7", "9991234567", "1234")

        self.assertIn("completeToken", result)
        self.assertEqual(len(calls), 1)
        path, payload, kwargs = calls[0]
        self.assertEqual(path, "/sso-api/Authorization/ConfirmAuthorization")
        self.assertNotIn("deviceToken", payload)
        self.assertEqual(api.access_token, "access")
        self.assertEqual(api.refresh_token, "refresh")

    async def test_logout_uses_refresh_token_and_clears_session(self):
        api = AospIntercomAPI(instance_id="0123456789abcdef")
        api.set_tokens("access", "refresh", "2099-01-01T00:00:00Z")
        calls = []

        async def fake_post(path, payload=None, **kwargs):
            calls.append((path, payload, kwargs))
            return ""

        api._post = fake_post
        result = await api.logout()
        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0], "/sso-api/Authorization/Logout")
        self.assertEqual(calls[0][1], {"refreshToken": "refresh"})
        self.assertIsNone(api.access_token)
        self.assertIsNone(api.refresh_token)


if __name__ == "__main__":
    unittest.main()
