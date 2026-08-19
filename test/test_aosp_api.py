import re
import unittest

from custom_components.domonap.aosp_api import AospIntercomAPI


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

    async def test_sms_confirm_sends_null_device_token_and_stores_auth(self):
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
        self.assertIsNone(payload["deviceToken"])
        self.assertEqual(api.access_token, "access")
        self.assertEqual(api.refresh_token, "refresh")


if __name__ == "__main__":
    unittest.main()
