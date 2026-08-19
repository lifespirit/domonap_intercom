from __future__ import annotations

import json
import logging
from secrets import token_hex
from typing import Any, Dict, Optional, Union

import aiohttp

from .api import DEFAULT_JSON_CONTENT_TYPE, IntercomAPI

_LOGGER = logging.getLogger(__name__)

AOSP_APP_VERSION_CODE = "9845"
AOSP_APP_VERSION_NAME = "9845"


def _build_aosp_device_info(instance_id: str) -> str:
    """Build a stable synthetic tablet DeviceInfoModel.

    The APK reads these fields from Android Build.* at runtime, so the APK does
    not contain one universally correct hardware model. The values below model
    a generic AOSP tablet while preserving the exact field layout and the
    analyzed prodAospRelease application version.
    """
    info = {
        "OsVersion": "5.10.0-android12",
        "Release": "12",
        "Device": "aosp_tablet",
        "Model": "AOSP Tablet",
        "Product": "aosp_tablet",
        "Brand": "AOSP",
        "ID": "SP1A.210812.016",
        "Manufacturer": "AOSP",
        "InstanceId": instance_id,
        "versionCode": AOSP_APP_VERSION_CODE,
        "versionName": AOSP_APP_VERSION_NAME,
    }
    return json.dumps(info, separators=(",", ":"), ensure_ascii=False)


class AospIntercomAPI(IntercomAPI):
    """Domonap API profile matching the prodAospRelease tablet application.

    The AOSP tablet flavor has no GMS/HMS push core. Its persistent identity is
    instanceId, while incoming events are delivered over a long-lived SignalR
    WebSocket. A push-provider deviceToken is therefore neither generated for
    authentication nor registered with UpdateDeviceToken.
    """

    def __init__(
        self,
        base_url: str = "https://api.domonap.ru",
        instance_id: Optional[str] = None,
    ) -> None:
        # Settings.Secure.ANDROID_ID is normally a stable 64-bit hex value.
        instance_id = instance_id or token_hex(8)

        super().__init__(
            base_url=base_url,
            instance_id=instance_id,
            device_platform="panel",
            dom_app="panel",
        )
        self.device_token = None
        self.headers["device-info"] = _build_aosp_device_info(self.instance_id)

        if self._session and not self._session.closed:
            self._session._default_headers.clear()
            self._session._default_headers.update(self.headers)

    async def _post(
        self,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        need_auth: bool = False,
        ensure_alive: bool = True,
        send_auth: Optional[bool] = None,
        expect: str = "json",
        retry_on_401: bool = True,
        header_set: Optional[Dict[str, str]] = None,
    ) -> Union[Dict[str, Any], str]:
        """AOSP REST request with normal TLS verification and APK-style refresh."""
        if send_auth is None:
            send_auth = need_auth
        if need_auth:
            if self._refresh_token_invalid:
                return self._refresh_unavailable_error("Session expired")
            if not self.access_token:
                return {"error": "No access token available", "ok": False, "body": ""}
            if ensure_alive:
                await self._ensure_alive()
            if not self.access_token:
                return self._refresh_unavailable_error("Session expired")

        session = await self._ensure_session()
        url = f"{self.base_url}{path}"
        first_try_access_token = self.access_token

        async def _do() -> aiohttp.ClientResponse:
            headers = dict(self.headers if header_set is None else header_set)
            if payload is not None:
                headers["Content-Type"] = DEFAULT_JSON_CONTENT_TYPE
            if send_auth and self.access_token:
                headers["Authorization"] = f"Bearer {self.access_token}"
            if payload is None:
                return await session.post(url, headers=headers)
            return await session.post(url, json=payload, headers=headers)

        resp = await _do()
        if resp.status == 401 and retry_on_401 and self.refresh_token:
            _LOGGER.warning("401 Unauthorized, refreshing token and retrying %s", path)
            if await self._refresh_for_retry(first_try_access_token):
                resp.release()
                resp = await _do()

        if 200 <= resp.status < 300:
            if expect == "json":
                return await resp.json()
            return await resp.text()

        try:
            body_text = await resp.text()
        except Exception:
            body_text = ""
        err = {
            "error": f"HTTP {resp.status}",
            "status": resp.status,
            "body": body_text[:2000],
        }
        # Never log payload here: auth payloads may contain SMS codes or refresh tokens.
        _LOGGER.error("AOSP REST failed: POST %s -> %s", path, err)
        return err

    async def authorize(
        self, country_code: str, phone_number: str
    ) -> Union[bool, Dict[str, Any]]:
        _LOGGER.info("AOSP authorization: requesting SMS code")
        result = await super().authorize(country_code, phone_number)
        if result is True:
            _LOGGER.info("AOSP authorization: SMS code requested")
        return result

    async def confirm_authorization(
        self,
        country_code: str,
        phone_number: str,
        confirm_code: str,
        device_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Confirm SMS authorization exactly as the no-push AOSP flavor does.

        The Kotlin model carries deviceToken=null. The APK's Gson configuration
        has serializeNulls=false, so that null property is omitted from JSON.
        """
        _LOGGER.info("AOSP authorization: confirming SMS code without push token")
        payload = {
            "phoneNumber": self._phone_number(country_code, phone_number),
            "confirmCode": confirm_code,
        }
        res = await self._post(
            "/sso-api/Authorization/ConfirmAuthorization",
            payload,
            expect="json",
            need_auth=False,
        )
        if isinstance(res, dict) and "error" in res and "status" in res:
            return res

        try:
            complete_token = res["completeToken"]
            self.set_tokens(
                complete_token["accessToken"],
                complete_token["refreshToken"],
                complete_token["refreshExpirationDate"],
            )
            if self.token_update_callback:
                self.token_update_callback(
                    complete_token["accessToken"],
                    complete_token["refreshToken"],
                    complete_token["refreshExpirationDate"],
                )
            _LOGGER.info("AOSP authorization: session established")
        except Exception as err:
            _LOGGER.exception("Unexpected AOSP confirm_authorization response: %s", err)
        return res

    async def logout(self) -> Dict[str, Any]:
        """Invalidate the current server session using the refresh token.

        This is intentionally not called from Home Assistant unload/restart.
        It is for an explicit future "sign out/remove account" operation.
        """
        if not self.refresh_token:
            return {"ok": True, "skipped": True, "reason": "no_refresh_token"}

        refresh_token = self.refresh_token
        result = await self._post(
            "/sso-api/Authorization/Logout",
            {"refreshToken": refresh_token},
            need_auth=False,
            expect="text",
            retry_on_401=False,
        )
        if isinstance(result, dict) and "error" in result:
            return result

        self.set_tokens(None, None, None)
        if self.token_update_callback:
            self.token_update_callback(None, None, None)
        return {"ok": True, "body": result}
