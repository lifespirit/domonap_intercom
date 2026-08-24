from __future__ import annotations

import base64
import json
import logging
import re
from secrets import token_hex
from typing import Any, Dict, Optional

from .api import IntercomAPI, SIGNALR_USER_AGENT

_LOGGER = logging.getLogger(__name__)

PANEL_APP_VERSION_CODE = "9845"
PANEL_APP_VERSION_NAME = "9845"
_PANEL_INSTANCE_ID_RE = re.compile(r"^[0-9a-fA-F]{16}$")
_PANEL_ROLE_CLAIM = (
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
)
_PANEL_NAME_CLAIM = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
)


def _build_panel_device_info(instance_id: str) -> str:
    """Build the prodAospRelease device-info observed during panel activation.

    The values intentionally describe the AOSP emulator profile used to activate
    the captured Panel session. The important contract is the PascalCase JSON
    shape, stable 16-hex InstanceId and APK version 9845.
    """
    info = {
        "Brand": "Android",
        "Device": "emulator64_x86_64",
        "ID": "SE1B.240122.005",
        "InstanceId": instance_id,
        "Manufacturer": "unknown",
        "Model": "Android SDK built for x86_64",
        "OsVersion": "5.10.101-android12-9-00027-g1292f517889e-ab8602202",
        "Product": "sdk_phone64_x86_64",
        "Release": "12",
        "versionCode": PANEL_APP_VERSION_CODE,
        "versionName": PANEL_APP_VERSION_NAME,
    }
    return json.dumps(info, separators=(",", ":"), ensure_ascii=False)


def _normalize_panel_device_info(value: Any, instance_id: str) -> str:
    if value is None:
        return _build_panel_device_info(instance_id)
    if isinstance(value, str):
        parsed = json.loads(value)
    elif isinstance(value, dict):
        parsed = dict(value)
    else:
        raise ValueError("panel deviceInfo must be a JSON object")
    if not isinstance(parsed, dict):
        raise ValueError("panel deviceInfo must be a JSON object")
    parsed["InstanceId"] = instance_id
    return json.dumps(parsed, separators=(",", ":"), ensure_ascii=False)


def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    try:
        encoded = token.split(".", 2)[1]
        encoded += "=" * (-len(encoded) % 4)
        raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except Exception as err:
        raise ValueError("accessToken is not a readable JWT") from err
    if not isinstance(payload, dict):
        raise ValueError("accessToken JWT payload is invalid")
    return payload


class RubetekPanelIntercomAPI(IntercomAPI):
    """Rubetek panel authorization/runtime profile.

    Panel-only identity is isolated here. The legacy phone/SMS IntercomAPI keeps
    its existing mobile device-token lifecycle and SignalR implementation.
    Shared REST endpoints and refresh-token handling remain in IntercomAPI.
    """

    def __init__(
        self,
        base_url: str = "https://api.domonap.ru",
        instance_id: Optional[str] = None,
        device_info: Optional[Any] = None,
    ) -> None:
        instance_id = instance_id or token_hex(8)
        if not _PANEL_INSTANCE_ID_RE.fullmatch(instance_id):
            raise ValueError("Rubetek panel instanceId must contain 16 hex digits")

        super().__init__(
            base_url=base_url,
            instance_id=instance_id.lower(),
            device_platform="panel",
            dom_app="panel",
        )

        # The prodAospRelease panel flow does not register an FCM/HMS token.
        self.device_token = None
        self.device_info = _normalize_panel_device_info(device_info, self.instance_id)
        self.headers["device-info"] = self.device_info
        self.panel: Dict[str, Any] = {}

    def signalr_headers(self) -> Dict[str, str]:
        """Headers supplied to the direct Microsoft SignalR WebSocket.

        dom-app/dom-platform, instanceId and device-info are REST headers. The
        SignalR access-token provider adds Authorization separately.
        """
        return {"User-Agent": SIGNALR_USER_AGENT}

    async def confirm_panel_authorization(
        self, confirm_code: str
    ) -> Dict[str, Any]:
        """Exchange the 8-digit provisioning code for a Panel session."""
        result = await self._post(
            "/sso-api/Authorization/ConfirmAuthorizationCode",
            {"confirmCode": confirm_code},
            need_auth=False,
            expect="json",
        )
        if isinstance(result, dict) and "error" in result and "status" in result:
            return result

        try:
            complete_token = result["completeToken"]
            self.panel = dict(result.get("panel") or {})
            self._install_panel_tokens(complete_token)
        except Exception as err:
            _LOGGER.exception("Unexpected panel authorization response: %s", err)
        return result

    def _install_panel_tokens(self, complete_token: Dict[str, Any]) -> None:
        access_token = complete_token["accessToken"]
        refresh_token = complete_token["refreshToken"]
        refresh_expiration = complete_token["refreshExpirationDate"]
        claims = _decode_jwt_payload(access_token)
        if claims.get(_PANEL_ROLE_CLAIM) != "Panel":
            raise ValueError("accessToken does not contain the Panel role")
        if self._parse_dt(refresh_expiration) is None:
            raise ValueError("refreshExpirationDate is invalid")

        self.set_tokens(access_token, refresh_token, refresh_expiration)
        if not self.panel.get("userId") and claims.get(_PANEL_NAME_CLAIM):
            self.panel["userId"] = claims[_PANEL_NAME_CLAIM]
        if self.token_update_callback:
            self.token_update_callback(
                access_token,
                refresh_token,
                refresh_expiration,
            )

    @classmethod
    def from_session_payload(
        cls,
        payload: str | Dict[str, Any],
        *,
        base_url: str = "https://api.domonap.ru",
    ) -> "RubetekPanelIntercomAPI":
        """Restore an already activated Panel session without consuming a code.

        Accepted JSON mirrors the captured activation exchange and adds the two
        request identity values needed to recreate the same client:

        {
          "instanceId": "0123456789abcdef",
          "deviceInfo": {...},
          "panel": {...},
          "completeToken": {...}
        }
        """
        if isinstance(payload, str):
            try:
                data = json.loads(payload)
            except json.JSONDecodeError as err:
                raise ValueError("panel session is not valid JSON") from err
        elif isinstance(payload, dict):
            data = dict(payload)
        else:
            raise ValueError("panel session must be a JSON object")

        instance_id = data.get("instanceId") or data.get("instance_id")
        if not isinstance(instance_id, str) or not _PANEL_INSTANCE_ID_RE.fullmatch(
            instance_id
        ):
            raise ValueError("panel session has no valid 16-hex instanceId")

        device_info = (
            data.get("deviceInfo")
            or data.get("device-info")
            or data.get("panel_device_info")
        )
        complete_token = data.get("completeToken") or data.get("complete_token")
        if not isinstance(complete_token, dict):
            raise ValueError("panel session has no completeToken object")

        api = cls(
            base_url=base_url,
            instance_id=instance_id,
            device_info=device_info,
        )
        panel = data.get("panel")
        if isinstance(panel, dict):
            api.panel = dict(panel)
        api._install_panel_tokens(complete_token)
        if not api.has_valid_refresh_token():
            raise ValueError("panel refresh token is missing or expired")
        return api

    def session_export(self) -> Dict[str, Any]:
        """Return the persistent non-code state needed to recreate this panel."""
        return {
            "instanceId": self.instance_id,
            "deviceInfo": json.loads(self.device_info),
            "panel": dict(self.panel),
            "completeToken": {
                "accessToken": self.access_token,
                "refreshToken": self.refresh_token,
                "refreshExpirationDate": self.refresh_expiration_date,
            },
        }

    async def logout(self) -> Dict[str, Any]:
        """Explicitly invalidate a panel session.

        Runtime unload/restart must not call this; refresh token persistence is
        identical to the regular API session lifecycle.
        """
        if not self.refresh_token:
            return {"ok": True, "skipped": True}
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
