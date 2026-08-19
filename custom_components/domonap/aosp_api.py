from __future__ import annotations

import logging
from secrets import token_hex
from typing import Any, Dict, Optional

from .api import IntercomAPI

_LOGGER = logging.getLogger(__name__)


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
        # Android's Settings.Secure.ANDROID_ID is represented as a stable 64-bit
        # hexadecimal string. Home Assistant has no Android ID, so create the
        # closest synthetic equivalent once and persist it in ConfigEntry.
        instance_id = instance_id or token_hex(8)

        # IntercomAPI owns the common REST/session implementation. It still
        # creates a legacy internal device_token during construction, but AOSP
        # mode immediately discards it and never persists or sends it.
        super().__init__(
            base_url=base_url,
            instance_id=instance_id,
            device_platform="panel",
            dom_app="panel",
        )
        self.device_token = None

    async def confirm_authorization(
        self,
        country_code: str,
        phone_number: str,
        confirm_code: str,
        device_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Confirm SMS authorization exactly as the no-push AOSP flavor does."""
        payload = {
            "phoneNumber": self._phone_number(country_code, phone_number),
            "confirmCode": confirm_code,
            "deviceToken": None,
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
        except Exception as err:
            _LOGGER.exception("Unexpected AOSP confirm_authorization response: %s", err)
        return res
