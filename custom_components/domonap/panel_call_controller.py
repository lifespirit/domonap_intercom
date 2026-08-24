from __future__ import annotations

import asyncio
import logging
from typing import Any

from homeassistant.core import HomeAssistant

from .const import EVENT_CALL_ENDED
from .external_sip import AsteriskSipAccount, ExternalSipConfig, parse_host_port
from .panel_sip import RubetekPanelSipCall

_LOGGER = logging.getLogger(__name__)


class PanelCallController:
    """Coordinate Domonap Panel SIP, relay actions and an optional Asterisk leg.

    The controller is intentionally outside IntercomAPI. Authentication and
    Domonap REST stay unchanged, while call routing policy can evolve without
    leaking Asterisk-specific behavior into phone/SMS mode.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        api: Any,
        *,
        enabled: bool = False,
        user: str = "",
        password: str = "",
        domain: str = "",
        transport: str = "udp",
        call_number: str = "",
    ) -> None:
        self._hass = hass
        self._api = api
        self._enabled = bool(enabled)
        self._user = user.strip()
        self._password = password
        self._domain = domain.strip()
        self._transport = transport.lower().strip() or "udp"
        self._call_number = call_number.strip()
        self._account: AsteriskSipAccount | None = None
        self._active_call_id: str | None = None
        self._active_door_id: str | None = None
        self._forward_task: asyncio.Task | None = None
        self._ending_from_external = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def external_call_active(self) -> bool:
        return bool(self._account and self._account.has_active_call)

    @property
    def external_call_established(self) -> bool:
        call = self._account.active_call if self._account else None
        return bool(call and call.established)

    async def start(self) -> None:
        if not self._enabled:
            return
        if not all((self._user, self._domain, self._call_number)):
            raise ValueError("External SIP requires user, domain and call number")
        host, port = parse_host_port(self._domain)
        config = ExternalSipConfig(
            enabled=True,
            user=self._user,
            password=self._password,
            host=host,
            port=port,
            transport=self._transport,
            call_number=self._call_number,
        )
        self._account = AsteriskSipAccount(
            config,
            on_dtmf=self._on_external_dtmf,
            on_hangup=self._on_external_hangup,
        )
        await self._account.start()

    async def stop(self) -> None:
        task = self._forward_task
        self._forward_task = None
        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        account = self._account
        self._account = None
        if account is not None:
            await account.close()

    def on_incoming_call(self, push_data: dict[str, Any]) -> None:
        self._active_call_id = self._string_value(
            push_data.get("CallId") or push_data.get("callId")
        )
        self._active_door_id = self._string_value(
            push_data.get("DoorId") or push_data.get("doorId")
        )
        if not self._enabled or self._account is None:
            return

        panel_call = getattr(self._api, "_active_sip_call", None)
        if not isinstance(panel_call, RubetekPanelSipCall):
            _LOGGER.warning("Cannot forward panel call: Domonap SIP leg is unavailable")
            return

        previous = self._forward_task
        if previous is not None and not previous.done():
            previous.cancel()
        self._forward_task = asyncio.create_task(
            self._forward_to_external(panel_call, self._active_call_id or ""),
            name="domonap_forward_to_external_sip",
        )

    async def on_panel_call_ended(self, call_id: str | None) -> None:
        normalized = self._string_value(call_id)
        if normalized and self._active_call_id and normalized != self._active_call_id:
            return
        call = self._account.active_call if self._account else None
        if call is not None:
            try:
                await call.hangup(local=True)
            except Exception:
                _LOGGER.debug(
                    "Failed to close external SIP after Panel call ended",
                    exc_info=True,
                )
        self._active_call_id = None
        self._active_door_id = None

    async def open_door_by_door_id(self, door_id: str) -> Any:
        """Open a door while applying the configured call policy.

        Only an established external conversation owns the Domonap call
        lifetime. While the forwarded destination is merely ringing, a regular
        HA/Telegram relay action keeps the old behavior: answer/open/end.
        """
        if self.external_call_established:
            return await self._open_panel_relay_only(door_id)
        return await self._api.open_relay_by_door_id(door_id)

    async def open_door_by_key_id(self, key_id: str) -> Any:
        if not self.external_call_established:
            answer = getattr(self._api, "_answer_active_sip_before_open", None)
            if callable(answer):
                try:
                    await answer()
                except Exception:
                    _LOGGER.debug("Panel SIP pre-answer failed", exc_info=True)
        return await self._api.open_relay_by_key_id(key_id)

    def should_end_after_relay(self) -> bool:
        """Return whether an HA relay action should also terminate the call."""
        return not self.external_call_established

    async def _forward_to_external(
        self, panel_call: RubetekPanelSipCall, call_id: str
    ) -> None:
        account = self._account
        if account is None:
            return
        try:
            await account.dial(panel_call, call_id=call_id)
            _LOGGER.info(
                "Forwarding Domonap call %s to external SIP number %s",
                call_id,
                self._call_number,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.warning("Cannot start external SIP forwarding", exc_info=True)
            await self._end_domonap_after_external_hangup()

    async def _on_external_dtmf(self, digit: str) -> None:
        if digit != "1":
            _LOGGER.debug("Ignoring external SIP DTMF digit=%s", digit)
            return
        door_id = self._active_door_id
        if not door_id:
            _LOGGER.warning("DTMF 1 received but active Domonap door is unknown")
            return
        try:
            result = await self._open_panel_relay_only(door_id)
        except Exception:
            _LOGGER.exception("Failed to open Domonap relay on external SIP DTMF 1")
            return
        if isinstance(result, dict) and result.get("ok") is True:
            _LOGGER.info(
                "Door %s opened by external SIP DTMF 1; call remains active",
                door_id,
            )
        else:
            _LOGGER.error("External SIP DTMF 1 relay opening failed: %s", result)

    async def _on_external_hangup(self) -> None:
        _LOGGER.info("External SIP call ended; terminating the Domonap call")
        await self._end_domonap_after_external_hangup()

    async def _end_domonap_after_external_hangup(self) -> None:
        if self._ending_from_external:
            return
        self._ending_from_external = True
        call_id = getattr(self._api, "active_call_id", None)
        try:
            if call_id:
                result = await self._api.end_active_call()
                if isinstance(result, dict) and result.get("ok") is True:
                    _LOGGER.info(
                        "Domonap call %s ended after external SIP hangup", call_id
                    )
                    self._hass.bus.fire(EVENT_CALL_ENDED, {"CallId": call_id})
                else:
                    _LOGGER.warning(
                        "Domonap call termination after external SIP hangup failed: %s",
                        result,
                    )
        finally:
            self._ending_from_external = False

    async def _open_panel_relay_only(self, door_id: str) -> Any:
        """Resolve DoorId -> KeyId without changing either SIP dialog."""
        keys_response = await self._api.get_paged_keys()
        if not isinstance(keys_response, dict):
            return {
                "ok": False,
                "error": "Unexpected key list response",
                "body": str(keys_response),
            }
        if "error" in keys_response:
            return keys_response

        wanted = str(door_id)
        for key in keys_response.get("results", []):
            if not isinstance(key, dict) or str(key.get("doorId", "")) != wanted:
                continue
            key_id = key.get("id")
            if not key_id:
                return {
                    "ok": False,
                    "error": "Door key has no id",
                    "door_id": wanted,
                }
            _LOGGER.debug(
                "External-call relay DoorId=%s resolved to KeyId=%s", wanted, key_id
            )
            return await self._api.open_relay_by_key_id(str(key_id))
        return {
            "ok": False,
            "error": "No panel key found for DoorId",
            "door_id": wanted,
        }

    @staticmethod
    def _string_value(value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None