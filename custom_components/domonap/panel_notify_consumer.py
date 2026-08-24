from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Iterable, Optional, Union

import aiohttp
from homeassistant.core import HomeAssistant

from .api import IntercomAPI
from .const import (
    EVENT_INCOMING_CALL,
    PANEL_WS_HANDSHAKE_TIMEOUT,
    PANEL_WS_KEEPALIVE_INTERVAL,
    PANEL_WS_SERVER_TIMEOUT,
    PANEL_WS_URL,
    WS_HANDSHAKE_MESSAGE,
    WS_MESSAGE_END,
    WS_PING_MESSAGE,
)

_LOGGER = logging.getLogger(__name__)


class RubetekPanelNotifyConsumer:
    """SignalR transport used by the Rubetek/AOSP panel profile.

    Panel behavior is deliberately separate from the legacy phone/SMS consumer:
    no device-token registration, no /negotiate and no connectionToken query.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        api: IntercomAPI,
        media_proxy=None,
        media_proxy_secret: Optional[str] = None,
    ) -> None:
        self._hass = hass
        self._api = api
        self._media_proxy = media_proxy
        self._media_proxy_secret = media_proxy_secret
        self._callbacks: set[Callable[[], Union[None, Any]]] = set()
        self._connected = False
        self._stop_event = asyncio.Event()
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None

    @property
    def connected(self) -> bool:
        return self._connected

    def register_callback(self, callback: Callable[[], Any]) -> None:
        self._callbacks.add(callback)

    def remove_callback(self, callback: Callable[[], Any]) -> None:
        self._callbacks.discard(callback)

    async def start(self) -> None:
        self._stop_event.clear()
        delay = 2
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=delay)
                break
            except asyncio.TimeoutError:
                pass

            connected = False
            try:
                connected = await self._connect_and_run()
            except asyncio.CancelledError:
                raise
            except Exception as err:
                _LOGGER.warning(
                    "Panel SignalR error: %s: %s", type(err).__name__, err
                )

            if self._stop_event.is_set():
                break
            delay = 0 if connected else min(max(delay, 2) * 2, 60)

    async def stop(self) -> None:
        self._stop_event.set()
        if self._ws is not None and not self._ws.closed:
            await self._ws.close()

    async def _connect_and_run(self) -> bool:
        headers = dict(self._api.signalr_headers())
        # The panel WebSocket observed in the APK uses Bearer authentication;
        # REST-only instanceId/device-info are not required on the upgrade.
        headers.pop("dom-app", None)
        headers.pop("dom-platform", None)
        headers["Authorization"] = f"Bearer {self._api.access_token or ''}"

        timeout = aiohttp.ClientTimeout(total=None)
        handshake_completed = False
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(
                    PANEL_WS_URL,
                    headers=headers,
                    receive_timeout=PANEL_WS_SERVER_TIMEOUT,
                    autoping=False,
                ) as ws:
                    self._ws = ws
                    _LOGGER.info("Panel SignalR connected to %s", PANEL_WS_URL)
                    await ws.send_bytes(WS_HANDSHAKE_MESSAGE.encode("utf-8"))
                    await self._wait_for_handshake(ws)
                    handshake_completed = True
                    self._connected = True
                    _LOGGER.info("Panel SignalR handshake completed")

                    ping_task = asyncio.create_task(self._keepalive(ws))
                    try:
                        async for msg in ws:
                            if self._stop_event.is_set():
                                break
                            await self._handle_ws_message(msg, ws)
                    finally:
                        ping_task.cancel()
                        try:
                            await ping_task
                        except asyncio.CancelledError:
                            pass
        finally:
            self._connected = False
            self._ws = None
            if handshake_completed:
                _LOGGER.info("Panel SignalR disconnected")
        return handshake_completed

    async def _wait_for_handshake(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        msg = await asyncio.wait_for(ws.receive(), timeout=PANEL_WS_HANDSHAKE_TIMEOUT)
        payload = self._payload(msg)
        if payload is None:
            raise RuntimeError("Panel SignalR handshake returned no payload")
        records = [r for r in payload.split(WS_MESSAGE_END) if r]
        if "{}" not in records:
            raise RuntimeError(f"Panel SignalR handshake failed: {payload[:300]}")

    async def _keepalive(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        while not ws.closed and not self._stop_event.is_set():
            await asyncio.sleep(PANEL_WS_KEEPALIVE_INTERVAL)
            if ws.closed or self._stop_event.is_set():
                break
            await ws.send_bytes(WS_PING_MESSAGE.encode("utf-8"))

    async def _handle_ws_message(
        self, msg: aiohttp.WSMessage, ws: aiohttp.ClientWebSocketResponse
    ) -> None:
        if msg.type == aiohttp.WSMsgType.PING:
            await ws.pong(msg.data)
            return
        if msg.type in (aiohttp.WSMsgType.PONG, aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
            return
        if msg.type == aiohttp.WSMsgType.ERROR:
            raise RuntimeError(f"Panel WebSocket error: {ws.exception()}")

        payload = self._payload(msg)
        if payload is None:
            return
        for record in payload.split(WS_MESSAGE_END):
            if record:
                await self._handle_record(record)
        if self._callbacks:
            await self._publish_updates()

    @staticmethod
    def _payload(msg: aiohttp.WSMessage) -> Optional[str]:
        if msg.type == aiohttp.WSMsgType.TEXT:
            return msg.data
        if msg.type == aiohttp.WSMsgType.BINARY:
            try:
                return msg.data.decode("utf-8")
            except UnicodeDecodeError:
                return None
        return None

    async def _handle_record(self, payload: str) -> None:
        if payload == "{}":
            return
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            _LOGGER.debug("Non-JSON panel SignalR frame: %s", payload[:300])
            return
        if data.get("type") == 1:
            await self._handle_invocation(data)
        elif data.get("type") == 6:
            _LOGGER.debug("Panel SignalR server ping")
        elif data.get("type") == 7:
            raise RuntimeError(f"Panel SignalR closed: {data.get('error') or data}")

    async def _handle_invocation(self, data: dict[str, Any]) -> None:
        target = data.get("target")
        args: Iterable[Any] = data.get("arguments") or []
        args = list(args)
        _LOGGER.debug("Panel SignalR invocation: target=%s args=%d", target, len(args))

        if target == "ReceivePush":
            push_data = args[2] if len(args) >= 3 else None
            if not isinstance(push_data, dict):
                return
            push_data = dict(push_data)
            push_data.setdefault("Title", args[0] if len(args) >= 1 else "")
            push_data.setdefault("Body", args[1] if len(args) >= 2 else "")
            event_message = push_data.get("EventMessage")
            if event_message == "DomofonCalling":
                await self._prepare_incoming_call_event(push_data)
                self._hass.bus.fire(EVENT_INCOMING_CALL, push_data)
                _LOGGER.info(
                    "Panel incoming call: DoorId=%s CallId=%s",
                    push_data.get("DoorId"),
                    push_data.get("CallId"),
                )
            else:
                _LOGGER.debug(
                    "Panel ReceivePush EventMessage=%s payload=%s",
                    event_message,
                    str(push_data)[:500],
                )
            return

        if target in ("ReceiveOnline", "ReceiveOffline"):
            user = args[0] if args else None
            status = "online" if target == "ReceiveOnline" else "offline"
            self._hass.bus.fire(
                "domonap_user_status_changed",
                {"user": user, "status": status},
            )

    async def _prepare_incoming_call_event(self, push_data: dict[str, Any]) -> None:
        # Keep the same normalized payload contract used by the existing
        # Home Assistant automations and binary_sensor/image entities.
        preview = push_data.get("VideoPreview") or push_data.get("WebrtcVideoUrl")
        if preview:
            push_data.setdefault("PhotoUrl", preview)

        if self._media_proxy and self._media_proxy_secret:
            try:
                await self._media_proxy.prepare_incoming_call(
                    push_data, self._api, self._media_proxy_secret
                )
            except Exception:
                _LOGGER.debug("Panel media proxy preparation failed", exc_info=True)

    async def _publish_updates(self) -> None:
        for callback in tuple(self._callbacks):
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                _LOGGER.exception("Panel notify callback failed")
