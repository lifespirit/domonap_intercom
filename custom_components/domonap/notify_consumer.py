import asyncio
import json
import logging
from typing import Any, Callable, Iterable, Optional, Union

import aiohttp
from homeassistant.core import HomeAssistant

from .api import IntercomAPI
from .const import (
    EVENT_CALL_ANSWERED,
    EVENT_CALL_ENDED,
    EVENT_INCOMING_CALL,
    WS_HANDSHAKE_MESSAGE,
    WS_HANDSHAKE_TIMEOUT,
    WS_KEEPALIVE_INTERVAL,
    WS_MESSAGE_END,
    WS_PING_MESSAGE,
    WS_RECONNECT_INITIAL,
    WS_RECONNECT_MAX,
    WS_SERVER_TIMEOUT,
    WS_URL,
)

_LOGGER = logging.getLogger(__name__)


class IntercomNotifyConsumer:
    """Persistent SignalR consumer matching the prodAospRelease tablet flavor."""

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

        # Rebuilt before every connection so a refreshed access token is always
        # used by the next HubConnection.start(), like withAccessTokenProvider().
        self._headers: dict[str, str] = {}

    async def start(self) -> None:
        """Keep one direct SignalR WebSocket alive until the integration stops.

        APK behavior:
          * service start: wait 2 seconds before the first attempt;
          * unexpected disconnect: retry immediately once;
          * subsequent failures: 2, 4, 8, 16, 32, 60, 60... seconds.
        """
        self._stop_event.clear()
        delay = WS_RECONNECT_INITIAL
        first_start = True

        while not self._stop_event.is_set():
            if delay > 0:
                _LOGGER.debug("SignalR connect scheduled in %d seconds", delay)
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
            except aiohttp.WSServerHandshakeError as err:
                if err.status == 401:
                    _LOGGER.error("SignalR WebSocket 401 Unauthorized")
                else:
                    _LOGGER.warning(
                        "SignalR WebSocket handshake failed: status=%s %s",
                        err.status,
                        err,
                    )
            except Exception as err:
                _LOGGER.warning(
                    "SignalR loop error: %s: %s", type(err).__name__, err
                )

            if self._stop_event.is_set():
                break

            if connected:
                # A successfully established connection closed unexpectedly:
                # the tablet immediately tries once more.
                delay = 0
            else:
                # Failed start/reconnect: exponential backoff as in the APK.
                if first_start:
                    # The initial 2 s delay was already consumed.
                    delay = min(WS_RECONNECT_INITIAL * 2, WS_RECONNECT_MAX)
                elif delay <= 0:
                    delay = WS_RECONNECT_INITIAL
                else:
                    delay = min(delay * 2, WS_RECONNECT_MAX)

            first_start = False

    async def stop(self) -> None:
        self._stop_event.set()
        if self._ws is not None and not self._ws.closed:
            try:
                await self._ws.close(code=1000, message=b"HubConnection stopped.")
            except Exception:
                _LOGGER.debug("Error stopping SignalR WebSocket", exc_info=True)

    def register_callback(self, callback: Callable[[], Any]) -> None:
        self._callbacks.add(callback)

    def remove_callback(self, callback: Callable[[], Any]) -> None:
        self._callbacks.discard(callback)

    @property
    def connected(self) -> bool:
        return self._connected

    async def _connect_and_run(self) -> bool:
        """Open WebSocket directly; prodAospRelease skips SignalR negotiate."""
        self._headers = dict(self._api.signalr_headers())
        if self._api.access_token:
            self._headers["Authorization"] = f"Bearer {self._api.access_token}"

        # Microsoft SignalR Java with shouldSkipNegotiate(true) converts the
        # https hub URL directly to wss and does not append ?id=...
        ws_url = WS_URL
        if self._api.base_url != "https://api.domonap.ru":
            base = self._api.base_url.rstrip("/")
            if base.startswith("https://"):
                base = "wss://" + base[len("https://") :]
            elif base.startswith("http://"):
                base = "ws://" + base[len("http://") :]
            ws_url = base + "/notificationHub"

        timeout = aiohttp.ClientTimeout(total=None)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.ws_connect(
                ws_url,
                headers=self._headers,
                receive_timeout=WS_SERVER_TIMEOUT,
                autoping=False,
            ) as ws:
                self._ws = ws
                _LOGGER.info("SignalR WebSocket connected to %s", ws_url)

                # SignalR Java sends HubProtocol messages through ByteBuffer,
                # therefore OkHttp emits binary WebSocket frames.
                await ws.send_bytes(WS_HANDSHAKE_MESSAGE.encode("utf-8"))

                await self._wait_for_handshake(ws)
                self._connected = True
                _LOGGER.info("SignalR handshake completed")

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
                    self._connected = False
                    self._ws = None
                    _LOGGER.info("SignalR WebSocket disconnected")

        return True

    async def _wait_for_handshake(
        self, ws: aiohttp.ClientWebSocketResponse
    ) -> None:
        """Wait for the SignalR handshake response, capped at APK's 100 s."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + WS_HANDSHAKE_TIMEOUT

        while not self._stop_event.is_set():
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError("SignalR handshake response timeout")

            msg = await asyncio.wait_for(ws.receive(), timeout=remaining)
            if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
                raise RuntimeError("WebSocket closed before SignalR handshake")
            if msg.type == aiohttp.WSMsgType.ERROR:
                raise RuntimeError(f"WebSocket error before handshake: {ws.exception()}")

            payload = self._payload_from_message(msg)
            if payload is None:
                continue

            if await self._handle_text(payload, ws):
                return

    async def _handle_ws_message(
        self,
        msg: aiohttp.WSMessage,
        ws: aiohttp.ClientWebSocketResponse,
    ) -> None:
        if msg.type == aiohttp.WSMsgType.PING:
            await ws.pong(msg.data)
            return
        if msg.type == aiohttp.WSMsgType.PONG:
            return
        if msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
            return
        if msg.type == aiohttp.WSMsgType.ERROR:
            raise RuntimeError(f"WebSocket error: {ws.exception()}")

        payload = self._payload_from_message(msg)
        if payload is None:
            return

        await self._handle_text(payload, ws)
        if self._callbacks:
            await self._publish_updates()

    @staticmethod
    def _payload_from_message(msg: aiohttp.WSMessage) -> Optional[str]:
        if msg.type == aiohttp.WSMsgType.TEXT:
            return msg.data
        if msg.type == aiohttp.WSMsgType.BINARY:
            try:
                return msg.data.decode("utf-8")
            except UnicodeDecodeError:
                _LOGGER.debug("Non-UTF8 SignalR binary frame (%d bytes)", len(msg.data))
        return None

    async def _keepalive(self, ws: aiohttp.ClientWebSocketResponse) -> None:
        """Send SignalR application-level ping every 3 seconds."""
        try:
            while not ws.closed and not self._stop_event.is_set():
                await asyncio.sleep(WS_KEEPALIVE_INTERVAL)
                if ws.closed or self._stop_event.is_set():
                    break
                await ws.send_bytes(WS_PING_MESSAGE.encode("utf-8"))
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.debug("SignalR keepalive stopped", exc_info=True)

    async def _handle_text(
        self, raw: str, ws: aiohttp.ClientWebSocketResponse
    ) -> bool:
        """Handle one frame; return True if it contained handshake ACK."""
        handshake_seen = False
        for record in raw.split(WS_MESSAGE_END):
            if not record:
                continue
            if await self._handle_record(record, ws):
                handshake_seen = True
        return handshake_seen

    async def _handle_record(
        self, payload: str, ws: aiohttp.ClientWebSocketResponse
    ) -> bool:
        if payload == "{}":
            _LOGGER.debug("SignalR handshake ack")
            return True

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            _LOGGER.debug("Non-JSON SignalR frame: %s", payload[:300])
            return False

        msg_type = data.get("type")
        if msg_type == 1:
            await self._handle_invocation(data, ws)
        elif msg_type == 6:
            _LOGGER.debug("SignalR server ping")
        elif msg_type == 3:
            _LOGGER.debug("SignalR completion frame: %s", data)
        elif msg_type == 7:
            raise RuntimeError(f"SignalR close frame: {data.get('error') or data}")
        else:
            _LOGGER.debug("Unknown SignalR frame type=%s data=%s", msg_type, payload[:300])
        return False

    async def _handle_invocation(
        self, data: dict, ws: aiohttp.ClientWebSocketResponse
    ) -> None:
        target = data.get("target")
        args: Iterable = data.get("arguments") or []
        args = list(args)

        if target == "ReceivePush":
            title = args[0] if len(args) >= 1 else ""
            body = args[1] if len(args) >= 2 else ""
            push_data = args[2] if len(args) >= 3 else None
            if not isinstance(push_data, dict):
                _LOGGER.debug("ReceivePush without map payload: %s", args)
                return

            # NotificationHub in the tablet app merges title/body into the map
            # before domain-specific processing.
            push_data = dict(push_data)
            push_data.setdefault("Title", title or "")
            push_data.setdefault("Body", body or "")

            event_message = push_data.get("EventMessage")
            if event_message == "DomofonCalling":
                self._prepare_incoming_call_event(push_data)
                self._hass.bus.fire(EVENT_INCOMING_CALL, push_data)
                _LOGGER.info(
                    "Incoming Domonap call: DoorId=%s CallId=%s",
                    push_data.get("DoorId"),
                    push_data.get("CallId"),
                )
            elif event_message == "DomofonCallAnswered":
                self._hass.bus.fire(EVENT_CALL_ANSWERED, push_data)
                _LOGGER.info("Domonap call answered: CallId=%s", push_data.get("CallId"))
            elif event_message == "DomofonCallEnded":
                # The tablet treats this as a domain event. It does NOT rebuild
                # SignalR after a call ends.
                self._hass.bus.fire(EVENT_CALL_ENDED, push_data)
                _LOGGER.info("Domonap call ended: CallId=%s", push_data.get("CallId"))
            else:
                _LOGGER.debug(
                    "ReceivePush EventMessage=%s payload=%s",
                    event_message,
                    str(push_data)[:500],
                )
            return

        if target in ("ReceiveOnline", "ReceiveOffline"):
            user = args[0] if args else None
            status = "online" if target == "ReceiveOnline" else "offline"
            self._hass.bus.fire(
                "domonap_user_status_changed",
                {"user": user, "status": status, "arguments": args},
            )
            _LOGGER.debug("Domonap user %s is %s", user, status)
            return

        if target == "ReceiveMessage":
            chat_data = args[0] if args else {}
            self._hass.bus.fire("domonap_receive_message", chat_data)
            _LOGGER.debug("Domonap ReceiveMessage: %s", str(chat_data)[:500])
            return

        if target == "ReceiveRead":
            self._hass.bus.fire(
                "domonap_receive_read",
                {"arguments": args},
            )
            _LOGGER.debug("Domonap ReceiveRead: %s", args)
            return

        if target == "ReceiveTyping":
            self._hass.bus.fire(
                "domonap_receive_typing",
                {"arguments": args},
            )
            _LOGGER.debug("Domonap ReceiveTyping: %s", args)
            return

        _LOGGER.debug("Unknown SignalR target %s: %s", target, data)

    def _prepare_incoming_call_event(self, push_data: dict) -> None:
        """Add only local media-proxy aliases; never block call delivery on REST."""
        video_preview = push_data.get("VideoPreview") or push_data.get("videoPreview")
        proxied_preview = self._proxied_media_url(video_preview)
        if video_preview:
            push_data.setdefault("OriginalVideoPreview", video_preview)
            push_data["VideoPreview"] = proxied_preview or video_preview
            push_data["videoPreview"] = proxied_preview or video_preview
            # Existing automations use PhotoUrl first. The APK push already has
            # VideoPreview, so use it immediately instead of delaying the event
            # while polling CallLog.
            push_data.setdefault("PhotoUrl", proxied_preview or video_preview)
            push_data.setdefault("photoUrl", proxied_preview or video_preview)

    def _proxied_media_url(
        self,
        url: Optional[str],
        *,
        fallback_url: Optional[str] = None,
        authorized: bool = True,
        fallback_authorized: bool = True,
    ) -> Optional[str]:
        if not url or not self._media_proxy or not self._media_proxy_secret:
            return None
        try:
            return self._media_proxy.register_url(
                self._media_proxy_secret,
                self._api,
                url,
                fallback_url=fallback_url,
                authorized=authorized,
                fallback_authorized=fallback_authorized,
            )
        except Exception:
            _LOGGER.debug("Failed to register Domonap media proxy URL", exc_info=True)
            return None

    async def _publish_updates(self) -> None:
        for callback in list(self._callbacks):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback()
                else:
                    callback()
            except Exception as err:
                _LOGGER.debug("Domonap callback error: %s", err)
