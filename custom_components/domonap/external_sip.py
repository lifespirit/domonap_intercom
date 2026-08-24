from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import socket
from dataclasses import dataclass
from secrets import token_hex
from typing import Any, Awaitable, Callable
from uuid import uuid4

from .sip import _SipMessage

_LOGGER = logging.getLogger(__name__)

_DIGEST_PARAM_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^,\s]+))')
_SIP_URI_RE = re.compile(r"<(sips?:[^>]+)>|(sips?:[^;,\s]+)", re.IGNORECASE)
_STATIC_RTPMAP = {
    0: "PCMU/8000",
    3: "GSM/8000",
    8: "PCMA/8000",
    9: "G722/8000",
    18: "G729/8000",
}


@dataclass
class AudioSdp:
    host: str
    port: int
    proto: str
    payloads: list[int]
    codecs: dict[int, str]
    fmtp: dict[int, str]
    telephone_event_pt: int | None = None

    def codec_payload(self, codec: str) -> int | None:
        wanted = codec.lower()
        for payload, name in self.codecs.items():
            if name.lower() == wanted:
                return payload
        return None


@dataclass
class ExternalSipConfig:
    enabled: bool
    user: str
    password: str
    host: str
    port: int
    transport: str
    call_number: str


class _UdpSipProtocol(asyncio.DatagramProtocol):
    def __init__(self, owner: "AsteriskSipAccount") -> None:
        self._owner = owner

    def datagram_received(self, data: bytes, addr) -> None:
        self._owner._datagram_received(data, addr)

    def error_received(self, exc: Exception) -> None:
        _LOGGER.debug("External SIP UDP error: %s", exc)


class AsteriskSipAccount:
    """Small UDP SIP UAC used as an optional Asterisk-facing call leg.

    This is deliberately isolated from Domonap signalling.  It registers one
    configured account with Asterisk and places at most one outgoing call.  The
    media itself is bridged by :class:`AsteriskBridgeCall` without transcoding.
    """

    def __init__(
        self,
        config: ExternalSipConfig,
        *,
        on_dtmf: Callable[[str], Awaitable[None]],
        on_hangup: Callable[[], Awaitable[None]],
    ) -> None:
        if config.transport.lower() != "udp":
            raise ValueError("External SIP currently supports UDP transport only")
        self.config = config
        self._on_dtmf = on_dtmf
        self._on_hangup = on_hangup
        self._transport: asyncio.DatagramTransport | None = None
        self._server_addr: tuple[str, int] | None = None
        self._local_host: str | None = None
        self._local_port: int | None = None
        self._transactions: dict[tuple[str, int, str], asyncio.Queue[_SipMessage]] = {}
        self._register_call_id = f"{uuid4()}@home-assistant"
        self._register_cseq = 0
        self._from_tag = token_hex(8)
        self._auth: dict[str, str] | None = None
        self._auth_header = "Authorization"
        self._nonce_count = 0
        self._registered = False
        self._register_lock = asyncio.Lock()
        self._active_call: AsteriskBridgeCall | None = None
        self._closed = False

    @property
    def registered(self) -> bool:
        return self._registered

    @property
    def active_call(self) -> "AsteriskBridgeCall | None":
        call = self._active_call
        return call if call is not None and not call.ended else None

    @property
    def has_active_call(self) -> bool:
        return self.active_call is not None

    async def start(self) -> None:
        if self._transport is not None:
            return
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            self.config.host,
            self.config.port,
            type=socket.SOCK_DGRAM,
        )
        if not infos:
            raise OSError(f"Cannot resolve external SIP host {self.config.host}")
        family, _, _, _, sockaddr = infos[0]
        server_host = sockaddr[0]
        self._server_addr = (server_host, self.config.port)

        probe = socket.socket(family, socket.SOCK_DGRAM)
        try:
            probe.connect(self._server_addr)
            self._local_host = probe.getsockname()[0]
        finally:
            probe.close()

        local_addr = (self._local_host, 0)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpSipProtocol(self),
            local_addr=local_addr,
            family=family,
        )
        self._transport = transport
        sockname = transport.get_extra_info("sockname")
        self._local_port = int(sockname[1])
        _LOGGER.info(
            "External SIP socket ready on %s:%s for %s:%s",
            self._local_host,
            self._local_port,
            self.config.host,
            self.config.port,
        )

        try:
            await self.ensure_registered()
        except Exception:
            # Registration failure must not take the Domonap integration down.
            _LOGGER.warning("External SIP initial registration failed", exc_info=True)

    async def close(self) -> None:
        self._closed = True
        call = self._active_call
        self._active_call = None
        if call is not None:
            try:
                await call.hangup(local=True)
            except Exception:
                _LOGGER.debug("Failed to hang up external SIP on close", exc_info=True)
        transport = self._transport
        self._transport = None
        if transport is not None:
            transport.close()

    async def ensure_registered(self) -> bool:
        if self._registered:
            return True
        async with self._register_lock:
            if self._registered:
                return True
            await self._register()
            return self._registered

    async def dial(
        self,
        panel_call: Any,
        *,
        call_id: str,
    ) -> "AsteriskBridgeCall":
        if self._transport is None:
            await self.start()
        await self.ensure_registered()

        previous = self.active_call
        if previous is not None:
            await previous.hangup(local=True)

        call = AsteriskBridgeCall(
            self,
            panel_call,
            domonap_call_id=call_id,
            on_dtmf=self._on_dtmf,
            on_hangup=self._on_hangup,
        )
        self._active_call = call
        call.start()
        return call

    async def clear_call(self, call: "AsteriskBridgeCall") -> None:
        if self._active_call is call:
            self._active_call = None

    async def _register(self) -> None:
        self._register_cseq += 1
        cseq = self._register_cseq
        request_uri = self._server_uri()
        identity = f"sip:{self.config.user}@{self.config.host}"
        headers = self._base_headers(
            method="REGISTER",
            call_id=self._register_call_id,
            cseq=cseq,
            from_value=f"<{identity}>;tag={self._from_tag}",
            to_value=f"<{identity}>",
        )
        headers.extend(
            [
                f"Contact: <{self._contact_uri()}>;expires=300",
                "Expires: 300",
            ]
        )
        response = await self._request_final(
            "REGISTER", request_uri, headers, b"", self._register_call_id, cseq
        )

        if self._status(response) in (401, 407):
            self._update_auth(response)
            self._register_cseq += 1
            cseq = self._register_cseq
            headers = self._base_headers(
                method="REGISTER",
                call_id=self._register_call_id,
                cseq=cseq,
                from_value=f"<{identity}>;tag={self._from_tag}",
                to_value=f"<{identity}>",
            )
            headers.extend(
                [
                    f"Contact: <{self._contact_uri()}>;expires=300",
                    "Expires: 300",
                    f"{self._auth_header}: {self._digest_authorization('REGISTER', request_uri)}",
                ]
            )
            response = await self._request_final(
                "REGISTER", request_uri, headers, b"", self._register_call_id, cseq
            )

        status = self._status(response)
        if 200 <= status < 300:
            self._registered = True
            _LOGGER.info(
                "External SIP account %s registered at %s:%s",
                self.config.user,
                self.config.host,
                self.config.port,
            )
            return
        raise RuntimeError(f"External SIP registration failed with {status}")

    def _datagram_received(self, data: bytes, addr) -> None:
        try:
            message = parse_sip_datagram(data)
        except Exception:
            _LOGGER.debug("Cannot parse external SIP datagram", exc_info=True)
            return

        if message.start_line.startswith("SIP/2.0"):
            call_id = message.first("call-id") or ""
            cseq_header = message.first("cseq") or ""
            try:
                cseq_text, method = cseq_header.split(None, 1)
                key = (call_id, int(cseq_text), method.upper())
            except (ValueError, TypeError):
                _LOGGER.debug("External SIP response has invalid CSeq: %s", cseq_header)
                return
            queue = self._transactions.get(key)
            if queue is not None:
                queue.put_nowait(message)
            elif self.active_call is not None:
                self.active_call.handle_unsolicited_response(message)
            return

        call = self.active_call
        if call is not None:
            asyncio.create_task(call.handle_request(message), name="domonap_external_sip_request")
            return

        method = message.start_line.split(" ", 1)[0].upper()
        if method == "OPTIONS":
            self._send_response(message, 200, "OK")

    async def _request_final(
        self,
        method: str,
        request_uri: str,
        headers: list[str],
        body: bytes,
        call_id: str,
        cseq: int,
        *,
        timeout: float = 8.0,
    ) -> _SipMessage:
        key = (call_id, cseq, method.upper())
        queue: asyncio.Queue[_SipMessage] = asyncio.Queue()
        self._transactions[key] = queue
        try:
            self._send_request(method, request_uri, headers, body)
            while True:
                response = await asyncio.wait_for(queue.get(), timeout=timeout)
                status = self._status(response)
                if status < 200:
                    _LOGGER.debug("External SIP %s provisional response: %s", method, status)
                    continue
                return response
        finally:
            self._transactions.pop(key, None)

    def _send_request(
        self, method: str, request_uri: str, headers: list[str], body: bytes = b""
    ) -> None:
        packet = self._encode(f"{method} {request_uri} SIP/2.0", headers, body)
        self._send_raw(packet)

    def _send_response(
        self,
        request: _SipMessage,
        status: int,
        reason: str,
        *,
        add_to_tag: bool = False,
    ) -> None:
        headers: list[str] = []
        for via in request.headers.get("via", []) or request.headers.get("v", []):
            headers.append(f"Via: {via}")
        for name in ("from", "to", "call-id", "cseq"):
            value = request.first(name)
            if value is None:
                continue
            if name == "to" and add_to_tag and ";tag=" not in value.lower():
                value += f";tag={token_hex(6)}"
            headers.append(f"{self._display_header(name)}: {value}")
        headers.append("Server: Domonap Home Assistant")
        self._send_raw(self._encode(f"SIP/2.0 {status} {reason}", headers, b""))

    def _send_raw(self, packet: bytes) -> None:
        if self._transport is None or self._server_addr is None:
            raise ConnectionError("External SIP UDP socket is not open")
        self._transport.sendto(packet, self._server_addr)

    def _base_headers(
        self,
        *,
        method: str,
        call_id: str,
        cseq: int,
        from_value: str,
        to_value: str,
        branch: str | None = None,
    ) -> list[str]:
        branch = branch or f"z9hG4bK{token_hex(12)}"
        return [
            f"Via: SIP/2.0/UDP {self._local_host}:{self._local_port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: {from_value}",
            f"To: {to_value}",
            f"Call-ID: {call_id}",
            f"CSeq: {cseq} {method}",
            f"Contact: <{self._contact_uri()}>",
            "User-Agent: Domonap Home Assistant",
        ]

    def _contact_uri(self) -> str:
        return f"sip:{self.config.user}@{self._local_host}:{self._local_port};transport=udp"

    def _server_uri(self) -> str:
        return f"sip:{self.config.host}:{self.config.port}"

    def _update_auth(self, response: _SipMessage) -> None:
        status = self._status(response)
        challenge_name = "www-authenticate" if status == 401 else "proxy-authenticate"
        challenge = response.first(challenge_name)
        if not challenge:
            raise RuntimeError("External SIP digest challenge is missing")
        self._auth = self._parse_digest(challenge)
        self._auth_header = "Authorization" if status == 401 else "Proxy-Authorization"

    def _digest_authorization(self, method: str, uri: str) -> str:
        auth = self._auth or {}
        realm = auth.get("realm", "")
        nonce = auth.get("nonce", "")
        algorithm = auth.get("algorithm", "MD5").upper()
        if algorithm not in ("MD5", "MD5-SESS"):
            raise RuntimeError(f"Unsupported SIP digest algorithm {algorithm}")
        cnonce = token_hex(8)
        self._nonce_count += 1
        nc = f"{self._nonce_count:08x}"
        ha1 = self._md5(f"{self.config.user}:{realm}:{self.config.password}")
        if algorithm == "MD5-SESS":
            ha1 = self._md5(f"{ha1}:{nonce}:{cnonce}")
        ha2 = self._md5(f"{method}:{uri}")
        qop_values = [value.strip() for value in auth.get("qop", "").split(",")]
        qop = "auth" if "auth" in qop_values else ""
        response = (
            self._md5(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}")
            if qop
            else self._md5(f"{ha1}:{nonce}:{ha2}")
        )
        values = [
            f'username="{self.config.user}"',
            f'realm="{realm}"',
            f'nonce="{nonce}"',
            f'uri="{uri}"',
            f'response="{response}"',
            f"algorithm={algorithm}",
        ]
        if qop:
            values.extend((f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'))
        if opaque := auth.get("opaque"):
            values.append(f'opaque="{opaque}"')
        return "Digest " + ", ".join(values)

    @staticmethod
    def _parse_digest(value: str) -> dict[str, str]:
        if value.lower().startswith("digest "):
            value = value[7:]
        return {
            match.group(1).lower(): match.group(2) or match.group(3) or ""
            for match in _DIGEST_PARAM_RE.finditer(value)
        }

    @staticmethod
    def _md5(value: str) -> str:
        return hashlib.md5(value.encode(), usedforsecurity=False).hexdigest()

    @staticmethod
    def _status(message: _SipMessage) -> int:
        try:
            return int(message.start_line.split(" ", 2)[1])
        except (IndexError, ValueError):
            return 0

    @staticmethod
    def _display_header(name: str) -> str:
        return {"call-id": "Call-ID", "cseq": "CSeq"}.get(name, name.title())

    @staticmethod
    def _encode(start_line: str, headers: list[str], body: bytes) -> bytes:
        header_lines = list(headers)
        if body and not any(line.lower().startswith("content-type:") for line in header_lines):
            header_lines.append("Content-Type: application/sdp")
        return (
            start_line
            + "\r\n"
            + "\r\n".join(header_lines)
            + f"\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode() + body


class AsteriskBridgeCall:
    def __init__(
        self,
        account: AsteriskSipAccount,
        panel_call: Any,
        *,
        domonap_call_id: str,
        on_dtmf: Callable[[str], Awaitable[None]],
        on_hangup: Callable[[], Awaitable[None]],
    ) -> None:
        self._account = account
        self._panel_call = panel_call
        self._domonap_call_id = domonap_call_id
        self._on_dtmf = on_dtmf
        self._on_hangup = on_hangup
        self._call_id = f"{uuid4()}@home-assistant"
        self._from_tag = token_hex(8)
        self._cseq = 1
        self._task: asyncio.Task | None = None
        self._established = False
        self._ended = False
        self._ending = False
        self._remote_to: str | None = None
        self._remote_target: str | None = None
        self._record_routes: list[str] = []
        self._rtp_socket: socket.socket | None = None
        self._rtp_bridge: RtpBridge | None = None
        self._external_sdp: AudioSdp | None = None

    @property
    def established(self) -> bool:
        return self._established

    @property
    def ended(self) -> bool:
        return self._ended

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="domonap_asterisk_bridge")

    async def _run(self) -> None:
        try:
            if hasattr(self._panel_call, "wait_for_invite"):
                ready = await self._panel_call.wait_for_invite(timeout=8.0)
                if not ready:
                    raise RuntimeError("Domonap SIP INVITE was not received")

            self._rtp_socket = self._allocate_rtp_socket(self._account._local_host or "0.0.0.0")
            local_rtp_port = int(self._rtp_socket.getsockname()[1])
            offer = build_external_sdp_offer(
                self._panel_call.sdp_offer,
                self._account._local_host or "127.0.0.1",
                local_rtp_port,
            )
            response = await self._invite(offer)
            status = self._account._status(response)
            if not 200 <= status < 300:
                _LOGGER.info("External SIP call ended before answer with %s", status)
                await self._notify_hangup_once()
                return

            self._remote_to = response.first("to")
            self._remote_target = extract_sip_uri(response.first("contact"))
            self._record_routes = list(response.headers.get("record-route", []))
            self._external_sdp = parse_audio_sdp(response.body)
            if self._external_sdp is None:
                raise RuntimeError("External SIP 200 OK has no usable audio SDP")

            await self._send_ack(response)
            answer = await self._panel_call.answer(timeout=2.0, direction="sendrecv")
            if not (isinstance(answer, dict) and answer.get("ok") is True):
                raise RuntimeError(f"Cannot answer Domonap SIP leg: {answer}")

            panel_sdp = self._panel_call.audio_offer
            panel_socket = self._panel_call.media_socket
            panel_remote = self._panel_call.remote_media_endpoint
            if panel_sdp is None or panel_socket is None or panel_remote is None:
                raise RuntimeError("Domonap SIP media endpoint is incomplete")

            self._rtp_bridge = RtpBridge(
                panel_socket=panel_socket,
                panel_remote=panel_remote,
                panel_sdp=panel_sdp,
                external_socket=self._rtp_socket,
                external_remote=(self._external_sdp.host, self._external_sdp.port),
                external_sdp=self._external_sdp,
                on_dtmf=self._on_dtmf,
            )
            self._rtp_bridge.start()
            self._established = True
            _LOGGER.info(
                "External SIP call to %s established; RTP bridge active",
                self._account.config.call_number,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.warning("External SIP call setup failed", exc_info=True)
            await self._notify_hangup_once()

    async def _invite(self, body: bytes) -> _SipMessage:
        cfg = self._account.config
        request_uri = f"sip:{cfg.call_number}@{cfg.host}:{cfg.port}"
        from_value = f"<sip:{cfg.user}@{cfg.host}>;tag={self._from_tag}"
        to_value = f"<sip:{cfg.call_number}@{cfg.host}>"

        for attempt in range(2):
            headers = self._account._base_headers(
                method="INVITE",
                call_id=self._call_id,
                cseq=self._cseq,
                from_value=from_value,
                to_value=to_value,
            )
            headers.extend(
                [
                    "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, INFO",
                    "Supported: replaces, timer",
                    "Content-Type: application/sdp",
                ]
            )
            if attempt and self._account._auth is not None:
                headers.append(
                    f"{self._account._auth_header}: "
                    f"{self._account._digest_authorization('INVITE', request_uri)}"
                )
            response = await self._account._request_final(
                "INVITE", request_uri, headers, body, self._call_id, self._cseq, timeout=35.0
            )
            status = self._account._status(response)
            if status not in (401, 407):
                return response
            await self._send_non_2xx_ack(response, request_uri, from_value, to_value)
            self._account._update_auth(response)
            self._cseq += 1
        return response

    async def _send_non_2xx_ack(
        self,
        response: _SipMessage,
        request_uri: str,
        from_value: str,
        to_value: str,
    ) -> None:
        headers = self._account._base_headers(
            method="ACK",
            call_id=self._call_id,
            cseq=self._cseq,
            from_value=from_value,
            to_value=response.first("to") or to_value,
        )
        self._account._send_request("ACK", request_uri, headers)

    async def _send_ack(self, response: _SipMessage) -> None:
        cfg = self._account.config
        target = extract_sip_uri(response.first("contact")) or (
            f"sip:{cfg.call_number}@{cfg.host}:{cfg.port}"
        )
        from_value = response.first("from") or f"<sip:{cfg.user}@{cfg.host}>;tag={self._from_tag}"
        to_value = response.first("to") or f"<sip:{cfg.call_number}@{cfg.host}>"
        headers = self._account._base_headers(
            method="ACK",
            call_id=self._call_id,
            cseq=self._cseq,
            from_value=from_value,
            to_value=to_value,
        )
        for route in self._record_routes:
            headers.append(f"Route: {route}")
        self._account._send_request("ACK", target, headers)

    async def handle_request(self, message: _SipMessage) -> None:
        call_id = message.first("call-id")
        if call_id != self._call_id:
            return
        method = message.start_line.split(" ", 1)[0].upper()
        if method == "BYE":
            self._account._send_response(message, 200, "OK", add_to_tag=True)
            _LOGGER.info("External SIP peer hung up")
            await self._finish_media()
            self._ended = True
            await self._account.clear_call(self)
            await self._notify_hangup_once()
        elif method == "INFO":
            digit = parse_info_dtmf(message.body)
            self._account._send_response(message, 200, "OK", add_to_tag=True)
            if digit:
                _LOGGER.info("External SIP DTMF INFO digit=%s", digit)
                await self._on_dtmf(digit)
        elif method == "OPTIONS":
            self._account._send_response(message, 200, "OK", add_to_tag=True)

    def handle_unsolicited_response(self, message: _SipMessage) -> None:
        # Retransmitted 2xx INVITE responses are harmless; ACK them again.
        cseq = message.first("cseq") or ""
        if cseq.upper().endswith(" INVITE") and 200 <= self._account._status(message) < 300:
            asyncio.create_task(self._send_ack(message))

    async def hangup(self, *, local: bool) -> None:
        if self._ending or self._ended:
            return
        self._ending = True
        try:
            if self._established:
                await self._send_bye()
            await self._finish_media()
            self._ended = True
            await self._account.clear_call(self)
            if not local:
                await self._notify_hangup_once()
        finally:
            self._ending = False

    async def _send_bye(self) -> None:
        cfg = self._account.config
        target = self._remote_target or f"sip:{cfg.call_number}@{cfg.host}:{cfg.port}"
        self._cseq += 1
        from_value = f"<sip:{cfg.user}@{cfg.host}>;tag={self._from_tag}"
        to_value = self._remote_to or f"<sip:{cfg.call_number}@{cfg.host}>"
        headers = self._account._base_headers(
            method="BYE",
            call_id=self._call_id,
            cseq=self._cseq,
            from_value=from_value,
            to_value=to_value,
        )
        for route in self._record_routes:
            headers.append(f"Route: {route}")
        try:
            response = await self._account._request_final(
                "BYE", target, headers, b"", self._call_id, self._cseq, timeout=4.0
            )
            _LOGGER.debug("External SIP BYE response=%s", self._account._status(response))
        except asyncio.TimeoutError:
            _LOGGER.warning("External SIP BYE timed out")

    async def _finish_media(self) -> None:
        bridge = self._rtp_bridge
        self._rtp_bridge = None
        if bridge is not None:
            bridge.stop()
        sock = self._rtp_socket
        self._rtp_socket = None
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    async def _notify_hangup_once(self) -> None:
        callback = self._on_hangup
        self._on_hangup = _noop_async
        await callback()

    @staticmethod
    def _allocate_rtp_socket(host: str) -> socket.socket:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        if family == socket.AF_INET6:
            sock.bind((host, 0, 0, 0))
        else:
            sock.bind((host, 0))
        return sock


class RtpBridge:
    def __init__(
        self,
        *,
        panel_socket: socket.socket,
        panel_remote: tuple[str, int],
        panel_sdp: AudioSdp,
        external_socket: socket.socket,
        external_remote: tuple[str, int],
        external_sdp: AudioSdp,
        on_dtmf: Callable[[str], Awaitable[None]],
    ) -> None:
        self._panel_socket = panel_socket
        self._panel_remote = panel_remote
        self._panel_sdp = panel_sdp
        self._external_socket = external_socket
        self._external_remote = external_remote
        self._external_sdp = external_sdp
        self._on_dtmf = on_dtmf
        self._loop: asyncio.AbstractEventLoop | None = None
        self._last_dtmf: tuple[int, int] | None = None
        self._ext_to_panel = build_payload_map(external_sdp, panel_sdp)
        self._panel_to_ext = build_payload_map(panel_sdp, external_sdp)

    def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._loop.add_reader(self._panel_socket.fileno(), self._read_panel)
        self._loop.add_reader(self._external_socket.fileno(), self._read_external)
        _LOGGER.debug(
            "RTP bridge started panel=%s external=%s maps=%s/%s",
            self._panel_remote,
            self._external_remote,
            self._panel_to_ext,
            self._ext_to_panel,
        )

    def stop(self) -> None:
        loop = self._loop
        if loop is not None:
            for sock in (self._panel_socket, self._external_socket):
                try:
                    loop.remove_reader(sock.fileno())
                except Exception:
                    pass
        self._loop = None

    def _read_panel(self) -> None:
        try:
            packet, _ = self._panel_socket.recvfrom(65535)
        except (BlockingIOError, OSError):
            return
        payload = rtp_payload_type(packet)
        if payload is None:
            return
        mapped = self._panel_to_ext.get(payload)
        if mapped is None:
            return
        try:
            self._external_socket.sendto(rewrite_rtp_payload_type(packet, mapped), self._external_remote)
        except OSError:
            pass

    def _read_external(self) -> None:
        try:
            packet, _ = self._external_socket.recvfrom(65535)
        except (BlockingIOError, OSError):
            return
        payload = rtp_payload_type(packet)
        if payload is None:
            return

        if payload == self._external_sdp.telephone_event_pt:
            event = parse_rfc2833_event(packet)
            if event is not None:
                number, ended, timestamp = event
                marker = (number, timestamp)
                if ended and marker != self._last_dtmf:
                    self._last_dtmf = marker
                    digit = rfc2833_digit(number)
                    if digit:
                        _LOGGER.info("External SIP RTP DTMF digit=%s", digit)
                        asyncio.create_task(self._on_dtmf(digit))
            return

        mapped = self._ext_to_panel.get(payload)
        if mapped is None:
            return
        try:
            self._panel_socket.sendto(rewrite_rtp_payload_type(packet, mapped), self._panel_remote)
        except OSError:
            pass


async def _noop_async() -> None:
    return None


def parse_host_port(value: str, default_port: int = 5060) -> tuple[str, int]:
    text = value.strip()
    if not text:
        raise ValueError("SIP domain is empty")
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError("Invalid IPv6 SIP domain")
        host = text[1:end]
        rest = text[end + 1 :]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if text.count(":") == 1:
        host, port_text = text.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text)
    return text, default_port


def parse_sip_datagram(data: bytes) -> _SipMessage:
    header_blob, separator, body = data.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("SIP datagram has no header terminator")
    lines = header_blob.decode(errors="replace").split("\r\n")
    start_line = lines[0]
    headers: dict[str, list[str]] = {}
    current_name: str | None = None
    for line in lines[1:]:
        if line[:1] in (" ", "\t") and current_name:
            headers[current_name][-1] += " " + line.strip()
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        current_name = name.strip().lower()
        headers.setdefault(current_name, []).append(value.strip())
    length_value = (headers.get("content-length") or headers.get("l") or [str(len(body))])[0]
    try:
        length = int(length_value)
    except ValueError:
        length = len(body)
    return _SipMessage(start_line, headers, body[:length])


def parse_audio_sdp(body: bytes | str) -> AudioSdp | None:
    text = body.decode(errors="replace") if isinstance(body, bytes) else body
    lines = [line.strip() for line in text.replace("\r", "").split("\n") if line.strip()]
    session_host = ""
    current_media = None
    media_host = ""
    media_port = 0
    media_proto = ""
    payloads: list[int] = []
    codecs: dict[int, str] = {}
    fmtp: dict[int, str] = {}

    for line in lines:
        if line.startswith("c="):
            parts = line.split()
            host = parts[-1] if parts else ""
            if current_media == "audio":
                media_host = host
            elif current_media is None:
                session_host = host
        elif line.startswith("m="):
            parts = line[2:].split()
            current_media = parts[0].lower() if parts else None
            if current_media == "audio" and len(parts) >= 4:
                try:
                    media_port = int(parts[1])
                except ValueError:
                    media_port = 0
                media_proto = parts[2]
                payloads = []
                for value in parts[3:]:
                    try:
                        payloads.append(int(value))
                    except ValueError:
                        pass
                codecs = {pt: _STATIC_RTPMAP[pt] for pt in payloads if pt in _STATIC_RTPMAP}
        elif current_media == "audio" and line.lower().startswith("a=rtpmap:"):
            try:
                left, codec = line[9:].split(None, 1)
                codecs[int(left)] = codec.strip()
            except (ValueError, IndexError):
                pass
        elif current_media == "audio" and line.lower().startswith("a=fmtp:"):
            try:
                left, value = line[7:].split(None, 1)
                fmtp[int(left)] = value.strip()
            except (ValueError, IndexError):
                pass

    host = media_host or session_host
    if not host or not media_port or not payloads:
        return None
    telephone_event_pt = next(
        (pt for pt, codec in codecs.items() if codec.lower().startswith("telephone-event/")),
        None,
    )
    return AudioSdp(host, media_port, media_proto, payloads, codecs, fmtp, telephone_event_pt)


def build_external_sdp_offer(panel_offer: bytes | str, host: str, port: int) -> bytes:
    parsed = parse_audio_sdp(panel_offer)
    if parsed is None:
        # Safe Asterisk-oriented fallback; the Panel side still validates its own SDP.
        parsed = AudioSdp(
            host="0.0.0.0",
            port=0,
            proto="RTP/AVP",
            payloads=[8, 0],
            codecs={8: "PCMA/8000", 0: "PCMU/8000"},
            fmtp={},
        )

    media_payloads = [pt for pt in parsed.payloads if pt != parsed.telephone_event_pt]
    if not media_payloads:
        media_payloads = [8, 0]
    telephone_pt = parsed.telephone_event_pt
    if telephone_pt is None or telephone_pt in media_payloads:
        telephone_pt = 101 if 101 not in media_payloads else 110

    family = "IP6" if ":" in host else "IP4"
    payloads = media_payloads + [telephone_pt]
    lines = [
        "v=0",
        f"o=- 1 1 IN {family} {host}",
        "s=Domonap-Asterisk-Bridge",
        f"c=IN {family} {host}",
        "t=0 0",
        f"m=audio {port} RTP/AVP {' '.join(str(pt) for pt in payloads)}",
    ]
    for payload in media_payloads:
        codec = parsed.codecs.get(payload) or _STATIC_RTPMAP.get(payload)
        if codec:
            lines.append(f"a=rtpmap:{payload} {codec}")
        if payload in parsed.fmtp:
            lines.append(f"a=fmtp:{payload} {parsed.fmtp[payload]}")
    lines.extend(
        [
            f"a=rtpmap:{telephone_pt} telephone-event/8000",
            f"a=fmtp:{telephone_pt} 0-16",
            "a=sendrecv",
        ]
    )
    return ("\r\n".join(lines) + "\r\n").encode()


def build_payload_map(source: AudioSdp, destination: AudioSdp) -> dict[int, int]:
    result: dict[int, int] = {}
    for source_pt, source_codec in source.codecs.items():
        if source_pt == source.telephone_event_pt:
            continue
        dest_pt = destination.codec_payload(source_codec)
        if dest_pt is not None:
            result[source_pt] = dest_pt
    return result


def rtp_payload_type(packet: bytes) -> int | None:
    if len(packet) < 12 or packet[0] >> 6 != 2:
        return None
    return packet[1] & 0x7F


def rewrite_rtp_payload_type(packet: bytes, payload: int) -> bytes:
    if len(packet) < 2:
        return packet
    mutable = bytearray(packet)
    mutable[1] = (mutable[1] & 0x80) | (payload & 0x7F)
    return bytes(mutable)


def parse_rfc2833_event(packet: bytes) -> tuple[int, bool, int] | None:
    if len(packet) < 16:
        return None
    csrc_count = packet[0] & 0x0F
    extension = bool(packet[0] & 0x10)
    offset = 12 + csrc_count * 4
    if extension:
        if len(packet) < offset + 4:
            return None
        extension_words = int.from_bytes(packet[offset + 2 : offset + 4], "big")
        offset += 4 + extension_words * 4
    if len(packet) < offset + 4:
        return None
    event = packet[offset]
    ended = bool(packet[offset + 1] & 0x80)
    timestamp = int.from_bytes(packet[4:8], "big")
    return event, ended, timestamp


def rfc2833_digit(event: int) -> str | None:
    if 0 <= event <= 9:
        return str(event)
    return {10: "*", 11: "#", 12: "A", 13: "B", 14: "C", 15: "D"}.get(event)


def parse_info_dtmf(body: bytes) -> str | None:
    text = body.decode(errors="replace")
    for line in text.replace("\r", "").split("\n"):
        if "=" in line:
            key, value = line.split("=", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            continue
        if key.strip().lower() in ("signal", "digit"):
            digit = value.strip()
            return digit[:1] if digit else None
    return None


def extract_sip_uri(value: str | None) -> str | None:
    if not value:
        return None
    match = _SIP_URI_RE.search(value)
    return (match.group(1) or match.group(2)) if match else None
