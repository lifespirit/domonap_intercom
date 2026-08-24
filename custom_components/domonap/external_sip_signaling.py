from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import socket
from dataclasses import dataclass
from secrets import token_hex
from typing import Awaitable, Callable
from uuid import uuid4

from .sip import _SipMessage

_LOGGER = logging.getLogger(__name__)

_DIGEST_PARAM_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^,\s]+))')
_SIP_URI_RE = re.compile(r"<(sips?:[^>]+)>|(sips?:[^;,\s]+)", re.IGNORECASE)


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
    """Small SIP UAC used to bridge Domonap signaling to Asterisk.

    Home Assistant never opens an RTP socket in this implementation.  The
    Domonap SDP offer is passed unchanged to Asterisk and Asterisk's SDP answer
    is passed unchanged back to Domonap, so media flows directly between those
    two endpoints.  The integration owns only REGISTER/INVITE/ACK/BYE/CANCEL and
    SIP INFO DTMF signaling.
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
        self._register_task: asyncio.Task | None = None
        self._active_call: AsteriskSignalingCall | None = None
        self._closed = False

    @property
    def registered(self) -> bool:
        return self._registered

    @property
    def active_call(self) -> "AsteriskSignalingCall | None":
        call = self._active_call
        return call if call is not None and not call.ended else None

    @property
    def has_active_call(self) -> bool:
        return self.active_call is not None

    async def start(self) -> None:
        if self._transport is not None:
            return
        self._closed = False
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

        transport, _ = await loop.create_datagram_endpoint(
            lambda: _UdpSipProtocol(self),
            local_addr=(self._local_host, 0),
            family=family,
        )
        self._transport = transport
        sockname = transport.get_extra_info("sockname")
        self._local_port = int(sockname[1])
        _LOGGER.info(
            "External SIP signaling socket ready on %s:%s for %s:%s",
            self._local_host,
            self._local_port,
            self.config.host,
            self.config.port,
        )

        await self.ensure_registered()
        self._register_task = asyncio.create_task(
            self._registration_loop(), name="domonap_external_sip_register"
        )

    async def close(self) -> None:
        self._closed = True
        register_task = self._register_task
        self._register_task = None
        if register_task is not None and not register_task.done():
            register_task.cancel()
            try:
                await register_task
            except asyncio.CancelledError:
                pass

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
        self._registered = False

    async def _registration_loop(self) -> None:
        while not self._closed:
            try:
                await asyncio.sleep(240)
                self._registered = False
                await self.ensure_registered()
            except asyncio.CancelledError:
                raise
            except Exception:
                _LOGGER.warning("External SIP registration refresh failed", exc_info=True)

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
        panel_call,
        *,
        call_id: str,
    ) -> "AsteriskSignalingCall":
        if self._transport is None:
            await self.start()
        await self.ensure_registered()

        previous = self.active_call
        if previous is not None:
            await previous.hangup(local=True)

        call = AsteriskSignalingCall(
            self,
            panel_call,
            domonap_call_id=call_id,
            on_dtmf=self._on_dtmf,
            on_hangup=self._on_hangup,
        )
        self._active_call = call
        call.start()
        return call

    async def clear_call(self, call: "AsteriskSignalingCall") -> None:
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
            asyncio.create_task(
                call.handle_request(message), name="domonap_external_sip_request"
            )
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
                    _LOGGER.debug(
                        "External SIP %s provisional response: %s", method, status
                    )
                    continue
                return response
        finally:
            self._transactions.pop(key, None)

    def _send_request(
        self, method: str, request_uri: str, headers: list[str], body: bytes = b""
    ) -> None:
        self._send_raw(self._encode(f"{method} {request_uri} SIP/2.0", headers, body))

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
        if body and not any(
            line.lower().startswith("content-type:") for line in header_lines
        ):
            header_lines.append("Content-Type: application/sdp")
        return (
            start_line
            + "\r\n"
            + "\r\n".join(header_lines)
            + f"\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode() + body


class AsteriskSignalingCall:
    """One external SIP dialog whose SDP is exchanged without media proxying."""

    def __init__(
        self,
        account: AsteriskSipAccount,
        panel_call,
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
        self._request_uri: str | None = None
        self._from_value: str | None = None
        self._to_value: str | None = None
        self._invite_branch: str | None = None

    @property
    def established(self) -> bool:
        return self._established

    @property
    def ended(self) -> bool:
        return self._ended

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(
                self._run(), name="domonap_asterisk_signaling_bridge"
            )

    async def _run(self) -> None:
        try:
            ready = await self._panel_call.wait_for_invite(timeout=8.0)
            if not ready:
                raise RuntimeError("Domonap SIP INVITE was not received")

            panel_offer = bytes(self._panel_call.sdp_offer)
            if not panel_offer:
                raise RuntimeError("Domonap SIP INVITE has no SDP offer")

            response = await self._invite(panel_offer)
            status = self._account._status(response)
            if not 200 <= status < 300:
                _LOGGER.info("External SIP call ended before answer with %s", status)
                self._ended = True
                await self._account.clear_call(self)
                await self._notify_hangup_once()
                return

            self._remote_to = response.first("to")
            self._remote_target = extract_sip_uri(response.first("contact"))
            self._record_routes = list(reversed(response.headers.get("record-route", [])))
            await self._send_ack(response)

            # Crucial media behavior: do not rewrite or terminate RTP in HA.
            # Asterisk's SDP answer is copied byte-for-byte into the Domonap 200 OK.
            answer = await self._panel_call.answer_with_sdp(
                response.body, timeout=2.0
            )
            if not (isinstance(answer, dict) and answer.get("ok") is True):
                raise RuntimeError(f"Cannot answer Domonap SIP leg: {answer}")

            self._established = True
            _LOGGER.info(
                "External SIP call to %s established; RTP is direct Domonap <-> Asterisk",
                self._account.config.call_number,
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.warning("External SIP signaling bridge failed", exc_info=True)
            try:
                await self.hangup(local=True)
            except Exception:
                _LOGGER.debug("Failed to clean external SIP dialog", exc_info=True)
            await self._notify_hangup_once()

    async def _invite(self, body: bytes) -> _SipMessage:
        cfg = self._account.config
        request_uri = f"sip:{cfg.call_number}@{cfg.host}:{cfg.port}"
        from_value = f"<sip:{cfg.user}@{cfg.host}>;tag={self._from_tag}"
        to_value = f"<sip:{cfg.call_number}@{cfg.host}>"
        self._request_uri = request_uri
        self._from_value = from_value
        self._to_value = to_value

        response: _SipMessage | None = None
        for attempt in range(2):
            branch = f"z9hG4bK{token_hex(12)}"
            self._invite_branch = branch
            headers = self._account._base_headers(
                method="INVITE",
                call_id=self._call_id,
                cseq=self._cseq,
                from_value=from_value,
                to_value=to_value,
                branch=branch,
            )
            headers.extend(
                [
                    f"Contact: <{self._account._contact_uri()}>",
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
                "INVITE",
                request_uri,
                headers,
                body,
                self._call_id,
                self._cseq,
                timeout=35.0,
            )
            status = self._account._status(response)
            if status not in (401, 407):
                return response
            await self._send_non_2xx_ack(
                response, request_uri, from_value, to_value, branch
            )
            self._account._update_auth(response)
            self._cseq += 1

        assert response is not None
        return response

    async def _send_non_2xx_ack(
        self,
        response: _SipMessage,
        request_uri: str,
        from_value: str,
        to_value: str,
        branch: str,
    ) -> None:
        headers = self._account._base_headers(
            method="ACK",
            call_id=self._call_id,
            cseq=self._cseq,
            from_value=from_value,
            to_value=response.first("to") or to_value,
            branch=branch,
        )
        self._account._send_request("ACK", request_uri, headers)

    async def _send_ack(self, response: _SipMessage) -> None:
        cfg = self._account.config
        target = extract_sip_uri(response.first("contact")) or (
            f"sip:{cfg.call_number}@{cfg.host}:{cfg.port}"
        )
        from_value = response.first("from") or self._from_value or ""
        to_value = response.first("to") or self._to_value or ""
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
        if message.first("call-id") != self._call_id:
            return
        method = message.start_line.split(" ", 1)[0].upper()
        if method == "BYE":
            self._account._send_response(message, 200, "OK", add_to_tag=True)
            _LOGGER.info("External SIP peer hung up")
            self._ended = True
            self._established = False
            await self._account.clear_call(self)
            await self._notify_hangup_once()
        elif method == "INFO":
            digit = parse_info_dtmf(message.body)
            self._account._send_response(message, 200, "OK", add_to_tag=True)
            if digit:
                _LOGGER.info("External SIP INFO DTMF digit=%s", digit)
                await self._on_dtmf(digit)
        elif method == "OPTIONS":
            self._account._send_response(message, 200, "OK", add_to_tag=True)

    def handle_unsolicited_response(self, message: _SipMessage) -> None:
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
            elif self._request_uri and self._invite_branch:
                self._send_cancel()

            self._ended = True
            self._established = False
            await self._account.clear_call(self)

            task = self._task
            if task is not None and task is not asyncio.current_task() and not task.done():
                task.cancel()
            if not local:
                await self._notify_hangup_once()
        finally:
            self._ending = False

    async def _send_bye(self) -> None:
        cfg = self._account.config
        target = self._remote_target or f"sip:{cfg.call_number}@{cfg.host}:{cfg.port}"
        self._cseq += 1
        from_value = self._from_value or f"<sip:{cfg.user}@{cfg.host}>;tag={self._from_tag}"
        to_value = self._remote_to or self._to_value or f"<sip:{cfg.call_number}@{cfg.host}>"
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

    def _send_cancel(self) -> None:
        if not self._request_uri or not self._from_value or not self._to_value:
            return
        headers = self._account._base_headers(
            method="CANCEL",
            call_id=self._call_id,
            cseq=self._cseq,
            from_value=self._from_value,
            to_value=self._to_value,
            branch=self._invite_branch,
        )
        _LOGGER.info("Cancelling ringing external SIP call")
        self._account._send_request("CANCEL", self._request_uri, headers)

    async def _notify_hangup_once(self) -> None:
        callback = self._on_hangup
        self._on_hangup = _noop_async
        await callback()


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
    length_value = (
        headers.get("content-length") or headers.get("l") or [str(len(body))]
    )[0]
    try:
        length = int(length_value)
    except ValueError:
        length = len(body)
    return _SipMessage(start_line, headers, body[:length])


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
