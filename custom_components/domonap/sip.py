from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass
from secrets import token_hex
from typing import Any
from uuid import uuid4

_LOGGER = logging.getLogger(__name__)

_DIGEST_PARAM_RE = re.compile(r'(\w+)=(?:"([^"]*)"|([^,\s]+))')


@dataclass
class _SipMessage:
    start_line: str
    headers: dict[str, list[str]]
    body: bytes

    def first(self, name: str) -> str | None:
        normalized_name = name.lower()
        aliases = {
            "via": "v",
            "from": "f",
            "to": "t",
            "call-id": "i",
            "content-length": "l",
        }
        values = self.headers.get(normalized_name) or self.headers.get(
            aliases.get(normalized_name, "")
        )
        return values[0] if values else None


class DomonapSipCall:
    """Minimal SIP/TCP client used only to terminate an incoming intercom call."""

    def __init__(self, account: str, password: str, domain: str, port: int) -> None:
        self._account = account
        self._password = password
        self._domain = domain
        self._port = port
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._task: asyncio.Task | None = None
        self._write_lock = asyncio.Lock()
        self._invite_event = asyncio.Event()
        self._registered_event = asyncio.Event()
        self._invite: _SipMessage | None = None
        self._stopping = False
        self._ended = False
        self._local_host = "127.0.0.1"
        self._local_port = 5060
        self._register_call_id = f"{uuid4()}@home-assistant"
        self._from_tag = token_hex(8)
        self._to_tag = token_hex(8)
        self._cseq = 0
        self._nonce_count = 0
        self._expires = 300
        self._auth: dict[str, str] | None = None
        self._auth_header = "Authorization"

    @property
    def registered(self) -> bool:
        return self._registered_event.is_set()

    @property
    def has_invite(self) -> bool:
        return self._invite is not None

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run(), name="domonap_sip_call")

    async def stop(self) -> None:
        self._stopping = True
        writer = self._writer
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        task = self._task
        if (
            task is not None
            and task is not asyncio.current_task()
            and not task.done()
        ):
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass

    async def end(self, timeout: float = 5.0) -> dict[str, Any]:
        """Reject the pending INVITE, which is the SIP equivalent of ending it."""
        self.start()
        try:
            await asyncio.wait_for(self._invite_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return {
                "ok": False,
                "error": "sip_invite_timeout",
                "registered": self.registered,
            }

        invite = self._invite
        if invite is None:
            return {"ok": self._ended, "registered": self.registered}

        try:
            await self._send_response(invite, 603, "Decline", add_to_tag=True)
            self._ended = True
            _LOGGER.info("Active Domonap call ended via SIP")
            return {"ok": True, "registered": self.registered, "method": "sip_decline"}
        except Exception as err:
            _LOGGER.warning("Failed to end Domonap call via SIP: %s", err)
            return {"ok": False, "error": str(err), "registered": self.registered}

    async def _run(self) -> None:
        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self._domain, self._port), timeout=5
            )
            sockname = self._writer.get_extra_info("sockname")
            if sockname:
                self._local_host = str(sockname[0])
                self._local_port = int(sockname[1])

            await self._register()
            while not self._stopping:
                message = await self._read_message()
                await self._handle_message(message)
        except asyncio.CancelledError:
            raise
        except (EOFError, ConnectionError):
            if not self._stopping:
                _LOGGER.debug("Domonap SIP connection closed")
        except Exception:
            if not self._stopping:
                _LOGGER.warning("Domonap SIP session failed", exc_info=True)
        finally:
            self._invite_event.set()
            writer = self._writer
            if writer is not None:
                writer.close()
            self._writer = None
            self._reader = None

    async def _register(self) -> None:
        await self._send_register()
        while True:
            response = await asyncio.wait_for(self._read_message(), timeout=5)
            if not response.start_line.startswith("SIP/2.0"):
                await self._handle_message(response)
                continue
            status = self._status_code(response)
            if status in (401, 407):
                challenge_name = (
                    "www-authenticate" if status == 401 else "proxy-authenticate"
                )
                challenge = response.first(challenge_name)
                if not challenge:
                    raise RuntimeError("SIP authentication challenge is missing")
                self._auth = self._parse_digest(challenge)
                self._auth_header = (
                    "Authorization" if status == 401 else "Proxy-Authorization"
                )
                await self._send_register()
                continue
            if 200 <= status < 300:
                self._registered_event.set()
                _LOGGER.info("Domonap SIP account registered")
                return
            if status == 423:
                min_expires = response.first("min-expires")
                try:
                    self._expires = max(self._expires, int(min_expires or ""))
                except ValueError:
                    raise RuntimeError("SIP registrar rejected registration expiry")
                await self._send_register()
                continue
            if status < 200:
                continue
            raise RuntimeError(f"SIP registration failed with {status}")

    async def _handle_message(self, message: _SipMessage) -> None:
        if message.start_line.startswith("SIP/2.0"):
            return
        method = message.start_line.split(" ", 1)[0].upper()
        if method == "INVITE":
            self._invite = message
            await self._send_response(message, 100, "Trying")
            self._invite_event.set()
            _LOGGER.info("Incoming Domonap SIP INVITE received")
        elif method == "CANCEL":
            await self._send_response(message, 200, "OK", add_to_tag=True)
            if self._invite is not None:
                await self._send_response(
                    self._invite, 487, "Request Terminated", add_to_tag=True
                )
            self._ended = True
            self._invite = None
            self._invite_event.set()
        elif method == "BYE":
            await self._send_response(message, 200, "OK", add_to_tag=True)
            self._ended = True
            self._invite = None
            self._invite_event.set()
        elif method == "OPTIONS":
            await self._send_response(message, 200, "OK", add_to_tag=True)

    async def _send_register(self) -> None:
        self._cseq += 1
        branch = f"z9hG4bK{token_hex(12)}"
        host = self._format_host(self._local_host)
        request_uri = f"sip:{self._domain}:{self._port}"
        identity = f"sip:{self._account}@{self._domain}"
        contact = f"sip:{self._account}@{host}:{self._local_port};transport=tcp"
        headers = [
            f"Via: SIP/2.0/TCP {host}:{self._local_port};branch={branch};rport;alias",
            "Max-Forwards: 70",
            f"From: <{identity}>;tag={self._from_tag}",
            f"To: <{identity}>",
            f"Call-ID: {self._register_call_id}",
            f"CSeq: {self._cseq} REGISTER",
            f"Contact: <{contact}>;expires={self._expires}",
            f"Expires: {self._expires}",
            "Supported: path, outbound, gruu",
            "User-Agent: Domonap Home Assistant",
        ]
        if self._auth is not None:
            authorization = self._digest_authorization("REGISTER", request_uri)
            headers.append(f"{self._auth_header}: {authorization}")
        await self._send(f"REGISTER {request_uri} SIP/2.0", headers)

    async def _send_response(
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
                value = f"{value};tag={self._to_tag}"
            headers.append(f"{self._display_header(name)}: {value}")
        headers.append("Server: Domonap Home Assistant")
        await self._send(f"SIP/2.0 {status} {reason}", headers)

    async def _send(self, start_line: str, headers: list[str], body: bytes = b"") -> None:
        writer = self._writer
        if writer is None:
            raise ConnectionError("SIP connection is not open")
        packet = (
            start_line
            + "\r\n"
            + "\r\n".join(headers)
            + f"\r\nContent-Length: {len(body)}\r\n\r\n"
        ).encode() + body
        async with self._write_lock:
            writer.write(packet)
            await writer.drain()

    async def _read_message(self) -> _SipMessage:
        reader = self._reader
        if reader is None:
            raise ConnectionError("SIP connection is not open")
        while True:
            raw_headers = await reader.readuntil(b"\r\n\r\n")
            while raw_headers.startswith(b"\r\n"):
                raw_headers = raw_headers[2:]
            if not raw_headers:
                continue
            break
        lines = raw_headers[:-4].decode(errors="replace").split("\r\n")
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
        length_value = (headers.get("content-length") or headers.get("l") or ["0"])[0]
        try:
            length = int(length_value)
        except ValueError:
            length = 0
        body = await reader.readexactly(length) if length else b""
        return _SipMessage(start_line, headers, body)

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
        ha1 = self._md5(f"{self._account}:{realm}:{self._password}")
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
            f'username="{self._account}"',
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
    def _status_code(message: _SipMessage) -> int:
        try:
            return int(message.start_line.split(" ", 2)[1])
        except (IndexError, ValueError):
            return 0

    @staticmethod
    def _format_host(host: str) -> str:
        return f"[{host}]" if ":" in host and not host.startswith("[") else host

    @staticmethod
    def _display_header(name: str) -> str:
        return {"call-id": "Call-ID", "cseq": "CSeq"}.get(name, name.title())
