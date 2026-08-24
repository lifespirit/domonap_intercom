from __future__ import annotations

import asyncio
import logging
import re
import socket
import time
from secrets import token_hex
from typing import Any

from .sip import DomonapSipCall, _SipMessage

_LOGGER = logging.getLogger(__name__)

_SIP_URI_RE = re.compile(r"<(sips?:[^>]+)>|(sips?:[^;,\s]+)", re.IGNORECASE)


class RubetekPanelSipCall(DomonapSipCall):
    """Panel SIP leg with the answer -> open -> BYE lifecycle used by the APK.

    The generic DomonapSipCall from main is intentionally left untouched.  The
    Rubetek incoming-call UI calls CallOrchestrator.answer() before requesting
    the relay opening and only then calls endCallSmart().  For an incoming SIP
    dialog that means a 200/ACK exchange followed by BYE, not a 603 rejection.
    """

    def __init__(self, account: str, password: str, domain: str, port: int) -> None:
        super().__init__(account, password, domain, port)
        self._answered = False
        self._ack_event = asyncio.Event()
        self._bye_response_event = asyncio.Event()
        self._bye_response_status: int | None = None
        self._bye_cseq = 1
        self._media_sockets: list[socket.socket] = []

    @property
    def answered(self) -> bool:
        return self._answered

    async def stop(self) -> None:
        for media_socket in self._media_sockets:
            try:
                media_socket.close()
            except Exception:
                pass
        self._media_sockets.clear()
        await super().stop()

    async def answer(self, timeout: float = 2.0) -> dict[str, Any]:
        """Accept the pending INVITE so the originating call stops forking/ringing."""
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
            return {
                "ok": False,
                "error": "sip_invite_missing",
                "registered": self.registered,
            }
        if self._answered:
            return {
                "ok": True,
                "method": "sip_answer",
                "already_answered": True,
                "ack": self._ack_event.is_set(),
            }

        body = self._build_sdp_answer(invite)
        await self._send_invite_ok(invite, body)
        self._answered = True
        _LOGGER.info("Domonap panel SIP INVITE answered with 200 OK")

        # Do not hold the relay opening for long.  ACK normally arrives on the
        # same TCP connection almost immediately; end() will wait once more.
        try:
            await asyncio.wait_for(self._ack_event.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            _LOGGER.debug("Panel SIP ACK not received before relay request")

        return {
            "ok": True,
            "method": "sip_answer",
            "ack": self._ack_event.is_set(),
        }

    async def end(self, timeout: float = 2.0) -> dict[str, Any]:
        """End an answered panel call with BYE; reject only if never answered."""
        if not self._answered:
            return await super().end(timeout=timeout)
        if self._ended:
            return {
                "ok": True,
                "registered": self.registered,
                "method": "sip_bye",
                "already_ended": True,
            }

        if not self._ack_event.is_set():
            try:
                await asyncio.wait_for(self._ack_event.wait(), timeout=min(timeout, 1.0))
            except asyncio.TimeoutError:
                _LOGGER.warning("Panel SIP ACK timeout; sending BYE anyway")

        try:
            await self._send_bye()
        except Exception as err:
            _LOGGER.warning("Failed to send panel SIP BYE: %s", err)
            return {
                "ok": False,
                "error": str(err),
                "registered": self.registered,
                "method": "sip_bye",
            }

        _LOGGER.info("Domonap panel SIP BYE sent")
        try:
            await asyncio.wait_for(self._bye_response_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return {
                "ok": False,
                "error": "sip_bye_response_timeout",
                "registered": self.registered,
                "method": "sip_bye",
                "ack": self._ack_event.is_set(),
            }

        status = self._bye_response_status or 0
        ok = 200 <= status < 300
        if ok:
            self._ended = True
            _LOGGER.info("Domonap panel SIP BYE accepted with %s", status)
        else:
            _LOGGER.warning("Domonap panel SIP BYE failed with %s", status)
        return {
            "ok": ok,
            "status": status,
            "registered": self.registered,
            "method": "sip_bye",
            "ack": self._ack_event.is_set(),
        }

    async def _handle_message(self, message: _SipMessage) -> None:
        if message.start_line.startswith("SIP/2.0"):
            cseq = message.first("cseq") or ""
            if cseq.upper().endswith(" BYE"):
                self._bye_response_status = self._status_code(message)
                self._bye_response_event.set()
                _LOGGER.debug(
                    "Panel SIP BYE response: %s", self._bye_response_status
                )
                return
        else:
            method = message.start_line.split(" ", 1)[0].upper()
            if method == "ACK":
                self._ack_event.set()
                _LOGGER.debug("Panel SIP ACK received")
                return

        await super()._handle_message(message)

    async def _send_invite_ok(self, invite: _SipMessage, body: bytes) -> None:
        headers = self._dialog_response_headers(invite)
        host = self._format_host(self._local_host)
        headers.extend(
            [
                f"Contact: <sip:{self._account}@{host}:{self._local_port};transport=tcp>",
                "Content-Type: application/sdp",
                "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS",
                "Supported: replaces",
                "User-Agent: Domonap Home Assistant",
            ]
        )
        await self._send("SIP/2.0 200 OK", headers, body)

    def _dialog_response_headers(self, request: _SipMessage) -> list[str]:
        headers: list[str] = []
        for via in request.headers.get("via", []) or request.headers.get("v", []):
            headers.append(f"Via: {via}")
        for name in ("from", "to", "call-id", "cseq"):
            value = request.first(name)
            if value is None:
                continue
            if name == "to" and ";tag=" not in value.lower():
                value = f"{value};tag={self._to_tag}"
            headers.append(f"{self._display_header(name)}: {value}")
        return headers

    async def _send_bye(self) -> None:
        invite = self._invite
        if invite is None:
            raise RuntimeError("No SIP INVITE available for BYE")

        remote_target = self._extract_uri(invite.first("contact"))
        if remote_target is None:
            remote_target = self._extract_uri(invite.first("from"))
        if remote_target is None:
            raise RuntimeError("Incoming SIP dialog has no remote target")

        local_to = invite.first("to")
        remote_from = invite.first("from")
        call_id = invite.first("call-id")
        if not local_to or not remote_from or not call_id:
            raise RuntimeError("Incoming SIP dialog identifiers are incomplete")
        if ";tag=" not in local_to.lower():
            local_to = f"{local_to};tag={self._to_tag}"

        host = self._format_host(self._local_host)
        branch = f"z9hG4bK{token_hex(12)}"
        headers = [
            f"Via: SIP/2.0/TCP {host}:{self._local_port};branch={branch};rport;alias",
            "Max-Forwards: 70",
            f"From: {local_to}",
            f"To: {remote_from}",
            f"Call-ID: {call_id}",
            f"CSeq: {self._bye_cseq} BYE",
            "User-Agent: Domonap Home Assistant",
        ]
        # A UAS constructs its route set from Record-Route in the received
        # INVITE.  Domonap uses loose routing; keeping these headers makes the
        # in-dialog BYE follow the same proxy path as Linphone.
        for route in invite.headers.get("record-route", []):
            headers.append(f"Route: {route}")

        self._bye_response_event.clear()
        self._bye_response_status = None
        await self._send(f"BYE {remote_target} SIP/2.0", headers)
        self._bye_cseq += 1

    def _build_sdp_answer(self, invite: _SipMessage) -> bytes:
        """Build a minimal audio-only SDP answer for the incoming offer.

        We do not need media in Home Assistant, but a 2xx response to an INVITE
        containing an SDP offer must contain a valid SDP answer.  An offered
        plain RTP audio stream gets a real local UDP port and is marked recvonly;
        all other media streams are rejected with port 0.
        """
        offer = invite.body.decode("utf-8", errors="replace")
        lines = [line.strip() for line in offer.replace("\r", "").split("\n") if line.strip()]

        host = self._local_host
        addr_type = "IP6" if ":" in host else "IP4"
        stamp = int(time.time() * 1000)
        answer = [
            "v=0",
            f"o=- {stamp} {stamp} IN {addr_type} {host}",
            "s=Domonap",
            f"c=IN {addr_type} {host}",
            "t=0 0",
        ]

        sections: list[list[str]] = []
        current: list[str] | None = None
        for line in lines:
            if line.startswith("m="):
                current = [line]
                sections.append(current)
            elif current is not None:
                current.append(line)

        audio_accepted = False
        for section in sections:
            parts = section[0][2:].split()
            if len(parts) < 4:
                continue
            media, _remote_port, proto, *formats = parts
            plain_rtp = proto.upper() in ("RTP/AVP", "RTP/AVPF")
            if media.lower() == "audio" and plain_rtp and not audio_accepted:
                media_socket = self._allocate_media_socket(host)
                port = int(media_socket.getsockname()[1])
                self._media_sockets.append(media_socket)
                answer.append(f"m=audio {port} {proto} {' '.join(formats)}")
                answer.append(f"c=IN {addr_type} {host}")
                for attribute in section[1:]:
                    lower = attribute.lower()
                    if lower.startswith(("a=rtpmap:", "a=fmtp:", "a=rtcp-fb:")):
                        answer.append(attribute)
                    elif lower == "a=rtcp-mux":
                        answer.append(attribute)
                answer.append("a=recvonly")
                audio_accepted = True
            else:
                answer.append(f"m={media} 0 {proto} {' '.join(formats)}")

        if not sections:
            _LOGGER.warning("Incoming panel SIP INVITE has no SDP media sections")
        elif not audio_accepted:
            _LOGGER.warning("Panel SIP offer has no supported plain RTP audio stream")

        return ("\r\n".join(answer) + "\r\n").encode("utf-8")

    @staticmethod
    def _allocate_media_socket(host: str) -> socket.socket:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        media_socket = socket.socket(family, socket.SOCK_DGRAM)
        media_socket.setblocking(False)
        if family == socket.AF_INET6:
            media_socket.bind((host, 0, 0, 0))
        else:
            media_socket.bind((host, 0))
        return media_socket

    @staticmethod
    def _extract_uri(value: str | None) -> str | None:
        if not value:
            return None
        match = _SIP_URI_RE.search(value)
        if not match:
            return None
        return match.group(1) or match.group(2)
