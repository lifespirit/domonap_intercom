from __future__ import annotations

import asyncio
import logging
import re
import time
from secrets import token_hex
from typing import Any

from .sip import DomonapSipCall, _SipMessage

_LOGGER = logging.getLogger(__name__)

_SIP_URI_RE = re.compile(r"<(sips?:[^>]+)>|(sips?:[^;,\s]+)", re.IGNORECASE)


class RubetekPanelSipCall(DomonapSipCall):
    """Panel SIP leg with the lifecycle used by the Rubetek APK.

    The generic DomonapSipCall from main is intentionally left untouched. For
    optional Asterisk forwarding this class exposes the original SDP offer and
    accepts an externally supplied SDP answer. It never proxies RTP itself.

    The APK treats the SIP account as a per-call object: after terminating the
    current dialog it disables registration/removes the account and stops the SIP
    core. ``destroy()`` mirrors that behavior by terminating the dialog, sending
    REGISTER with Expires: 0 and only then closing the TCP session.
    """

    def __init__(self, account: str, password: str, domain: str, port: int) -> None:
        super().__init__(account, password, domain, port)
        self._answered = False
        self._ack_event = asyncio.Event()
        self._bye_response_event = asyncio.Event()
        self._bye_response_status: int | None = None
        self._bye_cseq = 1
        self._unregister_response_event = asyncio.Event()
        self._unregister_response: _SipMessage | None = None
        self._unregister_cseq: int | None = None
        self._destroy_lock = asyncio.Lock()
        self._destroyed = False

    @property
    def answered(self) -> bool:
        return self._answered

    @property
    def sdp_offer(self) -> bytes:
        invite = self._invite
        return invite.body if invite is not None else b""

    async def wait_for_invite(self, timeout: float = 8.0) -> bool:
        self.start()
        try:
            await asyncio.wait_for(self._invite_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return False
        return self._invite is not None

    async def answer(
        self,
        timeout: float = 2.0,
        *,
        direction: str = "recvonly",
    ) -> dict[str, Any]:
        """Accept the pending INVITE without setting up an RTP endpoint.

        This path is used when external SIP forwarding is disabled. The call is
        answered only so the relay-open flow can reproduce the panel lifecycle,
        then it is immediately terminated. SDP therefore advertises discard
        port 9 instead of opening a media socket in Home Assistant.
        """
        invite = await self._wait_invite(timeout)
        if isinstance(invite, dict):
            return invite
        if self._answered:
            return self._already_answered_result()
        if direction not in ("recvonly", "sendrecv", "inactive"):
            raise ValueError(f"Unsupported SIP media direction: {direction}")

        body = self._build_no_media_sdp_answer(invite, direction=direction)
        return await self._answer_with_body(invite, body, description=direction)

    async def answer_with_sdp(
        self,
        sdp_answer: bytes | str,
        *,
        timeout: float = 2.0,
    ) -> dict[str, Any]:
        """Accept the Domonap INVITE with Asterisk's SDP answer unchanged.

        No RTP address, port, payload type or codec is rewritten here. Asterisk
        is therefore the media endpoint visible to Domonap and is responsible
        for RTP/NAT/transcoding toward the final extension.
        """
        invite = await self._wait_invite(timeout)
        if isinstance(invite, dict):
            return invite
        if self._answered:
            return self._already_answered_result()

        body = sdp_answer.encode() if isinstance(sdp_answer, str) else bytes(sdp_answer)
        if not body:
            return {
                "ok": False,
                "error": "external_sip_answer_has_no_sdp",
                "registered": self.registered,
            }
        return await self._answer_with_body(
            invite,
            body,
            description="external-sdp-pass-through",
        )

    async def _wait_invite(self, timeout: float) -> _SipMessage | dict[str, Any]:
        self.start()
        try:
            await asyncio.wait_for(self._invite_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return {
                "ok": False,
                "error": "sip_invite_timeout",
                "registered": self.registered,
            }
        if self._invite is None:
            return {
                "ok": False,
                "error": "sip_invite_missing",
                "registered": self.registered,
            }
        return self._invite

    async def _answer_with_body(
        self,
        invite: _SipMessage,
        body: bytes,
        *,
        description: str,
    ) -> dict[str, Any]:
        await self._send_invite_ok(invite, body)
        self._answered = True
        _LOGGER.info(
            "Domonap panel SIP INVITE answered with 200 OK mode=%s",
            description,
        )

        try:
            await asyncio.wait_for(self._ack_event.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            _LOGGER.debug("Panel SIP ACK not received before continuation")

        return {
            "ok": True,
            "method": "sip_answer",
            "ack": self._ack_event.is_set(),
            "mode": description,
        }

    def _already_answered_result(self) -> dict[str, Any]:
        return {
            "ok": True,
            "method": "sip_answer",
            "already_answered": True,
            "ack": self._ack_event.is_set(),
        }

    async def end(self, timeout: float = 2.0) -> dict[str, Any]:
        """Terminate the current SIP dialog but keep registration alive."""
        if not self._answered:
            _LOGGER.debug("Panel SIP dialog is still ringing; terminating as reject")
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

    async def unregister(self, timeout: float = 2.0) -> dict[str, Any]:
        """Remove the temporary per-call SIP registration.

        The APK disables registration and removes the account when a call session
        is destroyed. On the wire the equivalent operation is REGISTER with
        Expires: 0 for the same Contact.
        """
        if not self.registered:
            return {
                "ok": True,
                "skipped": True,
                "reason": "not_registered",
                "method": "sip_unregister",
            }
        if self._writer is None:
            return {
                "ok": False,
                "error": "sip_connection_closed_before_unregister",
                "method": "sip_unregister",
            }

        response: _SipMessage | None = None
        for attempt in range(2):
            self._cseq += 1
            cseq = self._cseq
            self._unregister_cseq = cseq
            self._unregister_response = None
            self._unregister_response_event.clear()

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
                f"CSeq: {cseq} REGISTER",
                f"Contact: <{contact}>;expires=0",
                "Expires: 0",
                "Supported: path, outbound, gruu",
                "User-Agent: Domonap Home Assistant",
            ]
            if self._auth is not None:
                authorization = self._digest_authorization("REGISTER", request_uri)
                headers.append(f"{self._auth_header}: {authorization}")

            _LOGGER.info("Domonap panel SIP UNREGISTER sent (CSeq=%s)", cseq)
            await self._send(f"REGISTER {request_uri} SIP/2.0", headers)
            try:
                await asyncio.wait_for(
                    self._unregister_response_event.wait(), timeout=timeout
                )
            except asyncio.TimeoutError:
                _LOGGER.warning("Domonap panel SIP UNREGISTER response timeout")
                return {
                    "ok": False,
                    "error": "sip_unregister_response_timeout",
                    "method": "sip_unregister",
                }

            response = self._unregister_response
            if response is None:
                return {
                    "ok": False,
                    "error": "sip_unregister_response_missing",
                    "method": "sip_unregister",
                }

            status = self._status_code(response)
            if status in (401, 407) and attempt == 0:
                challenge_name = (
                    "www-authenticate" if status == 401 else "proxy-authenticate"
                )
                challenge = response.first(challenge_name)
                if not challenge:
                    return {
                        "ok": False,
                        "status": status,
                        "error": "sip_unregister_auth_challenge_missing",
                        "method": "sip_unregister",
                    }
                self._auth = self._parse_digest(challenge)
                self._auth_header = (
                    "Authorization" if status == 401 else "Proxy-Authorization"
                )
                continue

            ok = 200 <= status < 300
            if ok:
                self._registered_event.clear()
                _LOGGER.info("Domonap panel SIP registration removed with %s", status)
            else:
                _LOGGER.warning("Domonap panel SIP UNREGISTER failed with %s", status)
            return {
                "ok": ok,
                "status": status,
                "method": "sip_unregister",
            }

        status = self._status_code(response) if response is not None else 0
        return {
            "ok": False,
            "status": status,
            "method": "sip_unregister",
        }

    async def destroy(
        self,
        *,
        timeout: float = 2.0,
        terminate_dialog: bool = True,
        reason: str = "call_end",
    ) -> dict[str, Any]:
        """Terminate dialog, unregister account and close the SIP TCP session."""
        async with self._destroy_lock:
            if self._destroyed:
                return {
                    "ok": True,
                    "already_destroyed": True,
                    "method": "sip_destroy",
                }

            _LOGGER.info(
                "Destroying Domonap panel SIP session reason=%s answered=%s invite=%s registered=%s",
                reason,
                self._answered,
                self.has_invite,
                self.registered,
            )

            terminate_result: dict[str, Any] | None = None
            if terminate_dialog and self.has_invite and not self._ended:
                try:
                    terminate_result = await self.end(timeout=timeout)
                except Exception as err:
                    _LOGGER.warning("Panel SIP dialog termination failed: %s", err)
                    terminate_result = {"ok": False, "error": str(err)}

            try:
                unregister_result = await self.unregister(timeout=timeout)
            except Exception as err:
                _LOGGER.warning("Panel SIP unregister failed: %s", err)
                unregister_result = {"ok": False, "error": str(err)}

            await self.stop()
            self._destroyed = True
            self._invite = None
            self._invite_event.set()

            terminate_ok = (
                terminate_result is None
                or (isinstance(terminate_result, dict) and terminate_result.get("ok") is True)
            )
            unregister_ok = (
                isinstance(unregister_result, dict)
                and unregister_result.get("ok") is True
            )
            result = {
                "ok": terminate_ok and unregister_ok,
                "method": "sip_destroy",
                "terminate": terminate_result,
                "unregister": unregister_result,
            }
            _LOGGER.info(
                "Domonap panel SIP session destroyed terminate_ok=%s unregister_ok=%s",
                terminate_ok,
                unregister_ok,
            )
            return result

    async def _handle_message(self, message: _SipMessage) -> None:
        if message.start_line.startswith("SIP/2.0"):
            cseq = message.first("cseq") or ""
            cseq_upper = cseq.upper()
            if cseq_upper.endswith(" BYE"):
                self._bye_response_status = self._status_code(message)
                self._bye_response_event.set()
                _LOGGER.debug(
                    "Panel SIP BYE response: %s", self._bye_response_status
                )
                return
            if cseq_upper.endswith(" REGISTER") and self._unregister_cseq is not None:
                try:
                    response_cseq = int(cseq.split(None, 1)[0])
                except (ValueError, IndexError):
                    response_cseq = -1
                if response_cseq == self._unregister_cseq:
                    self._unregister_response = message
                    self._unregister_response_event.set()
                    _LOGGER.debug(
                        "Panel SIP UNREGISTER response: %s",
                        self._status_code(message),
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
        for route in invite.headers.get("record-route", []):
            headers.append(f"Route: {route}")

        self._bye_response_event.clear()
        self._bye_response_status = None
        await self._send(f"BYE {remote_target} SIP/2.0", headers)
        self._bye_cseq += 1

    def _build_no_media_sdp_answer(
        self,
        invite: _SipMessage,
        *,
        direction: str,
    ) -> bytes:
        """Build an audio answer using the discard port instead of an RTP socket."""
        offer = invite.body.decode("utf-8", errors="replace")
        lines = [
            line.strip()
            for line in offer.replace("\r", "").split("\n")
            if line.strip()
        ]
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
                answer.append(f"m=audio 9 {proto} {' '.join(formats)}")
                answer.append(f"c=IN {addr_type} {host}")
                for attribute in section[1:]:
                    lower = attribute.lower()
                    if lower.startswith(("a=rtpmap:", "a=fmtp:", "a=rtcp-fb:")):
                        answer.append(attribute)
                answer.append(f"a={direction}")
                audio_accepted = True
            else:
                answer.append(f"m={media} 0 {proto} {' '.join(formats)}")

        if not sections:
            _LOGGER.warning("Incoming panel SIP INVITE has no SDP media sections")
        elif not audio_accepted:
            _LOGGER.warning("Panel SIP offer has no supported plain RTP audio stream")

        return ("\r\n".join(answer) + "\r\n").encode("utf-8")

    @staticmethod
    def _extract_uri(value: str | None) -> str | None:
        if not value:
            return None
        match = _SIP_URI_RE.search(value)
        if not match:
            return None
        return match.group(1) or match.group(2)
