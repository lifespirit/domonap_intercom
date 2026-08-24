import importlib.util
import sys
import types
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "custom_components" / "domonap"

custom_components = types.ModuleType("custom_components")
custom_components.__path__ = [str(ROOT / "custom_components")]
sys.modules.setdefault("custom_components", custom_components)

domonap_pkg = types.ModuleType("custom_components.domonap")
domonap_pkg.__path__ = [str(PKG)]
sys.modules.setdefault("custom_components.domonap", domonap_pkg)


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, PKG / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sip = load_module("custom_components.domonap.sip", "sip.py")
external_sip = load_module(
    "custom_components.domonap.external_sip_signaling",
    "external_sip_signaling.py",
)


class ExternalSipContractTests(unittest.IsolatedAsyncioTestCase):
    def test_parse_host_port(self):
        self.assertEqual(
            external_sip.parse_host_port("192.168.10.1:5060"),
            ("192.168.10.1", 5060),
        )
        self.assertEqual(
            external_sip.parse_host_port("asterisk.lan"),
            ("asterisk.lan", 5060),
        )

    def test_sip_info_digit(self):
        self.assertEqual(
            external_sip.parse_info_dtmf(b"Signal=1\r\nDuration=160\r\n"),
            "1",
        )

    def test_signaling_module_has_no_rtp_bridge(self):
        self.assertFalse(hasattr(external_sip, "RtpBridge"))
        self.assertFalse(hasattr(external_sip, "parse_rfc2833_event"))
        self.assertFalse(hasattr(external_sip, "build_payload_map"))

    def test_sip_encoder_keeps_sdp_bytes_unchanged(self):
        body = (
            b"v=0\r\n"
            b"c=IN IP4 203.0.113.10\r\n"
            b"m=audio 40000 RTP/AVP 8 101\r\n"
            b"a=rtpmap:8 PCMA/8000\r\n"
        )
        packet = external_sip.AsteriskSipAccount._encode(
            "INVITE sip:100@asterisk SIP/2.0",
            ["Call-ID: test", "CSeq: 1 INVITE"],
            body,
        )
        self.assertTrue(packet.endswith(body))
        self.assertIn(f"Content-Length: {len(body)}".encode(), packet)

    async def test_asterisk_answer_is_passed_to_panel_without_rewrite(self):
        panel_offer = (
            b"v=0\r\n"
            b"c=IN IP4 198.51.100.20\r\n"
            b"m=audio 41000 RTP/AVP 8\r\n"
        )
        asterisk_answer = (
            b"v=0\r\n"
            b"c=IN IP4 192.168.10.1\r\n"
            b"m=audio 18042 RTP/AVP 8\r\n"
            b"a=rtpmap:8 PCMA/8000\r\n"
        )

        class FakePanelCall:
            sdp_offer = panel_offer

            def __init__(self):
                self.answer = None

            async def wait_for_invite(self, timeout=8.0):
                return True

            async def answer_with_sdp(self, body, timeout=2.0):
                self.answer = bytes(body)
                return {"ok": True}

        class FakeAccount:
            config = SimpleNamespace(
                call_number="100",
                host="192.168.10.1",
                port=5060,
                user="10",
            )

            @staticmethod
            def _status(message):
                return 200

            async def clear_call(self, call):
                return None

        panel = FakePanelCall()
        account = FakeAccount()

        async def noop_dtmf(digit):
            return None

        async def noop_hangup():
            return None

        call = external_sip.AsteriskSignalingCall(
            account,
            panel,
            domonap_call_id="domonap-call",
            on_dtmf=noop_dtmf,
            on_hangup=noop_hangup,
        )
        captured_offer = None

        async def fake_invite(body):
            nonlocal captured_offer
            captured_offer = bytes(body)
            return sip._SipMessage(
                "SIP/2.0 200 OK",
                {
                    "from": ["<sip:10@192.168.10.1>;tag=local"],
                    "to": ["<sip:100@192.168.10.1>;tag=remote"],
                    "call-id": ["external-call"],
                    "cseq": ["1 INVITE"],
                    "contact": ["<sip:100@192.168.10.1:5060>"],
                },
                asterisk_answer,
            )

        async def fake_ack(response):
            return None

        call._invite = fake_invite
        call._send_ack = fake_ack
        await call._run()

        self.assertEqual(captured_offer, panel_offer)
        self.assertEqual(panel.answer, asterisk_answer)
        self.assertTrue(call.established)


if __name__ == "__main__":
    unittest.main()
