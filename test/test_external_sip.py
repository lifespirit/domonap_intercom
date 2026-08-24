import importlib.util
import sys
import types
import unittest
from pathlib import Path

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


load_module("custom_components.domonap.sip", "sip.py")
external_sip = load_module("custom_components.domonap.external_sip", "external_sip.py")


class ExternalSipContractTests(unittest.TestCase):
    def test_parse_host_port(self):
        self.assertEqual(
            external_sip.parse_host_port("192.168.10.1:5060"),
            ("192.168.10.1", 5060),
        )
        self.assertEqual(
            external_sip.parse_host_port("asterisk.lan"),
            ("asterisk.lan", 5060),
        )

    def test_external_offer_preserves_panel_codec_and_adds_telephone_event(self):
        panel_offer = (
            "v=0\r\n"
            "o=- 1 1 IN IP4 10.0.0.10\r\n"
            "s=-\r\n"
            "c=IN IP4 10.0.0.10\r\n"
            "t=0 0\r\n"
            "m=audio 40000 RTP/AVP 8\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
        )
        offer = external_sip.build_external_sdp_offer(
            panel_offer, "192.168.10.20", 32000
        ).decode()
        self.assertIn("m=audio 32000 RTP/AVP 8 101", offer)
        self.assertIn("a=rtpmap:8 PCMA/8000", offer)
        self.assertIn("a=rtpmap:101 telephone-event/8000", offer)
        self.assertIn("a=sendrecv", offer)

    def test_payload_map_by_codec_name(self):
        panel = external_sip.AudioSdp(
            "10.0.0.1", 10000, "RTP/AVP", [8], {8: "PCMA/8000"}, {}
        )
        asterisk = external_sip.AudioSdp(
            "10.0.0.2", 20000, "RTP/AVP", [96], {96: "PCMA/8000"}, {}
        )
        self.assertEqual(external_sip.build_payload_map(asterisk, panel), {96: 8})
        self.assertEqual(external_sip.build_payload_map(panel, asterisk), {8: 96})

    def test_rfc2833_digit_one(self):
        packet = bytearray(16)
        packet[0] = 0x80
        packet[1] = 101
        packet[4:8] = (1234).to_bytes(4, "big")
        packet[12] = 1
        packet[13] = 0x80
        event = external_sip.parse_rfc2833_event(bytes(packet))
        self.assertEqual(event, (1, True, 1234))
        self.assertEqual(external_sip.rfc2833_digit(event[0]), "1")

    def test_sip_info_digit(self):
        self.assertEqual(
            external_sip.parse_info_dtmf(b"Signal=1\r\nDuration=160\r\n"),
            "1",
        )


if __name__ == "__main__":
    unittest.main()
