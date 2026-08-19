import importlib.util
import sys
import types
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "custom_components" / "domonap"

custom_components = sys.modules.setdefault("custom_components", types.ModuleType("custom_components"))
custom_components.__path__ = [str(ROOT / "custom_components")]
domonap_pkg = sys.modules.setdefault("custom_components.domonap", types.ModuleType("custom_components.domonap"))
domonap_pkg.__path__ = [str(PKG)]

# Minimal Home Assistant stubs needed by const.py and notify_consumer.py.
homeassistant = types.ModuleType("homeassistant")
homeassistant_core = types.ModuleType("homeassistant.core")
homeassistant_core.HomeAssistant = object

homeassistant_const = types.ModuleType("homeassistant.const")


class Platform:
    BUTTON = "button"
    CAMERA = "camera"
    BINARY_SENSOR = "binary_sensor"
    SENSOR = "sensor"
    IMAGE = "image"


homeassistant_const.Platform = Platform
sys.modules.setdefault("homeassistant", homeassistant)
sys.modules.setdefault("homeassistant.core", homeassistant_core)
sys.modules.setdefault("homeassistant.const", homeassistant_const)


def load_module(name: str, filename: str):
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, PKG / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


load_module("custom_components.domonap.api", "api.py")
const = load_module("custom_components.domonap.const", "const.py")
aosp_mod = load_module("custom_components.domonap.aosp_api", "aosp_api.py")
notify_mod = load_module("custom_components.domonap.notify_consumer", "notify_consumer.py")

AospIntercomAPI = aosp_mod.AospIntercomAPI
IntercomNotifyConsumer = notify_mod.IntercomNotifyConsumer


class FakeBus:
    def __init__(self):
        self.events = []

    def fire(self, event_type, data):
        self.events.append((event_type, data))


class FakeHass:
    def __init__(self):
        self.bus = FakeBus()


class FakeWs:
    def __init__(self):
        self.closed = False
        self.close_calls = 0

    async def close(self, *args, **kwargs):
        self.close_calls += 1
        self.closed = True


class AospSignalRContractTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.hass = FakeHass()
        self.api = AospIntercomAPI(instance_id="0123456789abcdef")
        self.api.access_token = "access"
        self.consumer = IntercomNotifyConsumer(self.hass, self.api)

    def test_direct_hub_url_and_apk_timeouts(self):
        self.assertEqual(const.WS_URL, "wss://api.domonap.ru/notificationHub")
        self.assertEqual(const.WS_HANDSHAKE_TIMEOUT, 100)
        self.assertEqual(const.WS_KEEPALIVE_INTERVAL, 3)
        self.assertEqual(const.WS_SERVER_TIMEOUT, 300)
        self.assertNotIn("?id=", const.WS_URL)

    async def test_calling_fires_incoming_call_immediately(self):
        ws = FakeWs()
        data = {
            "target": "ReceivePush",
            "arguments": [
                "Doorbell",
                "Incoming call",
                {
                    "EventMessage": "DomofonCalling",
                    "DoorId": "door-1",
                    "CallId": "call-1",
                    "VideoPreview": "https://example.invalid/preview.jpg",
                },
            ],
        }
        await self.consumer._handle_invocation(data, ws)
        self.assertEqual(len(self.hass.bus.events), 1)
        event_type, payload = self.hass.bus.events[0]
        self.assertEqual(event_type, const.EVENT_INCOMING_CALL)
        self.assertEqual(payload["DoorId"], "door-1")
        self.assertEqual(payload["Title"], "Doorbell")
        self.assertEqual(payload["Body"], "Incoming call")
        self.assertEqual(payload["PhotoUrl"], payload["VideoPreview"])
        self.assertEqual(ws.close_calls, 0)

    async def test_call_ended_is_event_not_reconnect(self):
        ws = FakeWs()
        data = {
            "target": "ReceivePush",
            "arguments": [
                "",
                "",
                {"EventMessage": "DomofonCallEnded", "CallId": "call-1"},
            ],
        }
        await self.consumer._handle_invocation(data, ws)
        self.assertEqual(self.hass.bus.events[0][0], const.EVENT_CALL_ENDED)
        self.assertEqual(ws.close_calls, 0)

    async def test_call_answered_has_separate_event(self):
        ws = FakeWs()
        data = {
            "target": "ReceivePush",
            "arguments": [
                "",
                "",
                {"EventMessage": "DomofonCallAnswered", "CallId": "call-1"},
            ],
        }
        await self.consumer._handle_invocation(data, ws)
        self.assertEqual(self.hass.bus.events[0][0], const.EVENT_CALL_ANSWERED)
        self.assertEqual(ws.close_calls, 0)

    async def test_signalr_close_message_closes_transport(self):
        ws = FakeWs()
        await self.consumer._handle_record('{"type":7,"error":"bye"}', ws)
        self.assertEqual(ws.close_calls, 1)


if __name__ == "__main__":
    unittest.main()
