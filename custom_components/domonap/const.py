from homeassistant.const import Platform


DOMAIN = "domonap"
API = "api"
CONF_COUNTRY_CODE = "country_code"
CONF_PHONE_NUMBER = "phone_number"
CONF_CONFIRM_CODE = "confirm_code"

PARAM_ACCESS_TOKEN = "access_token"
PARAM_REFRESH_TOKEN = "refresh_token"
PARAM_REFRESH_EXPIRATION = "refresh_expiration_date"
# Legacy mobile/FCM-HMS field. Kept only so schema migration can remove it.
PARAM_DEVICE_TOKEN = "device_token"
PARAM_INSTANCE_ID = "instance_id"
PARAM_WEBRTC_PROXY_SECRET = "webrtc_proxy_secret"

EVENT_INCOMING_CALL = "domonap_incoming_call"
EVENT_CALL_ANSWERED = "domonap_call_answered"
EVENT_CALL_ENDED = "domonap_call_ended"
WEBRTC_PROXY = "webrtc_proxy"
MEDIA_PROXY = "media_proxy"

PLATFORMS: list[Platform] = [
    Platform.BUTTON,
    Platform.CAMERA,
    Platform.BINARY_SENSOR,
    Platform.SENSOR,
    Platform.IMAGE,
]

RESET_DELAY = 10  # seconds

WS_MESSAGE_END = "\x1e"
WS_HANDSHAKE_MESSAGE = '{"protocol":"json","version":1}' + WS_MESSAGE_END
WS_PING_MESSAGE = '{"type":6}' + WS_MESSAGE_END
# prodAospRelease uses shouldSkipNegotiate(true) + WebSockets only, so there is
# no /negotiate request and no ?id=<connectionToken> suffix.
WS_URL = "wss://api.domonap.ru/notificationHub"

# Values recovered from the prodAospRelease tablet APK.
WS_HANDSHAKE_TIMEOUT = 100  # seconds
WS_KEEPALIVE_INTERVAL = 3  # seconds
WS_SERVER_TIMEOUT = 300  # seconds
WS_RECONNECT_INITIAL = 2  # initial service start delay
WS_RECONNECT_MAX = 60
