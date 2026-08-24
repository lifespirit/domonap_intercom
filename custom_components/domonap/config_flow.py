from homeassistant import config_entries
import voluptuous as vol
import re
from secrets import token_urlsafe
from typing import Any, Optional

from .const import (
    DOMAIN,
    CONF_COUNTRY_CODE,
    CONF_PHONE_NUMBER,
    CONF_CONFIRM_CODE,
    CONF_AUTH_MODE,
    AUTH_MODE_PHONE,
    AUTH_MODE_PANEL,
    PARAM_REFRESH_EXPIRATION,
    PARAM_REFRESH_TOKEN,
    PARAM_ACCESS_TOKEN,
    PARAM_WEBRTC_PROXY_SECRET,
    PARAM_DEVICE_TOKEN,
    PARAM_INSTANCE_ID,
    PARAM_AUTH_MODE,
    PARAM_PANEL_USER_ID,
    PARAM_PANEL_NAME,
)
from .api import IntercomAPI, is_android_guid
from .panel_api import RubetekPanelIntercomAPI


class IntercomFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    # Keep schema version 1: old entries remain valid and default to phone mode.
    VERSION = 1

    def __init__(self):
        self._auth_mode = AUTH_MODE_PHONE
        self._country_code = None
        self._phone_number = None
        self._confirm_code = None
        self._api = IntercomAPI()
        self._reauth_entry = None

    async def async_step_reauth(self, entry_data: dict[str, Any]):
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        self._auth_mode = entry_data.get(PARAM_AUTH_MODE, AUTH_MODE_PHONE)

        if self._auth_mode == AUTH_MODE_PANEL:
            self._api = RubetekPanelIntercomAPI(
                instance_id=entry_data.get(PARAM_INSTANCE_ID),
            )
            return await self.async_step_panel()

        # Legacy phone/SMS reauth path stays behavior-compatible with main.
        self._country_code = entry_data.get(CONF_COUNTRY_CODE)
        self._phone_number = entry_data.get(CONF_PHONE_NUMBER)
        stored_device_token = entry_data.get(PARAM_DEVICE_TOKEN)
        self._api = IntercomAPI(
            device_token=(
                stored_device_token if is_android_guid(stored_device_token) else None
            ),
            instance_id=entry_data.get(PARAM_INSTANCE_ID),
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        errors = {}
        if user_input is not None:
            if not self._country_code or not self._phone_number:
                self._auth_mode = AUTH_MODE_PHONE
                return await self.async_step_phone()
            response = await self._send_authorization_code()
            if response is not True:
                errors["base"] = "authorization_failed"
            else:
                return await self.async_step_confirm()

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema({}),
            errors=errors,
        )

    async def async_step_user(self, user_input=None):
        """Choose authentication profile for a new integration entry."""
        if user_input is not None:
            self._auth_mode = user_input[CONF_AUTH_MODE]
            if self._auth_mode == AUTH_MODE_PANEL:
                self._api = RubetekPanelIntercomAPI()
                return await self.async_step_panel()
            self._api = IntercomAPI()
            return await self.async_step_phone()

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(
                        CONF_AUTH_MODE, default=AUTH_MODE_PHONE
                    ): vol.In([AUTH_MODE_PHONE, AUTH_MODE_PANEL])
                }
            ),
        )

    async def async_step_phone(self, user_input=None):
        """Original phone + SMS authorization path."""
        errors = {}
        if user_input is not None:
            self._country_code = self._sanitize_number(user_input[CONF_COUNTRY_CODE])
            self._phone_number = self._sanitize_number(user_input[CONF_PHONE_NUMBER])

            response = await self._send_authorization_code()
            if response is not True:
                errors["base"] = "authorization_failed"
            else:
                return await self.async_step_confirm()

        data_schema = vol.Schema({
            vol.Required(CONF_COUNTRY_CODE): str,
            vol.Required(CONF_PHONE_NUMBER): str,
        })

        return self.async_show_form(
            step_id="phone", data_schema=data_schema, errors=errors
        )

    async def async_step_confirm(self, user_input=None):
        """Original SMS confirmation path, kept isolated from panel auth."""
        errors = {}
        if user_input is not None:
            self._confirm_code = user_input[CONF_CONFIRM_CODE]

            response = await self._api.confirm_authorization(
                self._country_code, self._phone_number, self._confirm_code
            )
            if (
                not self._api.access_token
                or not self._api.refresh_token
                or (
                    isinstance(response, dict)
                    and ("errorText" in response or "error" in response)
                )
            ):
                errors["base"] = "confirmation_failed"
            else:
                data = self._entry_data_phone()
                title = "+" + self._country_code + " " + self._phone_number
                if self._reauth_entry is not None:
                    self.hass.config_entries.async_update_entry(
                        self._reauth_entry,
                        title=title,
                        data=data,
                    )
                    await self.hass.config_entries.async_reload(
                        self._reauth_entry.entry_id
                    )
                    return self.async_abort(reason="reauth_successful")
                return self.async_create_entry(title=title, data=data)

        return self.async_show_form(
            step_id="confirm",
            data_schema=vol.Schema({vol.Required(CONF_CONFIRM_CODE): str}),
            errors=errors,
        )

    async def async_step_panel(self, user_input=None):
        """Rubetek panel provisioning code flow."""
        errors = {}
        if user_input is not None:
            confirm_code = self._sanitize_number(user_input[CONF_CONFIRM_CODE])
            if len(confirm_code) != 8:
                errors["base"] = "invalid_panel_code"
            else:
                if not isinstance(self._api, RubetekPanelIntercomAPI):
                    self._api = RubetekPanelIntercomAPI(
                        instance_id=(
                            self._reauth_entry.data.get(PARAM_INSTANCE_ID)
                            if self._reauth_entry is not None
                            else None
                        )
                    )
                response = await self._api.confirm_panel_authorization(confirm_code)
                if (
                    not self._api.access_token
                    or not self._api.refresh_token
                    or (
                        isinstance(response, dict)
                        and ("errorText" in response or "error" in response)
                    )
                ):
                    errors["base"] = "panel_confirmation_failed"
                else:
                    data = self._entry_data_panel()
                    panel_name = self._api.panel.get("name") or "Rubetek Panel"
                    if self._reauth_entry is not None:
                        self.hass.config_entries.async_update_entry(
                            self._reauth_entry,
                            title=panel_name,
                            data=data,
                        )
                        await self.hass.config_entries.async_reload(
                            self._reauth_entry.entry_id
                        )
                        return self.async_abort(reason="reauth_successful")
                    return self.async_create_entry(title=panel_name, data=data)

        return self.async_show_form(
            step_id="panel",
            data_schema=vol.Schema({vol.Required(CONF_CONFIRM_CODE): str}),
            errors=errors,
        )

    def _sanitize_number(self, input_string):
        return re.sub(r'\D', '', input_string)

    async def _send_authorization_code(self):
        return await self._api.authorize(self._country_code, self._phone_number)

    def _entry_data_phone(self) -> dict[str, Optional[str]]:
        data = dict(self._reauth_entry.data) if self._reauth_entry is not None else {}
        data.setdefault(PARAM_WEBRTC_PROXY_SECRET, token_urlsafe(24))
        data.update(
            {
                PARAM_AUTH_MODE: AUTH_MODE_PHONE,
                PARAM_ACCESS_TOKEN: self._api.access_token,
                PARAM_REFRESH_TOKEN: self._api.refresh_token,
                PARAM_REFRESH_EXPIRATION: self._api.refresh_expiration_date,
                PARAM_DEVICE_TOKEN: self._api.device_token,
                PARAM_INSTANCE_ID: self._api.instance_id,
                CONF_COUNTRY_CODE: self._country_code,
                CONF_PHONE_NUMBER: self._phone_number,
            }
        )
        data.pop(PARAM_PANEL_USER_ID, None)
        data.pop(PARAM_PANEL_NAME, None)
        return data

    def _entry_data_panel(self) -> dict[str, Optional[str]]:
        data = dict(self._reauth_entry.data) if self._reauth_entry is not None else {}
        data.setdefault(PARAM_WEBRTC_PROXY_SECRET, token_urlsafe(24))
        data.update(
            {
                PARAM_AUTH_MODE: AUTH_MODE_PANEL,
                PARAM_ACCESS_TOKEN: self._api.access_token,
                PARAM_REFRESH_TOKEN: self._api.refresh_token,
                PARAM_REFRESH_EXPIRATION: self._api.refresh_expiration_date,
                PARAM_INSTANCE_ID: self._api.instance_id,
                PARAM_PANEL_USER_ID: self._api.panel.get("userId"),
                PARAM_PANEL_NAME: self._api.panel.get("name"),
            }
        )
        # Panel provisioning has no mobile push token or phone identity.
        data.pop(PARAM_DEVICE_TOKEN, None)
        data.pop(CONF_COUNTRY_CODE, None)
        data.pop(CONF_PHONE_NUMBER, None)
        return data
