"""Utitility functions for communication with 2N devices."""
from __future__ import annotations

import logging
import aiohttp
import asyncio
import hashlib
import secrets
import re

from typing import Any, List
from urllib.parse import urlsplit

from .const import (
    HTTP_CALL_TIMEOUT,
    CONTENT_TYPE,
    API_SYSTEM_INFO,
    API_SYSTEM_STATUS,
    API_SYSTEM_RESTART,
    API_SWITCH_CAPS,
    API_SWITCH_STATUS,
    API_SWITCH_CONTROL,
    API_IO_CAPS,
    API_IO_CONTROL,
    API_IO_STATUS,
    API_AUDIO_TEST,
    API_LOG_CAPS,
    API_LOG_SUBSCRIBE,
    API_LOG_UNSUBSCRIBE,
    API_LOG_PULL,
    API_DIR_TEMPLATE,
    API_DIR_UPDATE,
    API_DIR_QUERY,
)

from .model import Py2NConnectionData, Py2NDeviceSwitch, Py2NDevicePort

from .exceptions import (
    DeviceConnectionError,
    DeviceUnsupportedError,
    ApiError,
    DeviceApiError,
)

_LOGGER = logging.getLogger(__name__)


_DIGEST_PARAM_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,]+))')


def _parse_digest_challenge(challenge: str) -> dict[str, str]:
    if not challenge:
        return {}
    challenge = challenge.strip()
    if challenge.lower().startswith("digest "):
        challenge = challenge[7:]
    parsed: dict[str, str] = {}
    for key, quoted_value, plain_value in _DIGEST_PARAM_RE.findall(challenge):
        parsed[key.lower()] = (quoted_value or plain_value).strip()
    return parsed


def _get_digest_hash(algorithm: str):
    algorithm_map = {
        "md5": hashlib.md5,
        "sha-256": hashlib.sha256,
    }
    return algorithm_map.get(algorithm.lower())


def _build_digest_authorization(
    method: str,
    url: str,
    username: str,
    password: str,
    challenge_header: str,
) -> str | None:
    challenge = _parse_digest_challenge(challenge_header)
    realm = challenge.get("realm")
    nonce = challenge.get("nonce")
    if not realm or not nonce:
        return None

    algorithm = challenge.get("algorithm", "MD5")
    hash_fn = _get_digest_hash(algorithm)
    if hash_fn is None:
        return None

    uri_parts = urlsplit(url)
    digest_uri = uri_parts.path or "/"
    if uri_parts.query:
        digest_uri = f"{digest_uri}?{uri_parts.query}"

    qop = challenge.get("qop")
    if qop:
        qop_values = [value.strip() for value in qop.split(",")]
        qop = "auth" if "auth" in qop_values else qop_values[0]

    cnonce = secrets.token_hex(8)
    nc = "00000001"
    ha1 = hash_fn(f"{username}:{realm}:{password}".encode()).hexdigest()
    ha2 = hash_fn(f"{method.upper()}:{digest_uri}".encode()).hexdigest()
    if qop:
        response = hash_fn(f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode()).hexdigest()
    else:
        response = hash_fn(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()

    auth_fields = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{digest_uri}"',
        f'response="{response}"',
    ]
    if "opaque" in challenge:
        auth_fields.append(f'opaque="{challenge["opaque"]}"')
    auth_fields.append(f'algorithm={algorithm}')
    if qop:
        auth_fields.extend([f"qop={qop}", f"nc={nc}", f'cnonce="{cnonce}"'])
    return "Digest " + ", ".join(auth_fields)


async def _request_with_optional_digest_auth(
    aiohttp_session: aiohttp.ClientSession,
    options: Py2NConnectionData,
    method: str,
    url: str,
    request_kwargs: dict[str, Any],
) -> aiohttp.ClientResponse:
    response = await aiohttp_session.request(method, url, **request_kwargs)
    if options.auth_method != "digest":
        return response

    if response.status != 401:
        return response

    if not options.username or options.password is None:
        return response

    challenge_header = response.headers.get("WWW-Authenticate", "")
    authorization = _build_digest_authorization(
        method, url, options.username, options.password, challenge_header
    )
    if not authorization:
        return response

    response.release()
    retry_kwargs = dict(request_kwargs)
    headers = dict(retry_kwargs.get("headers") or {})
    headers["Authorization"] = authorization
    retry_kwargs["headers"] = headers
    return await aiohttp_session.request(method, url, **retry_kwargs)


async def get_info(
    aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData
) -> dict[str, Any]:
    """Get info from device through REST call."""
    try:
        result = await api_request(
            aiohttp_session, options, f"{API_SYSTEM_INFO}"
        )
    except DeviceApiError as err:
        raise

    return result


async def get_status(
    aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData
) -> dict[str, Any]:
    """Get status from device through REST call."""
    try:
        result = await api_request(
            aiohttp_session, options, f"{API_SYSTEM_STATUS}"
        )
    except DeviceApiError as err:
        raise

    return result

async def get_log_caps(
    aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData
) -> List[str]:
    """Get log caps from device through REST call."""
    try:
        result = await api_request(
            aiohttp_session, options, f"{API_LOG_CAPS}"
        )
    except DeviceApiError as err:
        # some devices don't offer switches
        if err.error == ApiError.NOT_SUPPORTED:
            return []
        raise

    return result["events"]

async def log_subscribe(
    aiohttp_session: aiohttp.ClientSession,
    options: Py2NConnectionData,
    include: str,
    filter: list[str],
    duration: int,
) -> int:
    """Subscribe to log events REST call."""
    filterstring = "" if filter is None else ",".join(filter)
    filterarg = "" if filterstring == "" else f"&filter={filterstring}"
    try:
        result = await api_request(
            aiohttp_session,
            options,
            f"{API_LOG_SUBSCRIBE}?include={include}&duration={duration}{filterarg}",
        )
    except DeviceApiError as err:
        raise
    
    return result["id"]

async def log_unsubscribe(
    aiohttp_session: aiohttp.ClientSession,
    options: Py2NConnectionData,
    id: int,
) -> None:
    """Unubscribe to log events REST call."""
    try:
        await api_request(
            aiohttp_session,
            options,
            f"{API_LOG_UNSUBSCRIBE}?id={id}",
        )
    except DeviceApiError as err:
        raise

async def log_pull(
    aiohttp_session: aiohttp.ClientSession,
    options: Py2NConnectionData,
    id: int,
    timeout: int=0,
) -> list[dict]:
    """Pull log events REST call."""
    try:
        result = await api_request(
            aiohttp_session,
            options,
            f"{API_LOG_PULL}?id={id}&timeout={timeout}",
            timeout+5
        )
    except DeviceApiError as err:
        raise
    
    return result["events"]


async def restart(
    aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData
) -> None:
    """Restart device through REST call."""
    try:
        await api_request(
            aiohttp_session, options, f"{API_SYSTEM_RESTART}"
        )
    except DeviceApiError as err:
        raise


async def test_audio(
    aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData
) -> None:
    """Test device audio through REST call."""
    try:
        await api_request(
            aiohttp_session, options, f"{API_AUDIO_TEST}"
        )
    except DeviceApiError as err:
        raise


async def get_switch_status(
    aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData
) -> List[Any]:
    """Get switches from device through REST call."""
    try:
        result = await api_request(
            aiohttp_session, options, f"{API_SWITCH_STATUS}"
        )
    except DeviceApiError as err:
        # some devices don't offer switches
        if err.error == ApiError.NOT_SUPPORTED:
            return []
        raise

    return result["switches"]

async def get_switch_caps(
    aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData
) -> List[Any]:
    """Get switch caps from device through REST call."""
    try:
        result = await api_request(
            aiohttp_session, options, f"{API_SWITCH_CAPS}"
        )
    except DeviceApiError as err:
        # some devices don't offer switches
        if err.error == ApiError.NOT_SUPPORTED:
            return []
        raise

    return result["switches"]

async def get_switches(
    aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData
) -> List[dict]:
    switch_caps: List[Any] = await get_switch_caps(aiohttp_session, options)
    statuses = await get_switch_status(aiohttp_session, options)
    switch_status_by_id = {
        switch["switch"]: switch for switch in statuses
    }
    switches = []
    for caps in switch_caps:
        switch_id = caps["switch"]
        enabled = caps["enabled"]
        mode = caps["mode"] if enabled else None
        status = switch_status_by_id.get(switch_id, {})
        switches.append(
            Py2NDeviceSwitch(
                id=switch_id,
                enabled=enabled,
                active=status.get("active", False),
                locked=status.get("locked", False),
                mode=mode,
            )
        )
    return switches

async def set_switch(
    aiohttp_session: aiohttp.ClientSession,
    options: Py2NConnectionData,
    switch_id: int,
    on: bool,
) -> None:
    """Set switch value of device via REST call."""
    try:
        await api_request(
            aiohttp_session,
            options,
            f"{API_SWITCH_CONTROL}?switch={switch_id}&action={'on' if on else 'off'}",
        )
    except DeviceApiError as err:
        raise

async def get_port_caps(aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData) ->  list[dict]:
    try:
        result = await api_request(
            aiohttp_session,
            options,
            f"{API_IO_CAPS}"
        )
    except DeviceApiError as err:
        raise

    return result["ports"]

async def get_port_status(aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData) ->  list[dict]:
    try:
        result = await api_request(
            aiohttp_session,
            options,
            f"{API_IO_STATUS}"
        )
    except DeviceApiError as err:
        raise

    return result["ports"]

async def get_ports(aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData) ->  list[Py2NDevicePort]:
    caps = await get_port_caps(aiohttp_session, options)
    statuses = await get_port_status(aiohttp_session, options)
    ports = []
    for cap in caps:
        for status in statuses:
            if status["port"] == cap["port"]:
                ports.append(Py2NDevicePort(cap["port"], cap["type"], status["state"]))
                break
    return ports

async def set_port(aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData, port_id: str, on: bool) -> None:
    try:
        await api_request(
            aiohttp_session,
            options,
            f"{API_IO_CONTROL}?port={port_id}&action={'on' if on else 'off'}",
        )
    except DeviceApiError as err:
        raise

async def get_dir_template(aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData) ->  list[dict]:
    try:
        result = await api_request(
            aiohttp_session,
            options,
            f"{API_DIR_TEMPLATE}"
        )
    except DeviceApiError as err:
        raise

    return result["users"]

async def query_dir(aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData, query: dict) ->  list[dict]:
    try:
        result = await api_request(
            aiohttp_session,
            options,
            f"{API_DIR_QUERY}",
            method = "POST",
            json = query
        )
    except DeviceApiError as err:
        raise

    return result["users"]

async def update_dir(aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData, users: dict) ->  list[dict]:
    try:
        result = await api_request(
            aiohttp_session,
            options,
            f"{API_DIR_UPDATE}",
            method = "PUT",
            json = {'users': users}
        )
    except DeviceApiError as err:
        raise

    return result["users"]


async def api_request(
        aiohttp_session: aiohttp.ClientSession, options: Py2NConnectionData, endpoint: str, timeout: int = HTTP_CALL_TIMEOUT, method: str = "GET", data = None, json = None
) -> dict[str, Any] | None:
    """Perform REST call to device."""

    if endpoint.startswith("/"):
        endpoint=endpoint[1:]

    if not endpoint.startswith("api/"):
        endpoint="api/"+endpoint

    url=f"{options.protocol}://{options.host}/{endpoint}"
    request_id = f"{method.upper()} {url}"
    request_kwargs = {
        "timeout": timeout,
        "data": data,
        "json": json,
    }
    if options.auth is not None:
        request_kwargs["auth"] = options.auth
    if (options.protocol or "").lower() == "https":
        request_kwargs["ssl"] = options.ssl_verify

    try:
        response = await _request_with_optional_digest_auth(
            aiohttp_session, options, method, url, request_kwargs
        )
        if response.content_type != CONTENT_TYPE:
            _LOGGER.debug("%s failed: invalid content type: %s", request_id, response.content_type)
            raise DeviceUnsupportedError(f"invalid content type: {response.content_type}")

        result: dict[str, Any] = await response.json()
    except (asyncio.exceptions.TimeoutError, aiohttp.ClientConnectionError) as err:
        error = DeviceConnectionError(err)
        _LOGGER.debug("%s failed: connect error: %r", request_id, error)
        raise error from err

    if "success" not in result:
        error = DeviceUnsupportedError("response malformed")
        _LOGGER.debug("%s failed: api error: %r", request_id, error)
        raise error

    if not result["success"]:
        _LOGGER.debug("%s failed: api unsuccessful: %r", request_id, result)
        code = result["error"]["code"]
        has_credentials = options.username is not None and options.password is not None
        try:
            error = ApiError(code)
            if error == ApiError.INSUFFICIENT_PRIVILEGES and not has_credentials:
                error = ApiError.AUTHORIZATION_REQUIRED

            err = DeviceApiError(error)
        except ValueError:
            err = DeviceUnsupportedError("invalid error code")

        _LOGGER.debug("%s failed: api error: %r", request_id, err)
        raise err

    if "result" in result:
        return result["result"]
