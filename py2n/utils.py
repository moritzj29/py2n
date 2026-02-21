"""Utitility functions for communication with 2N devices."""
from __future__ import annotations

import logging
import aiohttp
import asyncio
import hashlib
import secrets

from collections import OrderedDict
from dataclasses import dataclass
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


@dataclass
class _DigestAuthState:
    realm: str
    nonce: str
    algorithm: str
    qop: str | None
    opaque: str | None
    cnonce: str
    nonce_count: int


_DIGEST_CACHE_MAX_ENTRIES = 256
_DIGEST_AUTH_CACHE: OrderedDict[tuple[int, str, str, str, str], _DigestAuthState] = OrderedDict()
_DIGEST_REALM_HINTS: OrderedDict[tuple[int, str, str, str], str] = OrderedDict()


def _digest_credential_fingerprint(username: str, password: str) -> str:
    # Avoid keeping plaintext passwords in cache keys.
    return hashlib.sha256(f"{username}:{password}".encode()).hexdigest()


def _prune_digest_cache() -> None:
    while len(_DIGEST_AUTH_CACHE) > _DIGEST_CACHE_MAX_ENTRIES:
        _DIGEST_AUTH_CACHE.popitem(last=False)
    while len(_DIGEST_REALM_HINTS) > _DIGEST_CACHE_MAX_ENTRIES:
        _DIGEST_REALM_HINTS.popitem(last=False)


def _split_quoted_csv(value: str) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and in_quotes:
            escaped = True
            continue
        if char == '"':
            in_quotes = not in_quotes
            current.append(char)
            continue
        if char == "," and not in_quotes:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(char)
    if current:
        parts.append("".join(current).strip())
    return [part for part in parts if part]


def _extract_digest_challenge(challenge_header: str) -> str:
    if not challenge_header:
        return ""

    parts = _split_quoted_csv(challenge_header)
    for idx, part in enumerate(parts):
        lowered = part.lower()
        if not lowered.startswith("digest"):
            continue

        digest_parts: list[str] = []
        first = part[6:].strip()
        if first:
            digest_parts.append(first)

        for next_part in parts[idx + 1:]:
            scheme_candidate, sep, remainder = next_part.partition(" ")
            if (
                sep
                and "=" in remainder
                and "=" not in scheme_candidate
                and scheme_candidate.replace("-", "").isalnum()
            ):
                break
            if "=" not in next_part:
                break
            digest_parts.append(next_part)
        return ", ".join(digest_parts)

    return ""


def _parse_digest_challenge(challenge_header: str) -> dict[str, str]:
    challenge = _extract_digest_challenge(challenge_header)
    if not challenge:
        return {}

    parsed: dict[str, str] = {}
    i = 0
    length = len(challenge)
    while i < length:
        while i < length and challenge[i] in (" ", ",", "\t"):
            i += 1
        if i >= length:
            break

        key_start = i
        while i < length and (challenge[i].isalnum() or challenge[i] in "_-"):
            i += 1
        key = challenge[key_start:i].strip().lower()
        if not key:
            break

        while i < length and challenge[i] in (" ", "\t"):
            i += 1
        if i >= length or challenge[i] != "=":
            break
        i += 1
        while i < length and challenge[i] in (" ", "\t"):
            i += 1
        if i >= length:
            break

        if challenge[i] == '"':
            i += 1
            value_chars: list[str] = []
            while i < length:
                if challenge[i] == "\\" and i + 1 < length:
                    value_chars.append(challenge[i + 1])
                    i += 2
                    continue
                if challenge[i] == '"':
                    i += 1
                    break
                value_chars.append(challenge[i])
                i += 1
            value = "".join(value_chars).strip()
        else:
            value_start = i
            while i < length and challenge[i] != ",":
                i += 1
            value = challenge[value_start:i].strip()

        parsed[key] = value

    return parsed


def _get_digest_hash(algorithm: str):
    algorithm_map = {
        "md5": hashlib.md5,
        "md5-sess": hashlib.md5,
        "sha-256": hashlib.sha256,
        "sha-256-sess": hashlib.sha256,
    }
    return algorithm_map.get(algorithm.lower())


def _normalize_digest_qop(challenge_qop: str | None) -> str | None:
    if not challenge_qop:
        return None
    qop_values = [value.strip().lower() for value in challenge_qop.split(",")]
    if "auth" in qop_values:
        return "auth"
    # Do not silently downgrade unsupported qop (e.g. auth-int) to no-qop.
    return None


def _update_digest_state_from_challenge(
    session_key: tuple[int, str, str, str], challenge_header: str
) -> _DigestAuthState | None:
    challenge = _parse_digest_challenge(challenge_header)
    realm = challenge.get("realm")
    nonce = challenge.get("nonce")
    if not realm or not nonce:
        return None

    algorithm = challenge.get("algorithm", "MD5")
    if _get_digest_hash(algorithm) is None:
        return None

    normalized_qop = _normalize_digest_qop(challenge.get("qop"))
    if challenge.get("qop") and normalized_qop is None:
        return None

    state = _DigestAuthState(
        realm=realm,
        nonce=nonce,
        algorithm=algorithm,
        qop=normalized_qop,
        opaque=challenge.get("opaque"),
        cnonce=secrets.token_hex(8),
        nonce_count=0,
    )
    cache_key = (*session_key, realm)
    _DIGEST_AUTH_CACHE[cache_key] = state
    _DIGEST_AUTH_CACHE.move_to_end(cache_key)
    _DIGEST_REALM_HINTS[session_key] = realm
    _DIGEST_REALM_HINTS.move_to_end(session_key)
    _prune_digest_cache()
    return state


def clear_digest_auth_cache_for_session(aiohttp_session: aiohttp.ClientSession) -> None:
    session_id = id(aiohttp_session)
    auth_keys_to_delete = [key for key in _DIGEST_AUTH_CACHE if key[0] == session_id]
    for key in auth_keys_to_delete:
        del _DIGEST_AUTH_CACHE[key]

    hint_keys_to_delete = [key for key in _DIGEST_REALM_HINTS if key[0] == session_id]
    for key in hint_keys_to_delete:
        del _DIGEST_REALM_HINTS[key]


def _build_digest_authorization_from_state(
    state: _DigestAuthState,
    method: str,
    url: str,
    username: str,
    password: str,
) -> str | None:
    hash_fn = _get_digest_hash(state.algorithm)
    if hash_fn is None:
        return None

    uri_parts = urlsplit(url)
    digest_uri = uri_parts.path or "/"
    if uri_parts.query:
        digest_uri = f"{digest_uri}?{uri_parts.query}"

    state.nonce_count += 1
    nc = f"{state.nonce_count:08x}"
    algorithm = state.algorithm.lower()
    ha1 = hash_fn(f"{username}:{state.realm}:{password}".encode()).hexdigest()
    if algorithm.endswith("-sess"):
        ha1 = hash_fn(f"{ha1}:{state.nonce}:{state.cnonce}".encode()).hexdigest()
    ha2 = hash_fn(f"{method.upper()}:{digest_uri}".encode()).hexdigest()
    if state.qop:
        response = hash_fn(
            f"{ha1}:{state.nonce}:{nc}:{state.cnonce}:{state.qop}:{ha2}".encode()
        ).hexdigest()
    else:
        response = hash_fn(f"{ha1}:{state.nonce}:{ha2}".encode()).hexdigest()

    auth_fields = [
        f'username="{username}"',
        f'realm="{state.realm}"',
        f'nonce="{state.nonce}"',
        f'uri="{digest_uri}"',
        f'response="{response}"',
    ]
    if state.opaque:
        auth_fields.append(f'opaque="{state.opaque}"')
    auth_fields.append(f"algorithm={state.algorithm}")
    if state.qop:
        auth_fields.extend([f"qop={state.qop}", f"nc={nc}", f'cnonce="{state.cnonce}"'])
    return "Digest " + ", ".join(auth_fields)


async def _request_with_optional_digest_auth(
    aiohttp_session: aiohttp.ClientSession,
    options: Py2NConnectionData,
    method: str,
    url: str,
    request_kwargs: dict[str, Any],
) -> aiohttp.ClientResponse:
    if options.auth_method != "digest":
        return await aiohttp_session.request(method, url, **request_kwargs)

    if not options.username or options.password is None:
        return await aiohttp_session.request(method, url, **request_kwargs)

    credential_fingerprint = _digest_credential_fingerprint(
        options.username, options.password
    )
    session_key = (
        id(aiohttp_session),
        f"{(options.protocol or 'http').lower()}://{options.host}",
        options.username,
        credential_fingerprint,
    )
    state = None
    realm_hint = _DIGEST_REALM_HINTS.get(session_key)
    if realm_hint:
        cache_key = (*session_key, realm_hint)
        state = _DIGEST_AUTH_CACHE.get(cache_key)
        if state:
            _DIGEST_AUTH_CACHE.move_to_end(cache_key)
            _DIGEST_REALM_HINTS.move_to_end(session_key)

    initial_kwargs = dict(request_kwargs)
    initial_headers = dict(initial_kwargs.get("headers") or {})
    if state:
        authorization = _build_digest_authorization_from_state(
            state, method, url, options.username, options.password
        )
        if authorization:
            initial_headers["Authorization"] = authorization
            initial_kwargs["headers"] = initial_headers

    response = await aiohttp_session.request(method, url, **initial_kwargs)
    if response.status != 401:
        return response

    challenge_header = response.headers.get("WWW-Authenticate", "")
    refreshed_state = _update_digest_state_from_challenge(session_key, challenge_header)
    if not refreshed_state:
        return response

    retry_auth = _build_digest_authorization_from_state(
        refreshed_state, method, url, options.username, options.password
    )
    if not retry_auth:
        return response

    response.release()
    retry_kwargs = dict(request_kwargs)
    retry_headers = dict(retry_kwargs.get("headers") or {})
    retry_headers["Authorization"] = retry_auth
    retry_kwargs["headers"] = retry_headers
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
