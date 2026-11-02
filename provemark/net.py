from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any

from . import __version__

USER_AGENT = f"provemark/{__version__} (+https://github.com/)"


class NetworkError(Exception):
    pass


def http_json(
    url: str,
    payload: Any | None = None,
    *,
    timeout: float = 20.0,
    retries: int = 1,
    headers: dict[str, str] | None = None,
) -> Any:
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")
    else:
        body = None
    if headers:
        request_headers.update(headers)

    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(
            url, data=body, headers=request_headers, method="POST" if body else "GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
            return json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 404):
                return None
            last_error = exc
        except (urllib.error.URLError, socket.timeout, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
        if attempt < retries:
            time.sleep(0.8 * (attempt + 1))
    raise NetworkError(str(last_error) if last_error else "unknown network error")


def http_text(url: str, *, timeout: float = 20.0, retries: int = 0) -> str:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (400, 404):
                return ""
            last_error = exc
        except (urllib.error.URLError, socket.timeout, TimeoutError) as exc:
            last_error = exc
        if attempt < retries:
            time.sleep(0.8 * (attempt + 1))
    raise NetworkError(str(last_error) if last_error else "unknown network error")
