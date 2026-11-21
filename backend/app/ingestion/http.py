"""Retry, timeout, and rate-limit handling for source HTTP requests."""

import asyncio
import random
from typing import Any

import httpx


class HttpResponseError(RuntimeError):
    """Raised after an HTTP request exhausts bounded retries."""


async def request_with_retry(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    attempts: int = 5,
    **kwargs: Any,
) -> httpx.Response:
    """Send a request with exponential backoff and Retry-After support."""
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            response = await client.request(method, url, **kwargs)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            last_error = exc
        else:
            if response.status_code in {429, 500, 502, 503, 504}:
                last_error = httpx.HTTPStatusError(
                    f"{response.status_code} while fetching {url}",
                    request=response.request,
                    response=response,
                )
                retry_after = response.headers.get("Retry-After")
                if attempt < attempts - 1 and retry_after:
                    try:
                        await asyncio.sleep(min(60.0, float(retry_after)))
                    except ValueError:
                        pass
                    continue
            elif 200 <= response.status_code < 300:
                return response
            else:
                response.raise_for_status()

        if attempt == attempts - 1:
            break
        await asyncio.sleep(
            min(
                60.0,
                (2**attempt) + random.uniform(0, 0.25),
            )
        )
    raise HttpResponseError(f"Request failed after {attempts} attempts") from last_error
