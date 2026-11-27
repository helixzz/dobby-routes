import ipaddress
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from typing import Optional
from urllib.parse import urlsplit

import requests

logger = logging.getLogger(__name__)


def _user_agent() -> str:
    try:
        return f"dobby-routes/{_pkg_version('dobby-routes')}"
    except PackageNotFoundError:
        return "dobby-routes/dev"


_USER_AGENT = _user_agent()

APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
GITHUB_OPERATOR_URLS = {
    "chinanet": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet.txt",
    "unicom": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom.txt",
    "cmcc": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc.txt",
    "cernet": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet.txt",
}
GITHUB_OPERATOR_URLS_V6 = {
    "chinanet": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet6.txt",
    "unicom": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom6.txt",
    "cmcc": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc6.txt",
    "cernet": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet6.txt",
}
GITHUB_CHINA_URL = "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"
GITHUB_CHINA_URL_V6 = (
    "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china6.txt"
)
CHNROUTES2_URL = "https://chnroutes2.cdn.skk.moe/chnroutes.txt"
CHNROUTES2_FALLBACK_URL = (
    "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"
)
TELEGRAM_CIDR_SOURCE_URL = "https://core.telegram.org/resources/cidr.txt"
REVIEWED_CIDR_SOURCE_SCOPES = {
    TELEGRAM_CIDR_SOURCE_URL: (
        "91.108.56.0/22",
        "91.108.4.0/22",
        "91.108.8.0/22",
        "91.108.16.0/22",
        "91.108.12.0/22",
        "149.154.160.0/20",
        "91.105.192.0/23",
        "91.108.20.0/22",
        "185.76.151.0/24",
    ),
}
REVIEWED_CIDR_SOURCE_SCOPES_V6 = {
    TELEGRAM_CIDR_SOURCE_URL: (
        "2001:b28:f23d::/48",
        "2001:b28:f23f::/48",
        "2001:67c:4e8::/48",
        "2001:b28:f23c::/48",
        "2a0a:f280::/32",
    ),
}

DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 30
MAX_CIDR_SOURCE_BYTES = 5 * 1024 * 1024


def _is_retryable_request_error(exc: requests.RequestException) -> bool:
    if isinstance(exc, requests.HTTPError) and exc.response is not None:
        status = exc.response.status_code
        if isinstance(status, int) and 400 <= status < 500 and status not in (408, 429):
            return False
    return True


def fetch_url(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    retries: int = DEFAULT_RETRIES,
    allow_redirects: bool = True,
    max_content_bytes: Optional[int] = None,
) -> str:
    if retries <= 0:
        raise ValueError("retries must be greater than zero")
    if max_content_bytes is not None and max_content_bytes <= 0:
        raise ValueError("max_content_bytes must be greater than zero")

    logger.info("Fetching %s", url)
    last_exc: Optional[requests.RequestException] = None
    for attempt in range(retries):
        try:
            response = _fetch_response(url, timeout, allow_redirects, max_content_bytes)
            if max_content_bytes is not None:
                try:
                    if not allow_redirects and 300 <= response.status_code < 400:
                        raise ValueError(f"Redirect response rejected for CIDR source: {url}")
                    response.raise_for_status()
                    return _read_response_text(response, max_content_bytes)
                finally:
                    response.close()
            if not allow_redirects and 300 <= response.status_code < 400:
                raise ValueError(f"Redirect response rejected for CIDR source: {url}")
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            if not _is_retryable_request_error(e):
                raise
            last_exc = e
            if attempt < retries - 1:
                wait = 2**attempt
                logger.warning(
                    "Fetch failed (attempt %d/%d), retrying in %ds: %s",
                    attempt + 1,
                    retries,
                    wait,
                    e,
                )
                time.sleep(wait)
    if last_exc is None:
        raise RuntimeError("Fetch failed without a request exception")
    raise last_exc


def validate_cidr_source_url(url: str) -> str:
    if any(character.isspace() for character in url):
        raise ValueError(f"Invalid CIDR source URL: {url}")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.fragment:
        raise ValueError(f"Invalid CIDR source URL: {url}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"Invalid CIDR source URL: {url}")
    try:
        port = parsed.port
    except ValueError as e:
        raise ValueError(f"Invalid CIDR source URL: {url}") from e
    if port is not None and port != 443:
        raise ValueError(f"Invalid CIDR source URL: {url}")

    hostname = parsed.hostname.lower()
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if not hostname:
        raise ValueError(f"Invalid CIDR source URL: {url}")
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError(f"Invalid CIDR source URL: {url}")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return url
    if not address.is_global:
        raise ValueError(f"Invalid CIDR source URL: {url}")
    return url


def fetch_cidr_source(url: str) -> str:
    return fetch_url(
        validate_cidr_source_url(url),
        allow_redirects=False,
        max_content_bytes=MAX_CIDR_SOURCE_BYTES,
    )


def _fetch_response(
    url: str,
    timeout: int,
    allow_redirects: bool,
    max_content_bytes: Optional[int],
) -> requests.Response:
    if allow_redirects and max_content_bytes is None:
        return requests.get(url, timeout=timeout, headers={"User-Agent": _USER_AGENT})
    if max_content_bytes is None:
        return requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": _USER_AGENT},
            allow_redirects=False,
        )
    return requests.get(
        url,
        timeout=timeout,
        headers={"User-Agent": _USER_AGENT},
        allow_redirects=allow_redirects,
        stream=True,
    )


def _read_response_text(response: requests.Response, max_content_bytes: int) -> str:
    chunks: list[bytes] = []
    size = 0
    for chunk in response.iter_content(chunk_size=64 * 1024):
        size += len(chunk)
        if size > max_content_bytes:
            raise ValueError("CIDR source response exceeds 5 MiB")
        chunks.append(chunk)
    return b"".join(chunks).decode(response.encoding or "utf-8")


def fetch_apnic() -> str:
    return fetch_url(APNIC_URL)


def fetch_operator(operator: str) -> str:
    if operator not in GITHUB_OPERATOR_URLS:
        raise ValueError(f"Unknown operator: {operator}")
    return fetch_url(GITHUB_OPERATOR_URLS[operator])


def fetch_operator_v6(operator: str) -> str:
    if operator not in GITHUB_OPERATOR_URLS_V6:
        raise ValueError(f"Unknown operator: {operator}")
    return fetch_url(GITHUB_OPERATOR_URLS_V6[operator])


def _fetch_operator_map(urls: dict[str, str]) -> dict[str, str]:
    fetched: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(fetch_url, url): name for name, url in urls.items()}
        for future in as_completed(futures):
            name = futures[future]
            fetched[name] = future.result()
    return {name: fetched[name] for name in urls}


def fetch_all_operators() -> dict[str, str]:
    return _fetch_operator_map(GITHUB_OPERATOR_URLS)


def fetch_all_operators_v6() -> dict[str, str]:
    return _fetch_operator_map(GITHUB_OPERATOR_URLS_V6)


def fetch_china_v6() -> str:
    return fetch_url(GITHUB_CHINA_URL_V6)


def fetch_chnroutes2() -> str:
    try:
        return fetch_url(CHNROUTES2_URL)
    except requests.RequestException as e:
        logger.warning(
            "Primary chnroutes2 source failed, falling back to %s: %s",
            CHNROUTES2_FALLBACK_URL,
            e,
        )
        return fetch_url(CHNROUTES2_FALLBACK_URL)
