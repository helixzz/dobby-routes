import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


logger = logging.getLogger(__name__)

try:
    from importlib.metadata import version as _pkg_version
    _USER_AGENT = f"dobby-routes/{_pkg_version('dobby-routes')}"
except Exception:
    _USER_AGENT = "dobby-routes/dev"

APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
GITHUB_OPERATOR_URLS = {
    "chinanet": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet.txt",
    "unicom": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom.txt",
    "cmcc": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc.txt",
    "cernet": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet.txt",
}
GITHUB_CHINA_URL = "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"
CHNROUTES2_URL = "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"

DEFAULT_RETRIES = 3
DEFAULT_TIMEOUT = 30


def fetch_url(url: str, timeout: int = DEFAULT_TIMEOUT, retries: int = DEFAULT_RETRIES) -> str:
    logger.info("Fetching %s", url)
    last_exc: Exception | None = None
    for attempt in range(retries):
        try:
            response = requests.get(
                url, timeout=timeout, headers={"User-Agent": _USER_AGENT},
            )
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            last_exc = e
            if attempt < retries - 1:
                wait = 2 ** attempt
                logger.warning(
                    "Fetch failed (attempt %d/%d), retrying in %ds: %s",
                    attempt + 1, retries, wait, e,
                )
                time.sleep(wait)
    raise last_exc  # type: ignore[misc]


def fetch_apnic() -> str:
    return fetch_url(APNIC_URL)


def fetch_operator(operator: str) -> str:
    if operator not in GITHUB_OPERATOR_URLS:
        raise ValueError(f"Unknown operator: {operator}")
    return fetch_url(GITHUB_OPERATOR_URLS[operator])


def fetch_all_operators() -> dict[str, str]:
    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(fetch_url, url): name
            for name, url in GITHUB_OPERATOR_URLS.items()
        }
        for future in as_completed(futures):
            name = futures[future]
            results[name] = future.result()
    return results


def fetch_chnroutes2() -> str:
    return fetch_url(CHNROUTES2_URL)
