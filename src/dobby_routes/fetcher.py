import logging

import requests


logger = logging.getLogger(__name__)

APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
GITHUB_OPERATOR_URLS = {
    "chinanet": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/chinanet.txt",
    "unicom": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/unicom.txt",
    "cmcc": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cmcc.txt",
    "cernet": "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/cernet.txt",
}
GITHUB_CHINA_URL = "https://raw.githubusercontent.com/gaoyifan/china-operator-ip/ip-lists/china.txt"
CHNROUTES2_URL = "https://raw.githubusercontent.com/misakaio/chnroutes2/master/chnroutes.txt"


def fetch_url(url: str, timeout: int = 30) -> str:
    logger.info("Fetching %s", url)
    response = requests.get(url, timeout=timeout, headers={"User-Agent": "dobby-routes/0.1.0"})
    response.raise_for_status()
    return response.text


def fetch_apnic() -> str:
    return fetch_url(APNIC_URL)


def fetch_operator(operator: str) -> str:
    try:
        url = GITHUB_OPERATOR_URLS[operator]
    except KeyError:
        logger.warning("Unknown operator: %s", operator)
        raise
    return fetch_url(url)


def fetch_all_operators() -> dict[str, str]:
    return {name: fetch_url(url) for name, url in GITHUB_OPERATOR_URLS.items()}


def fetch_chnroutes2() -> str:
    return fetch_url(CHNROUTES2_URL)
