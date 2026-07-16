from unittest.mock import MagicMock, patch

import pytest
import requests

from dobby_routes.fetcher import (
    _USER_AGENT,
    APNIC_URL,
    CHNROUTES2_URL,
    GITHUB_CHINA_URL,
    GITHUB_OPERATOR_URLS,
    MAX_CIDR_SOURCE_BYTES,
    fetch_all_operators,
    fetch_apnic,
    fetch_chnroutes2,
    fetch_cidr_source,
    fetch_operator,
    fetch_url,
    validate_cidr_source_url,
)


def test_apnic_url_format():
    assert APNIC_URL.startswith("https://")
    assert "apnic" in APNIC_URL


def test_github_operator_urls_contains_expected_keys():
    assert "chinanet" in GITHUB_OPERATOR_URLS
    assert "unicom" in GITHUB_OPERATOR_URLS
    assert "cmcc" in GITHUB_OPERATOR_URLS
    assert "cernet" in GITHUB_OPERATOR_URLS


def test_github_operator_urls_are_https():
    for url in GITHUB_OPERATOR_URLS.values():
        assert url.startswith("https://")


def test_github_china_url_format():
    assert GITHUB_CHINA_URL.startswith("https://")
    assert "china" in GITHUB_CHINA_URL


def test_chnroutes2_url_format():
    assert CHNROUTES2_URL.startswith("https://")
    assert "chnroutes" in CHNROUTES2_URL


def test_fetch_url_returns_text():
    mock_response = MagicMock()
    mock_response.text = "192.168.0.0/16\n"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        result = fetch_url("https://example.com/data.txt")

    assert result == "192.168.0.0/16\n"
    mock_get.assert_called_once_with(
        "https://example.com/data.txt",
        timeout=30,
        headers={"User-Agent": _USER_AGENT},
    )


def test_fetch_url_calls_raise_for_status():
    mock_response = MagicMock()
    mock_response.text = "data"

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response):
        fetch_url("https://example.com/")

    mock_response.raise_for_status.assert_called_once()


def test_fetch_url_custom_timeout():
    mock_response = MagicMock()
    mock_response.text = "data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        fetch_url("https://example.com/", timeout=10)

    mock_get.assert_called_once_with(
        "https://example.com/",
        timeout=10,
        headers={"User-Agent": _USER_AGENT},
    )


def test_fetch_apnic_uses_apnic_url():
    mock_response = MagicMock()
    mock_response.text = "apnic data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        result = fetch_apnic()

    assert result == "apnic data"
    args, _ = mock_get.call_args
    assert args[0] == APNIC_URL


def test_fetch_operator_known():
    mock_response = MagicMock()
    mock_response.text = "chinanet data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response):
        result = fetch_operator("chinanet")

    assert result == "chinanet data"


def test_fetch_operator_unknown_raises_value_error():
    with pytest.raises(ValueError, match="Unknown operator"):
        fetch_operator("unknown_operator_xyz")


def test_fetch_all_operators_returns_all_keys():
    mock_response = MagicMock()
    mock_response.text = "data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response):
        result = fetch_all_operators()

    assert set(result.keys()) == set(GITHUB_OPERATOR_URLS.keys())


def test_fetch_all_operators_values_are_strings():
    mock_response = MagicMock()
    mock_response.text = "some content"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response):
        result = fetch_all_operators()

    assert all(isinstance(v, str) for v in result.values())


def test_fetch_chnroutes2_uses_chnroutes2_url():
    mock_response = MagicMock()
    mock_response.text = "chnroutes data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        result = fetch_chnroutes2()

    assert result == "chnroutes data"
    args, _ = mock_get.call_args
    assert args[0] == CHNROUTES2_URL


@patch("dobby_routes.fetcher.time.sleep")
def test_fetch_url_retries_on_connection_error(mock_sleep):
    mock_response = MagicMock()
    mock_response.text = "ok"
    mock_response.raise_for_status = MagicMock()

    with patch(
        "dobby_routes.fetcher.requests.get",
        side_effect=[requests.ConnectionError("fail"), mock_response],
    ):
        result = fetch_url("https://example.com/", retries=2)

    assert result == "ok"
    mock_sleep.assert_called_once_with(1)


@patch("dobby_routes.fetcher.time.sleep")
def test_fetch_url_raises_after_all_retries_exhausted(mock_sleep):
    with patch(
        "dobby_routes.fetcher.requests.get",
        side_effect=requests.ConnectionError("fail"),
    ):
        with pytest.raises(requests.ConnectionError):
            fetch_url("https://example.com/", retries=3)

    assert mock_sleep.call_count == 2


def test_fetch_url_no_retry_on_success():
    mock_response = MagicMock()
    mock_response.text = "data"
    mock_response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=mock_response) as mock_get:
        fetch_url("https://example.com/", retries=3)

    mock_get.assert_called_once()


@patch("dobby_routes.fetcher.time.sleep")
def test_fetch_url_retries_on_http_error(mock_sleep):
    error = requests.HTTPError(response=MagicMock(status_code=500))
    mock_response = MagicMock()
    mock_response.text = "recovered"
    mock_response.raise_for_status = MagicMock()

    with patch(
        "dobby_routes.fetcher.requests.get",
        side_effect=[MagicMock(raise_for_status=MagicMock(side_effect=error)), mock_response],
    ):
        result = fetch_url("https://example.com/", retries=2)

    assert result == "recovered"


def test_validate_cidr_source_url_accepts_telegram_url():
    url = "https://core.telegram.org/resources/cidr.txt"

    assert validate_cidr_source_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com/routes.txt",
        "file:///tmp/routes.txt",
        "https:///routes.txt",
        "https://user@example.com/routes.txt",
        "https://example.com/routes.txt#fragment",
        "https://example.com/routes file.txt",
        "https://example.com:8443/routes.txt",
        "https://localhost/routes.txt",
        "https://localhost./routes.txt",
        "https://sub.localhost/routes.txt",
        "https://sub.localhost./routes.txt",
        "https://127.0.0.1/routes.txt",
        "https://127.0.0.1./routes.txt",
        "https://10.0.0.1/routes.txt",
    ],
)
def test_validate_cidr_source_url_rejects_unsafe_urls(url):
    with pytest.raises(ValueError, match="Invalid CIDR source URL"):
        validate_cidr_source_url(url)


def test_fetch_cidr_source_disables_redirects_and_returns_body():
    url = "https://example.com/routes.txt"
    response = MagicMock()
    response.status_code = 200
    response.encoding = "utf-8"
    response.iter_content.return_value = [b"8.8.8.0/24\n"]
    response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=response) as mock_get:
        result = fetch_cidr_source(url)

    assert result == "8.8.8.0/24\n"
    response.close.assert_called_once_with()
    mock_get.assert_called_once_with(
        url,
        timeout=30,
        headers={"User-Agent": _USER_AGENT},
        allow_redirects=False,
        stream=True,
    )


def test_fetch_cidr_source_rejects_redirect_response():
    response = MagicMock()
    response.status_code = 302

    with patch("dobby_routes.fetcher.requests.get", return_value=response):
        with pytest.raises(ValueError, match="Redirect response rejected"):
            fetch_cidr_source("https://example.com/routes.txt")

    response.close.assert_called_once_with()


def test_fetch_url_closes_streamed_response_before_body_on_http_error():
    response = MagicMock()
    response.status_code = 500
    response.raise_for_status.side_effect = requests.HTTPError("server error")

    with patch("dobby_routes.fetcher.requests.get", return_value=response):
        with pytest.raises(requests.HTTPError, match="server error"):
            fetch_url("https://example.com/routes.txt", retries=1, max_content_bytes=1024)

    response.iter_content.assert_not_called()
    response.close.assert_called_once_with()


def test_fetch_cidr_source_rejects_oversized_response():
    response = MagicMock()
    response.status_code = 200
    response.iter_content.return_value = [b"x" * (MAX_CIDR_SOURCE_BYTES + 1)]
    response.raise_for_status = MagicMock()

    with patch("dobby_routes.fetcher.requests.get", return_value=response):
        with pytest.raises(ValueError, match="exceeds 5 MiB"):
            fetch_cidr_source("https://example.com/routes.txt")

    response.close.assert_called_once_with()


def test_fetch_url_rejects_non_positive_retries():
    with pytest.raises(ValueError, match="retries must be greater than zero"):
        fetch_url("https://example.com/", retries=0)
