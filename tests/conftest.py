from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mock_http_response():
    def _make(text="data", status_code=200):
        response = MagicMock()
        response.text = text
        response.status_code = status_code
        response.raise_for_status = MagicMock()
        return response

    return _make


@pytest.fixture
def mock_requests_get(mock_http_response):
    response = mock_http_response()
    with patch("dobby_routes.fetcher.requests.get", return_value=response) as mock_get:
        yield mock_get
