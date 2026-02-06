import asyncio
import hashlib
import json

from starlette.requests import Request

from app.core.etag import (
    generate_etag,
    matches_any_etag,
    parse_if_none_match,
    validate_etag,
)
from app.core.etag_response import ETagResponse, check_etag_precondition
from app.core.json_encoder import CustomJSONEncoder


def _build_request(if_none_match: str) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"if-none-match", if_none_match.encode("utf-8"))],
    }
    return Request(scope)


def test_generate_etag_uses_rfc_quoted_format() -> None:
    strong_etag = generate_etag({"a": 1})
    weak_etag = generate_etag({"a": 1}, weak=True)

    assert strong_etag.startswith('"') and strong_etag.endswith('"')
    assert weak_etag.startswith('W/"') and weak_etag.endswith('"')


def test_parse_if_none_match_normalizes_standard_and_legacy_tokens() -> None:
    parsed = parse_if_none_match(' "abc" , W/"def" , * , ghi ')

    assert parsed == {'"abc"', 'W/"def"', "*", '"ghi"'}


def test_validate_etag_supports_weak_comparison_for_if_none_match() -> None:
    assert validate_etag('W/"abc"', '"abc"')
    assert validate_etag('"abc"', 'W/"abc"')
    assert validate_etag("*", '"abc"')
    assert not validate_etag('"abc"', '"def"')


def test_matches_any_etag_supports_standard_weak_header() -> None:
    current = '"abc"'
    assert matches_any_etag(current, 'W/"abc", "def"')


def test_check_etag_precondition_returns_304_for_legacy_unquoted_header() -> None:
    content = {"a": 1, "b": 2}
    current_etag = generate_etag(content)
    legacy_unquoted = current_etag.strip('"')
    request = _build_request(legacy_unquoted)

    response = asyncio.run(check_etag_precondition(request, content))

    assert response is not None
    assert response.status_code == 304
    assert response.headers["ETag"] == current_etag


def test_etag_response_etag_matches_response_body_hash() -> None:
    content = {"b": 1, "a": 2}
    response = ETagResponse(content=content)
    expected_body = json.dumps(
        content,
        cls=CustomJSONEncoder,
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    expected_hash = hashlib.sha256(expected_body).hexdigest()

    assert response.body == expected_body
    assert response.headers["ETag"] == f'"{expected_hash}"'
