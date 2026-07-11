from __future__ import annotations

import asyncio

import pytest

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from tabayyan import RedactionMode
from tabayyan.integrations.fastapi import TabayyanPrivacyMiddleware


def create_app(
    *,
    include_response_headers: bool = True,
    max_body_size: int | None = 1_000_000,
    include_fields: set[str] | None = None,
    exclude_fields: set[str] | None = None,
    include_paths: set[str] | None = None,
    exclude_paths: set[str] | None = None,
    include_methods: set[str] | None = None,
    exclude_methods: set[str] | None = None,
) -> FastAPI:
    app = FastAPI()

    app.add_middleware(
        TabayyanPrivacyMiddleware,
        destination="https://api.openai.com",
        include_response_headers=include_response_headers,
        max_body_size=max_body_size,
        include_fields=include_fields,
        exclude_fields=exclude_fields,
        include_paths=include_paths,
        exclude_paths=exclude_paths,
        include_methods=include_methods,
        exclude_methods=exclude_methods,
    )

    @app.post("/echo")
    @app.post("/chat")
    @app.post("/messages")
    @app.post("/health")
    @app.post("/metrics")
    def echo(payload: dict[str, object]) -> dict[str, object]:
        return payload

    @app.api_route(
        "/method-echo",
        methods=["GET", "POST", "PUT", "DELETE"],
    )
    def method_echo(
        payload: dict[str, object],
    ) -> dict[str, object]:
        return payload

    @app.post("/raw")
    async def raw(request: Request) -> dict[str, str]:
        return {
            "body": (await request.body()).decode("utf-8"),
        }

    return app


def test_fastapi_middleware_redacts_json_request_body() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/echo",
        json={
            "prompt": (
                "حلل حالة العميل. "
                "رقم الهوية 1158813996، "
                "الجوال +966512345678"
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert "+966512345678" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 2


def test_fastapi_middleware_redacts_nested_json_values() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/echo",
        json={
            "customer": {
                "name": "محمد بن عبدالله",
                "identifiers": {
                    "national_id": "1158813996",
                    "mobile": "+966512345678",
                },
            },
            "messages": [
                {
                    "role": "user",
                    "content": "رقم الهوية 1158813996",
                },
                {
                    "role": "assistant",
                    "content": "جاهز للمراجعة",
                },
            ],
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["customer"]["identifiers"]["national_id"]
    assert "+966512345678" not in body["customer"]["identifiers"]["mobile"]
    assert "1158813996" not in body["messages"][0]["content"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 3


def test_fastapi_middleware_preserves_non_sensitive_json() -> None:
    client = TestClient(create_app())

    payload = {
        "prompt": "Summarize this public product description.",
        "metadata": {
            "source": "public",
            "priority": 1,
            "enabled": True,
        },
    }

    response = client.post(
        "/echo",
        json=payload,
    )

    assert response.status_code == 200
    assert response.json() == payload
    assert response.headers["x-tabayyan-pii-detected"] == "false"
    assert response.headers["x-tabayyan-redacted-count"] == "0"


def test_fastapi_middleware_passes_non_json_requests_unchanged() -> None:
    client = TestClient(create_app())

    raw_body = "رقم الهوية 1158813996"

    response = client.post(
        "/raw",
        content=raw_body,
        headers={
            "content-type": "text/plain; charset=utf-8",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "body": raw_body,
    }
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_rejects_invalid_json_fail_closed() -> None:
    # PRIV-002 regression: an unparseable JSON body cannot be scanned, so it
    # must not reach the route handler, and the response must not claim the
    # request was clean.
    client = TestClient(create_app())

    invalid_json = '{"prompt": "رقم الهوية 1158813996"'

    response = client.post(
        "/raw",
        content=invalid_json,
        headers={
            "content-type": "application/json",
        },
    )

    assert response.status_code == 400
    assert "1158813996" not in response.text
    assert response.headers.get("x-tabayyan-pii-detected") != "false"


def test_fastapi_middleware_can_disable_response_headers() -> None:
    client = TestClient(
        create_app(
            include_response_headers=False,
        )
    )

    response = client.post(
        "/echo",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_empty_json_body_does_not_crash() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/raw",
        content=b"",
        headers={
            "content-type": "application/json",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "body": "",
    }
    assert response.headers["x-tabayyan-pii-detected"] == "false"
    assert response.headers["x-tabayyan-redacted-count"] == "0"


def test_fastapi_middleware_rejects_json_body_larger_than_limit() -> None:
    client = TestClient(
        create_app(
            max_body_size=32,
        )
    )

    response = client.post(
        "/echo",
        json={
            "prompt": "x" * 100,
        },
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": "Request body too large",
    }


def test_fastapi_middleware_can_disable_body_size_limit() -> None:
    client = TestClient(
        create_app(
            max_body_size=None,
        )
    )

    response = client.post(
        "/echo",
        json={
            "prompt": (
                f"{'x' * 2_000} "
                "رقم الهوية 1158813996"
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_include_fields_only_protects_selected_fields() -> None:
    client = TestClient(
        create_app(
            include_fields={"prompt"},
        )
    )

    response = client.post(
        "/echo",
        json={
            "prompt": "رقم الهوية 1158813996",
            "metadata": {
                "owner_id": "1158813996",
            },
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert body["metadata"]["owner_id"] == "1158813996"
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_include_fields_can_target_nested_content() -> None:
    client = TestClient(
        create_app(
            include_fields={"content"},
        )
    )

    response = client.post(
        "/echo",
        json={
            "messages": [
                {
                    "role": "user",
                    "content": "رقم الهوية 1158813996",
                }
            ],
            "metadata": {
                "owner_id": "1158813996",
            },
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["messages"][0]["content"]
    assert body["metadata"]["owner_id"] == "1158813996"
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_exclude_fields_skips_selected_subtree() -> None:
    client = TestClient(
        create_app(
            exclude_fields={"metadata"},
        )
    )

    response = client.post(
        "/echo",
        json={
            "prompt": "رقم الهوية 1158813996",
            "metadata": {
                "owner": {
                    "national_id": "1158813996",
                },
            },
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert body["metadata"]["owner"]["national_id"] == "1158813996"
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_exclude_fields_wins_over_include_fields() -> None:
    client = TestClient(
        create_app(
            include_fields={"metadata"},
            exclude_fields={"metadata"},
        )
    )

    response = client.post(
        "/echo",
        json={
            "metadata": {
                "owner_id": "1158813996",
            },
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["metadata"]["owner_id"] == "1158813996"
    assert response.headers["x-tabayyan-pii-detected"] == "false"
    assert response.headers["x-tabayyan-redacted-count"] == "0"


def test_fastapi_middleware_route_filtering_defaults_to_all_paths() -> None:
    client = TestClient(create_app())

    response = client.post(
        "/messages",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_include_paths_protects_matching_path() -> None:
    client = TestClient(
        create_app(
            include_paths={"/chat"},
        )
    )

    response = client.post(
        "/chat",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_include_paths_skips_non_matching_path() -> None:
    client = TestClient(
        create_app(
            include_paths={"/chat"},
        )
    )

    response = client.post(
        "/echo",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["prompt"] == "رقم الهوية 1158813996"
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_exclude_paths_skips_selected_path() -> None:
    client = TestClient(
        create_app(
            exclude_paths={"/health"},
        )
    )

    response = client.post(
        "/health",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["prompt"] == "رقم الهوية 1158813996"
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_exclude_paths_wins_over_include_paths() -> None:
    client = TestClient(
        create_app(
            include_paths={"/chat"},
            exclude_paths={"/chat"},
        )
    )

    response = client.post(
        "/chat",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["prompt"] == "رقم الهوية 1158813996"
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_normalizes_configured_paths() -> None:
    client = TestClient(
        create_app(
            include_paths={
                " chat/ ",
            },
        )
    )

    response = client.post(
        "/chat",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_method_filtering_defaults_to_all_methods() -> None:
    client = TestClient(create_app())

    response = client.request(
        "PUT",
        "/method-echo",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_include_methods_protects_matching_method() -> None:
    client = TestClient(
        create_app(
            include_methods={"POST"},
        )
    )

    response = client.request(
        "POST",
        "/method-echo",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_include_methods_skips_non_matching_method() -> None:
    client = TestClient(
        create_app(
            include_methods={"POST"},
        )
    )

    response = client.request(
        "PUT",
        "/method-echo",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["prompt"] == "رقم الهوية 1158813996"
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_exclude_methods_skips_selected_method() -> None:
    client = TestClient(
        create_app(
            exclude_methods={"DELETE"},
        )
    )

    response = client.request(
        "DELETE",
        "/method-echo",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["prompt"] == "رقم الهوية 1158813996"
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_exclude_methods_wins_over_include_methods() -> None:
    client = TestClient(
        create_app(
            include_methods={"POST"},
            exclude_methods={"POST"},
        )
    )

    response = client.request(
        "POST",
        "/method-echo",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["prompt"] == "رقم الهوية 1158813996"
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_normalizes_configured_methods() -> None:
    client = TestClient(
        create_app(
            include_methods={
                " post ",
            },
        )
    )

    response = client.request(
        "POST",
        "/method-echo",
        json={
            "prompt": "رقم الهوية 1158813996",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert "1158813996" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


def test_fastapi_middleware_skipped_method_bypasses_body_size_limit() -> None:
    client = TestClient(
        create_app(
            include_methods={"POST"},
            max_body_size=16,
        )
    )

    prompt = "رقم الهوية 1158813996 " + ("x" * 100)

    response = client.request(
        "PUT",
        "/method-echo",
        json={
            "prompt": prompt,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["prompt"] == prompt
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_combines_path_and_method_filters() -> None:
    client = TestClient(
        create_app(
            include_paths={"/method-echo"},
            include_methods={"POST"},
        )
    )

    prompt = "رقم الهوية 1158813996"

    response = client.request(
        "PUT",
        "/method-echo",
        json={
            "prompt": prompt,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["prompt"] == prompt
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers

@pytest.mark.parametrize(
    "content_type",
    [
        "application/json; charset=utf-8",
        "application/problem+json",
        "application/vnd.api+json; charset=utf-8",
        "Application/Merge-Patch+JSON",
    ],
)
def test_fastapi_middleware_protects_supported_json_media_types(
    content_type: str,
) -> None:
    client = TestClient(create_app())
    raw_body = '{"prompt":"رقم الهوية 1158813996"}'

    response = client.post(
        "/raw",
        content=raw_body,
        headers={
            "content-type": content_type,
        },
    )

    assert response.status_code == 200

    protected_body = response.json()["body"]

    assert "1158813996" not in protected_body
    assert response.headers["x-tabayyan-pii-detected"] == "true"
    assert int(response.headers["x-tabayyan-redacted-count"]) >= 1


@pytest.mark.parametrize(
    "content_type",
    [
        "application/jsonp",
        "text/json",
        "application/not-json",
        "application/xml",
    ],
)
def test_fastapi_middleware_skips_unsupported_json_like_media_types(
    content_type: str,
) -> None:
    client = TestClient(create_app())
    raw_body = '{"prompt":"رقم الهوية 1158813996"}'

    response = client.post(
        "/raw",
        content=raw_body,
        headers={
            "content-type": content_type,
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "body": raw_body,
    }
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_block_cross_border_returns_403() -> None:
    # PRIV-003 regression: when the guard blocks, the request must not reach
    # the route handler, and the 403 body must not leak the original text.
    app = FastAPI()
    app.add_middleware(
        TabayyanPrivacyMiddleware,
        destination="https://api.openai.com",
        block_cross_border=True,
    )

    handler_calls: list[object] = []

    @app.post("/chat")
    def chat(payload: dict[str, object]) -> dict[str, object]:
        handler_calls.append(payload)
        return payload

    client = TestClient(app)
    response = client.post(
        "/chat",
        json={"prompt": "National ID 1158813996"},
    )

    assert response.status_code == 403
    assert "1158813996" not in response.text
    assert handler_calls == []


def test_fastapi_middleware_block_cross_border_allows_clean_requests() -> None:
    app = FastAPI()
    app.add_middleware(
        TabayyanPrivacyMiddleware,
        destination="https://api.openai.com",
        block_cross_border=True,
    )

    @app.post("/chat")
    def chat(payload: dict[str, object]) -> dict[str, object]:
        return payload

    client = TestClient(app)
    response = client.post("/chat", json={"prompt": "nothing sensitive"})

    assert response.status_code == 200
    assert response.json() == {"prompt": "nothing sensitive"}


def test_fastapi_middleware_hash_mode_requires_salt_at_construction() -> None:
    # BUG-001 regression: HASH without a salt previously constructed fine and
    # raised per request, exactly on PII-bearing traffic.
    with pytest.raises(ValueError, match="salt"):
        TabayyanPrivacyMiddleware(None, mode=RedactionMode.HASH)


def test_fastapi_middleware_hash_mode_with_salt_redacts() -> None:
    app = FastAPI()
    app.add_middleware(
        TabayyanPrivacyMiddleware,
        destination="https://api.openai.com",
        mode=RedactionMode.HASH,
        salt="unit-test-key",
    )

    @app.post("/chat")
    def chat(payload: dict[str, object]) -> dict[str, object]:
        return payload

    client = TestClient(app)
    response = client.post("/chat", json={"prompt": "National ID 1158813996"})

    assert response.status_code == 200
    body = response.json()
    assert "1158813996" not in body["prompt"]
    assert "[HASH:" in body["prompt"]


def test_fastapi_middleware_tokenize_mode_is_rejected() -> None:
    # BUG-001/TOKENIZE policy: the middleware has no channel to return the
    # vault, so reversible tokenization would silently become irreversible.
    with pytest.raises(ValueError, match="TOKENIZE"):
        TabayyanPrivacyMiddleware(None, mode=RedactionMode.TOKENIZE)


def test_fastapi_middleware_clean_json_body_forwarded_byte_identical() -> None:
    # INFO-002: when nothing is redacted the original bytes pass through
    # unchanged (key order, spacing, and number formatting preserved).
    client = TestClient(create_app())
    raw_body = '{"note":  "no pii here", "n": 1.50}'

    response = client.post(
        "/raw",
        content=raw_body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 200
    assert response.json() == {"body": raw_body}
    assert response.headers["x-tabayyan-pii-detected"] == "false"


def test_fastapi_middleware_deeply_nested_json_rejected_fail_closed() -> None:
    # INFO-002: pathologically deep nesting must produce a controlled 400,
    # not an unhandled RecursionError.
    client = TestClient(create_app())
    depth = 20_000
    raw_body = ("[" * depth) + ("]" * depth)

    response = client.post(
        "/raw",
        content=raw_body,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 400


def test_fastapi_middleware_protects_chunked_request_body() -> None:
    # BUG-005-adjacent: multi-chunk (more_body=True) requests must be
    # reassembled and protected like single-chunk ones.
    client = TestClient(create_app())

    def chunks():
        yield b'{"prompt": "Nation'
        yield b"al ID 11588"
        yield b'13996"}'

    response = client.post(
        "/echo",
        content=chunks(),
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 200
    body = response.json()
    assert "1158813996" not in body["prompt"]
    assert response.headers["x-tabayyan-pii-detected"] == "true"


def test_fastapi_middleware_does_not_forward_truncated_body_on_disconnect() -> None:
    # BUG-005 regression: a disconnect mid-body must not deliver a truncated
    # body to the application.
    called: list[bool] = []

    async def inner_app(scope, receive, send):
        called.append(True)

    mw = TabayyanPrivacyMiddleware(
        inner_app, destination="https://api.openai.com"
    )

    messages = [
        {"type": "http.request", "body": b'{"prompt": "ID 11588', "more_body": True},
        {"type": "http.disconnect"},
    ]

    async def receive():
        return messages.pop(0)

    sent: list[dict] = []

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/chat",
        "headers": [(b"content-type", b"application/json")],
    }

    asyncio.run(mw(scope, receive, send))

    assert called == []
    assert sent == []


def test_fastapi_middleware_subsequent_receive_returns_disconnect() -> None:
    # BUG-005 regression: after the protected body is delivered once, further
    # receive() calls must reach the original channel (so http.disconnect is
    # observable) instead of replaying the body forever.
    results: dict[str, dict] = {}

    async def inner_app(scope, receive, send):
        results["first"] = await receive()
        results["second"] = await receive()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    mw = TabayyanPrivacyMiddleware(
        inner_app, destination="https://api.openai.com"
    )

    messages = [
        {"type": "http.request", "body": b'{"prompt": "hello"}', "more_body": False},
        {"type": "http.disconnect"},
    ]

    async def receive():
        return messages.pop(0)

    async def send(message):
        pass

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/chat",
        "headers": [(b"content-type", b"application/json")],
    }

    asyncio.run(mw(scope, receive, send))

    assert results["first"]["type"] == "http.request"
    assert results["second"]["type"] == "http.disconnect"
