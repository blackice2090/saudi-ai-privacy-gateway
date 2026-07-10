from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

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


def test_fastapi_middleware_invalid_json_does_not_crash() -> None:
    client = TestClient(create_app())

    invalid_json = '{"prompt": "رقم الهوية 1158813996"'

    response = client.post(
        "/raw",
        content=invalid_json,
        headers={
            "content-type": "application/json",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "body": invalid_json,
    }
    assert response.headers["x-tabayyan-pii-detected"] == "false"
    assert response.headers["x-tabayyan-redacted-count"] == "0"


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