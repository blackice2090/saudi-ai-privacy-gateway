from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from tabayyan.integrations.fastapi import TabayyanPrivacyMiddleware


def create_app(*, include_response_headers: bool = True) -> FastAPI:
    app = FastAPI()

    app.add_middleware(
        TabayyanPrivacyMiddleware,
        destination="https://api.openai.com",
        include_response_headers=include_response_headers,
    )

    @app.post("/echo")
    def echo(payload: dict[str, object]) -> dict[str, object]:
        return payload

    @app.post("/raw")
    async def raw(request: Request) -> dict[str, str]:
        return {"body": (await request.body()).decode("utf-8")}

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
                {"role": "user", "content": "رقم الهوية 1158813996"},
                {"role": "assistant", "content": "جاهز للمراجعة"},
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

    response = client.post("/echo", json=payload)

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
        headers={"content-type": "text/plain; charset=utf-8"},
    )

    assert response.status_code == 200
    assert response.json() == {"body": raw_body}
    assert "x-tabayyan-pii-detected" not in response.headers
    assert "x-tabayyan-redacted-count" not in response.headers


def test_fastapi_middleware_invalid_json_does_not_crash() -> None:
    client = TestClient(create_app())

    invalid_json = '{"prompt": "رقم الهوية 1158813996"'

    response = client.post(
        "/raw",
        content=invalid_json,
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 200
    assert response.json() == {"body": invalid_json}
    assert response.headers["x-tabayyan-pii-detected"] == "false"
    assert response.headers["x-tabayyan-redacted-count"] == "0"


def test_fastapi_middleware_can_disable_response_headers() -> None:
    client = TestClient(create_app(include_response_headers=False))

    response = client.post(
        "/echo",
        json={"prompt": "رقم الهوية 1158813996"},
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
        headers={"content-type": "application/json"},
    )

    assert response.status_code == 200
    assert response.json() == {"body": ""}
    assert response.headers["x-tabayyan-pii-detected"] == "false"
    assert response.headers["x-tabayyan-redacted-count"] == "0"