from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tabayyan.integrations.fastapi import TabayyanPrivacyMiddleware


def create_app() -> FastAPI:
    app = FastAPI()

    app.add_middleware(
        TabayyanPrivacyMiddleware,
        destination="https://api.openai.com",
    )

    @app.post("/echo")
    def echo(payload: dict[str, object]) -> dict[str, object]:
        return payload

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