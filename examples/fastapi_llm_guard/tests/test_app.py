from __future__ import annotations

from fastapi.testclient import TestClient

from examples.fastapi_llm_guard.app import app


client = TestClient(app)


def test_chat_redacts_sensitive_data_before_llm_response() -> None:
    response = client.post(
        "/chat",
        json={
            "prompt": (
                "حلل حالة العميل. الاسم محمد بن عبدالله، "
                "رقم الهوية 1158813996، الجوال +966512345678"
            )
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["detection"]["pii_detected"] is True
    assert body["detection"]["redacted_count"] >= 2
    assert "1158813996" not in body["safe_prompt"]
    assert "+966512345678" not in body["safe_prompt"]
    assert "1158813996" not in body["llm_response"]
    assert "+966512345678" not in body["llm_response"]