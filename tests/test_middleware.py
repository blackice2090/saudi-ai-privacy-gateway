import json
import random

import pytest

from tabayyan import AuditLog, Guard, RedactionMode, is_in_kingdom
from tabayyan.entities import Category
from tests.synthetic import make_national_id

AZURE = "https://contoso.openai.azure.com/v1/chat"
INK = "https://llm.myhospital.health.sa/v1"


def test_in_kingdom_detection():
    assert is_in_kingdom(INK) is True
    assert is_in_kingdom(AZURE) is False
    assert is_in_kingdom(None) is None
    assert is_in_kingdom(
        "https://api.openai.com",
        allowlist=["openai.com"],
    ) is True


def test_cross_border_flag_for_external_endpoint():
    nid = make_national_id(random.Random(90), "1")
    g = Guard()

    pr = g.protect(f"ID {nid}", destination=AZURE)

    assert pr.audit.cross_border_transfer is True
    assert pr.audit.personal_data_present is True
    assert pr.audit.action == "redact"
    assert nid not in pr.text


def test_no_cross_border_for_in_kingdom():
    nid = make_national_id(random.Random(91), "1")

    pr = Guard().protect(f"ID {nid}", destination=INK)

    assert pr.audit.cross_border_transfer is False
    assert pr.audit.in_kingdom is True


def test_no_personal_data_no_transfer_flag():
    pr = Guard().protect(
        "the quarterly report is ready",
        destination=AZURE,
    )

    assert pr.audit.personal_data_present is False
    assert pr.audit.cross_border_transfer is False
    assert pr.audit.action == "allow"


def test_block_on_category():
    nid = make_national_id(random.Random(92), "1")
    g = Guard(block_categories=[Category.NATIONAL_IDENTIFIER])

    pr = g.protect(f"ID {nid}", destination=AZURE)

    assert pr.blocked is True
    assert pr.audit.action == "block"


def test_block_does_not_leak_raw_pii_in_text():
    nid = make_national_id(random.Random(921), "1")
    g = Guard(block_categories=[Category.NATIONAL_IDENTIFIER])

    pr = g.protect(f"ID {nid}", destination=AZURE)

    # Even though the call is blocked, the returned text must not carry the
    # raw identifier. A caller that mistakenly forwards it cannot leak PII.
    assert nid not in pr.text


def test_block_cross_border_personal_data():
    nid = make_national_id(random.Random(93), "1")
    g = Guard(block_cross_border=True)

    external_result = g.protect(f"ID {nid}", destination=AZURE)
    in_kingdom_result = g.protect(f"ID {nid}", destination=INK)

    assert external_result.blocked is True
    assert in_kingdom_result.blocked is False


def test_audit_log_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    g = Guard(audit=AuditLog(path=str(path)))
    nid = make_national_id(random.Random(94), "1")

    g.protect(f"ID {nid}", destination=AZURE)
    g.protect("nothing here", destination=AZURE)

    lines = path.read_text().strip().splitlines()

    assert len(lines) == 2

    rec0 = json.loads(lines[0])

    assert rec0["cross_border_transfer"] is True
    assert "national_identifier" in rec0["category_summary"]

    # Raw values must not be logged by default.
    assert rec0["values"] is None


def test_audit_values_opt_in():
    nid = make_national_id(random.Random(95), "1")
    g = Guard(record_values=True)

    pr = g.protect(f"ID {nid}", destination=AZURE)

    assert nid in (pr.audit.values or [])


def test_wrap_openai_redacts_before_send():
    nid = make_national_id(random.Random(96), "1")

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                def create(model, messages, **kwargs):
                    response = type("Response", (), {})()
                    response.sent = messages
                    return response

    g = Guard()
    wrapped = g.wrap(
        FakeClient(),
        provider="openai",
        destination=AZURE,
    )

    out = wrapped.create(
        model="gpt",
        messages=[
            {
                "role": "user",
                "content": f"ID {nid}",
            }
        ],
    )

    assert nid not in out.sent[0]["content"]


def test_wrap_openai_blocks():
    nid = make_national_id(random.Random(97), "1")

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                def create(model, messages, **kwargs):
                    raise AssertionError(
                        "client must not be called when the request is blocked"
                    )

    g = Guard(block_cross_border=True)
    wrapped = g.wrap(
        FakeClient(),
        provider="openai",
        destination=AZURE,
    )

    with pytest.raises(PermissionError):
        wrapped.create(
            model="gpt",
            messages=[
                {
                    "role": "user",
                    "content": f"ID {nid}",
                }
            ],
        )


def test_tokenize_restore_roundtrip_in_wrapper():
    nid = make_national_id(random.Random(98), "1")

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                def create(model, messages, **kwargs):
                    # Echo the protected content back as the model response.
                    content = messages[0]["content"]
                    message = type("Message", (), {"content": content})()
                    choice = type("Choice", (), {"message": message})()

                    return type(
                        "Response",
                        (),
                        {"choices": [choice]},
                    )()

    g = Guard(mode=RedactionMode.TOKENIZE)
    wrapped = g.wrap(
        FakeClient(),
        provider="openai",
        destination=AZURE,
        restore_response=True,
    )

    out = wrapped.create(
        model="gpt",
        messages=[
            {
                "role": "user",
                "content": f"ID {nid}",
            }
        ],
    )

    # The tokenized response is restored to the original value.
    assert nid in out.choices[0].message.content


def test_guard_openai_emits_deprecation_warning():
    with pytest.warns(
        DeprecationWarning,
        match=r"Guard\.guard_openai\(\) is deprecated",
    ):
        Guard().guard_openai(
            object(),
            destination=AZURE,
        )


# --- hardened message-shape handling (v0.5.x) ---


def test_protect_messages_string_and_roles():
    nid = make_national_id(random.Random(100), "1")
    g = Guard()

    messages = [
        {
            "role": "system",
            "content": f"system note id {nid}",
        },
        {
            "role": "user",
            "content": "hello",
        },
    ]

    safe, _audits, _vault, blocked = g.protect_messages(
        messages,
        destination=AZURE,
    )

    # PII is redacted even in the system role.
    assert nid not in safe[0]["content"]
    assert safe[1]["content"] == "hello"
    assert blocked is False


def test_protect_messages_multimodal_list_content():
    nid = make_national_id(random.Random(101), "1")
    g = Guard()

    messages = [
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": f"patient id {nid}",
                },
                {
                    "type": "image_url",
                    "image_url": {
                        "url": "https://x/y.png",
                    },
                },
            ],
        }
    ]

    safe, _audits, _vault, _blocked = g.protect_messages(
        messages,
        destination=AZURE,
    )

    parts = safe[0]["content"]

    # Text content is protected.
    assert nid not in parts[0]["text"]

    # Non-text content is left unchanged.
    assert parts[1]["type"] == "image_url"


def test_protect_messages_none_content_passthrough():
    g = Guard()

    messages = [
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "1",
                }
            ],
        }
    ]

    safe, _audits, _vault, _blocked = g.protect_messages(messages)

    assert safe[0]["tool_calls"] == [{"id": "1"}]


def test_wrapper_streaming_redacts_request_skips_restore():
    nid = make_national_id(random.Random(102), "1")
    captured = {}

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                def create(model, messages, **kwargs):
                    captured["sent"] = messages[0]["content"]
                    captured["stream"] = kwargs.get("stream")

                    return iter(["chunk1", "chunk2"])

    g = Guard(mode=RedactionMode.TOKENIZE)
    wrapped = g.wrap(
        FakeClient(),
        provider="openai",
        destination=AZURE,
        restore_response=True,
    )

    out = wrapped.create(
        model="gpt",
        messages=[
            {
                "role": "user",
                "content": f"id {nid}",
            }
        ],
        stream=True,
    )

    # The outbound request is protected.
    assert nid not in captured["sent"]
    assert captured["stream"] is True

    # Streaming responses pass through without token restoration.
    assert list(out) == ["chunk1", "chunk2"]