"""Offline request-shape contract tests (SEC-001).

Realistic OpenAI / Anthropic request payloads (as plain dicts, matching what
the SDKs serialize) are pushed through Guard.protect_messages to pin down:

  * every documented text channel is redacted (content strings, multimodal
    text parts, tool-call arguments, tool_use input, tool_result content);
  * non-text channels (image blocks, ids, model params) survive untouched;
  * unrecognized shapes are surfaced per the on_unrecognized policy instead
    of silently passing through looking protected;
  * caller-owned message structures are never mutated.

Synthetic identifiers only.
"""
import copy
import random

import pytest

from tabayyan import Guard
from tabayyan.middleware import UnscannedContentWarning
from tests.synthetic import make_national_id

NID = make_national_id(random.Random(500), "1")
DEST = "https://api.openai.com"


# --- unrecognized-shape policy ---

def test_non_dict_message_warns_and_passes_through():
    g = Guard()
    with pytest.warns(UnscannedContentWarning):
        safe, audits, vault, blocked = g.protect_messages(
            [("user", f"ID {NID}")], destination=DEST
        )
    assert safe == [("user", f"ID {NID}")]
    assert audits == []


def test_non_dict_message_error_policy_raises():
    g = Guard(on_unrecognized="error")
    with pytest.raises(ValueError, match="WITHOUT scanning"):
        g.protect_messages([("user", f"ID {NID}")], destination=DEST)


def test_non_dict_message_pass_policy_is_silent():
    import warnings as _warnings

    g = Guard(on_unrecognized="pass")
    with _warnings.catch_warnings():
        _warnings.simplefilter("error")  # any warning would fail the test
        safe, *_ = g.protect_messages([("user", "x")], destination=DEST)
    assert safe == [("user", "x")]


def test_typed_object_content_warns():
    class TypedContent:  # stand-in for a typed SDK content object
        text = f"ID {NID}"

    g = Guard()
    with pytest.warns(UnscannedContentWarning):
        g.protect_messages(
            [{"role": "user", "content": TypedContent()}], destination=DEST
        )


def test_invalid_on_unrecognized_value_rejected():
    with pytest.raises(ValueError):
        Guard(on_unrecognized="ignore")


def test_none_content_passes_without_warning():
    import warnings as _warnings

    g = Guard()
    with _warnings.catch_warnings():
        _warnings.simplefilter("error")
        safe, *_ = g.protect_messages(
            [{"role": "assistant", "content": None}], destination=DEST
        )
    assert safe == [{"role": "assistant", "content": None}]


# --- OpenAI chat.completions request shape ---

def _openai_request():
    return [
        {"role": "system", "content": "You are a support agent."},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": f"Customer ID {NID}, see photo"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
            ],
        },
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "lookup_customer",
                        "arguments": f'{{"national_id": "{NID}"}}',
                    },
                }
            ],
        },
        {"role": "tool", "tool_call_id": "call_1", "content": f"record for {NID}"},
    ]


def test_openai_tool_call_arguments_are_redacted():
    g = Guard()
    safe, audits, vault, blocked = g.protect_messages(_openai_request(), destination=DEST)

    args = safe[2]["tool_calls"][0]["function"]["arguments"]
    assert NID not in args
    assert safe[2]["tool_calls"][0]["function"]["name"] == "lookup_customer"
    assert safe[2]["tool_calls"][0]["id"] == "call_1"


def test_openai_multimodal_and_tool_result_channels():
    g = Guard()
    safe, *_ = g.protect_messages(_openai_request(), destination=DEST)

    # text part redacted, image part byte-identical
    assert NID not in safe[1]["content"][0]["text"]
    assert safe[1]["content"][1] == {
        "type": "image_url",
        "image_url": {"url": "data:image/png;base64,AAAA"},
    }
    # tool role string content redacted
    assert NID not in safe[3]["content"]


def test_openai_legacy_function_call_arguments_are_redacted():
    g = Guard()
    safe, *_ = g.protect_messages(
        [
            {
                "role": "assistant",
                "content": None,
                "function_call": {
                    "name": "lookup",
                    "arguments": f'{{"id": "{NID}"}}',
                },
            }
        ],
        destination=DEST,
    )
    assert NID not in safe[0]["function_call"]["arguments"]
    assert safe[0]["function_call"]["name"] == "lookup"


def test_caller_messages_are_not_mutated():
    g = Guard()
    original = _openai_request()
    snapshot = copy.deepcopy(original)
    g.protect_messages(original, destination=DEST)
    assert original == snapshot


# --- Anthropic messages request shape ---

def _anthropic_request():
    return [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": f"my id is {NID}"},
                {
                    "type": "image",
                    "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"},
                },
            ],
        },
        {
            "role": "assistant",
            "content": [
                {
                    "type": "tool_use",
                    "id": "toolu_1",
                    "name": "lookup_customer",
                    "input": {"national_id": NID, "fields": ["name", NID]},
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": [{"type": "text", "text": f"found {NID}"}],
                }
            ],
        },
    ]


def test_anthropic_tool_use_input_is_redacted():
    g = Guard()
    safe, *_ = g.protect_messages(_anthropic_request(), destination=DEST)

    tool_use = safe[1]["content"][0]
    assert NID not in tool_use["input"]["national_id"]
    assert NID not in tool_use["input"]["fields"][1]
    assert tool_use["input"]["fields"][0] == "name"
    assert tool_use["id"] == "toolu_1" and tool_use["name"] == "lookup_customer"


def test_anthropic_tool_result_and_image_channels():
    g = Guard()
    safe, *_ = g.protect_messages(_anthropic_request(), destination=DEST)

    assert NID not in safe[2]["content"][0]["content"][0]["text"]
    assert safe[0]["content"][1]["source"]["data"] == "AAAA"  # image untouched
    assert NID not in safe[0]["content"][0]["text"]


def test_anthropic_string_tool_result_is_redacted():
    g = Guard()
    safe, *_ = g.protect_messages(
        [
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_2",
                        "content": f"record {NID}",
                    }
                ],
            }
        ],
        destination=DEST,
    )
    assert NID not in safe[0]["content"][0]["content"]


def test_anthropic_caller_data_not_mutated():
    g = Guard()
    original = _anthropic_request()
    snapshot = copy.deepcopy(original)
    g.protect_messages(original, destination=DEST)
    assert original == snapshot
