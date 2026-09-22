from __future__ import annotations

from pathlib import Path

import pytest
from llm_client import CompletionRequest, LlmClient, ReplayProvider
from schema_validate import SchemaRegistry
from secure_base import redact

from sec_check.main import build_digest, load_prompt, render_prompt
from sec_check.models import SecFindings

CASSETTES = Path(__file__).resolve().parents[1] / "cassettes"

RAW = """diff --git a/cli.py b/cli.py
+def run():
+    client_id = persona@ejemplo.com
+    key = "AZERTYUIOPQSDFGHJKLMWXCVBN123456"
+    token = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456
+    auth = Bearer eyJhbGciOiJIUzI1NiJ9.abc.def
"""


def _has_tape() -> bool:
    return CASSETTES.is_dir() and list(CASSETTES.glob("complete-*.jsonl"))


@pytest.mark.skipif(not _has_tape(), reason="tape real no grabada (scripts/record_tape_opencode.py)")
def test_sec_check_replay_triage_validates() -> None:
    registry = SchemaRegistry()
    registry.register("sec-findings-v1", SecFindings)
    sanitized = redact(RAW)

    provider = ReplayProvider(CASSETTES, record=False)
    prompt_id, prompt_version, _ = load_prompt()
    client = LlmClient(
        provider,
        consumer_repo="sec-check",
        model_aliases={"fast": "opencode/big-pickle"},
        renderer=render_prompt,
        validator=registry.make_validator("sec-findings-v1"),
    )
    result = client.complete(
        CompletionRequest(
            prompt_id=prompt_id,
            prompt_version=prompt_version,
            variables={"redacted_text": sanitized.text, "digest": build_digest(sanitized.findings)},
            model_alias="fast",
            response_schema="sec-findings-v1",
            tags=["replay", "week-4"],
        )
    )

    assert result.provider == "replay"
    assert result.validation.ok is True
    assert isinstance(result.parsed, SecFindings)
    assert result.parsed.items
    assert result.parsed.leaked_secrets_count >= 2