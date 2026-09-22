from __future__ import annotations

from pathlib import Path

import pytest
from llm_client import CompletionRequest, CompletionResult, LlmClient, ReplayProvider
from schema_validate import SchemaRegistry
from test_kit import EvalCase, EvalDataset, run

from sec_check.main import load_prompt, render_prompt
from sec_check.models import SecFindings

ROOT = Path(__file__).resolve().parents[1]
CASSETTES = ROOT / "cassettes"
SCHEMA_ID = "sec-findings-v1"


@pytest.mark.skipif(
    not CASSETTES.is_dir() or not list(CASSETTES.glob("complete-*.jsonl")),
    reason="tape real no grabada (scripts/record_tape_opencode.py)",
)
def test_sec_check_replay_dataset_en_verde() -> None:
    registry = SchemaRegistry()
    registry.register(SCHEMA_ID, SecFindings)

    dataset = EvalDataset.from_jsonl(ROOT / "evals/sec-findings-generator.jsonl")
    provider = ReplayProvider(CASSETTES, record=False)
    prompt_id, prompt_version, _ = load_prompt()
    client = LlmClient(
        provider,
        consumer_repo="sec-check",
        model_aliases={"fast": "opencode/big-pickle"},
        renderer=render_prompt,
        validator=registry.make_validator(SCHEMA_ID),
    )

    def judge(case: EvalCase) -> CompletionResult:
        return client.complete(
            CompletionRequest(
                prompt_id=case.prompt_id,
                prompt_version=case.prompt_version,
                variables=case.input,
                model_alias="fast",
                response_schema=SCHEMA_ID,
            )
        )

    report = run(dataset, judge, mode="full", threshold=1.0)
    assert report.threshold_ok, report.model_dump()
    assert report.total == 3