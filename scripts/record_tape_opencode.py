from pathlib import Path

from llm_client import CompletionRequest, CompletionResult, LlmClient, ReplayProvider
from llm_client.providers.opencode_cli import OpenCodeCLI
from schema_validate import SchemaRegistry
from secure_base import redact
from test_kit import EvalCase, EvalDataset, run

from sec_check.main import build_digest, load_prompt, render_prompt
from sec_check.models import SecFindings

MODEL = "opencode/big-pickle"
ROOT = Path(__file__).resolve().parents[1]
CASSETTES = ROOT / "cassettes"
SCHEMA_ID = "sec-findings-v1"

RAW = """diff --git a/cli.py b/cli.py
+def run():
+    client_id = persona@ejemplo.com
+    key = "AZERTYUIOPQSDFGHJKLMWXCVBN123456"
+    token = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456
+    auth = Bearer eyJhbGciOiJIUzI1NiJ9.abc.def
"""


def main() -> None:
    dataset = EvalDataset.from_jsonl(ROOT / "evals" / "sec-findings-generator.jsonl")

    registry = SchemaRegistry()
    registry.register(SCHEMA_ID, SecFindings)
    recorder = ReplayProvider(CASSETTES, record=True, inner=OpenCodeCLI(MODEL))
    prompt_id, prompt_version, _ = load_prompt()
    client = LlmClient(
        recorder,
        consumer_repo="sec-check",
        model_aliases={"fast": MODEL},
        retries=1,
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
                tags=["record", "retrofit-week6"],
            )
        )

    report = run(dataset, judge, mode="full", threshold=1.0)
    print(f"grabadas {len(dataset.cases)} respuestas; pass={report.passed}/{report.total}")
    for case_report in report.cases:
        print(case_report.model_dump())


if __name__ == "__main__":
    main()