from pathlib import Path

from llm_client import CompletionRequest, LlmClient, ReplayProvider
from llm_client.providers.opencode_cli import OpenCodeCLI
from schema_validate import SchemaRegistry
from secure_base import redact

from sec_check.main import build_digest, load_prompt, render_prompt
from sec_check.models import SecFindings

MODEL = "opencode/big-pickle"
CASSETTES = Path(__file__).resolve().parents[1] / "cassettes"

RAW = """diff --git a/cli.py b/cli.py
+def run():
+    client_id = persona@ejemplo.com
+    key = "AZERTYUIOPQSDFGHJKLMWXCVBN123456"
+    token = ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456
+    auth = Bearer eyJhbGciOiJIUzI1NiJ9.abc.def
"""


def main() -> None:
    sanitized = redact(RAW)
    registry = SchemaRegistry()
    registry.register("sec-findings-v1", SecFindings)
    recorder = ReplayProvider(CASSETTES, record=True, inner=OpenCodeCLI(MODEL))
    prompt_id, prompt_version, _ = load_prompt()
    client = LlmClient(
        recorder,
        consumer_repo="sec-check",
        model_aliases={"fast": MODEL},
        retries=1,
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
            tags=["record", "seed-week4"],
        )
    )
    print(f"validated={result.validation.ok} parsed={result.parsed}")


if __name__ == "__main__":
    main()