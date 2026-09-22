from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from decimal import Decimal
from pathlib import Path

import yaml
from llm_client import CompletionRequest, LlmClient, ReplayProvider, Span
from llm_client.providers.opencode_cli import OpenCodeCLI
from schema_validate import SchemaRegistry
from secure_base import assert_redacted, redact

from .models import SecFindings

DEFAULT_MODEL = "opencode/big-pickle"
SCHEMA_ID = "sec-findings-v1"
ROOT = Path(__file__).resolve().parents[2]
PROMPT_FILE = ROOT / "prompts" / "sec-findings.md"


def load_prompt() -> tuple[str, str, str]:
    text = PROMPT_FILE.read_text()
    if not text.startswith("---"):
        raise SystemExit(f"{PROMPT_FILE}: falta frontmatter")
    _, frontmatter, body = text.split("---", 2)
    data = yaml.safe_load(frontmatter)
    return data["id"], data["version"], body.strip()


def render_prompt(prompt_id: str, prompt_version: str, variables: dict) -> list[dict]:
    _, _, body = load_prompt()
    system_part = body.split("## Sistema\n", 1)[1].split("## Usuario\n", 1)[0].strip()
    user_part = body.split("## Usuario\n", 1)[1].strip().format(
        redacted_text=variables["redacted_text"],
        digest=variables["digest"],
    )
    return [
        {"role": "system", "content": system_part},
        {"role": "user", "content": user_part},
    ]


def build_digest(findings) -> str:
    counter = Counter(f.type for f in findings)
    return "\n".join(f"{ftype}: {count} vez(es)" for ftype, count in sorted(counter.items()))


def git_diff(root: Path, from_ref: str, to_ref: str) -> str:
    cmd = ["git", "-C", str(root), "diff", from_ref, to_ref, "--", ".", ":(exclude)uv.lock"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        sys.exit(1)
    return proc.stdout


def build_emitter(span_file: Path | None):
    def emit(span: Span, _result) -> None:
        if span_file is not None:
            with span_file.open("a") as handle:
                handle.write(span.as_jsonl() + "\n")
        else:
            sys.stderr.write(span.as_jsonl() + "\n")

    return emit


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sec-check", description="Escáner de secretos con triaje LLM")
    parser.add_argument("--from-ref", default=None, help="ref inicial del rango git (excluida)")
    parser.add_argument("--to-ref", default="HEAD", help="ref final del rango git (incluida)")
    parser.add_argument("--path", default=None, help="escanear un archivo en vez de un rango git")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"modelo opencode (default: {DEFAULT_MODEL})")
    parser.add_argument("--replay", metavar="DIR", default=None, help="reproducir cassettes en vez de llamar al LLM")
    parser.add_argument("--span-file", metavar="PATH", default=None, help="escribir spans a un archivo JSONL")
    parser.add_argument("--cost-cap", metavar="USD", type=Decimal, default=None, help="costo semanal por llamada")
    parser.add_argument("--out", metavar="PATH", default=None, help="escribir el reporte JSON a un archivo")
    parser.add_argument("--repo", default=None, help="raíz del repo a inspeccionar (default: cwd)")
    args = parser.parse_args(argv)

    root = Path(args.repo).resolve() if args.repo else Path.cwd()
    if args.path:
        text = (root / args.path).read_text()
    else:
        if not args.from_ref:
            sys.stderr.write("sec-check: usa --path o --from-ref … --to-ref\n")
            return 2
        text = git_diff(root, args.from_ref, args.to_ref)
        if not text.strip():
            sys.stderr.write("sec-check: no hay cambios en el rango\n")
            return 0

    findings = redact(text).findings
    if not findings:
        report = SecFindings(summary="Sin secretos detectados en la entrada.", risk="none")
        print(report.model_dump_json(indent=2))
        return 0

    sanitized = redact(text)
    if assert_redacted(sanitized.text):
        raise RuntimeError("sec-check: la redacción falló; nada se envía al LLM")

    if args.replay:
        provider = ReplayProvider(args.replay, record=False)
    else:
        provider = OpenCodeCLI(args.model, cwd=str(root))

    registry = SchemaRegistry()
    registry.register(SCHEMA_ID, SecFindings)

    variables = {"redacted_text": sanitized.text, "digest": build_digest(findings)}
    prompt_id, prompt_version, _ = load_prompt()
    client = LlmClient(
        provider,
        consumer_repo="sec-check",
        model_aliases={"fast": args.model},
        emitter=build_emitter(Path(args.span_file) if args.span_file else None),
        cost_cap_usd=args.cost_cap,
        renderer=render_prompt,
        validator=registry.make_validator(SCHEMA_ID),
    )
    result = client.complete(
        CompletionRequest(
            prompt_id=prompt_id,
            prompt_version=prompt_version,
            variables=variables,
            model_alias="fast",
            response_schema=SCHEMA_ID,
            tags=["sec-check", "week-4"],
        )
    )

    if not result.validation.ok:
        sys.stderr.write(f"sec-check: respuesta no válida ({', '.join(result.validation.errors)})\n")
        return 2

    report = result.parsed
    report.leaked_secrets_count = len(findings)
    payload = report.model_dump_json(indent=2)
    if args.out:
        Path(args.out).write_text(payload + "\n")
    print(payload)
    return 1 if report.leaked_secrets_count else 0


if __name__ == "__main__":
    raise SystemExit(main())