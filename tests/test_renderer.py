from __future__ import annotations

from pathlib import Path

from sec_check.main import load_prompt, render_prompt


def test_renderer_never_leaks_raw_secret() -> None:
    raw = "el token ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456 y persona@ejemplo.com deben ir enmascarados"
    from secure_base import redact

    sanitized = redact(raw)
    messages = render_prompt("x", "0.1.0", {"redacted_text": sanitized.text, "digest": "email: 1 vez(es)"})

    prompt_text = "\n".join(m["content"] for m in messages)
    assert "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz123456" not in prompt_text
    assert "persona@ejemplo.com" not in prompt_text
    assert "[REDACTED:email:1]" in prompt_text
    assert "[REDACTED:github_token:1]" in prompt_text