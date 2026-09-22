# sec-check

> **Semana:** 4 · **Core:** `llm-dev-core` 0.4.0

## Problema

Los diffs y los archivos están llenos de secretos accidentales: tokens pegados, claves de
API, emails. El error clásico es mandar eso a un LLM antes de mirarlo. `sec-check` lo
invierte: **primero detecta y redacta** (con `secure-base`), y **solo lo ya enmascarado**
viaja a un LLM que clasifica el riesgo y sugiere remediación.

## Demo

```bash
cd tu-repo
sec-check --from-ref v1.0.0 --to-ref HEAD   # escanea el diff de una release
sec-check --path .env.example               # o un archivo suelto
```

Exit codes: `0` = sin secretos · `1` = secretos detectados (reporte impreso) · `2` = inválido.

## Arquitectura

```
┌────────────┐   texto    ┌───────────────────────────────────────────┐
│ git diff / │ ────────▶ │ sec-check (este proyecto)                  │
│ archivo    │            │  · secure-base: detect → redact           │
└────────────┘            │  · assert_redacted(.) == [] (garantía)    │
                          │  · LlmClient SOLO con texto enmascarado   │
                          │  · schema-validate: sec-findings-v1       │
                          │  · span JSONL → stderr                    │
                          └──────────────┬────────────────────────────┘
                                         │ provider
                                         ▼
                        ┌──────────────────────────────────┐
                        │ opencode run (tu sesión, free)   │
                        │   · o ReplayProvider (cassettes) │
                        └──────────────────────────────────┘
```

El invariante de la semana: si `assert_redacted(texto_enmascarado)` no está vacío, el
proceso aborta **antes** de formar un prompt. Nada crudo cruza el límite.

## Recicla de

| Módulo del core | Qué aporta |
|---|---|
| `llm-client` | Llamadas LLM con retry+backoff, span de 20 campos, costo, record/replay sin API key |
| `schema-validate` | El reporte de triaje se valida contra `sec-findings-v1` (JSON con/sin caretas, reparación de 2 intentos) |
| `secure-base` | `detect` + `redact` + `assert_redacted`: los secretos se enmascaran antes de cualquier prompt |

## Limitaciones

- Los detectores son heurísticos: un secreto que no sigue patrones conocidos puede escapar
  del escáner (la garantía fuerte es que *lo que sí detectó* nunca viaja crudo).
- El triaje depende de la calidad del modelo; `leaked_secrets_count` es determinista (del escaneo),
  la prosa de severidad/remediación es propuesta, no veredicto.
- Los commits salen del repo tal cual hacia el escáner local; nada del contenido se envía al proveedor
  salvo el texto ya enmascarado.

## Roadmap

- [x] Evaluación `eval-smoke` con el dataset de `evals/` (sem. 5, test-kit; 3 casos congelados en el retrofit #0 de la sem. 6)
- [ ] Lint anti-secretos en CI para cualquier consumidor (`ci-pack`, sem. 7)
- [ ] Detector por hook de git (`pre-commit`) para bloquear antes del commit
- [ ] `--max-ratio` para fallar si un diff es mayoría de secretos (Delta a priorizar)