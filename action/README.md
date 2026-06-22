# GlyphHound GitHub Action

Scan a model file / Hugging Face repo / Ollama model for **code-executing chat templates**
(load-time RCE, CVE-2024-34359 / CVE-2026-5760 class) in CI, and surface the findings in
GitHub **code scanning** as SARIF. Deterministic, **parse-only, no weights downloaded**, no LLM.

> Status: prepared for release, **not yet published** to the Marketplace. The examples below use
> `ydarwish1/glyphhound/action@v1` as the intended ref; adjust to your fork/tag.

## Usage

```yaml
# .github/workflows/glyphhound.yml
name: GlyphHound
on: [push, pull_request]

permissions:
  contents: read
  security-events: write    # required to upload SARIF to code scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ydarwish1/glyphhound/action@v1
        with:
          ref: Qwen/Qwen2.5-0.5B-Instruct        # an HF repo id (canonical template)
          revision: 7ae557604adf67be50417f59c2c2f167def9a775   # pin a SHA for determinism
```

Scan a local model file committed to the repo instead:

```yaml
      - uses: ydarwish1/glyphhound/action@v1
        with:
          ref: models/my-model.gguf
          source: file
```

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `ref` | *(required)* | Local `.gguf`/template path, a `.gguf` URL, an HF repo id, or an Ollama name. |
| `source` | `auto` | `auto \| file \| gguf \| gguf-url \| hf \| ollama`. |
| `file` | `""` | Optional `.gguf` filename inside an HF repo (without it, the canonical template is read). |
| `revision` | `main` | Git revision / commit SHA for an HF repo (pin a SHA for determinism). |
| `threshold` | `high` | Minimum severity of a reachable finding that gates: `critical \| high`. |
| `sarif-file` | `glyphhound.sarif` | Where to write the SARIF report. |
| `upload-sarif` | `true` | Upload SARIF to code scanning (needs `security-events: write`). |
| `fail-on-finding` | `true` | Fail the job when the scan gates (a reachable finding) or errors. |
| `python-version` | `3.12` | Python version to run under. |

## Outputs

| Output | Description |
|--------|-------------|
| `exit-code` | `0` clean, `1` a reachable finding gated, `2` the scan could not run. |
| `sarif-file` | Path to the written SARIF report. |

## How it works

The action sets up Python, `pip install`s GlyphHound (from this repo checkout — no PyPI release
required), runs `glyphhound scan <ref> --format sarif`, uploads the SARIF via
`github/codeql-action/upload-sarif`, and (optionally) fails the job on a gating finding. The scan
fetches only template metadata (never weights) and only *parses* the template
— it never renders it, so scanning a malicious model cannot execute it.
