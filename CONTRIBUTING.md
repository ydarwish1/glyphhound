# Contributing

Thanks for your interest in GlyphHound.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest              # the full offline test suite should pass
```

## How this project is built

GlyphHound is developed in small, verified stages: each change is finished, proven with
real output, and only then is the next one started. Most stages have a re-runnable
`scripts/verify_phase*.py` that demonstrates them; the rest are covered by the pytest suite.

When you change the analyzer, please re-measure the false-positive rate
(`scripts/verify_phase7.py`) -- staying at 0 false positives on the real corpus is a core
invariant of the project.

## Pull requests

- Keep changes focused, and add a test where relevant (a should-flag fixture in
  `fixtures/malicious/` or a should-not-flag one in `fixtures/benign/`).
- Make sure `python -m pytest` passes.
- Be conservative about new runtime dependencies -- the runtime set is intentionally just jinja2.

## Reporting security issues

See [SECURITY.md](SECURITY.md) -- please report privately, not in a public issue.
