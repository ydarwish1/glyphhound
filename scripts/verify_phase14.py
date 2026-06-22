"""Phase 14 verification -- scan the real source (HF tokenizer_config.json / chat_template.jinja).

Checks (`scan <owner/name>` (no --file) scans the
canonical template end-to-end, bytes << total; covers transformers models, not just GGUF):
  (a) NETWORK: a pinned real transformers repo (no GGUF, no --file) scans end-to-end via the
      canonical tokenizer_config.json -- a tiny metadata read (no weights), a benign
      real model -> exit 0, and `_detect_source` routes a bare owner/name here.
  (b) OFFLINE: a synthetic tokenizer_config.json carrying a MARKER chat_template gates CI, and
      the multi-template list form tags a sink hidden in a NAMED variant.

The analyzer only PARSES the template (never renders), so reading a malicious source cannot
execute it. (a) needs the network; (b) is offline + deterministic.

Run:  .venv/Scripts/python.exe scripts/verify_phase14.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from glyphhound.acquire import read_hf_source_template  # noqa: E402
from glyphhound.acquire.hf_source import _templates_from_config  # noqa: E402
from glyphhound.analyze import analyze_raw  # noqa: E402
from glyphhound.report import make_report  # noqa: E402
from glyphhound.scan import _detect_source, scan_source  # noqa: E402

# A pinned real transformers repo whose chat template lives in tokenizer_config.json (no
# GGUF). Pin by commit SHA for determinism. Its weights (~1 GB model.safetensors)
# are never requested by this path.
REPO = "Qwen/Qwen2.5-0.5B-Instruct"
REVISION = "7ae557604adf67be50417f59c2c2f167def9a775"
_BYTES_CAP = 4 * 1024 * 1024  # a metadata read is KB; this is far under any weights file

MARKER = "{{ ''.__class__.__mro__[1].__subclasses__()['os'].system('GLYPHHOUND_PHASE14_MARKER') }}"
BENIGN = "{% for m in messages %}{{ m.role }}: {{ m.content }}{% endfor %}"


def verify_real_repo() -> bool:
    print("=" * 78)
    print("Phase 14 (a) -- NETWORK: a real transformers repo scans via its canonical template")
    print("=" * 78)
    print(f"repo: {REPO}  revision: {REVISION}")
    routed = _detect_source(REPO)
    raw = read_hf_source_template(REPO, revision=REVISION)
    report = scan_source(REPO, revision=REVISION)  # NO --file -> the canonical source
    no_weights = 0 < raw.bytes_fetched < _BYTES_CAP
    print(f"  _detect_source({REPO!r}) = {routed!r}  (bare owner/name routes to the HF source)")
    print(f"  templates found: {len(raw.templates)}  bytes_fetched: {raw.bytes_fetched} "
          f"(< {_BYTES_CAP} cap, no weights)")
    print(f"  scan exit code (benign real model): {report.exit_code}")
    ok = (routed == "hf") and bool(raw.templates) and no_weights and report.exit_code == 0
    print(f"[{'OK' if ok else 'FAIL'}] real repo scanned end-to-end, tiny metadata read, benign -> exit 0.")
    return ok


def verify_synthetic_malicious() -> bool:
    print("\n" + "=" * 78)
    print("Phase 14 (b) -- OFFLINE: a synthetic tokenizer_config.json MARKER gates; named tagged")
    print("=" * 78)
    # string form -> one default template carrying the marker.
    string_form = _templates_from_config(json.loads(json.dumps({"chat_template": MARKER})))
    string_findings = analyze_raw_from(string_form)
    string_ok = make_report(string_findings).exit_code == 1
    print(f"  string-form chat_template -> {len(string_findings)} finding(s), "
          f"exit {make_report(string_findings).exit_code}  [{'OK' if string_ok else 'FAIL'}]")

    # list form -> benign default + a malicious NAMED variant that must be caught + tagged.
    list_form = _templates_from_config({"chat_template": [
        {"name": "default", "template": BENIGN},
        {"name": "tool_use", "template": MARKER},
    ]})
    list_findings = analyze_raw_from(list_form)
    tagged = any(f.template_name == "tool_use" and f.reachable for f in list_findings)
    list_ok = tagged and make_report(list_findings).exit_code == 1
    print(f"  list-form (default benign + named 'tool_use' marker) -> sink tagged to 'tool_use': "
          f"{tagged}, exit {make_report(list_findings).exit_code}  [{'OK' if list_ok else 'FAIL'}]")
    ok = string_ok and list_ok
    print(f"[{'OK' if ok else 'FAIL'}] a marker in the canonical source gates CI; a named variant is tagged.")
    return ok


def analyze_raw_from(templates):
    """Analyze a list of ChatTemplate as if acquired (mirrors analyze_raw over a RawTemplate)."""
    from glyphhound.acquire import ChatTemplate, RawTemplate
    raw = RawTemplate("synthetic://hf", tuple(templates), bytes_fetched=1, total_size=1)
    return analyze_raw(raw)


def main() -> int:
    a_ok = verify_real_repo()
    b_ok = verify_synthetic_malicious()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok
    print(f"Phase 14: {'PASS' if ok else 'FAIL'} "
          f"(real-repo {'ok' if a_ok else 'FAIL'}, synthetic-marker {'ok' if b_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
