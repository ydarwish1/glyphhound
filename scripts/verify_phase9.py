"""Phase 9 verification — end-to-end scan wiring the Stage-1 acquirer into the CLI.

Proves the headline command is real: ``glyphhound scan <reference>`` resolves the source,
extracts the template(s) without loading weights, scans every one, and gates CI by exit
code. Has a NETWORK part (a pinned real Hugging Face GGUF) and an OFFLINE part (a locally
built MARKER GGUF), so it needs the network like ``verify_phase0`` does.

Checks (the project history Phase 9 tracker — "`glyphhound scan <pinned HF repo --file>` runs
end-to-end no-weights -> exit 0 benign; a marker GGUF -> exit != 0"):
  (a) A pinned real HF repo scans end-to-end: ``bytes_fetched << total_size`` (Rule 6),
      exit 0 (a benign real model), via the HF-repo path AND the direct .gguf-URL path.
  (b) A local MARKER GGUF with the marker hidden in a NAMED template (benign default) is
      caught and tagged to that template -> exit != 0, both in-process and via the real
      ``python -m glyphhound`` process; a benign local GGUF -> exit 0.

Run:  .venv/Scripts/python.exe scripts/verify_phase9.py
Exit code is non-zero if any check fails.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(__file__)
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))  # reuse the canonical synthetic GGUF builder

from glyphhound.acquire import read_gguf_template  # noqa: E402
from glyphhound.scan import scan_source  # noqa: E402
from synthetic import build_gguf  # noqa: E402

# A pinned real benign model (mirrors scripts/verify_phase0.py — pinned by commit SHA for
# determinism, Rule 7).
HF_REPO = "Qwen/Qwen2.5-0.5B-Instruct-GGUF"
HF_FILE = "qwen2.5-0.5b-instruct-q4_k_m.gguf"
HF_SHA = "9217f5db79a29953eb74d5343926648285ec7e67"
HF_URL = f"https://huggingface.co/{HF_REPO}/resolve/{HF_SHA}/{HF_FILE}"

MARKER_PAYLOAD = open(
    os.path.join(ROOT, "fixtures", "malicious", "reachable_sink_marker.jinja"),
    encoding="utf-8",
).read()
BENIGN_TEMPLATE = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}"


def _human(n: int) -> str:
    f = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if f < 1024 or unit == "GiB":
            return f"{f:.1f} {unit}" if unit != "B" else f"{n} B"
        f /= 1024


def _cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "glyphhound", "scan", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


def verify_real_model_end_to_end() -> bool:
    print("=" * 78)
    print("Phase 9 (a) — a pinned real HF model scans end-to-end, no weights, exit 0")
    print("=" * 78)
    try:
        raw = read_gguf_template(HF_REPO, filename=HF_FILE, revision=HF_SHA)
        raw.assert_no_weights_loaded()
    except Exception as exc:  # noqa: BLE001 - any failure is a real failure to report
        print(f"[FAIL] could not acquire {HF_REPO}: {type(exc).__name__}: {exc}")
        return False

    names = [t.name or "<default>" for t in raw.templates]
    print(f"[OK]   acquired {HF_REPO}/{HF_FILE} @ {HF_SHA[:12]}")
    print(f"       fetched  : {_human(raw.bytes_fetched)} of {_human(raw.total_size)} "
          f"= {raw.fraction_fetched:.3%}  (<< total, no weights)")
    print(f"       templates: {len(raw.templates)} ({', '.join(names)})")

    ok = True
    try:
        repo_report = scan_source(HF_REPO, source="hf", filename=HF_FILE, revision=HF_SHA)
        url_report = scan_source(HF_URL)  # auto -> gguf-url
    except Exception as exc:  # noqa: BLE001
        print(f"[FAIL] end-to-end scan raised: {type(exc).__name__}: {exc}")
        return False

    for label, report in (("hf-repo --file", repo_report), ("auto gguf-url", url_report)):
        passed = report.exit_code == 0 and report.summary.gating == 0
        ok = ok and passed
        print(f"[{'OK' if passed else 'FAIL'}]   {label:16s} exit={report.exit_code}, "
              f"{report.summary.total} finding(s), {report.summary.gating} gating")
    print(f"[{'OK' if ok else 'FAIL'}] real benign model scans to exit 0 via both source paths.")
    return ok


def verify_marker_gguf_gates_ci() -> bool:
    print("\n" + "=" * 78)
    print("Phase 9 (b) — a local MARKER GGUF (sink in a NAMED template) gates CI")
    print("=" * 78)
    mal_gguf = build_gguf(
        chat_template=BENIGN_TEMPLATE,
        named_templates={"tokenizer.chat_template.tool_use": MARKER_PAYLOAD},
    )
    benign_gguf = build_gguf(chat_template=BENIGN_TEMPLATE)

    with tempfile.TemporaryDirectory() as d:
        mal_path = os.path.join(d, "marker-model.gguf")
        benign_path = os.path.join(d, "benign-model.gguf")
        with open(mal_path, "wb") as fh:
            fh.write(mal_gguf)
        with open(benign_path, "wb") as fh:
            fh.write(benign_gguf)

        report = scan_source(mal_path)
        tagged = [f for f in report.findings if f.template_name == "tool_use" and f.reachable]
        in_proc_ok = report.exit_code != 0 and bool(tagged)
        print(f"[{'OK' if in_proc_ok else 'FAIL'}]   in-process: exit={report.exit_code}, "
              f"{len(tagged)} reachable finding(s) tagged to 'tool_use'")

        cli = _cli([mal_path, "--format", "json"])
        try:
            doc = json.loads(cli.stdout)
            cli_tagged = any(f["template_name"] == "tool_use" for f in doc["findings"])
        except (ValueError, KeyError):
            cli_tagged = False
        cli_ok = cli.returncode != 0 and cli_tagged
        print(f"[{'OK' if cli_ok else 'FAIL'}]   real CLI : exit={cli.returncode}, "
              f"finding tagged to 'tool_use' in JSON: {cli_tagged}")

        benign_cli = _cli([benign_path])
        benign_ok = benign_cli.returncode == 0
        print(f"[{'OK' if benign_ok else 'FAIL'}]   benign GGUF via real CLI: exit={benign_cli.returncode}")

    ok = in_proc_ok and cli_ok and benign_ok
    print(f"[{'OK' if ok else 'FAIL'}] marker GGUF gates CI (in-process + real process); benign is clean.")
    return ok


def main() -> int:
    a_ok = verify_real_model_end_to_end()
    b_ok = verify_marker_gguf_gates_ci()
    print("\n" + "=" * 78)
    ok = a_ok and b_ok
    print(f"Phase 9: {'PASS' if ok else 'FAIL'} "
          f"(real-model {'ok' if a_ok else 'FAIL'}, marker-gguf {'ok' if b_ok else 'FAIL'})")
    print("=" * 78)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
