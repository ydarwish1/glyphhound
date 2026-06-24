"""Phase 8 -- head-to-head benchmark: GlyphHound vs Promptfoo ModelAudit.

Runs BOTH scanners over the SAME artifacts -- each committed MARKER-only payload in
``benchmark/payloads/`` is wrapped at run time into a minimal GGUF (tests/synthetic.
build_gguf), so GlyphHound (reading the template back out of the .gguf) and ModelAudit
(scanning the .gguf) see byte-identical input -- and prints a deterministic catch/miss
table plus summary catch-rates.

Honest positioning: ModelAudit EXISTS and is a capable scanner. The
table reports its real verdict on every payload, including the obfuscations it ALSO catches.
GlyphHound's narrow, provable edge is the string-concat-via-subscript obfuscation that leaves
no literal trigger token -- its Stage-2 de-obfuscator folds it; ModelAudit's pattern matcher
does not. The comparison is informational: this script exits non-zero only on a *harness*
failure (ModelAudit missing, a scan error), never because of how the comparison turned out.

Determinism: payloads run in manifest order; the table contains no timestamps,
temp paths, or other run-varying data, so the same inputs + pinned ModelAudit version yield
a byte-identical table. The .gguf artifacts are generated at run time (never committed --
*.gguf is gitignored) and cleaned up.

Setup (one time): create the isolated ModelAudit env and install the pinned version
    python -m venv .venv-modelaudit
    .venv-modelaudit/Scripts/python -m pip install "modelaudit==0.2.47"
Run:
    .venv/Scripts/python.exe scripts/run_benchmark.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "src"))
sys.path.insert(0, os.path.join(ROOT, "tests"))

# Avoid a UnicodeEncodeError when stdout is a cp1252 pipe/console (Windows). Output is
# ASCII-only anyway; this is belt-and-suspenders so the script never crashes on glyphs.
try:  # pragma: no cover - environment dependent
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # pragma: no cover
    pass

from glyphhound.acquire import read_gguf_template  # noqa: E402
from glyphhound.analyze import analyze_raw  # noqa: E402
from glyphhound.report import DEFAULT_SEVERITY_THRESHOLD, make_report  # noqa: E402
from synthetic import build_gguf  # noqa: E402

PAYLOAD_DIR = os.path.join(ROOT, "benchmark", "payloads")
MANIFEST_PATH = os.path.join(PAYLOAD_DIR, "MANIFEST.json")


class HarnessError(RuntimeError):
    """A failure of the benchmark machinery itself (not a tool's verdict)."""


def load_manifest() -> dict:
    with open(MANIFEST_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def find_modelaudit() -> str | None:
    """Locate the ModelAudit CLI: env override, the isolated venv, then PATH.

    ModelAudit lives in a SEPARATE virtualenv (``.venv-modelaudit``) on purpose, so its
    ~80-package dependency tree never perturbs GlyphHound's pinned/locked environment.
    A real user invokes its packaged CLI exactly like this.
    """
    override = os.environ.get("GLYPHHOUND_MODELAUDIT")
    if override and os.path.exists(override):
        return override
    candidates = [
        os.path.join(ROOT, ".venv-modelaudit", "Scripts", "modelaudit.exe"),  # Windows
        os.path.join(ROOT, ".venv-modelaudit", "bin", "modelaudit"),          # POSIX
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return shutil.which("modelaudit")


def _modelaudit_env() -> dict:
    # PYTHONIOENCODING=utf-8: ModelAudit emits unicode and crashes on a cp1252 pipe
    # otherwise (its own help/output uses arrows). This does NOT alter its verdicts.
    # PROMPTFOO_DISABLE_TELEMETRY / NO_ANALYTICS: ModelAudit ships posthog telemetry;
    # disable it so the benchmark never phones home (offline/clean, no scan-data egress).
    return dict(os.environ, PYTHONIOENCODING="utf-8",
                PROMPTFOO_DISABLE_TELEMETRY="1", NO_ANALYTICS="1")


def modelaudit_version(exe: str) -> str:
    out = subprocess.run([exe, "--version"], capture_output=True, text=True,
                         env=_modelaudit_env())
    text = (out.stdout or out.stderr).strip()
    # e.g. "modelaudit, version 0.2.47"
    return text.rsplit(" ", 1)[-1] if text else "unknown"


def modelaudit_sandbox_render_available(exe: str) -> bool:
    """Whether ModelAudit's optional DYNAMIC sandbox-render test is active in this env.

    The render test only runs when ``jinja2`` is importable in ModelAudit's interpreter
    (``HAS_JINJA2_SANDBOX`` in its scanner). We benchmark this STRONGEST config, so
    a deterministic check that jinja2 is present beside the modelaudit CLI proves we are not
    benchmarking a regex-only, under-powered incumbent. (We do not assert a render *catch*
    itself: that worker is timing-dependent and non-deterministic -- see ../benchmark/README.md.)
    """
    py = os.path.join(os.path.dirname(exe), "python.exe")
    if not os.path.exists(py):
        py = os.path.join(os.path.dirname(exe), "python")
    if not os.path.exists(py):
        return False
    proc = subprocess.run([py, "-c", "import jinja2, gguf"], capture_output=True, text=True,
                          env=_modelaudit_env())
    return proc.returncode == 0


def glyphhound_verdict(gguf_path: str, *, severity_threshold: str = DEFAULT_SEVERITY_THRESHOLD) -> dict:
    """GlyphHound's verdict on a .gguf: read the template back out and run the real CI gate.

    'caught' == the scan report gates CI (>=1 reachable finding at severity >= threshold),
    i.e. exactly the exit code a user's ``glyphhound scan`` would return.
    """
    raw = read_gguf_template(gguf_path)
    findings = analyze_raw(raw)
    report = make_report(findings, severity_threshold=severity_threshold)
    reachable_rules = sorted({f.rule_id for f in findings if f.reachable is True})
    return {
        "caught": report.exit_code != 0,
        "exit_code": report.exit_code,
        "reachable_rules": reachable_rules,
        "bytes_fetched": raw.bytes_fetched,
        "total_size": raw.total_size,
    }


def modelaudit_verdict(exe: str, gguf_path: str) -> dict:
    """ModelAudit's verdict on a .gguf via its real CLI (``scan --format json --no-cache``).

    'caught' == ModelAudit's chat-template SSTI scanner flagged it: a ``jinja2_template_check``
    issue carrying a ``details.pattern_type``. We key on that specific detector (not merely a
    non-zero exit) so the comparison is like-for-like with GlyphHound's chat-template finding --
    and not credited to some unrelated scanner. Raises HarnessError on a scan error (exit 2).
    """
    proc = subprocess.run([exe, "scan", gguf_path, "--format", "json", "--no-cache"],
                          capture_output=True, text=True, env=_modelaudit_env())
    data = _parse_json(proc.stdout)
    if data is None:
        raise HarnessError(
            f"could not parse ModelAudit JSON (exit {proc.returncode}) for {os.path.basename(gguf_path)}; "
            f"stderr head: {proc.stderr[:200]!r}"
        )
    issues = data.get("issues", []) or []
    ssti = [i for i in issues
            if i.get("type") == "jinja2_template_check" and i.get("details", {}).get("pattern_type")]
    if proc.returncode not in (0, 1):
        raise HarnessError(
            f"ModelAudit scan errored (exit {proc.returncode}) on {os.path.basename(gguf_path)}; "
            f"stderr head: {proc.stderr[:200]!r}"
        )
    patterns = sorted({i["details"]["pattern_type"] for i in ssti})
    return {
        "caught": bool(ssti),
        "returncode": proc.returncode,
        "patterns": patterns,
    }


def _parse_json(text: str):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        if start > 0:
            try:
                return json.loads(text[start:])
            except json.JSONDecodeError:
                return None
        return None


def run_benchmark(exe: str, manifest: dict | None = None) -> list[dict]:
    """Build each payload's GGUF and collect both tools' verdicts, in manifest order."""
    manifest = manifest or load_manifest()
    rows: list[dict] = []
    workdir = tempfile.mkdtemp(prefix="glyphhound_bench_")
    try:
        for entry in manifest["payloads"]:
            src = os.path.join(PAYLOAD_DIR, entry["file"])
            with open(src, encoding="utf-8") as fh:
                template_text = fh.read()
            gguf_path = os.path.join(workdir, entry["file"] + ".gguf")
            with open(gguf_path, "wb") as fh:
                fh.write(build_gguf(template_text))
            gh = glyphhound_verdict(gguf_path)
            ma = modelaudit_verdict(exe, gguf_path)
            rows.append({"entry": entry, "glyphhound": gh, "modelaudit": ma})
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    return rows


def _cell(caught: bool, malicious: bool) -> str:
    # FLAG = flagged. For a malicious payload that is the desired catch; for a benign
    # control a FLAG would be a false positive (marked so it is unmissable).
    if caught:
        return "FLAG" if malicious else "FLAG(FP!)"
    return "miss" if malicious else "ok-clean"


def format_table(rows: list[dict], *, modelaudit_version_str: str) -> str:
    lines: list[str] = []
    lines.append("=" * 92)
    lines.append("GlyphHound vs ModelAudit  --  obfuscated chat-template SSTI catch/miss (same GGUF per row)")
    lines.append(f"ModelAudit version: {modelaudit_version_str}   (FLAG = flagged; FP! = false positive on a benign control)")
    lines.append("=" * 92)
    header = f"{'#':<3}{'payload':<42}{'obfuscation':<26}{'GlyphHound':<12}{'ModelAudit':<12}"
    lines.append(header)
    lines.append("-" * 92)
    last_malicious = True
    for i, row in enumerate(rows, 1):
        e = row["entry"]
        if e["malicious"] != last_malicious:
            lines.append("-" * 92 + "   (benign controls below)")
            last_malicious = e["malicious"]
        gh = _cell(row["glyphhound"]["caught"], e["malicious"])
        ma = _cell(row["modelaudit"]["caught"], e["malicious"])
        label = e["label"][:40]
        obf = e["obfuscation"][:24]
        lines.append(f"{i:<3}{label:<42}{obf:<26}{gh:<12}{ma:<12}")
    lines.append("-" * 92)
    return "\n".join(lines)


def summarize(rows: list[dict]) -> dict:
    malicious = [r for r in rows if r["entry"]["malicious"]]
    benign = [r for r in rows if not r["entry"]["malicious"]]
    obfuscated = [r for r in malicious if r["entry"]["obfuscation"] != "none"]
    gh_only_misses_by_ma = [r["entry"] for r in obfuscated
                            if r["glyphhound"]["caught"] and not r["modelaudit"]["caught"]]
    return {
        "malicious_total": len(malicious),
        "obfuscated_total": len(obfuscated),
        "benign_total": len(benign),
        "gh_malicious_caught": sum(1 for r in malicious if r["glyphhound"]["caught"]),
        "ma_malicious_caught": sum(1 for r in malicious if r["modelaudit"]["caught"]),
        "gh_obfuscated_caught": sum(1 for r in obfuscated if r["glyphhound"]["caught"]),
        "ma_obfuscated_caught": sum(1 for r in obfuscated if r["modelaudit"]["caught"]),
        "gh_benign_fp": sum(1 for r in benign if r["glyphhound"]["caught"]),
        "ma_benign_fp": sum(1 for r in benign if r["modelaudit"]["caught"]),
        "ma_misses_gh_catches": gh_only_misses_by_ma,
    }


def _rate(n: int, d: int) -> str:
    return f"{n}/{d} ({(n / d * 100):.0f}%)" if d else f"{n}/0 (n/a)"


def format_summary(s: dict) -> str:
    lines: list[str] = []
    lines.append("Summary (headline = obfuscated-payload catch rate):")
    lines.append(f"  Obfuscated malicious payloads (excludes the plain control): {s['obfuscated_total']}")
    lines.append(f"    GlyphHound caught: {_rate(s['gh_obfuscated_caught'], s['obfuscated_total'])}")
    lines.append(f"    ModelAudit caught: {_rate(s['ma_obfuscated_caught'], s['obfuscated_total'])}")
    lines.append(f"  All malicious payloads (incl. plain control): {s['malicious_total']}")
    lines.append(f"    GlyphHound caught: {_rate(s['gh_malicious_caught'], s['malicious_total'])}")
    lines.append(f"    ModelAudit caught: {_rate(s['ma_malicious_caught'], s['malicious_total'])}")
    lines.append(f"  Benign controls: {s['benign_total']}   "
                 f"false positives: GlyphHound {s['gh_benign_fp']}/{s['benign_total']}, "
                 f"ModelAudit {s['ma_benign_fp']}/{s['benign_total']}")
    if s["ma_misses_gh_catches"]:
        lines.append("  Obfuscations GlyphHound catches and ModelAudit MISSES:")
        for e in s["ma_misses_gh_catches"]:
            lines.append(f"    - {e['label']}  ({e['obfuscation']})")
    else:
        lines.append("  ModelAudit caught every obfuscated payload too (no GlyphHound-only catch this run).")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    exe = find_modelaudit()
    if exe is None:
        sys.stderr.write(
            "ERROR: ModelAudit CLI not found. The benchmark needs the incumbent installed in an\n"
            "isolated venv (keeps its deps out of GlyphHound's locked env):\n\n"
            "  python -m venv .venv-modelaudit\n"
            "  .venv-modelaudit/Scripts/python -m pip install \"modelaudit==0.2.47\"\n\n"
            "Or set GLYPHHOUND_MODELAUDIT to the modelaudit executable.\n"
        )
        return 2
    version = modelaudit_version(exe)
    manifest = load_manifest()
    try:
        rows = run_benchmark(exe, manifest)
    except HarnessError as exc:
        sys.stderr.write(f"ERROR (harness): {exc}\n")
        return 2
    print(format_table(rows, modelaudit_version_str=version))
    print()
    print(format_summary(summarize(rows)))
    pinned = manifest.get("modelaudit_version")
    if version != pinned:
        print()
        print(f"NOTE: live ModelAudit version {version} != manifest-pinned {pinned}; "
              "results may differ from the recorded table -- re-measure and update the pin.")
    return 0  # the comparison is informational; only harness failures return non-zero


if __name__ == "__main__":
    raise SystemExit(main())
