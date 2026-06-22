"""End-to-end scan: a model reference / template string -> a :class:`~.report.Report`.

Two entry points:

* :func:`scan_template_string` — analyze one chat-template string already in hand
  (Stage 2 -> 3 -> 5). Fully offline; used by the stdin path and as the raw-text core.
* :func:`scan_source` — the Phase-9 headline: resolve a *model reference* (local file /
  ``.gguf`` URL / Hugging Face repo / Ollama name) through the Stage-1 acquirer, scan
  **every** template it carries (default + named), and build one report. The acquirer
  only fetches the metadata block, so this never downloads the weights.

Both paths only ever *parse* a template (the analyzer walks the AST; it never renders),
so reading a malicious model cannot execute it. The optional, off-by-default ``confirm``
stage (Phase 6) is the only thing that renders, and it does so in a locked-down subprocess.
"""

from __future__ import annotations

import os
import re

from .acquire import (
    ChatTemplate,
    RawTemplate,
    read_gguf_template,
    read_hf_source_template,
    read_ollama_template,
)
from .acquire.hf_source import smallest_gguf_filename
from .analyze import analyze_template
from .report import DEFAULT_SEVERITY_THRESHOLD, Report, make_report

# The source kinds the CLI's --source flag accepts (besides "auto").
SOURCES = ("file", "gguf", "gguf-url", "hf", "ollama")
AUTO = "auto"

# A Hugging Face repo id is exactly ``owner/name`` (one slash, neither segment a path
# fragment). An Ollama model is ``name[:tag]`` (no slash). Both start with an
# alphanumeric so a leading ``.`` / ``/`` / ``~`` (a path) does not match either.
_HF_REPO_RE = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+$")
_OLLAMA_RE = re.compile(r"^[A-Za-z0-9][\w.-]*(:[\w.-]+)?$")


class ScanError(Exception):
    """The scan could not start — an ambiguous reference or a missing required option.

    Distinct from :class:`~.acquire.AcquireError` (which is raised once acquisition is
    under way): a ``ScanError`` means we could not even decide *how* to fetch the template.
    """


def _analyze_one(text: str, *, template_name: str | None, confirm: bool):
    """Analyze one template string; optionally confirm reachable findings in the sandbox.

    The sandbox import lives inside the ``if confirm:`` branch so the default static path
    never touches the subprocess machinery and its reports stay byte-identical (the
    ``confirmed`` flag stays None). Confirmation is annotation-only — it never changes the
    reachable-based CI exit-code gate.
    """
    findings = analyze_template(text, template_name=template_name)
    if confirm:
        from .sandbox import confirm_findings
        findings = confirm_findings(text, findings, template_name=template_name)
    return findings


def scan_template_string(template_string: str, *, template_name: str | None = None,
                         severity_threshold: str = DEFAULT_SEVERITY_THRESHOLD,
                         confirm: bool = False) -> Report:
    """Analyze one chat-template string and return its :class:`~.report.Report`."""
    return make_report(
        _analyze_one(template_string, template_name=template_name, confirm=confirm),
        severity_threshold=severity_threshold,
    )


def scan_source(ref: str, *, source: str = AUTO, filename: str | None = None,
                revision: str = "main", severity_threshold: str = DEFAULT_SEVERITY_THRESHOLD,
                confirm: bool = False) -> Report:
    """Resolve ``ref`` through the Stage-1 acquirer and scan **all** of its templates.

    ``source`` is one of :data:`SOURCES` or ``"auto"`` (the default, which detects the
    kind from ``ref``). For a Hugging Face repo, ``filename`` is optional: with it, that
    ``.gguf`` quant inside the repo is read (Phase 9); without it, the repo's canonical
    template is read from ``tokenizer_config.json`` / ``chat_template.jinja`` / the
    safetensors header (Phase 14), covering transformers models that ship no GGUF.
    ``revision`` pins the git revision (use a commit SHA for determinism).

    Scanning every template — and tagging each finding with its template name — is the
    security payoff of the multi-template acquirer (ARCHITECTURE.md §7): a sink hidden in a
    ``tokenizer.chat_template.<name>`` variant cannot escape just because the default is
    benign. With ``confirm=False`` this loop is exactly :func:`~.analyze.analyze_raw`.
    """
    raw = _acquire(ref, source=source, filename=filename, revision=revision)
    findings = []
    for template in raw.templates:
        findings.extend(_analyze_one(template.text, template_name=template.name, confirm=confirm))
    return make_report(findings, severity_threshold=severity_threshold)


def _acquire(ref: str, *, source: str, filename: str | None, revision: str) -> RawTemplate:
    """Resolve ``ref`` to a :class:`~.acquire.RawTemplate`, dispatching on the source kind."""
    kind = source if source != AUTO else _detect_source(ref)

    if kind == "gguf-url":
        if not _url_path(ref).lower().endswith(".gguf"):
            raise ScanError(f"{ref!r}: a gguf-url must point directly at a .gguf file")
        return read_gguf_template(ref)
    if kind == "gguf":
        return read_gguf_template(ref)
    if kind == "hf":
        # --file NAME reads that .gguf quant inside the repo (Phase 9); --file auto picks the
        # smallest .gguf in the repo (Phase 20); without --file, read the repo's CANONICAL
        # template from tokenizer_config.json / chat_template.jinja / the safetensors header
        # (Phase 14) — covering every transformers model, no weights.
        gguf_name = filename
        if gguf_name == "auto":
            gguf_name = smallest_gguf_filename(ref, revision=revision)
        if gguf_name:
            return read_gguf_template(ref, filename=gguf_name, revision=revision)
        return read_hf_source_template(ref, revision=revision)
    if kind == "ollama":
        return read_ollama_template(ref)
    if kind == "file":
        return _wrap_template_file(ref)
    raise ScanError(f"unknown source type {source!r}")


def _detect_source(ref: str) -> str:
    """Deterministically classify ``ref`` (Phase-9 design).

    Order: an http(s) URL is a gguf-url; an existing path is sniffed by magic bytes
    (``GGUF`` -> a GGUF file, else a raw template file); ``owner/name`` is a Hugging Face
    repo (read from its canonical template metadata, or a ``.gguf`` quant if ``--file`` is
    given); ``name[:tag]`` is an Ollama model; anything else is ambiguous and the caller
    must pass an explicit ``--source``.
    """
    if ref.startswith(("http://", "https://")):
        return "gguf-url"
    if os.path.exists(ref):
        return "gguf" if _is_gguf_file(ref) else "file"
    if _HF_REPO_RE.match(ref):
        return "hf"
    if _OLLAMA_RE.match(ref):
        return "ollama"
    raise ScanError(
        f"could not determine what {ref!r} refers to. Pass "
        "--source file|gguf|gguf-url|hf|ollama to disambiguate."
    )


def _is_gguf_file(path: str) -> bool:
    """True if ``path`` begins with the GGUF magic bytes."""
    with open(path, "rb") as fh:
        return fh.read(4) == b"GGUF"


def _url_path(url: str) -> str:
    """The path part of a URL, without the query string or fragment."""
    return url.split("?", 1)[0].split("#", 1)[0]


def _wrap_template_file(path: str) -> RawTemplate:
    """Read a raw chat-template file and wrap it as a single-template RawTemplate.

    This is a bare template (not a model file), so there are no weights to avoid; the
    no-weights invariant does not apply and bytes_fetched == total_size by construction.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScanError(f"{path!r}: not a valid UTF-8 template file ({exc})") from exc
    return RawTemplate(
        source_ref=path,
        templates=(ChatTemplate(None, text),),
        bytes_fetched=len(data),
        total_size=len(data),
    )
