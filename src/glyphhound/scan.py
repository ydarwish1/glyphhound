"""End-to-end scan: a model reference / template string -> a :class:`~.report.Report`.

Two entry points:

* :func:`scan_template_string` -- analyze one chat-template string already in hand
  (Stage 2 -> 3 -> 5). Fully offline; used by the stdin path and as the raw-text core.
* :func:`scan_source` -- the Phase-9 headline: resolve a *model reference* (local file /
  ``.gguf`` URL / Hugging Face repo / Ollama name) through the Stage-1 acquirer, scan
  **every** template it carries (default + named), and build one report. The acquirer
  only fetches the metadata block, so this never downloads the weights.

:func:`find_template_files` lists the template-bearing files under a local directory, each
then scanned as a target of its own.

Both paths only ever *parse* a template (the analyzer walks the AST; it never renders),
so reading a malicious model cannot execute it. The optional, off-by-default ``confirm``
stage (Phase 6) is the only thing that renders, and it does so in a locked-down subprocess.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass

from .acquire import (
    ChatTemplate,
    RawTemplate,
    read_gguf_template,
    read_hf_source_template,
    read_ollama_template,
    read_tokenizer_config_file,
)
from .acquire.hf_source import smallest_gguf_filename
from .analyze import analyze_template
from .report import DEFAULT_SEVERITY_THRESHOLD, Report, make_report

# The source kinds the CLI's --source flag accepts (besides "auto").
SOURCES = ("file", "gguf", "gguf-url", "hf", "ollama")
AUTO = "auto"

# A local tokenizer_config.json found by a directory scan (not a --source choice).
TOKENIZER_CONFIG = "tokenizer-config"
_TOKENIZER_CONFIG_NAME = "tokenizer_config.json"
# File suffixes a directory scan reads (matched case-insensitively), and how.
_DIRECTORY_SUFFIXES = ((".jinja", "file"), (".gguf", "gguf"))

# A Hugging Face repo id is exactly ``owner/name`` (one slash, neither segment a path
# fragment). An Ollama model is ``name[:tag]`` (no slash). Both start with an
# alphanumeric so a leading ``.`` / ``/`` / ``~`` (a path) does not match either.
_HF_REPO_RE = re.compile(r"^[A-Za-z0-9][\w.-]*/[\w.-]+$")
_OLLAMA_RE = re.compile(r"^[A-Za-z0-9][\w.-]*(:[\w.-]+)?$")


class ScanError(Exception):
    """The scan could not start -- an ambiguous reference or a missing required option.

    Distinct from :class:`~.acquire.AcquireError` (which is raised once acquisition is
    under way): a ``ScanError`` means we could not even decide *how* to fetch the template.
    """


@dataclass(frozen=True)
class ScanTarget:
    """One target to scan: a reference (or a file a directory scan found), the source kind
    to read it as, or why it cannot be read."""

    ref: str
    source: str = AUTO
    error: str | None = None


def _analyze_one(text: str, *, template_name: str | None, confirm: bool):
    """Analyze one template string; optionally confirm reachable findings in the sandbox.

    The sandbox import lives inside the ``if confirm:`` branch so the default static path
    never touches the subprocess machinery and its reports stay byte-identical (the
    ``confirmed`` flag stays None). Confirmation is annotation-only -- it never changes the
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

    Scanning every template -- and tagging each finding with its template name -- is the
    security payoff of the multi-template acquirer (ARCHITECTURE.md section 7): a sink hidden in a
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
    kind = resolve_source(ref, source)

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
        # (Phase 14) -- covering every transformers model, no weights.
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
    if kind == TOKENIZER_CONFIG:
        return read_tokenizer_config_file(ref)
    raise ScanError(f"unknown source type {source!r}")


def resolve_source(ref: str, source: str = AUTO) -> str:
    """The source kind ``ref`` is read as: ``source`` itself, or the detected kind for auto."""
    return source if source != AUTO else _detect_source(ref)


def is_directory(ref: str, source: str = AUTO) -> bool:
    """True when ``ref`` is a local directory to search: auto-detect only, never a URL."""
    return (source == AUTO and not ref.startswith(("http://", "https://"))
            and os.path.isdir(ref))


def find_template_files(directory: str) -> list[ScanTarget]:
    """Every ``*.jinja``, ``*.gguf`` and ``tokenizer_config.json`` under ``directory``.

    Walked in sorted order without entering symlinked directories. Nothing is skipped
    silently: a subdirectory that cannot be listed, a match that is a symlink out of
    ``directory`` (not followed) and a match that is not a readable regular file are each
    returned with an ``error``. Raises :class:`ScanError` if nothing matches.
    """
    root = os.path.realpath(directory)
    found: list[ScanTarget] = []

    def unlisted(exc: OSError) -> None:
        path = exc.filename or directory
        reason = f"{path!r}: cannot list directory ({exc.strerror or exc})"
        found.append(ScanTarget(path, error=reason))

    for parent, dirnames, filenames in os.walk(directory, onerror=unlisted):
        dirnames.sort()
        for name in sorted(filenames):
            source = _directory_source(name)
            if source is not None:
                path = os.path.join(parent, name)
                found.append(ScanTarget(path, source, _unreadable_reason(path, root)))
    if not found:
        raise ScanError(
            f"{directory!r}: no *.jinja, tokenizer_config.json or *.gguf file under it"
        )
    return found


def _directory_source(name: str) -> str | None:
    """The source kind a directory scan reads the file ``name`` as, or None to pass it by."""
    if name == _TOKENIZER_CONFIG_NAME:
        return TOKENIZER_CONFIG
    for suffix, source in _DIRECTORY_SUFFIXES:
        if name.lower().endswith(suffix):
            return source
    return None


def _unreadable_reason(path: str, root: str) -> str | None:
    """Why a directory scan must not read ``path`` (under the real directory ``root``)."""
    if not _is_within(os.path.realpath(path), root):
        return f"{path!r}: a symlink out of the scanned directory; not followed"
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        return f"{path!r}: cannot read ({exc.strerror or exc})"
    if not stat.S_ISREG(mode):
        return f"{path!r}: not a regular file"
    return None


def _is_within(path: str, root: str) -> bool:
    """True if the real path ``path`` is ``root`` or under it."""
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # on another drive (Windows)
        return False


def _detect_source(ref: str) -> str:
    """Deterministically classify ``ref`` (Phase-9 design).

    Order: an http(s) URL is a gguf-url; an existing regular file is sniffed by magic bytes
    (``GGUF`` -> a GGUF file, else a raw template file); ``owner/name`` is a Hugging Face
    repo (read from its canonical template metadata, or a ``.gguf`` quant if ``--file`` is
    given); ``name[:tag]`` is an Ollama model; anything else is ambiguous and the caller
    must pass an explicit ``--source``.
    """
    if ref.startswith(("http://", "https://")):
        return "gguf-url"
    if os.path.isfile(ref):
        return "gguf" if _is_gguf_file(ref) else "file"
    if os.path.exists(ref):
        raise ScanError(f"{ref!r} is not a file")
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
    try:
        with open(path, "rb") as fh:
            return fh.read(4) == b"GGUF"
    except OSError:
        return False


def _url_path(url: str) -> str:
    """The path part of a URL, without the query string or fragment."""
    return url.split("?", 1)[0].split("#", 1)[0]


def _wrap_template_file(path: str) -> RawTemplate:
    """Read a raw chat-template file and wrap it as a single-template RawTemplate.

    This is a bare template (not a model file), so there are no weights to avoid; the
    no-weights invariant does not apply and bytes_fetched == total_size by construction.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise ScanError(f"{path!r}: cannot read template file ({exc})") from exc
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
