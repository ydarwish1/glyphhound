"""CLI: scan a model reference (or local template) for code-execution sinks; gate CI.

Usage::

    python -m glyphhound scan <ref | dir | -> [<ref> ...]
                              [--source auto|file|gguf|gguf-url|hf|ollama]
                              [--file NAME.gguf] [--revision REV]
                              [--format human|json|sarif] [--output FILE]
                              [--threshold critical|high]
                              [--template-name NAME] [--confirm]

``<ref>`` is a local file (a ``.gguf`` or a raw template), a direct ``.gguf`` URL, a
Hugging Face repo id (its canonical ``tokenizer_config.json``/``chat_template.jinja``
template, or a ``.gguf`` quant with ``--file``), or an Ollama model name; ``-`` reads a raw
template from stdin; a local directory is searched for templates (below). The acquirer
fetches only metadata, so this never downloads the weights, and the analyzer only *parses*
the template (never renders it). Exit codes: ``0`` clean, ``1`` a reachable finding gates
CI, ``2`` the scan could not run (bad reference, network/acquire error, unreadable file,
unparseable template).

Several references are scanned one by one and reported each under its own heading (JSON: a
list with one report per target; SARIF: one run listing every target as an artifact). The
exit code is then ``1`` if any target gates CI, else ``2`` if any could not be scanned,
else ``0``. With one non-directory reference every format is exactly the single-target
output.

A directory (with the default ``--source auto``) stands for every ``*.jinja``, ``*.gguf`` and
``tokenizer_config.json`` file under it, each scanned as a target of its own; symlinks out of
it are not followed but reported. A match that cannot be read, or a directory with no match,
exits 2.

``--output FILE`` writes the ``--format`` report to FILE and prints the human report to stdout;
the exit code is the same. FILE that is a directory or one of the targets exits 2 before any
scan, and FILE that cannot be written exits 2 unless a finding gates CI (1).
"""

from __future__ import annotations

import argparse
import os
import sys

from .acquire import AcquireError
from .acquire.models import decode_utf8_or_raise
from .analyze.models import CRITICAL, HIGH
from .parse import ParseError
from .report import (
    Report,
    TargetResult,
    display_text,
    render_human,
    render_human_targets,
    render_json,
    render_json_targets,
    render_sarif,
    render_sarif_targets,
    targets_exit_code,
)
from .scan import (
    AUTO,
    SOURCES,
    TOKENIZER_CONFIG,
    ScanTarget,
    ScanError,
    find_template_files,
    is_directory,
    resolve_source,
    scan_source,
    scan_template_string,
)

_RENDERERS = {"human": render_human, "json": render_json, "sarif": render_sarif}
_TARGET_RENDERERS = {"human": render_human_targets, "json": render_json_targets,
                     "sarif": render_sarif_targets}

# What makes one target unscannable (exit 2) rather than a crash.
_SCAN_ERRORS = (ScanError, AcquireError, ParseError, OSError)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glyphhound",
        description="Scan a model's chat template for code-execution sinks; exit non-zero if it gates CI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a model reference or local chat-template file")
    scan.add_argument(
        "refs", nargs="+", metavar="ref",
        help="a local file (.gguf or raw template), a .gguf URL, a Hugging Face repo id "
             "(its canonical template, or a .gguf quant with --file), an Ollama model name, "
             "or - to read a raw template from stdin. A directory is searched for *.jinja, "
             "*.gguf and tokenizer_config.json files. Give several to scan each one; the "
             "other options apply to every target, and a repeated target is scanned once.",
    )
    scan.add_argument("--source", choices=[AUTO, *SOURCES], default=AUTO,
                      help="how to interpret the reference (default: auto-detect)")
    scan.add_argument("--file", dest="file", default=None,
                      help="a .gguf filename inside a Hugging Face repo, or 'auto' to pick the "
                           "smallest .gguf (optional; without it the repo's canonical "
                           "tokenizer_config.json/chat_template.jinja is read). Set HF_TOKEN for "
                           "gated/private repos.")
    scan.add_argument("--revision", default="main",
                      help="git revision / commit SHA for a Hugging Face repo "
                           "(default: main; pin a SHA for determinism)")
    scan.add_argument("--format", choices=list(_RENDERERS), default="human",
                      help="output format (default: human)")
    scan.add_argument("--output", metavar="FILE", default=None,
                      help="write the --format report to FILE (replacing it) and print the "
                           "human report to stdout; the exit code is unchanged")
    scan.add_argument("--threshold", choices=[CRITICAL, HIGH], default=HIGH,
                      help="minimum severity of a reachable finding that gates CI (default: high)")
    scan.add_argument("--template-name", default=None,
                      help="name to attribute a stdin template to (model sources name their own)")
    scan.add_argument("--confirm", action="store_true",
                      help="gated Stage-4: render the template in the locked-down sandbox to "
                           "confirm reachable findings (off by default; never renders in-process)")
    return parser


def _scan(ref: str, source: str, args: argparse.Namespace) -> Report:
    """Scan one target as ``source`` with the CLI options; raises one of
    :data:`_SCAN_ERRORS` on failure."""
    if ref == "-":
        # Read bytes, so a template that is not UTF-8 fails cleanly (exit 2) as a file does.
        text = decode_utf8_or_raise(sys.stdin.buffer.read(), "stdin", "template")
        return scan_template_string(
            text, template_name=args.template_name,
            severity_threshold=args.threshold, confirm=args.confirm,
        )
    return scan_source(
        ref, source=source, filename=args.file, revision=args.revision,
        severity_threshold=args.threshold, confirm=args.confirm,
    )


def _is_directory(ref: str, args: argparse.Namespace) -> bool:
    return ref != "-" and is_directory(ref, args.source)


def _expand(ref: str, args: argparse.Namespace) -> list[ScanTarget]:
    """The targets ``ref`` stands for: the files found under a directory, else ``ref``."""
    if not _is_directory(ref, args):
        return [ScanTarget(ref, args.source)]
    try:
        return find_template_files(ref)
    except ScanError as exc:
        return [ScanTarget(ref, error=str(exc))]


def _same_file_key(ref: str) -> str:
    """``ref`` keyed so that two spellings of one local file (``./a/x``, ``a/x``) match: its
    directory resolved, its own name kept (a symlink stays a target of its own)."""
    if ref == "-" or not os.path.exists(ref):
        return ref
    # Not abspath: it folds ``..`` before resolving, which is wrong after a symlinked folder.
    parent, name = os.path.split(os.path.join(os.getcwd(), ref))
    return os.path.join(os.path.realpath(parent), name)


def _targets(refs: list[str], args: argparse.Namespace) -> list[ScanTarget]:
    """Every target to scan, in order; a file both typed and found in a directory, once.

    A ``tokenizer_config.json`` found in a directory is read as a config even when the same
    file was also typed (which reads it as a raw template), in either order.
    """
    targets: dict[str, ScanTarget] = {}
    for ref in refs:
        for target in _expand(ref, args):
            key = _same_file_key(target.ref)
            if key not in targets or (target.source == TOKENIZER_CONFIG and target.error is None):
                targets[key] = target
    return list(targets.values())


def _failed_target(ref: str, error: str) -> TargetResult:
    """A target that could not be scanned, also told on stderr."""
    sys.stderr.write(f"glyphhound: {display_text(ref)}: {display_text(error)}\n")
    return TargetResult(ref, error=error)


def _scan_target(target: ScanTarget, args: argparse.Namespace) -> TargetResult:
    """Scan one of several targets; a failure is recorded (and told on stderr), not raised."""
    ref = target.ref
    if target.error is not None:
        return _failed_target(ref, target.error)
    try:
        template_file = ref != "-" and resolve_source(ref, target.source) == "file"
        return TargetResult(ref, report=_scan(ref, target.source, args),
                            template_file=template_file)
    except _SCAN_ERRORS as exc:
        return _failed_target(ref, str(exc))


def _same_file(path: str, ref: str) -> bool:
    """Whether ``ref`` is the local file at ``path`` (through any symlink or hard link)."""
    try:
        return ref != "-" and os.path.samefile(path, ref)
    except OSError:  # ``ref`` is not a local file (a repo id, URL, model name) or is unreadable
        return False


def _output_problem(path: str | None, targets: list[ScanTarget]) -> str | None:
    """Why ``--output FILE`` must not be written, checked before any scan; else None."""
    if path is None:
        return None
    if os.path.isdir(path):
        return "is a directory"
    if os.path.exists(path) and any(_same_file(path, target.ref) for target in targets):
        return "is one of the scan targets"
    return None


def _emit(renderers: dict, result: Report | list[TargetResult],
          args: argparse.Namespace) -> bool:
    """Print ``result`` in ``--format``; with ``--output`` print the human report and write
    ``--format`` to FILE instead. False (told on stderr) if FILE cannot be written."""
    if args.output is None:
        sys.stdout.write(renderers[args.format](result))
        return True
    sys.stdout.write(renderers["human"](result))
    try:
        with open(args.output, "w", encoding="utf-8") as out:
            out.write(renderers[args.format](result))
    except OSError as exc:
        reason = exc.strerror or str(exc)
        sys.stderr.write(
            f"glyphhound: --output {display_text(args.output)}: {display_text(reason)}\n")
        return False
    return True


def _exit_code(exit_code: int, written: bool) -> int:
    """The scan's exit code, or 2 when ``--output`` failed and no finding gates CI."""
    return exit_code if written or exit_code == 1 else 2


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns 0 (clean) / 1 (a finding gates CI) / 2 (the scan could not run)."""
    args = _build_parser().parse_args(argv)
    if args.command != "scan":
        return 2  # unreachable: argparse requires a subcommand

    refs = list(dict.fromkeys(args.refs))  # stdin can only be read once
    several = len(refs) > 1 or _is_directory(refs[0], args)
    targets = _targets(refs, args) if several else [ScanTarget(refs[0], args.source)]
    problem = _output_problem(args.output, targets)
    if problem is not None:
        sys.stderr.write(f"glyphhound: --output {display_text(args.output)}: {problem}\n")
        return 2

    if several:
        results = [_scan_target(target, args) for target in targets]
        written = _emit(_TARGET_RENDERERS, results, args)
        return _exit_code(targets_exit_code(results), written)

    try:
        report = _scan(refs[0], args.source, args)
    except _SCAN_ERRORS as exc:
        sys.stderr.write(f"glyphhound: {display_text(str(exc))}\n")
        return 2

    return _exit_code(report.exit_code, _emit(_RENDERERS, report, args))
