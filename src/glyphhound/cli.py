"""CLI: scan a model reference (or local template) for code-execution sinks; gate CI.

Usage::

    python -m glyphhound scan <ref | -> [--source auto|file|gguf|gguf-url|hf|ollama]
                                        [--file NAME.gguf] [--revision REV]
                                        [--format human|json|sarif]
                                        [--threshold critical|high]
                                        [--template-name NAME] [--confirm]

``<ref>`` is a local file (a ``.gguf`` or a raw template), a direct ``.gguf`` URL, a
Hugging Face repo id (its canonical ``tokenizer_config.json``/``chat_template.jinja``
template, or a ``.gguf`` quant with ``--file``), or an Ollama model name; ``-`` reads a raw
template from stdin. The acquirer fetches only metadata, so this never downloads the
weights, and the analyzer only *parses* the template (never renders
it). Exit codes: ``0`` clean, ``1`` a reachable finding gates CI, ``2`` the scan could not
run (bad reference, network/acquire error, unparseable template).
"""

from __future__ import annotations

import argparse
import sys

from .acquire import AcquireError
from .analyze.models import CRITICAL, HIGH
from .parse import ParseError
from .report import render_human, render_json, render_sarif
from .scan import AUTO, SOURCES, ScanError, scan_source, scan_template_string

_RENDERERS = {"human": render_human, "json": render_json, "sarif": render_sarif}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glyphhound",
        description="Scan a model's chat template for code-execution sinks; exit non-zero if it gates CI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a model reference or local chat-template file")
    scan.add_argument(
        "ref",
        help="a local file (.gguf or raw template), a .gguf URL, a Hugging Face repo id "
             "(its canonical template, or a .gguf quant with --file), an Ollama model name, "
             "or - to read a raw template from stdin",
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
    scan.add_argument("--threshold", choices=[CRITICAL, HIGH], default=HIGH,
                      help="minimum severity of a reachable finding that gates CI (default: high)")
    scan.add_argument("--template-name", default=None,
                      help="name to attribute a stdin template to (model sources name their own)")
    scan.add_argument("--confirm", action="store_true",
                      help="gated Stage-4: render the template in the locked-down sandbox to "
                           "confirm reachable findings (off by default; never renders in-process)")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI. Returns 0 (clean) / 1 (a finding gates CI) / 2 (the scan could not run)."""
    args = _build_parser().parse_args(argv)
    if args.command != "scan":
        return 2  # unreachable: argparse requires a subcommand

    try:
        if args.ref == "-":
            report = scan_template_string(
                sys.stdin.read(), template_name=args.template_name,
                severity_threshold=args.threshold, confirm=args.confirm,
            )
        else:
            report = scan_source(
                args.ref, source=args.source, filename=args.file, revision=args.revision,
                severity_threshold=args.threshold, confirm=args.confirm,
            )
    except (ScanError, AcquireError, ParseError) as exc:
        sys.stderr.write(f"glyphhound: {exc}\n")
        return 2

    sys.stdout.write(_RENDERERS[args.format](report))
    return report.exit_code
