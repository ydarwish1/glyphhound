# Roadmap

Each step is one small pull request with tests and README updates. Python 3.10+, and jinja2 stays the only runtime dependency. Detection never gets weaker: every malicious fixture still gates, the benign fixtures and corpus still produce zero findings, and nothing that is scanned today stops being scanned or starts exiting 0.

- [x] 1. Accept several targets in one `scan` (`glyphhound scan A B C`): scan each and report each under its own heading. Exit 1 if any target has a gating finding, else 2 if any target could not be scanned, else 0. JSON prints a list with one report per target, and SARIF one run listing every artifact. With one target, every format stays exactly as it is today.
- [x] 2. Scan a local directory: `glyphhound scan DIR` finds `*.jinja`, `chat_template.jinja`, `tokenizer_config.json` and `*.gguf` files under it, without following symlinks out of DIR, and scans each as in step 1. A matching file that cannot be read or parsed is reported and exits 2, never skipped. A directory with no matching file exits 2 with a message saying so.
- [x] 3. Add `--output FILE`: write the chosen `--format` to FILE and still print the human report to stdout, so one CI run can upload SARIF and show a readable log. The exit code does not change. An existing directory as FILE exits 2.
- [x] 4. Add `--format markdown` for a pull request comment: the same content as the human report, with every value taken from a template or model (names, paths, snippets, reasons quoting the template) put in an inline code span, so Markdown, HTML, links and @mentions show as plain text.
