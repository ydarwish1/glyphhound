# Security Policy

## Reporting a vulnerability

GlyphHound is a security tool, so detection bypasses and sandbox-escape issues are squarely in
scope. Please report them privately rather than opening a public issue:

- Use GitHub's **private vulnerability reporting** for this repository — the
  **"Report a vulnerability"** button under the **Security** tab.

Please include what you found, how to reproduce it, and the impact you expect. I'll acknowledge
the report and work with you on a fix and coordinated disclosure.

### In scope
- A code-executing chat template that GlyphHound fails to flag (a detection bypass).
- An escape from the optional `--confirm` sandbox.
- Any way the scanner itself can be made to execute code from an input it scans.

### Not in scope
- The deliberately malicious **MARKER** fixtures under `fixtures/` — they are harmless sentinels
  by design. No working exploit or poisoned model is included (see the README "Safety" section).

## Safe by design

GlyphHound never downloads model weights, makes no network or LLM calls at scan time, and runs the
optional dynamic confirmer only inside a locked-down subprocess. See `ARCHITECTURE.md`.
