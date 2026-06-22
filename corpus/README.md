# Benign corpus

120 distinct, real chat templates extracted from public Hugging Face model repositories,
vendored here solely to measure GlyphHound's false-positive rate — a correct scanner should
flag **none** of them.

- These templates are **unmodified third-party content**. Each is under the license of its
  originating model repository (Apache-2.0, the Meta Llama Community License, the Gemma Terms,
  and others) — **not** this project's Apache-2.0 license.
- Only the chat template (a small configuration string) is stored here; **no model weights**.
- Per-template provenance — source repository, pinned commit SHA, and sha256 — is in
  [`PROVENANCE.json`](PROVENANCE.json). The set is deduplicated by sha256.

See the repository [`NOTICE`](../NOTICE) for attribution. The measured false-positive rate on
this corpus is 0/120; `scripts/verify_phase7.py` re-measures it offline.
