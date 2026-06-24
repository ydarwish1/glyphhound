# Benign fixtures

A small set of real, benign chat templates used by the detection tests as the should-NOT-flag
controls (paired with the should-flag fixtures in `fixtures/malicious/`).

- These are **unmodified third-party** chat templates from public Hugging Face model
  repositories, each under the license of its originating model repo -- **not** this project's
  Apache-2.0 license. Only the template string is stored; **no model weights**.
- The larger false-positive measurement set lives in [`corpus/`](../../corpus/) (120 templates,
  with full provenance in `corpus/PROVENANCE.json`).

See the repository [`NOTICE`](../../NOTICE) for attribution.
