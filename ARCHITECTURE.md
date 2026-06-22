# ARCHITECTURE.md — GlyphHound

This file describes GlyphHound's design: a five-stage pipeline, with the exact input and output
of each stage. All five stages are implemented and verified — see `CHANGELOG.md` for the build
history and `scripts/verify_phase*.py` for the per-stage verification. The point of this file is
that a reader can trace **point A → point B**: what goes in, what each stage does, what comes out.

---

## 1. Principles
1. **Deterministic.** Same template → same finding, always. No runtime AI, no randomness in detection.
2. **Never load weights.** Read only the template bytes.
3. **Static carries the verdict; the sandbox only confirms.** The AST + taint analysis decides; dynamic rendering is optional proof.
4. **Auditable.** Every finding points to an exact source line and AST node.
5. **One pipeline, simple stages.** Five stages, each with a clear input and output.
6. **Honest scope.** Beats string-matchers on obfuscation. Nothing more.

---

## 2. The pipeline (point A → point B)

```
 A model reference                                                      A report
 (HF repo / .gguf URL / ollama name)                                    (human / JSON / SARIF)
        │                                                                     ▲
        ▼                                                                     │
 ┌──────────────┐   template   ┌──────────┐   AST   ┌───────────────┐ findings ┌──────────┐
 │ 1. ACQUIRER  │─────string──►│2. PARSER │────────►│3. ANALYZER    │─────────►│5. REPORTER│
 │ fetch header │              │ +deobfusc│         │ sinks + taint │          │          │
 │ only, no     │              │ ate      │         └───────┬───────┘          └──────────┘
 │ weights      │              └──────────┘                 │ suspicious?            ▲
 └──────────────┘                                           ▼                        │
                                                   ┌──────────────────┐  confirmed?   │
                                                   │ 4. SANDBOX        │───────────────┘
                                                   │ CONFIRMER (gated) │
                                                   │ render w/ MARKER  │
                                                   └──────────────────┘
```

---

## 3. Stages — exact input and output

### Stage 1 — ACQUIRER  *(Phase 0)*
- **In:** a model reference — a Hugging Face repo / direct `.gguf` URL, or a local Ollama model name.
- **Does:** for remote GGUF, issue **HTTP range requests** to fetch only the metadata key-value block and read the `tokenizer.chat_template` key. For Ollama, read the template blob from the local models directory. **Never downloads the weights.**
- **Out:** `RawTemplate { source_ref, templates[], bytes_fetched, total_size }`, where `templates` is every chat template found — `ChatTemplate { name, text }` with `name=None` for the default `tokenizer.chat_template` and the `<name>` of each `tokenizer.chat_template.<name>` variant. (`template_string` / `default_template` expose the default.) Returning *all* templates means a malicious named template cannot hide from the analyzer.
- **Invariant:** `bytes_fetched ≪ total_size` (asserted).

### Stage 2 — PARSER + DE-OBFUSCATOR  *(Phase 1 + Phase 4)*
- **In:** `template_string`.
- **Does:** parse with `jinja2.Environment().parse()` → an AST (the `do`, `loopcontrols` and HuggingFace `generation` tags are enabled). Then a **de-obfuscation pre-pass** folds the constant ways a payload assembles a dangerous identifier from string literals, before analysis:
  - string concatenation (`'__cl' + 'ass__'` → `'__class__'`) and the constant builders `str.format`, slice/index, and the `|join` / `|replace` filters — each folded only when **every** operand is a constant (never evaluating a dynamic expression or rendering)
  - `getattr`/`setattr` with a constant dangerous name — passed positionally **or** as a keyword (`getattr(x, name='__class__')`) — resolved to attribute access; `|attr('<const>')` / `|attr(name='<const>')` likewise classify as the precise sink
- **Out:** `NormalizedAST` (AST with obfuscation folded). Dynamic names (built from a runtime variable) are left unfolded for the taint stage.
- **Why this stage matters:** it is the whole reason GlyphHound beats string-matchers — they see `'__cl'+'ass__'` and miss it; we fold it first.

### Stage 3 — ANALYZER (sinks + taint)  *(Phase 2 + Phase 3)*
- **In:** `NormalizedAST`.
- **Does:** walk the tree.
  - **Sink detection:** flag nodes matching the **sink catalog** (§4).
  - **Reachability/taint:** only report a sink if a dangerous expression actually **builds toward it** (e.g., an attribute chain that climbs from a normal object to `__globals__`/`__builtins__`), not when a template merely uses a variable that happens to be named `class`. This is the false-positive killer.
- **Out:** `Finding[] { rule_id, severity, sink_kind, ast_span, source_line, evidence, reachable: bool }`.

### Stage 4 — SANDBOX CONFIRMER (gated, optional)  *(Phase 6)*
- **In:** a suspicious template + a **MARKER payload** substitution.
- **Does:** render the template in a **locked-down subprocess** guarded by a cross-platform `sys.addaudithook` policy — no network, no filesystem writes outside a temp scratch dir (symlink-resolved, with hardlink/symlink/rename creation denied), blocked process-spawn / `ctypes` (proven on Windows + Linux). The marker (e.g., "write sentinel file") fires only if code execution is actually reached. On **Linux** the child adds kernel/OS backstops under that hook — a **seccomp** syscall filter, `resource` **rlimits**, and best-effort **privilege-drop** (Phase 18, proven on Linux; see the Phase-6/18 note below).
- **Out:** `confirmed: bool` attached to the relevant `Finding`.
- **Containment is itself tested:** the sandbox must demonstrably **block** a real syscall attempt. If it can't, this stage is disabled and findings stay "static-only."
- **Never** runs a real harmful payload. MARKER only.
- **Implemented (Phase 6):** v1 containment is a **cross-platform restricted subprocess** — the render runs only in a `python -m glyphhound.sandbox._child` child, guarded by a `sys.addaudithook` policy that denies network / process spawn / `ctypes` / filesystem writes outside a temp scratch dir, with a temp scratch cwd (cleaned up), a wall-clock timeout, and a trimmed env. The MARKER fires when the SSTI chain reaches `__builtins__.open` and writes a sentinel **inside** the scratch dir; `confirmed=True` iff the parent observes that sentinel. Confirmation is **annotation-only** — it never changes the reachable-based CI exit-code gate. **Phase 18 added the Linux kernel/OS backstops** (`src/glyphhound/sandbox/harden.py`, applied in the child under the audit hook, a no-op off Linux so the Windows path is byte-identical): a **seccomp** filter via the system libseccomp (default-ALLOW, KILL_PROCESS on connect/sendto/sendmsg/sendmmsg/execve/execveat/ptrace/link/symlink/io_uring — native x86_64 backstop to the cross-ABI audit hook), `resource` **rlimits** (CPU/file-size/open-files/core), and best-effort **privilege-drop** (drop to nobody if root). The out-of-scratch write check resolves symlinks via `realpath` and denies hardlink/symlink/rename creation, closing inode-aliasing escapes. Containment is **proven on Linux** (`verify_phase18.py`: seccomp SIGSYS-kill, symlink + hardlink escape blocked, rlimit kill) as well as Windows (`verify_phase6.py`). The renderer uses a **plain** (non-sandboxed) Jinja2 Environment on purpose — it mirrors the vulnerable runtime so the escape fires; containment is at the OS/syscall layer, not Jinja's own sandbox.

### Stage 5 — REPORTER  *(Phase 5)*
- **In:** `Finding[]`.
- **Does:** render human text, JSON, and **SARIF 2.1.0** (each finding → a SARIF result with `ruleId`, `level`, `physicalLocation` = source line, and the evidence in `message`). Set a non-zero **exit code** when findings exceed a configurable severity, so it gates CI.
- **Out:** report files + exit code.

---

## 4. Sink Catalog (the dangerous things we look for)
Public, well-documented Jinja2 SSTI / sandbox-escape gadgets. Detection targets — fixtures simulate these with MARKER payloads only.
- **Attribute chains reaching:** `__class__`, `__base__`, `__bases__`, `__mro__`, `__subclasses__`, `__globals__`, `__builtins__`, `__init__`, `__import__`, `__dict__`.
- **Code-exec calls/names:** `eval`, `exec`, `__import__`, `os`, `subprocess`, `popen`, `system`, `getattr`/`setattr` used to reach the above.
- **Jinja gadget objects:** `cycler`, `joiner`, `namespace`, `lipsum`, `self` — taint **pivots**, not bare sinks. They are **never flagged on presence alone** (`namespace` is ubiquitous in real tool-calling templates), only when an attribute/subscript chain climbs *through* one into a dunder / code-exec name above (which GH-S001/S002 then catch). Reachability (Stage 3) is what makes them safe to treat as a taint source.
- **Filter pivots:** the `|attr('...')` filter used to dodge dot-access detection.

Each catalog entry = one `rule_id` with a severity and a short rationale, so findings are explainable.

---

## 5. Data Model
```
ChatTemplate  { name, text }                         # name=None for the default
RawTemplate   { source_ref, templates[], bytes_fetched, total_size }
NormalizedAST { ast, deobfuscations_applied[] }
Finding       { rule_id, severity, sink_kind, ast_span, source_line,
                evidence, reachable: bool, confirmed: bool|null }
Report        { findings[], summary, exit_code }
```

---

## 6. Repository Layout
```
glyphhound/
├─ README.md  ARCHITECTURE.md  CHANGELOG.md  LICENSE
├─ pyproject.toml              # pinned deps + `glyphhound` CLI entrypoint
├─ src/glyphhound/
│  ├─ acquire/                 # GGUF range-fetch, Ollama blob read (Stage 1)
│  ├─ parse/                   # Jinja parse + de-obfuscation pre-pass (Stage 2)
│  ├─ analyze/                 # sink catalog + taint/reachability (Stage 3)
│  ├─ sandbox/                 # restricted-subprocess confirmer (Stage 4)
│  ├─ report/                  # human / json / sarif (Stage 5)
│  └─ cli.py
├─ fixtures/
│  ├─ benign/                  # real-style safe templates (should NOT flag)
│  └─ malicious/               # MARKER-only attack templates (should flag)
├─ corpus/                     # benign FP corpus — 120 real HF templates for FP rate (Phase 7)
│  ├─ templates/               #   vendored *.jinja, SHA-pinned + deduped by sha256
│  └─ PROVENANCE.json          #   per-template repo/revision + bytes_fetched/total_size
├─ benchmark/                  # head-to-head vs ModelAudit (Phase 8)
├─ action/                     # GitHub Action wrapper (Phase 9)
└─ tests/                      # pytest; fixture-driven detection tests
```

---

## 7. Cross-Cutting
- **Determinism:** pinned Jinja2 + deps (lockfile); fixture models pinned by hash; no randomness in detection.
- **Sandboxing/safety:** Stage 4 only in a contained subprocess; MARKER payloads only; no real poisoned models in the repo.
- **Never load weights:** Stage 1 asserts `bytes_fetched ≪ total_size`.
- **Testing:** each detection rule has a malicious (should-flag) and benign (should-not-flag) fixture; FP rate measured on the real corpus.
- **CI:** GitHub Actions runs the fixture tests and scans a sample model; SARIF validated against schema.

---

## 8. What this architecture deliberately does NOT do
- Does **not** download or load model weights.
- Does **not** run the template outside the contained sandbox.
- Does **not** use any LLM or model API at scan time.
- Does **not** claim a template is safe-with-certainty — it reports detected risks and a measured false-positive rate.
- Does **not** claim to be the first/only chat-template scanner (ModelAudit exists).
