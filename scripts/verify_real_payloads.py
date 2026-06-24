"""Reproducible validation against real, third-party payloads and real benign templates.

What this does, in plain English:
  1. Downloads publicly documented Jinja2 attack payloads from two well-known security
     references (PayloadsAllTheThings and HackTricks).
  2. Downloads real chat templates from popular public Hugging Face models.
  3. Runs GlyphHound on each one and prints a results table: how many real attacks were
     caught (recall) and how many real templates were wrongly flagged (false positives).

Safety:
  GlyphHound only reads and statically analyzes the templates. It never renders or executes
  them, and this script never uses the optional --confirm sandbox mode. The payload text is
  downloaded and analyzed as data; nothing in it is run.

Requirements: `pip install glyphhound` and network access.
Usage: python scripts/verify_real_payloads.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.request

PAYLOAD_SOURCES = {
    "PayloadsAllTheThings (SSTI/Python)":
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/"
        "Server%20Side%20Template%20Injection/Python.md",
    "HackTricks (SSTI)":
        "https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/"
        "src/pentesting-web/ssti-server-side-template-injection/README.md",
}

BENIGN_MODELS = [
    "Qwen/Qwen2.5-7B-Instruct", "Qwen/Qwen2.5-0.5B-Instruct", "Qwen/Qwen2-7B-Instruct",
    "Qwen/Qwen2.5-1.5B-Instruct", "microsoft/Phi-3-mini-4k-instruct",
    "microsoft/Phi-3.5-mini-instruct", "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
    "HuggingFaceH4/zephyr-7b-beta", "teknium/OpenHermes-2.5-Mistral-7B",
    "openchat/openchat-3.5-0106", "deepseek-ai/deepseek-llm-7b-chat",
    "stabilityai/stablelm-2-zephyr-1_6b", "tiiuae/falcon-7b-instruct",
    "NousResearch/Hermes-3-Llama-3.1-8B", "cognitivecomputations/dolphin-2.9-llama3-8b",
    "Qwen/QwQ-32B-Preview",
]

# A line is treated as a malicious test payload when it is a Jinja2 expression that both
# references a Python object-model pivot AND reaches a code-execution action. This excludes
# pure detection probes such as {{ config.items() }}, which leak data but do not run code.
_PIVOT = re.compile(
    r"__class__|__mro__|__subclasses__|__globals__|__builtins__|__import__|__base__|"
    r"__init__|lipsum|cycler|joiner|namespace|popen|subprocess|get_flashed", re.I)
_ACTION = re.compile(
    r"__subclasses__|popen|os\.system|\bsystem\(|subprocess|__import__|__builtins__|"
    r"\.open\(|check_output|\beval\b|\bexec\b", re.I)


def fetch(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "glyphhound-validation"})
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "replace")


def collect_payloads() -> list[str]:
    found: dict[str, set] = {}
    for name, url in PAYLOAD_SOURCES.items():
        try:
            text = fetch(url)
        except Exception as exc:
            print("  warning: could not fetch %s (%s)" % (name, exc), file=sys.stderr)
            continue
        for line in text.splitlines():
            if ("{{" in line or "{%" in line) and _PIVOT.search(line):
                s = line.strip().strip("`").lstrip("-*> ").strip()
                if 10 <= len(s) <= 600 and _ACTION.search(s):
                    found.setdefault(s, set()).add(name)
    return sorted(found)


def collect_benign() -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for repo in BENIGN_MODELS:
        template = None
        for path in ("tokenizer_config.json", "chat_template.jinja"):
            try:
                raw = fetch("https://huggingface.co/%s/raw/main/%s" % (repo, path))
            except Exception:
                continue
            if path.endswith(".json"):
                try:
                    ct = json.loads(raw).get("chat_template")
                except Exception:
                    continue
                if isinstance(ct, list) and ct and isinstance(ct[0], dict):
                    ct = ct[0].get("template")
                if isinstance(ct, str) and ct.strip():
                    template = ct
                    break
            elif raw.strip():
                template = raw
                break
        if template:
            out.append((repo, template))
    return out


def scan(text: str, scan_path: str) -> int:
    """Static scan only. Returns the CLI exit code: 0 clean, 1 flagged, 2 parse error."""
    with open(scan_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    proc = subprocess.run(["glyphhound", "scan", "--source", "file", scan_path],
                          capture_output=True, text=True)
    return proc.returncode


def main() -> int:
    print("Downloading real third-party payloads and real Hugging Face templates...")
    malicious = collect_payloads()
    benign = collect_benign()
    print("  malicious payloads: %d" % len(malicious))
    print("  benign templates:   %d" % len(benign))
    if not malicious or not benign:
        print("Could not gather inputs (check network access).", file=sys.stderr)
        return 1

    work = tempfile.mkdtemp(prefix="glyphhound_validation_")
    scan_path = os.path.join(work, "input.jinja")
    try:
        caught = missed = out_of_scope = 0
        missed_list = []
        for payload in malicious:
            rc = scan(payload, scan_path)
            if rc == 1:
                caught += 1
            elif rc == 0:
                missed += 1
                missed_list.append(payload)
            else:
                out_of_scope += 1  # not valid Jinja2 (e.g. a different template engine)

        cleared = false_alarms = 0
        false_alarm_list = []
        for repo, template in benign:
            rc = scan(template, scan_path)
            if rc == 0:
                cleared += 1
            elif rc == 1:
                false_alarms += 1
                false_alarm_list.append(repo)
    finally:
        try:
            os.remove(scan_path)
            os.rmdir(work)
        except OSError:
            pass

    in_scope = caught + missed
    recall = (caught / in_scope * 100) if in_scope else 0.0
    precision = (caught / (caught + false_alarms) * 100) if (caught + false_alarms) else 0.0

    print()
    print("Results (GlyphHound, static analysis):")
    print("  malicious in scope: %d   caught: %d   missed: %d" % (in_scope, caught, missed))
    print("  benign:             %d   cleared: %d   false alarms: %d"
          % (cleared + false_alarms, cleared, false_alarms))
    if out_of_scope:
        print("  out of scope (non-Jinja2 parse errors, excluded): %d" % out_of_scope)
    print()
    print("  recall (real attacks caught):    %.1f%% (%d/%d)" % (recall, caught, in_scope))
    print("  precision (flags that are real): %.1f%% (%d/%d)"
          % (precision, caught, caught + false_alarms))
    if missed_list:
        print("  missed attacks:")
        for item in missed_list:
            print("    ", item[:100])
    if false_alarm_list:
        print("  false alarms:")
        for repo in false_alarm_list:
            print("    ", repo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
