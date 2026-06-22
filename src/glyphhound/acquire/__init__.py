"""Stage 1 — Acquirer. Extract a chat template without loading model weights.

See ARCHITECTURE.md §"Stage 1 — ACQUIRER".
"""

from .gguf import read_gguf_template
from .hf_source import read_hf_source_template
from .models import (
    AcquireError,
    ChatTemplate,
    RangeUnsupportedError,
    RawTemplate,
    TemplateNotFoundError,
    WeightsLoadedError,
)
from .ollama import default_models_dir, read_ollama_template

__all__ = [
    "RawTemplate",
    "ChatTemplate",
    "AcquireError",
    "RangeUnsupportedError",
    "TemplateNotFoundError",
    "WeightsLoadedError",
    "read_gguf_template",
    "read_hf_source_template",
    "read_ollama_template",
    "default_models_dir",
]
