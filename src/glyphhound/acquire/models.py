"""Stage 1 data model and errors (ARCHITECTURE.md §5)."""

from __future__ import annotations

from dataclasses import dataclass


class AcquireError(Exception):
    """Base error for template acquisition (Stage 1)."""


class RangeUnsupportedError(AcquireError):
    """A remote host would not honor an HTTP range request.

    Raised *before* reading the response body, so we never fall back to
    downloading the full file.
    """


class TemplateNotFoundError(AcquireError):
    """The model file / manifest contained no chat template."""


class WeightsLoadedError(AcquireError):
    """The fetched fraction is too large — we may have read into the weights."""


def decode_utf8_or_raise(raw: bytes, source_ref: str, what: str) -> str:
    """Decode template bytes as strict UTF-8, surfacing failures as AcquireError.

    Model files are adversarial input; a non-UTF-8 template must fail cleanly (so a
    caller's ``except AcquireError`` catches it) rather than crash with a raw
    UnicodeDecodeError. We never fall back to lossy decoding — corrupting bytes
    before the security analysis would be wrong for a scanner.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AcquireError(f"{source_ref}: {what} is not valid UTF-8: {exc}") from exc


@dataclass(frozen=True)
class ChatTemplate:
    """One chat template found in a model.

    ``name`` is ``None`` for the default ``tokenizer.chat_template``; otherwise it is
    the ``<name>`` of a ``tokenizer.chat_template.<name>`` variant. A model can ship
    several — a named one is a valid place to hide a payload (a runtime that selects
    it will render it), so Stage 1 surfaces *all* of them for the analyzer.
    """

    name: str | None
    text: str


@dataclass(frozen=True)
class RawTemplate:
    """The output of Stage 1 (ARCHITECTURE.md §5).

    Carries *every* chat template found in the model (``templates``), default and
    named, so a malicious named template cannot hide from the analyzer.
    ``bytes_fetched`` is how many bytes we actually read from the source;
    ``total_size`` is the full size of the model file (the weights we did *not*
    read). The Stage-1 invariant is ``bytes_fetched << total_size``.
    """

    source_ref: str
    templates: tuple[ChatTemplate, ...]
    bytes_fetched: int
    total_size: int

    @property
    def default_template(self) -> ChatTemplate:
        """The default template: the ``name is None`` entry, else the
        lexicographically-first named one (mirrors the old named-only fallback)."""
        named: list[ChatTemplate] = []
        for t in self.templates:
            if t.name is None:
                return t
            named.append(t)
        if not named:
            raise TemplateNotFoundError(f"{self.source_ref}: no chat templates")
        return min(named, key=lambda t: t.name or "")

    @property
    def template_string(self) -> str:
        """The default template's text. Kept so existing single-template call sites
        (scripts, tests) keep working after the multi-template change."""
        return self.default_template.text

    @property
    def fraction_fetched(self) -> float:
        """Share of the file we actually read (0.0–1.0)."""
        return self.bytes_fetched / self.total_size if self.total_size else 1.0

    def assert_no_weights_loaded(self, threshold: float = 0.10) -> "RawTemplate":
        """Enforce the Stage-1 invariant ``bytes_fetched << total_size``.

        Raises :class:`WeightsLoadedError` if we read at least ``threshold`` of the
        file (default 10%) — a sign we may have read into the weights. Returns
        ``self`` so callers can chain.
        """
        if self.total_size <= 0:
            raise WeightsLoadedError(
                f"{self.source_ref}: unknown total size; cannot verify the no-weights invariant"
            )
        if self.fraction_fetched >= threshold:
            raise WeightsLoadedError(
                f"{self.source_ref}: fetched {self.bytes_fetched} of {self.total_size} bytes "
                f"({self.fraction_fetched:.1%} >= {threshold:.0%} threshold) — "
                "may have read into the weights"
            )
        return self
