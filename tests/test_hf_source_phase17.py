"""Offline tests for Phase 17 step 1 -- HF_TOKEN auth + HTTP-429/503 backoff in hf_source.

No network: ``_urlopen`` (the urllib indirection) and ``_sleep`` are stubbed so the auth
header and the deterministic retry/backoff are exercised without real requests or real
waiting. The acquirer still only ever requests metadata and never reads weights --
this adds auth + rate-limit handling, it does not change *what* is fetched. Backoff is a
fixed exponential schedule with no random jitter.
"""

from __future__ import annotations

import urllib.error

import pytest

from glyphhound.acquire import hf_source
from glyphhound.acquire.models import AcquireError

_TC = "https://huggingface.co/owner/name/resolve/main/tokenizer_config.json"
_ST = "https://huggingface.co/owner/name/resolve/main/model.safetensors"


def _http_error(code: int, *, retry_after=None) -> urllib.error.HTTPError:
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else {}
    return urllib.error.HTTPError(_TC, code, "err", headers, None)


class _FakeResp:
    """A minimal urlopen response -- enough for _http_get / _http_range / _read_capped."""

    def __init__(self, *, status=200, headers=None, body=b"{}"):
        self.status = status
        self.headers = headers or {}
        self._body = body

    def read(self, n=-1):
        if n is None or n < 0:
            data, self._body = self._body, b""
            return data
        data, self._body = self._body[:n], self._body[n:]
        return data

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def no_sleep(monkeypatch):
    """Replace the backoff sleep with a recorder so retries never actually wait."""
    waits: list[float] = []
    monkeypatch.setattr(hf_source, "_sleep", waits.append)
    return waits


def _script(monkeypatch, items, recorder=None):
    """Stub ``_urlopen`` to yield ``items`` in order (the last repeats once exhausted). Each
    item is a ``_FakeResp`` to return or a ``BaseException`` to raise; ``recorder`` collects
    each ``Request`` so a test can inspect the headers that were sent."""
    seq = list(items)

    def fake(req):
        if recorder is not None:
            recorder.append(req)
        item = seq.pop(0) if len(seq) > 1 else seq[0]
        if isinstance(item, BaseException):
            raise item
        return item

    monkeypatch.setattr(hf_source, "_urlopen", fake)


# --- auth header ----------------------------------------------------------------

def test_authorization_header_present_when_token_set(monkeypatch, no_sleep):
    monkeypatch.setenv("HF_TOKEN", "hf_secret")
    reqs = []
    _script(monkeypatch, [_FakeResp(body=b"{}")], recorder=reqs)
    hf_source._http_get(_TC)
    assert reqs[0].get_header("Authorization") == "Bearer hf_secret"


def test_no_authorization_header_when_token_unset(monkeypatch, no_sleep):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    reqs = []
    _script(monkeypatch, [_FakeResp(body=b"{}")], recorder=reqs)
    hf_source._http_get(_TC)
    assert reqs[0].get_header("Authorization") is None


def test_token_read_at_call_time(monkeypatch, no_sleep):
    # Token set after import is still picked up -- env is read per call, not at import.
    monkeypatch.setenv("HF_TOKEN", "late_token")
    reqs = []
    _script(monkeypatch, [_FakeResp(status=206, body=b"12345678")], recorder=reqs)
    hf_source._http_range(_ST, 0, 8)
    assert reqs[0].get_header("Authorization") == "Bearer late_token"


# --- 429 / 503 backoff ----------------------------------------------------------

def test_retries_on_429_then_succeeds(monkeypatch, no_sleep):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    _script(monkeypatch, [_http_error(429), _FakeResp(body=b"{}")])
    assert hf_source._http_get(_TC) == b"{}"
    assert len(no_sleep) == 1


def test_retries_on_503_then_succeeds(monkeypatch, no_sleep):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    _script(monkeypatch, [_http_error(503), _FakeResp(body=b"{}")])
    assert hf_source._http_get(_TC) == b"{}"
    assert len(no_sleep) == 1


def test_honors_numeric_retry_after(monkeypatch, no_sleep):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    _script(monkeypatch, [_http_error(429, retry_after=7), _FakeResp(body=b"{}")])
    hf_source._http_get(_TC)
    assert no_sleep == [7.0]


def test_backoff_is_deterministic_exponential(monkeypatch, no_sleep):
    # Always 429, no Retry-After -> a fixed exponential schedule (no random jitter).
    monkeypatch.delenv("HF_TOKEN", raising=False)
    _script(monkeypatch, [_http_error(429)])
    with pytest.raises(AcquireError):
        hf_source._http_get(_TC)
    assert no_sleep == [1.0, 2.0, 4.0, 8.0, 16.0]


def test_exhausted_retries_raise_acquire_error(monkeypatch, no_sleep):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    _script(monkeypatch, [_http_error(429)])
    with pytest.raises(AcquireError):
        hf_source._http_get(_TC)
    assert len(no_sleep) == hf_source._MAX_RETRIES


def test_404_is_not_retried(monkeypatch, no_sleep):
    monkeypatch.delenv("HF_TOKEN", raising=False)
    _script(monkeypatch, [_http_error(404)])
    assert hf_source._http_get(_TC) is None
    assert no_sleep == []


def test_range_request_is_authed_and_retried(monkeypatch, no_sleep):
    monkeypatch.setenv("HF_TOKEN", "tok")
    reqs = []
    _script(monkeypatch, [_http_error(429), _FakeResp(status=206, body=b"12345678")], recorder=reqs)
    assert hf_source._http_range(_ST, 0, 8) == b"12345678"
    assert len(no_sleep) == 1
    assert reqs[0].get_header("Authorization") == "Bearer tok"
    assert reqs[0].get_header("Range") == "bytes=0-7"
