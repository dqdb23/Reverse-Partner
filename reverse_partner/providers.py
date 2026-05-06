# -*- coding: utf-8 -*-
"""
providers.py — AI provider abstraction layer
=============================================
Supported providers:
  gemini           — Google Generative AI (free tier available)
  groq             — Groq cloud (fast, free tier)
  openai           — OpenAI API (paid)
  openai_compatible — Any OpenAI-compatible server (vLLM, LiteLLM, …)
  ollama           — Local Ollama server (no key required)
  lmstudio         — Local LM Studio server (no key required)

Error classification:
  quota_exhausted | rate_limited | auth_error | model_not_found
  safety_block | network_timeout | unknown_error

Key masking: full keys are NEVER printed in logs.
"""

import time
import threading
from config import mask_key
from logger import log

# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------

class ProviderError(Exception):
    def __init__(self, msg: str, error_type: str = "unknown_error"):
        super().__init__(msg)
        self.error_type = error_type


def classify_provider_error(exc_msg: str) -> str:
    """
    Classify a provider exception message.
    Testable outside IDA.
    """
    msg = str(exc_msg).lower()
    if any(k in msg for k in ("quota", "resource_exhausted", "billing", "payment")):
        return "quota_exhausted"
    if any(k in msg for k in ("rate", "429", "too many", "ratelimit", "slow down", "throttle")):
        return "rate_limited"
    if any(k in msg for k in ("auth", "401", "403", "invalid_api_key",
                               "permission", "unauthorized", "invalid key")):
        return "auth_error"
    if any(k in msg for k in ("model not found", "model_not_found",
                               "no such model", "404", "does not exist")):
        return "model_not_found"
    if any(k in msg for k in ("safety", "blocked", "harmful", "policy", "finish_reason")):
        return "safety_block"
    if any(k in msg for k in ("timeout", "timed out", "connection", "network",
                               "socket", "ssl", "unreachable")):
        return "network_timeout"
    return "unknown_error"


# ---------------------------------------------------------------------------
# Key rotator
# ---------------------------------------------------------------------------

class KeyRotator:
    """
    v5: Distinguishes error types and handles each appropriately.
    - quota_exhausted / auth_error → disable key for session
    - rate_limited                 → exponential backoff on same key
    - safety_block                 → do NOT rotate, propagate to caller
    - model_not_found              → stop immediately, alert user
    - network_timeout              → short wait, same key
    Full API keys are never printed — mask_key() is used in all log lines.
    """

    def __init__(self, keys: list):
        if not keys:
            raise ValueError("No API keys provided!")
        self.keys      = list(keys)
        self._lock     = threading.Lock()
        self.index     = 0
        self.exhausted : set = set()   # permanently disabled for this session
        self._backoff  : dict = {}     # key_index → current backoff seconds

    @property
    def current_key(self) -> str:
        return self.keys[self.index]

    @property
    def current_masked(self) -> str:
        return mask_key(self.keys[self.index])

    def mark_exhausted(self, key_index: int):
        with self._lock:
            self.exhausted.add(key_index)

    def handle_error(self, exc) -> bool:
        """
        React to a provider exception.
        Returns True if the caller should retry (possibly after sleeping).
        Raises ProviderError for unrecoverable situations.
        """
        etype = classify_provider_error(str(exc))

        if etype == "model_not_found":
            raise ProviderError(
                "Model not found — check Settings. Error: %s" % str(exc)[:200],
                "model_not_found"
            )

        if etype == "safety_block":
            log.warn("  Key %s: safety block — not rotating." % self.current_masked)
            raise ProviderError("Safety block: %s" % str(exc)[:200], "safety_block")

        if etype in ("quota_exhausted", "auth_error"):
            with self._lock:
                self.exhausted.add(self.index)
            log.warn("  Key %s: %s — disabling for session." % (self.current_masked, etype))
            self._rotate(str(exc))
            return True   # retry with next key

        if etype == "rate_limited":
            with self._lock:
                delay = self._backoff.get(self.index, 5)
                self._backoff[self.index] = min(delay * 2, 120)
            log.warn("  Key %s: rate limited — waiting %ds." % (self.current_masked, delay))
            time.sleep(delay)
            return True   # retry same key

        if etype == "network_timeout":
            log.warn("  Key %s: network timeout — waiting 5s." % self.current_masked)
            time.sleep(5)
            return True

        raise ProviderError("Unknown provider error: %s" % str(exc)[:300], "unknown_error")

    def _rotate(self, error_msg: str = ""):
        with self._lock:
            if len(self.exhausted) >= len(self.keys):
                raise ProviderError(
                    "All %d keys exhausted/disabled. Error: %s" % (
                        len(self.keys), error_msg[:200]),
                    "quota_exhausted"
                )
            old = self.index
            for _ in range(len(self.keys)):
                self.index = (self.index + 1) % len(self.keys)
                if self.index not in self.exhausted:
                    log.warn("  Key #%d → Key #%d/%d" % (
                        old + 1, self.index + 1, len(self.keys)))
                    return
            raise ProviderError("No usable keys remaining.", "quota_exhausted")

    # Legacy compat for PerKeyProvider
    def is_quota_error(self, msg: str) -> bool:
        return classify_provider_error(msg) in (
            "quota_exhausted", "rate_limited", "auth_error")


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

from prompts import (
    BATCH_SYSTEM_PROMPT_V5, SINGLE_SYSTEM_PROMPT_V5,
    ANALYZE_SYSTEM_PROMPT_V5, RANGE_SYSTEM_PROMPT,
    WHOLE_PROGRAM_PROMPT, VARIABLE_RENAME_PROMPT,
    PROTOTYPE_INFERENCE_PROMPT, build_prompt,
)
from utils import parse_json_response_v5
from config import MAX_CHARS_PER_FUNC


# ---------------------------------------------------------------------------
# Base provider
# ---------------------------------------------------------------------------

class BaseProvider:
    """Abstract base class. Subclasses implement _call()."""

    def __init__(self, cfg: dict, rotator: KeyRotator):
        self.cfg     = cfg
        self.rotator = rotator
        self.model   = cfg.get("model", "")
        self.temp    = cfg.get("temperature", 0.1)
        self.timeout = cfg.get("timeout_sec", 60)

    def _call(self, system: str, prompt: str, max_tokens: int = 512) -> str:
        raise NotImplementedError

    # ── Public API ──────────────────────────────────────────────────────────

    def rename_single(self, code: str, name: str,
                      callees=None, callers=None, ctx_extra: str = "") -> dict:
        from prompts import get_naming_instruction
        naming = get_naming_instruction(self.cfg)
        ctx    = naming
        if callees:
            named = [c for c in callees if not _is_def(c)]
            if named:
                ctx += "\n// Calls: %s" % ", ".join(named[:10])
        if callers:
            named_c = [c for c in callers if not _is_def(c)]
            if named_c:
                ctx += "\n// Called by: %s" % ", ".join(named_c[:5])
        if ctx_extra:
            ctx += "\n" + ctx_extra
        prompt = "Function name: %s\n%s\n```\n%s\n```\n\nReturn JSON:" % (
            name, ctx, code[:MAX_CHARS_PER_FUNC])
        raw = self._call(SINGLE_SYSTEM_PROMPT_V5, prompt, max_tokens=400)
        return parse_json_response_v5(raw)

    def rename_batch(self, batch: list, cfg=None) -> dict:
        prompt = build_prompt(batch, cfg or self.cfg)
        raw    = self._call(BATCH_SYSTEM_PROMPT_V5, prompt,
                            max_tokens=max(512, len(batch) * 120))
        return parse_json_response_v5(raw)

    def analyze(self, code: str, name: str,
                callees=None, callers=None, ctx_extra: str = "") -> dict:
        from prompts import get_naming_instruction
        naming = get_naming_instruction(self.cfg)
        ctx    = naming
        if callees:
            named = [c for c in callees if not _is_def(c)]
            if named:
                ctx += "\n// Calls: %s" % ", ".join(named[:15])
        if callers:
            named_c = [c for c in callers if not _is_def(c)]
            if named_c:
                ctx += "\n// Called by: %s" % ", ".join(named_c[:8])
        if ctx_extra:
            ctx += "\n" + ctx_extra
        prompt = "Function name: %s\n%s\n```\n%s\n```\n\nReturn JSON:" % (
            name, ctx, code[:MAX_CHARS_PER_FUNC])
        raw = self._call(ANALYZE_SYSTEM_PROMPT_V5, prompt, max_tokens=900)
        return parse_json_response_v5(raw)

    def analyze_range(self, code_snippet: str) -> dict:
        prompt = "Code snippet:\n```\n%s\n```\n\nReturn JSON:" % code_snippet[:4000]
        raw    = self._call(RANGE_SYSTEM_PROMPT, prompt, max_tokens=600)
        return parse_json_response_v5(raw)

    def analyze_whole_program(self, summary_text: str) -> dict:
        prompt = "Binary summary:\n%s\n\nReturn JSON:" % summary_text[:6000]
        raw    = self._call(WHOLE_PROGRAM_PROMPT, prompt, max_tokens=900)
        return parse_json_response_v5(raw)

    def suggest_variable_renames(self, prompt_text: str) -> dict:
        raw = self._call(VARIABLE_RENAME_PROMPT, prompt_text[:9000], max_tokens=900)
        return parse_json_response_v5(raw)

    def suggest_prototype(self, prompt_text: str) -> dict:
        raw = self._call(PROTOTYPE_INFERENCE_PROMPT, prompt_text[:10000], max_tokens=900)
        return parse_json_response_v5(raw)


def _is_def(name: str) -> bool:
    from utils import is_default_name
    return is_default_name(name)


# ---------------------------------------------------------------------------
# Concrete providers
# ---------------------------------------------------------------------------

class GeminiProvider(BaseProvider):
    def _call(self, system: str, prompt: str, max_tokens: int = 512) -> str:
        while True:
            try:
                import google.generativeai as genai
                genai.configure(api_key=self.rotator.current_key)
                m = genai.GenerativeModel(
                    self.model,
                    system_instruction=system if system else None
                )
                return m.generate_content(prompt).text.strip()
            except ImportError:
                raise ProviderError(
                    "google-generativeai not installed. Run: pip install google-generativeai",
                    "model_not_found"
                )
            except Exception as exc:
                if not self.rotator.handle_error(exc):
                    raise


class GroqProvider(BaseProvider):
    def _call(self, system: str, user: str, max_tokens: int = 512) -> str:
        while True:
            try:
                from groq import Groq
                resp = Groq(api_key=self.rotator.current_key).chat.completions.create(
                    model=self.model,
                    messages=[{"role": "system", "content": system},
                              {"role": "user",   "content": user}],
                    max_tokens=max_tokens,
                    temperature=self.temp,
                    timeout=self.timeout,
                )
                return resp.choices[0].message.content.strip()
            except ImportError:
                raise ProviderError("groq not installed. Run: pip install groq",
                                    "model_not_found")
            except Exception as exc:
                if not self.rotator.handle_error(exc):
                    raise


class OpenAIProvider(BaseProvider):
    def __init__(self, cfg: dict, rotator: KeyRotator, base_url=None):
        super().__init__(cfg, rotator)
        self.base_url = base_url or cfg.get("base_url", "") or None

    def _call(self, system: str, user: str, max_tokens: int = 512) -> str:
        while True:
            try:
                from openai import OpenAI
                kwargs: dict = {
                    "api_key": self.rotator.current_key,
                    "timeout": self.timeout,
                }
                if self.base_url:
                    kwargs["base_url"] = self.base_url
                client = OpenAI(**kwargs)
                resp   = client.chat.completions.create(
                    model=self.model,
                    messages=[{"role": "system", "content": system},
                              {"role": "user",   "content": user}],
                    max_tokens=max_tokens,
                    temperature=self.temp,
                )
                return resp.choices[0].message.content.strip()
            except ImportError:
                raise ProviderError(
                    "openai not installed. Run: pip install openai", "model_not_found")
            except Exception as exc:
                if not self.rotator.handle_error(exc):
                    raise


class OllamaProvider(BaseProvider):
    """
    Ollama local provider.
    Tries /v1 OpenAI-compat endpoint first; falls back to /api/chat.
    No API key required.
    """
    DEFAULT_BASE = "http://127.0.0.1:11434"

    def __init__(self, cfg: dict, rotator: KeyRotator):
        super().__init__(cfg, rotator)
        self.base_url = cfg.get("base_url", "") or self.DEFAULT_BASE

    def _call(self, system: str, user: str, max_tokens: int = 512) -> str:
        # Try OpenAI-compat /v1
        try:
            from openai import OpenAI
            client = OpenAI(
                base_url=self.base_url.rstrip("/") + "/v1",
                api_key="ollama",
                timeout=self.timeout,
            )
            resp = client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": system},
                          {"role": "user",   "content": user}],
                max_tokens=max_tokens,
                temperature=self.temp,
            )
            return resp.choices[0].message.content.strip()
        except Exception:
            pass

        # Fallback: native /api/chat
        import json as _json
        import urllib.request
        payload = _json.dumps({
            "model": self.model,
            "messages": [{"role": "system", "content": system},
                         {"role": "user",   "content": user}],
            "stream": False,
        }).encode()
        try:
            req = urllib.request.Request(
                self.base_url.rstrip("/") + "/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = _json.loads(resp.read().decode())
                return data.get("message", {}).get("content", "").strip()
        except Exception as exc:
            raise ProviderError("Ollama call failed: %s" % str(exc)[:200],
                                "network_timeout")


class LMStudioProvider(OpenAIProvider):
    """LM Studio: OpenAI-compatible local. Default port 1234."""
    DEFAULT_BASE = "http://127.0.0.1:1234/v1"

    def __init__(self, cfg: dict, rotator: KeyRotator):
        url = cfg.get("base_url", "") or self.DEFAULT_BASE
        super().__init__(cfg, rotator, base_url=url)
        if not rotator.keys or not rotator.keys[0]:
            rotator.keys = ["lmstudio"]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_PROVIDER_MAP: dict = {
    "gemini":            GeminiProvider,
    "groq":              GroqProvider,
    "openai":            OpenAIProvider,
    "openai_compatible": OpenAIProvider,
    "ollama":            OllamaProvider,
    "lmstudio":          LMStudioProvider,
}


def _ensure_keys(cfg: dict) -> list:
    keys = cfg.get("api_keys", [])
    prov = cfg.get("provider", "gemini")
    if prov in ("ollama", "lmstudio"):
        keys = keys or ["local"]
    if not keys:
        raise ValueError("No API key configured. Open Settings (Ctrl+Shift+S).")
    return keys


def make_provider(cfg: dict) -> BaseProvider:
    """Create a provider for single-call operations."""
    keys    = _ensure_keys(cfg)
    rotator = KeyRotator(keys)
    return _build(cfg, rotator)


def make_parallel_providers(cfg: dict) -> tuple:
    """
    Create (main_provider, [PerKeyProvider, ...], rotator).
    One PerKeyProvider per API key for parallel batch processing.
    """
    keys    = _ensure_keys(cfg)
    rotator = KeyRotator(keys)
    main    = _build(cfg, rotator)
    per_key = [PerKeyProvider(cfg, k, i, rotator) for i, k in enumerate(keys)]
    return main, per_key, rotator


def _build(cfg: dict, rotator: KeyRotator) -> BaseProvider:
    prov = cfg.get("provider", "gemini")
    cls  = _PROVIDER_MAP.get(prov)
    if not cls:
        raise ValueError("Unknown provider: %s" % prov)
    return cls(cfg, rotator)


# ---------------------------------------------------------------------------
# PerKeyProvider — parallel batch worker
# ---------------------------------------------------------------------------

class PerKeyProvider:
    """
    Wraps one API key for use in a dedicated worker thread.
    Marks itself exhausted on quota/auth error so the thread exits cleanly.
    """

    def __init__(self, cfg: dict, key: str, key_index: int, rotator: KeyRotator):
        self.cfg        = cfg
        self.key        = key
        self.key_index  = key_index
        self.rotator    = rotator
        self.exhausted  = False
        single_rotator  = KeyRotator([key])
        self._provider  = _build(cfg, single_rotator)
        self._single_rot = single_rotator

    def rename_batch(self, batch: list) -> dict:
        try:
            return self._provider.rename_batch(batch, self.cfg)
        except ProviderError as exc:
            if exc.error_type in ("quota_exhausted", "auth_error"):
                self.exhausted = True
                self.rotator.mark_exhausted(self.key_index)
                log.warn("  Key #%d [%s] disabled: %s" % (
                    self.key_index + 1, mask_key(self.key), exc.error_type))
                raise
            raise
        except Exception as exc:
            if KeyRotator([self.key]).is_quota_error(str(exc)):
                self.exhausted = True
                self.rotator.mark_exhausted(self.key_index)
                raise
            raise
