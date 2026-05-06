# -*- coding: utf-8 -*-
"""
cache.py — Function analysis cache
=====================================
Prevents repeated AI calls for unchanged functions.
Cache key = sha256 of (ea, name, code, callers, callees, strings, apis,
                        prompt_version, model, provider).
Cache entries expire after cache_ttl_days.
Stored as a flat JSON file (up to 5000 entries; oldest are pruned).
"""

import os
import json
import hashlib
import time
from datetime import datetime, timedelta
from logger import log

_CACHE_PROMPT_VERSION = "v5.2"   # bump when prompt schema changes significantly


def _cache_path(cfg: dict) -> str:
    p = cfg.get("cache_file", "")
    if p:
        return p
    try:
        import idaapi
        return os.path.join(idaapi.get_user_idadir(), "reverse_partner_cache.json")
    except ImportError:
        return os.path.expanduser("~/.reverse_partner_cache.json")


def compute_cache_key(ea: int, name: str, code: str,
                      callers: list, callees: list,
                      strings: list, apis: list,
                      model: str, provider: str,
                      decoded_strings: list = None) -> str:
    """
    Deterministic SHA-256 cache key.
    Testable outside IDA.
    """
    h = hashlib.sha256()
    for part in (
        hex(ea), name, code or "",
        ",".join(sorted(callers or [])),
        ",".join(sorted(callees or [])),
        ",".join(sorted(strings or [])),
        ",".join(sorted(
            (s.get("value", "") if isinstance(s, dict) else str(s))
            for s in (decoded_strings or [])
        )),
        ",".join(sorted(apis    or [])),
        _CACHE_PROMPT_VERSION,
        model or "", provider or "",
    ):
        h.update(part.encode("utf-8", errors="replace"))
    return h.hexdigest()


def _load_raw(cfg: dict) -> dict:
    try:
        p = _cache_path(cfg)
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_raw(cfg: dict, cache: dict):
    try:
        p = _cache_path(cfg)
        with open(p, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        log.err("Cannot save cache: %s" % exc)


def cache_get(cfg: dict, cache_key: str):
    """
    Retrieve cached AI result.
    Returns normalized result dict or None on miss / expiry.
    """
    if not cfg.get("enable_cache", True):
        return None
    cache = _load_raw(cfg)
    entry = cache.get(cache_key)
    if not entry:
        return None
    try:
        ttl  = int(cfg.get("cache_ttl_days", 90))
        ts   = datetime.strptime(entry["timestamp"], "%Y-%m-%d %H:%M:%S")
        if datetime.now() - ts > timedelta(days=ttl):
            return None           # expired
    except Exception:
        return None
    return entry.get("result")


def cache_put(cfg: dict, cache_key: str, result, old_name: str, code_type: str):
    """Store an AI result in the cache."""
    if not cfg.get("enable_cache", True):
        return
    cache = _load_raw(cfg)
    cache[cache_key] = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "old_name":  old_name,
        "code_type": code_type,
        "result":    result,
    }
    # Prune oldest entries if over 5000
    if len(cache) > 5000:
        sorted_keys = sorted(cache, key=lambda k: cache[k].get("timestamp", ""))
        for k in sorted_keys[:len(cache) - 5000]:
            del cache[k]
    _save_raw(cfg, cache)


def cache_clear(cfg: dict):
    """Delete the cache file."""
    try:
        p = _cache_path(cfg)
        if os.path.exists(p):
            os.remove(p)
            log.ok("Cache cleared: %s" % p)
        else:
            log.info("Cache file not found (already empty).")
    except Exception as exc:
        log.err("Cannot clear cache: %s" % exc)


def cache_stats(cfg: dict) -> dict:
    """Return {'entries': int, 'path': str, 'size_kb': float}."""
    cache = _load_raw(cfg)
    p     = _cache_path(cfg)
    sz    = 0.0
    try:
        sz = os.path.getsize(p) / 1024.0
    except Exception:
        pass
    return {"entries": len(cache), "path": p, "size_kb": round(sz, 1)}
