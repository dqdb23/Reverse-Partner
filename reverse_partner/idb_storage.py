# -*- coding: utf-8 -*-
"""
idb_storage.py - IDB-backed GPT Renamer metadata storage
========================================================
Stores small per-function plugin metadata in a private netnode.

This module is intentionally limited to plugin metadata. It does not rename,
comment, type, patch, or otherwise modify the input program. All netnode access
is serialized through idaapi.execute_sync and a process-local lock.
"""

import json
import threading

try:
    import idaapi
    import ida_netnode
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

from logger import log


NETNODE_NAME = "$ reverse_partner_metadata"
INDEX_KEY = "_saved_functions"
CHUNK_SIZE = 4096
MAX_STORED_CHARS = 1024 * 1024
CHUNK_MARKER = "__gpt_renamer_chunked__"

SUPPORTED_KEYS = frozenset({
    "ai_summary",
    "readable_c",
    "analyst_notes",
    "chat_history",
    "last_analysis",
    "function_context",
    "static_program_analysis",
})

_lock = threading.RLock()


def _sync(fn, write=False):
    """Run fn on IDA's main thread through execute_sync."""
    if not _IN_IDA:
        return None
    flags = idaapi.MFF_WRITE if write else idaapi.MFF_READ
    box = {"value": None, "error": None}

    def _do():
        try:
            box["value"] = fn()
        except Exception as exc:
            box["error"] = exc
        return 1

    with _lock:
        try:
            idaapi.execute_sync(_do, flags)
        except TypeError:
            _do()
        except Exception:
            _do()
    if box["error"] is not None:
        raise box["error"]
    return box["value"]


def _make_key(func_ea, key):
    if key not in SUPPORTED_KEYS:
        raise ValueError("Unsupported IDB metadata key: %s" % key)
    return "%016X:%s" % (int(func_ea) & 0xFFFFFFFFFFFFFFFF, key)


def _json_pack(content):
    return json.dumps(content, ensure_ascii=False, sort_keys=True)


def _json_unpack(text):
    if text in (None, ""):
        return None
    if isinstance(text, bytes):
        text = text.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except Exception:
        return text


def _hash_set(node, key, value):
    try:
        return node.hashset(key, value, "S")
    except TypeError:
        try:
            return node.hashset(key, value)
        except TypeError:
            return node.hashset(key, value.encode("utf-8"), "S")


def _hash_get(node, key):
    for call in (
        lambda: node.hashstr(key, "S"),
        lambda: node.hashval(key, "S"),
        lambda: node.hashstr(key),
        lambda: node.hashval(key),
    ):
        try:
            value = call()
            if value not in (None, b"", ""):
                return value
        except Exception:
            pass
    return None


def _hash_del(node, key):
    for call in (
        lambda: node.hashdel(key, "S"),
        lambda: node.hashdel(key),
        lambda: node.hdel(key),
    ):
        try:
            return call()
        except Exception:
            pass
    return False


def _chunk_key(storage_key, index):
    return "%s:chunk:%04d" % (storage_key, index)


def _delete_value(node, storage_key):
    raw = _hash_get(node, storage_key)
    unpacked = _json_unpack(raw)
    if isinstance(unpacked, dict) and unpacked.get(CHUNK_MARKER):
        try:
            count = int(unpacked.get("count", 0))
        except Exception:
            count = 0
        for i in range(count):
            _hash_del(node, _chunk_key(storage_key, i))
    return bool(_hash_del(node, storage_key))


def _store_value(node, storage_key, packed):
    if len(packed) > MAX_STORED_CHARS:
        raise ValueError("metadata blob too large (%d chars)" % len(packed))
    _delete_value(node, storage_key)
    if len(packed) <= CHUNK_SIZE:
        return _hash_set(node, storage_key, packed)

    chunks = [packed[i:i + CHUNK_SIZE] for i in range(0, len(packed), CHUNK_SIZE)]
    for i, chunk in enumerate(chunks):
        _hash_set(node, _chunk_key(storage_key, i), chunk)
    manifest = _json_pack({CHUNK_MARKER: True, "count": len(chunks)})
    return _hash_set(node, storage_key, manifest)


def _load_value(node, storage_key):
    raw = _hash_get(node, storage_key)
    unpacked = _json_unpack(raw)
    if not (isinstance(unpacked, dict) and unpacked.get(CHUNK_MARKER)):
        return unpacked

    try:
        count = int(unpacked.get("count", 0))
    except Exception:
        return None
    parts = []
    for i in range(count):
        chunk = _hash_get(node, _chunk_key(storage_key, i))
        if chunk is None:
            return None
        if isinstance(chunk, bytes):
            chunk = chunk.decode("utf-8", errors="replace")
        parts.append(str(chunk))
    return _json_unpack("".join(parts))


def _get_netnode_raw(create=False):
    try:
        return ida_netnode.netnode(NETNODE_NAME, 0, bool(create))
    except TypeError:
        node = ida_netnode.netnode()
        if create:
            try:
                node.create(NETNODE_NAME)
            except Exception:
                pass
        return node


def get_netnode(create=False):
    """
    Return the private GPT Renamer metadata netnode.
    Creates it only when create=True.
    """
    if not _IN_IDA:
        return None

    try:
        return _sync(lambda: _get_netnode_raw(create), write=bool(create))
    except Exception as exc:
        log.warn("IDB metadata netnode unavailable: %s" % exc)
        return None


def _load_index(node):
    data = _load_value(node, INDEX_KEY)
    return data if isinstance(data, list) else []


def _save_index(node, values):
    clean = sorted(set(str(v) for v in values if str(v)))
    _store_value(node, INDEX_KEY, _json_pack(clean))


def save_blob(func_ea, key, content):
    """
    Save a small UTF-8 JSON/text blob for one function.
    This is plugin metadata only and is safe while the debugger is active.
    """
    packed = _json_pack(content)
    storage_key = _make_key(func_ea, key)
    ea_hex = "0x%X" % int(func_ea)

    def _do():
        node = _get_netnode_raw(create=True)
        if node is None:
            return False
        _store_value(node, storage_key, packed)
        index = _load_index(node)
        if ea_hex not in index:
            index.append(ea_hex)
            _save_index(node, index)
        return True

    try:
        return bool(_sync(_do, write=True))
    except Exception as exc:
        log.warn("IDB metadata save failed: %s" % exc)
        return False


def load_blob(func_ea, key):
    """Load one per-function metadata blob, returning None if absent."""
    storage_key = _make_key(func_ea, key)

    def _do():
        node = _get_netnode_raw(create=False)
        if node is None:
            return None
        return _load_value(node, storage_key)

    try:
        return _sync(_do, write=False)
    except Exception as exc:
        log.warn("IDB metadata load failed: %s" % exc)
        return None


def delete_blob(func_ea, key):
    """Delete one per-function metadata blob."""
    storage_key = _make_key(func_ea, key)
    ea_hex = "0x%X" % int(func_ea)

    def _do():
        node = _get_netnode_raw(create=False)
        if node is None:
            return False
        ok = bool(_delete_value(node, storage_key))
        if ok:
            any_left = False
            for supported in SUPPORTED_KEYS:
                if _hash_get(node, _make_key(func_ea, supported)):
                    any_left = True
                    break
            if not any_left:
                index = [v for v in _load_index(node) if v != ea_hex]
                _save_index(node, index)
        return ok

    try:
        return bool(_sync(_do, write=True))
    except Exception as exc:
        log.warn("IDB metadata delete failed: %s" % exc)
        return False


def list_saved_functions():
    """Return function EAs that currently have GPT Renamer metadata."""
    def _do():
        node = _get_netnode_raw(create=False)
        if node is None:
            return []
        values = _load_index(node)
        result = []
        for item in values:
            try:
                result.append(int(str(item), 16))
            except Exception:
                pass
        return result

    try:
        return _sync(_do, write=False) or []
    except Exception as exc:
        log.warn("IDB metadata index load failed: %s" % exc)
        return []
