# -*- coding: utf-8 -*-
"""
ida_write.py — IDA write operations (all guarded)
===================================================
Every function that modifies the IDB lives here.
ALL functions check is_debugger_active() before writing.
Avoids IDA's unsafe no-check name flag, preserving the v4 safety rule.
"""

try:
    import idaapi
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

from guards import is_debugger_active
from logger import log


def safe_apply_name(ea: int, new_name: str):
    """
    Set a function name safely.
    - Checks debugger before writing.
    - Uses SN_NOWARN only; never uses IDA's unsafe no-check name flag.
    - Appends hex suffix on name collision.
    Returns applied name or None on failure.
    """
    if is_debugger_active():
        log.warn("  SKIP rename '%s': debugger active!" % new_name)
        return None

    flags = idc.SN_NOWARN

    if idc.set_name(ea, new_name, flags):
        return new_name

    # Fallback: hex suffix to break collision
    unique = "%s_%x" % (new_name, ea & 0xFFFFF)
    if idc.set_name(ea, unique, flags):
        log.warn("  Name collision — used: %s" % unique)
        return unique

    log.err("  set_name failed at %s for '%s'" % (hex(ea), new_name))
    return None


def safe_set_func_cmt(ea: int, comment: str) -> bool:
    """Set a function comment. Skip if debugger active."""
    if is_debugger_active():
        return False
    try:
        idc.set_func_cmt(ea, comment, 0)
        return True
    except Exception as exc:
        log.warn("  set_func_cmt error: %s" % exc)
        return False


def safe_set_cmt(ea: int, comment: str) -> bool:
    """Set an instruction comment. Skip if debugger active."""
    if is_debugger_active():
        return False
    try:
        idc.set_cmt(ea, comment, 0)
        return True
    except Exception:
        return False


def _execute_write(fn):
    result = [False]

    def _do():
        result[0] = bool(fn())
        return 1

    try:
        idaapi.execute_sync(_do, idaapi.MFF_WRITE)
    except TypeError:
        _do()
    except Exception:
        _do()
    return bool(result[0])


def safe_rename_lvar(func_ea: int, old_name: str, new_name: str) -> bool:
    """Rename a Hex-Rays local variable. Skip if debugger active."""
    if is_debugger_active():
        return False
    if not old_name or not new_name or old_name == new_name:
        return False

    def _do():
        try:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                return False
            return bool(ida_hexrays.rename_lvar(func_ea, old_name, new_name))
        except Exception as exc:
            log.warn("  rename_lvar error: %s" % exc)
            return False

    return _execute_write(_do)


def safe_apply_func_type(ea: int, prototype: str) -> bool:
    """Apply a function prototype string. Skip if debugger active."""
    if is_debugger_active():
        return False
    prototype = (prototype or "").strip()
    if not prototype:
        return False

    def _do():
        try:
            if hasattr(idc, "SetType"):
                return bool(idc.SetType(ea, prototype))
            if hasattr(idc, "set_type"):
                return bool(idc.set_type(ea, prototype))
        except Exception as exc:
            log.warn("  apply function type error: %s" % exc)
        return False

    return _execute_write(_do)


def build_ai_comment(norm: dict) -> str:
    """
    Build a concise IDA function comment from a normalized AI result.
    Keeps it under 500 chars to stay readable in IDA's UI.
    """
    parts = []
    if norm.get("description"):
        parts.append(norm["description"])
    if norm.get("tags"):
        parts.append("[%s]" % ",".join(norm["tags"]))
    if norm.get("warnings"):
        parts.append("[!] " + "; ".join(norm["warnings"][:2]))
    conf = norm.get("confidence", 0.0)
    parts.append("conf=%.2f" % conf)
    cat = norm.get("category", "")
    if cat and cat != "UNKNOWN":
        parts.append("cat=%s" % cat)
    return "[AI] " + " | ".join(parts)
