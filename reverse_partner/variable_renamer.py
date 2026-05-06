# -*- coding: utf-8 -*-
"""
variable_renamer.py - AI-assisted Hex-Rays local variable rename review
=======================================================================
Collects local variables from Hex-Rays, asks the configured AI provider for
rename suggestions, validates the result, and stores approved suggestions in
the GPT Renamer review queue. Actual IDB changes happen only when a review
queue item is applied by the user.
"""

import re

try:
    import idaapi
    import ida_funcs
    import ida_kernwin
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

from config import MAX_FUNC_SIZE_FOR_DECOMPILE, load_config
from guards import require_static_mode, is_debugger_active
from logger import log
from review_queue import add_variable_rename_to_review_queue, show_review_queue_ui
from utils import sanitize_name


_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def _execute_read(fn):
    result = [None]

    def _do():
        result[0] = fn()
        return 1

    try:
        idaapi.execute_sync(_do, idaapi.MFF_READ)
    except TypeError:
        _do()
    except Exception:
        _do()
    return result[0]


def collect_local_variables(func_ea: int) -> dict:
    """Collect Hex-Rays pseudocode and local variables. Static mode only."""
    if is_debugger_active():
        return {"error": "debugger_active", "variables": [], "code": ""}
    func = ida_funcs.get_func(func_ea) if _IN_IDA else None
    if not func:
        return {"error": "no_function", "variables": [], "code": ""}
    if (func.end_ea - func.start_ea) > MAX_FUNC_SIZE_FOR_DECOMPILE:
        return {"error": "function_too_large", "variables": [], "code": ""}

    def _do():
        try:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                return {"error": "hexrays_unavailable", "variables": [], "code": ""}
            cfunc = ida_hexrays.decompile(func_ea)
            if not cfunc:
                return {"error": "decompile_failed", "variables": [], "code": ""}
            variables = []
            for lv in cfunc.get_lvars():
                name = lv.name or ""
                if not name:
                    continue
                try:
                    typ = str(lv.type())
                except Exception:
                    typ = "unknown"
                is_arg = getattr(lv, "is_arg_var", False)
                if callable(is_arg):
                    try:
                        is_arg = is_arg()
                    except Exception:
                        is_arg = False
                variables.append({
                    "name": name,
                    "type": typ,
                    "is_arg": bool(is_arg),
                })
            return {"error": "", "variables": variables, "code": str(cfunc)}
        except Exception as exc:
            return {"error": str(exc), "variables": [], "code": ""}

    return _execute_read(_do) or {"error": "unknown", "variables": [], "code": ""}


def _build_prompt(func_name: str, code: str, variables: list) -> str:
    var_lines = []
    for v in variables[:80]:
        var_lines.append("- %(name)s : %(type)s arg=%(is_arg)s" % v)
    return (
        "Function: %s\n\n"
        "Local variables:\n%s\n\n"
        "Pseudocode:\n```\n%s\n```\n\n"
        "Return JSON."
    ) % (func_name, "\n".join(var_lines), code[:7000])


def _validate_suggestions(raw: dict, known_vars: set) -> list:
    if not isinstance(raw, dict) or raw.get("_parse_error"):
        return []
    suggestions = raw.get("variables", [])
    if not isinstance(suggestions, list):
        return []
    valid = []
    seen = set()
    for item in suggestions:
        if not isinstance(item, dict):
            continue
        old_name = str(item.get("old_name", "")).strip()
        if old_name not in known_vars or old_name in seen:
            continue
        new_name = sanitize_name(str(item.get("new_name", "")).strip()).lower()
        if not _NAME_RE.match(new_name) or new_name == old_name:
            continue
        try:
            conf = max(0.0, min(1.0, float(item.get("confidence", 0.0))))
        except Exception:
            conf = 0.0
        reason = str(item.get("reason", ""))[:400]
        if not reason:
            conf = min(conf, 0.5)
        valid.append({
            "old_name": old_name,
            "new_name": new_name,
            "confidence": round(conf, 3),
            "reason": reason,
        })
        seen.add(old_name)
    return valid


def run_variable_renamer():
    """Analyze the current function and enqueue selected local variable renames."""
    if not _IN_IDA:
        log.warn("Variable renamer requires IDA.")
        return 1
    if not require_static_mode("Variable Rename Suggestions"):
        return 1

    cfg = load_config()
    ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        idaapi.warning("Cursor is not inside a function.")
        return 1
    func_ea = func.start_ea
    func_name = idc.get_func_name(func_ea) or ("sub_%x" % func_ea)

    collected = collect_local_variables(func_ea)
    if collected.get("error"):
        idaapi.warning("Cannot collect Hex-Rays locals: %s" % collected.get("error"))
        return 1
    variables = collected.get("variables", [])
    if not variables:
        idaapi.info("No Hex-Rays local variables found in %s." % func_name)
        return 1

    from actions import _run_ai_thread
    from providers import make_provider
    try:
        provider = make_provider(cfg)
    except Exception as exc:
        idaapi.warning("Provider is not available: %s" % str(exc)[:300])
        return 1
    prompt = _build_prompt(func_name, collected.get("code", ""), variables)

    ida_kernwin.show_wait_box("reverse_partner: Suggesting variable names for '%s' ..." % func_name)
    try:
        raw, err = _run_ai_thread(
            lambda: provider.suggest_variable_renames(prompt),
            timeout=cfg.get("timeout_sec", 90))
    finally:
        ida_kernwin.hide_wait_box()

    if err:
        idaapi.warning("AI error: %s" % err[:300])
        return 1

    known = set(v.get("name", "") for v in variables)
    suggestions = _validate_suggestions(raw, known)
    if not suggestions:
        idaapi.info("No valid variable rename suggestions for %s." % func_name)
        return 1

    preview = ["Variable rename suggestions for %s:" % func_name, ""]
    for s in suggestions[:20]:
        preview.append("%s -> %s  conf=%.2f  %s" % (
            s["old_name"], s["new_name"], s["confidence"], s["reason"]))
    if idaapi.ask_yn(
            idaapi.ASKBTN_YES,
            "\n".join(preview[:24]) + "\n\nQueue these suggestions for review?") != idaapi.ASKBTN_YES:
        return 1

    for s in suggestions:
        add_variable_rename_to_review_queue(
            func_ea, func_name, s["old_name"], s["new_name"],
            s["confidence"], s["reason"],
            cfg.get("model", "?"), cfg.get("provider", "?"))

    idaapi.info("Queued %d variable rename suggestion(s)." % len(suggestions))
    show_review_queue_ui()
    return 1
