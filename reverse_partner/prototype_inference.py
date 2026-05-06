# -*- coding: utf-8 -*-
"""
prototype_inference.py - AI-assisted function prototype suggestions
===================================================================
Builds static context for the current function, asks the configured provider
for a conservative C prototype, and lets the user copy, save as an analyst
note, or queue the prototype change for review. Applying the prototype is done
only from the review queue after confirmation.
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

from config import load_config
from guards import require_static_mode, is_debugger_active
from idb_storage import load_blob, save_blob
from logger import log
from review_queue import add_prototype_to_review_queue, show_review_queue_ui
from static_analysis import build_function_context


def _current_type(ea: int) -> str:
    try:
        if hasattr(idc, "get_type"):
            return idc.get_type(ea) or ""
        if hasattr(idc, "GetType"):
            return idc.GetType(ea) or ""
    except Exception:
        pass
    return ""


def _validate_prototype(proto: str, func_name: str) -> str:
    proto = (proto or "").strip().rstrip(";") + ";"
    if "\n" in proto or len(proto) > 300:
        return ""
    if "(" not in proto or ")" not in proto:
        return ""
    if re.search(r"\b%s\b" % re.escape(func_name), proto) is None:
        return ""
    if any(bad in proto.lower() for bad in ("typedef", "#include", "{", "}")):
        return ""
    return proto


def _build_prompt(ctx: dict) -> str:
    return (
        "Function: %(name)s\n"
        "EA: %(ea)s\n"
        "Callers: %(callers)s\n"
        "Callees: %(callees)s\n"
        "APIs: %(apis)s\n"
        "Strings: %(strings)s\n"
        "Decoded strings (FLOSS): %(decoded_strings)s\n"
        "Constants: %(constants)s\n"
        "Static tags: %(pre_tags)s\n\n"
        "Pseudocode:\n```\n%(code)s\n```\n\n"
        "Return JSON."
    ) % {
        "name": ctx.get("name", ""),
        "ea": ctx.get("ea", ""),
        "callers": ", ".join(ctx.get("callers", [])[:12]),
        "callees": ", ".join(ctx.get("callees", [])[:20]),
        "apis": ", ".join(ctx.get("apis", [])[:20]),
        "strings": "; ".join(ctx.get("strings", [])[:10]),
        "decoded_strings": "; ".join(
            (s.get("value", "") if isinstance(s, dict) else str(s))
            for s in ctx.get("decoded_strings", [])[:8]
        ),
        "constants": ", ".join(ctx.get("constants", [])[:16]),
        "pre_tags": ", ".join(ctx.get("pre_tags", [])),
        "code": (ctx.get("code", "") or "")[:7500],
    }


def _copy_to_clipboard(text: str):
    try:
        from PyQt5 import QtWidgets
    except ImportError:
        try:
            from PySide2 import QtWidgets
        except ImportError:
            QtWidgets = None
    if QtWidgets:
        app = QtWidgets.QApplication.instance()
        if app:
            app.clipboard().setText(text)


def _append_note(ea: int, text: str) -> bool:
    old = load_blob(ea, "analyst_notes") or ""
    if old:
        old = str(old).rstrip() + "\n\n"
    return save_blob(ea, "analyst_notes", old + text)


def run_prototype_inference():
    """Suggest a prototype for the current function and queue it for review."""
    if not _IN_IDA:
        log.warn("Prototype inference requires IDA.")
        return 1
    if not require_static_mode("Prototype Inference"):
        return 1
    if is_debugger_active():
        idaapi.warning("Prototype inference is disabled while debugger is active.")
        return 1

    cfg = load_config()
    ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        idaapi.warning("Cursor is not inside a function.")
        return 1
    func_ea = func.start_ea

    try:
        ctx = build_function_context(func_ea, cfg)
    except Exception as exc:
        idaapi.warning("Cannot collect function context: %s" % str(exc)[:300])
        return 1
    name = ctx.get("name", idc.get_func_name(func_ea) or ("sub_%x" % func_ea))
    if not ctx.get("code"):
        idaapi.warning("Cannot collect pseudocode/assembly for %s." % name)
        return 1

    from actions import _run_ai_thread
    from providers import make_provider
    try:
        provider = make_provider(cfg)
    except Exception as exc:
        idaapi.warning("Provider is not available: %s" % str(exc)[:300])
        return 1

    ida_kernwin.show_wait_box("reverse_partner: Inferring prototype for '%s' ..." % name)
    try:
        raw, err = _run_ai_thread(
            lambda: provider.suggest_prototype(_build_prompt(ctx)),
            timeout=cfg.get("timeout_sec", 90))
    finally:
        ida_kernwin.hide_wait_box()

    if err:
        idaapi.warning("AI error: %s" % err[:300])
        return 1
    if not isinstance(raw, dict) or raw.get("_parse_error"):
        idaapi.warning("AI returned no usable prototype.")
        return 1

    prototype = _validate_prototype(raw.get("prototype", ""), name)
    if not prototype:
        idaapi.warning("AI prototype failed validation.")
        return 1

    try:
        confidence = max(0.0, min(1.0, float(raw.get("confidence", 0.0))))
    except Exception:
        confidence = 0.0
    evidence = raw.get("evidence", [])
    warnings = raw.get("warnings", [])
    if isinstance(evidence, str):
        evidence = [evidence]
    if isinstance(warnings, str):
        warnings = [warnings]

    old_proto = _current_type(func_ea)
    preview = (
        "Prototype suggestion for %s\n\n"
        "Current:\n%s\n\n"
        "Suggested:\n%s\n\n"
        "Confidence: %.2f\n\n"
        "Evidence:\n%s\n\n"
        "Queue this prototype change for review?"
    ) % (
        name,
        old_proto or "-",
        prototype,
        confidence,
        "\n".join("  " + str(e) for e in evidence[:8]) or "  -",
    )

    ans = idaapi.ask_yn(idaapi.ASKBTN_YES, preview)
    if ans != idaapi.ASKBTN_YES:
        if idaapi.ask_yn(idaapi.ASKBTN_NO, "Copy suggested prototype to clipboard?") == idaapi.ASKBTN_YES:
            _copy_to_clipboard(prototype)
        if idaapi.ask_yn(idaapi.ASKBTN_NO, "Save prototype suggestion to analyst notes?") == idaapi.ASKBTN_YES:
            _append_note(func_ea, "[Prototype Suggestion]\n%s" % prototype)
        return 1

    add_prototype_to_review_queue(
        func_ea, name, old_proto, prototype, confidence, evidence, warnings,
        cfg.get("model", "?"), cfg.get("provider", "?"))

    if idaapi.ask_yn(idaapi.ASKBTN_NO, "Copy suggested prototype to clipboard?") == idaapi.ASKBTN_YES:
        _copy_to_clipboard(prototype)
    if idaapi.ask_yn(idaapi.ASKBTN_NO, "Save prototype suggestion to analyst notes?") == idaapi.ASKBTN_YES:
        _append_note(func_ea, "[Prototype Suggestion]\n%s" % prototype)

    idaapi.info("Queued prototype suggestion for %s." % name)
    show_review_queue_ui()
    return 1
