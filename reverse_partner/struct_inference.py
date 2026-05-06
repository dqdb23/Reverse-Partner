# -*- coding: utf-8 -*-
"""
struct_inference.py — AI-powered struct layout recovery
=========================================================
New v5 feature. Collects struct field accesses from a function via
static analysis, then sends them to the AI for layout inference.

Output: suggested field names, types, and offsets, formatted as
a C struct definition and optionally applied as IDA struct comments.
"""

import threading
from guards import is_debugger_active, require_static_mode
from ida_read import infer_struct_access, get_code, get_callee_names
from ida_write import safe_set_func_cmt, safe_set_cmt
from prompts import STRUCT_INFERENCE_PROMPT
from utils import parse_json_response_v5, sanitize_name
from logger import log

try:
    import idaapi, idc, ida_funcs
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


def build_struct_prompt(ea: int, accesses: list, cfg: dict) -> str:
    """Build the AI prompt for struct inference at a given function EA."""
    from ida_read import get_referenced_strings, get_referenced_apis
    func_name  = idc.get_func_name(ea) if _IN_IDA else hex(ea)
    code, ctype = get_code(ea, cfg.get("use_pseudocode", True))
    strings    = get_referenced_strings(ea, 10) if _IN_IDA else []
    apis       = get_referenced_apis(ea, 10) if _IN_IDA else []

    offset_list = sorted(set(a["offset"] for a in accesses))
    offsets_str = ", ".join("0x%x (+%d)" % (o, o) for o in offset_list[:cfg.get("max_struct_fields", 24)])

    parts = [
        "Function: %s  EA: %s" % (func_name, hex(ea) if _IN_IDA else "?"),
        "Struct field offsets accessed: %s" % offsets_str,
    ]
    if strings:
        parts.append("Referenced strings: %s" % "; ".join(strings[:6]))
    if apis:
        parts.append("Called APIs: %s" % ", ".join(apis[:8]))
    if code:
        parts.append("Code snippet:\n```\n%s\n```" % code[:2000])

    return "\n".join(parts)


def format_struct_c(result: dict) -> str:
    """
    Format a struct inference result as a C struct definition string.
    """
    name   = sanitize_name(result.get("struct_name", "inferred_struct"))
    fields = result.get("fields", [])
    conf   = result.get("confidence", 0.0)

    lines = [
        "// Struct inferred by reverse_partner  (confidence=%.2f)" % conf,
        "typedef struct _%s {" % name,
    ]
    for f in sorted(fields, key=lambda x: x.get("offset", 0)):
        offset  = f.get("offset", 0)
        fname   = sanitize_name(f.get("name", "field_%x" % offset))
        ftype   = f.get("type", "DWORD")
        purpose = f.get("purpose", "")
        comment = "  // +0x%02x %s" % (offset, purpose) if purpose else "  // +0x%02x" % offset
        lines.append("    %-10s %s;%s" % (ftype, fname, comment))
    lines.append("} %s;" % name)
    return "\n".join(lines)


def run_struct_inference(ea: int, cfg: dict) -> dict:
    """
    Infer struct layout for the function at EA.
    Returns normalized inference result dict, or {} on failure.
    """
    if not cfg.get("enable_struct_inference", True):
        log.info("Struct inference disabled in config.")
        return {}

    accesses = infer_struct_access(ea)
    if not accesses:
        log.info("  No struct field accesses detected at %s." % hex(ea))
        return {}

    log.info("  Struct inference: %d unique (reg, offset) accesses at %s" % (
        len(accesses), hex(ea)))

    prompt = build_struct_prompt(ea, accesses, cfg)

    from config import load_config
    from providers import make_provider

    try:
        provider   = make_provider(cfg)
        result_box = [None]
        err_box    = [None]

        def _ai():
            try:
                raw = provider._call(STRUCT_INFERENCE_PROMPT, prompt, max_tokens=600)
                result_box[0] = parse_json_response_v5(raw)
            except Exception as exc:
                err_box[0] = str(exc)

        t = threading.Thread(target=_ai, daemon=True)
        t.start()
        t.join(timeout=cfg.get("timeout_sec", 60))

        if err_box[0]:
            log.err("Struct inference AI error: %s" % err_box[0][:200])
            return {}

        res = result_box[0]
        if not res or "_parse_error" in res:
            log.warn("Struct inference: AI returned unparseable result.")
            return {}

        # Validate minimally
        if not res.get("fields"):
            log.warn("Struct inference: no fields returned.")
            return {}

        c_def = format_struct_c(res)
        log.sep()
        log.info("STRUCT INFERENCE RESULT for %s:" % (idc.get_func_name(ea) if _IN_IDA else hex(ea)))
        for line in c_def.split("\n"):
            log.info("  " + line)
        log.sep()

        # Apply as function comment if high confidence
        conf = float(res.get("confidence", 0.0))
        if conf >= 0.70 and _IN_IDA:
            existing = idc.get_func_cmt(ea, 0) or ""
            snippet  = ("Struct: %s (fields: %s)" % (
                res.get("struct_name", "?"),
                ", ".join(
                    "%s@+%x" % (sanitize_name(f.get("name", "?")), f.get("offset", 0))
                    for f in res.get("fields", [])[:6]
                )
            ))
            if snippet not in existing:
                safe_set_func_cmt(ea, (existing + "\n" if existing else "") + "[AI-Struct] " + snippet)

        res["_c_definition"] = c_def
        return res

    except Exception as exc:
        log.err("Struct inference failed: %s" % str(exc)[:200])
        return {}
