# -*- coding: utf-8 -*-
"""
actions.py — IDA action handler classes
=========================================
Each action = one IDA menu item / hotkey.
All write operations are guarded by require_static_mode().
All show_wait_box calls have matching hide_wait_box in try/finally.

Hotkey map:
  Shift+G        Rename current function
  Ctrl+Shift+U   Rename unnamed functions (sub_XXXX)
  Ctrl+Shift+G   Rename all functions
  Ctrl+Shift+A   Analyze current function (deep AI)
  Ctrl+Shift+R   Analyze whole program (3-phase)  [FIX v5 — was unregistered]
  Ctrl+Shift+O   Anti-obfuscation scanner (static)
  Ctrl+Shift+E   Export forensic report
  Ctrl+Shift+Q   Review queue                      [NEW v5]
  Ctrl+Alt+Z     Rollback last rename batch         [NEW v5]
  Ctrl+Shift+I   Extract IOCs                       [NEW v5]
  Ctrl+Shift+L   Analyze selected range             [NEW v5]
  Ctrl+Shift+X   Struct inference for current func  [NEW v5]
  Ctrl+Alt+G     Open workspace pane                [NEW]
  Ctrl+Alt+V     Variable rename suggestions         [NEW]
  Ctrl+Alt+P     Prototype inference                 [NEW]
  Ctrl+Shift+F   Run FLOSS string discovery          [NEW]
  Ctrl+Alt+D     Static Program Analyzer current     [NEW]
  Ctrl+Shift+S   Settings
"""

import threading
import traceback

try:
    import idaapi
    import idautils
    import idc
    import ida_funcs
    import ida_kernwin
    _IN_IDA = True
except ImportError:
    _IN_IDA = False
    class _DummyActionHandler(object):
        def __init__(self):
            pass

    class _DummyIdaapi(object):
        action_handler_t = _DummyActionHandler
        AST_ENABLE_ALWAYS = 1
        ASKBTN_YES = 1
        ASKBTN_NO = 0

    idaapi = _DummyIdaapi()
    idautils = None
    idc = None
    ida_funcs = None
    ida_kernwin = None

from guards import require_static_mode, is_debugger_active
from logger import log
from config import load_config
from utils import is_default_name, normalize_ai_result
from ida_read import get_code, get_callee_names, get_caller_names
from ida_read import get_referenced_strings, get_referenced_apis
from ida_write import safe_apply_name, safe_set_func_cmt, build_ai_comment
from static_analysis import classify_function_static
from cache import compute_cache_key, cache_get, cache_put
from history import record_rename_batch, rollback_last_batch
from review_queue import add_to_review_queue, show_review_queue_ui


# ---------------------------------------------------------------------------
# Helper: run AI in background thread, return result or error
# ---------------------------------------------------------------------------

def _run_ai_thread(fn, timeout: int) -> tuple:
    """
    Run fn() in a daemon thread.
    Returns (result, error_str).
    error_str is None on success.
    """
    result_box = [None]
    err_box    = [None]

    def _run():
        try:
            result_box[0] = fn()
        except Exception as exc:
            err_box[0] = str(exc)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout=timeout)
    return result_box[0], err_box[0]


# ---------------------------------------------------------------------------
# ActionRenameCurrent
# ---------------------------------------------------------------------------

class ActionRenameCurrent(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:rename_current"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not require_static_mode("Rename Current"):
            return 1
        cfg = load_config()
        if not cfg.get("api_keys"):
            idaapi.warning("No API key configured.\nOpen Settings (Ctrl+Shift+S).")
            return 1

        ea   = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            idaapi.warning("Cursor is not inside a function.")
            return 1
        ea   = func.start_ea
        name = idc.get_func_name(ea) or ""

        if cfg.get("skip_named") and not is_default_name(name):
            if idaapi.ask_yn(idaapi.ASKBTN_NO,
                    "'%s' already has a name.\nRename anyway?" % name) != idaapi.ASKBTN_YES:
                return 1

        code, code_type = get_code(ea, cfg.get("use_pseudocode", True))
        if not code:
            idaapi.warning("Cannot get code for '%s'.\nTry disabling use_pseudocode in Settings." % name)
            return 1

        callees  = get_callee_names(ea)
        callers  = get_caller_names(ea)
        strings  = get_referenced_strings(ea)
        decoded_strings = []
        try:
            if cfg.get("enable_floss", False):
                from floss_integration import get_floss_strings_for_function
                decoded_strings = get_floss_strings_for_function(ea)
        except Exception:
            decoded_strings = []
        apis     = get_referenced_apis(ea)
        pre_tags, _, _ = classify_function_static(ea)

        ctx_extra = ""
        if strings:  ctx_extra += "// Strings: %s\n" % "; ".join(strings[:6])
        if decoded_strings:
            vals = [(s.get("value", "") if isinstance(s, dict) else str(s))
                    for s in decoded_strings[:6]]
            vals = [s for s in vals if s]
            if vals:
                ctx_extra += "// Decoded strings (FLOSS): %s\n" % "; ".join(vals)
        if apis:     ctx_extra += "// APIs: %s\n"    % ", ".join(apis[:10])
        if pre_tags: ctx_extra += "// Static pre-tags: %s\n" % ", ".join(pre_tags)

        ck = compute_cache_key(ea, name, code, callers, callees, strings, apis,
                               cfg.get("model",""), cfg.get("provider",""),
                               decoded_strings)
        cached = cache_get(cfg, ck)
        if cached:
            log.info("[CACHE HIT] '%s'" % name)
            raw = cached
        else:
            from providers import make_provider
            provider = make_provider(cfg)

            ida_kernwin.show_wait_box("reverse_partner: Analyzing '%s' …" % name)
            try:
                raw, err = _run_ai_thread(
                    lambda: provider.rename_single(code, name, callees, callers, ctx_extra),
                    timeout=cfg.get("timeout_sec", 60)
                )
            finally:
                ida_kernwin.hide_wait_box()

            if err:
                log.err("AI error: %s" % err)
                return 1
            if not raw:
                log.err("AI returned no result.")
                return 1
            cache_put(cfg, ck, raw, name, code_type)

        norm     = normalize_ai_result(raw, name, cfg.get("prefix",""))
        new_name = norm["name"]
        conf     = norm["confidence"]
        evidence = norm["evidence"]

        # Show popup
        popup = [
            "Function : %s" % name,
            "Suggested: %s" % new_name,
            "Conf     : %.2f  Category: %s" % (conf, norm["category"]),
        ]
        if norm.get("tags"):
            popup.append("Tags     : %s" % " | ".join(norm["tags"]))
        if norm.get("description"):
            popup.append("\nSummary:\n  " + norm["description"])
        if evidence:
            popup.append("\nEvidence:")
            for ev in evidence[:5]:
                popup.append("  · " + ev)
        if norm.get("warnings"):
            popup.append("\nWarnings:")
            for w in norm["warnings"][:3]:
                popup.append("  [!] " + w)
        idaapi.info("\n".join(popup))

        bh = []
        st = {}
        from rename_engine import decide_and_apply
        decide_and_apply(ea, name, raw, cfg, bh, st)
        if bh:
            record_rename_batch(bh, cfg.get("provider","?"), cfg.get("model","?"))
            idaapi.refresh_idaview_anyway()
        elif st.get("queued"):
            log.info("  Result in Review Queue (Ctrl+Shift+Q).")
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionRenameUnnamed
# ---------------------------------------------------------------------------

class ActionRenameUnnamed(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:rename_unnamed"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not require_static_mode("Rename Unnamed"):
            return 1
        cfg = load_config()
        if not cfg.get("api_keys"):
            idaapi.warning("No API key.\nOpen Settings (Ctrl+Shift+S).")
            return 1
        cfg["skip_named"] = True
        from rename_engine import run_rename_all
        return run_rename_all(cfg)

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionRenameAll
# ---------------------------------------------------------------------------

class ActionRenameAll(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:rename_all"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not require_static_mode("Rename All"):
            return 1
        cfg = load_config()
        if not cfg.get("api_keys"):
            idaapi.warning("No API key.\nOpen Settings (Ctrl+Shift+S).")
            return 1
        from rename_engine import run_rename_all
        return run_rename_all(cfg)

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionAnalyzeCurrent
# ---------------------------------------------------------------------------

class ActionAnalyzeCurrent(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:analyze_current"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        cfg = load_config()
        if not cfg.get("api_keys"):
            idaapi.warning("No API key.")
            return 1

        ea   = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            idaapi.warning("Cursor is not inside a function.")
            return 1
        ea   = func.start_ea
        name = idc.get_func_name(ea) or ("sub_%x" % ea)

        code, code_type = get_code(ea, cfg.get("use_pseudocode", True))
        if not code:
            idaapi.warning("Cannot get code for '%s'." % name)
            return 1

        callees  = get_callee_names(ea)
        callers  = get_caller_names(ea)
        strings  = get_referenced_strings(ea)
        decoded_strings = []
        try:
            if cfg.get("enable_floss", False):
                from floss_integration import get_floss_strings_for_function
                decoded_strings = get_floss_strings_for_function(ea)
        except Exception:
            decoded_strings = []
        apis     = get_referenced_apis(ea)
        pre_tags, _, _ = classify_function_static(ea)

        ctx_extra = ""
        if strings:  ctx_extra += "// Strings: %s\n" % "; ".join(strings[:8])
        if decoded_strings:
            vals = [(s.get("value", "") if isinstance(s, dict) else str(s))
                    for s in decoded_strings[:6]]
            vals = [s for s in vals if s]
            if vals:
                ctx_extra += "// Decoded strings (FLOSS): %s\n" % "; ".join(vals)
        if apis:     ctx_extra += "// APIs: %s\n"    % ", ".join(apis[:12])
        if pre_tags: ctx_extra += "// Static pre-tags: %s\n" % ", ".join(pre_tags)

        from providers import make_provider
        provider = make_provider(cfg)

        ida_kernwin.show_wait_box("reverse_partner: Deep analyzing '%s' …" % name)
        try:
            raw, err = _run_ai_thread(
                lambda: provider.analyze(code, name, callees, callers, ctx_extra),
                timeout=cfg.get("timeout_sec", 90)
            )
        finally:
            ida_kernwin.hide_wait_box()

        if err:
            idaapi.warning("AI error: %s" % err[:300])
            return 1
        if not raw or isinstance(raw, dict) and raw.get("_parse_error"):
            idaapi.warning("AI returned no usable result.")
            return 1

        norm     = normalize_ai_result(raw, name, cfg.get("prefix",""))
        behavior = raw.get("behavior", "")

        # Log
        log.sep()
        log.info("ANALYSIS: %s" % name)
        log.info("  Suggested : %s (conf=%.2f, cat=%s)" % (
            norm["name"], norm["confidence"], norm["category"]))
        if norm.get("tags"):      log.info("  Tags      : %s" % " | ".join(norm["tags"]))
        if norm.get("description"): log.info("  Desc      : %s" % norm["description"][:200])
        if behavior:              log.info("  Behavior  : %s" % behavior[:300])
        log.sep()

        # Set function comment
        safe_set_func_cmt(ea, build_ai_comment(norm))

        # Popup
        popup = [
            "Function : %s" % name,
            "Suggested: %s" % norm["name"],
            "Conf     : %.2f  Category: %s" % (norm["confidence"], norm["category"]),
        ]
        if norm.get("tags"):
            popup.append("Tags     : %s" % "  |  ".join(norm["tags"]))
        if norm.get("description"):
            popup.append("\nSummary:\n" + norm["description"])
        if norm.get("evidence"):
            popup.append("\nEvidence:")
            for ev in norm["evidence"][:6]: popup.append("  · " + ev)
        if behavior:
            popup.append("\nBehavior:")
            for seg in behavior.split(". ")[:6]:
                if seg.strip(): popup.append("  · " + seg.strip())
        if norm.get("warnings"):
            popup.append("\nWarnings:")
            for w in norm["warnings"][:3]: popup.append("  [!] " + w)
        idaapi.info("\n".join(popup))

        # Offer rename if default name
        if norm["name"] and norm["name"] != name and is_default_name(name):
            if not is_debugger_active():
                if idaapi.ask_yn(idaapi.ASKBTN_YES,
                        "Rename '%s' → '%s'?" % (name, norm["name"])) == idaapi.ASKBTN_YES:
                    applied = safe_apply_name(ea, norm["name"])
                    if applied:
                        log.renamed(name, applied)
                        record_rename_batch(
                            [{"ea": ea, "old_name": name, "new_name": applied,
                              "confidence": norm["confidence"]}],
                            cfg.get("provider","?"), cfg.get("model","?"))
                        idaapi.refresh_idaview_anyway()
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionAnalyzeProgram  [FIX v5 — was listed in header but never registered]
# ---------------------------------------------------------------------------

class ActionAnalyzeProgram(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:analyze_program"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not require_static_mode("Analyze Whole Program"):
            return 1
        cfg = load_config()
        if not cfg.get("api_keys"):
            idaapi.warning("No API key.")
            return 1

        if idaapi.ask_yn(idaapi.ASKBTN_YES,
                "reverse_partner — Analyze Whole Program\n\n"
                "3 phases:\n"
                "  1. Static pre-tag all functions\n"
                "  2. AI batch rename (same as Rename All)\n"
                "  3. AI holistic binary summary\n\n"
                "This may take several minutes. Continue?") != idaapi.ASKBTN_YES:
            return 1

        # Phase 1 — static tagging
        log.sep()
        log.info("PHASE 1: Static pre-tagging …")
        tagged = sum(1 for ea in idautils.Functions()
                     if classify_function_static(ea)[0])
        log.ok("  → %d functions pre-tagged" % tagged)

        # Phase 2 — AI rename
        log.info("PHASE 2: AI rename all …")
        from rename_engine import run_rename_all
        run_rename_all(cfg)

        # Phase 3 — holistic summary
        log.info("PHASE 3: Holistic binary summary …")
        from ioc_extractor import extract_iocs_from_binary
        all_eas   = list(idautils.Functions())
        n_renamed = sum(1 for ea in all_eas
                        if not is_default_name(idc.get_func_name(ea) or ""))
        top_names = [idc.get_func_name(ea) for ea in all_eas
                     if not is_default_name(idc.get_func_name(ea) or "")][:40]
        iocs      = extract_iocs_from_binary()
        from ioc_extractor import ioc_values

        summary_parts = [
            "Binary: %s" % (idc.get_input_file_path() or "unknown"),
            "Total functions: %d  Renamed: %d" % (len(all_eas), n_renamed),
            "Top renamed: %s" % ", ".join(top_names[:20]),
        ]
        for t, vals in sorted(iocs.items()):
            summary_parts.append("%s: %s" % (t.upper(), ", ".join(ioc_values(vals)[:8])))

        from providers import make_provider
        provider = make_provider(cfg)

        ida_kernwin.show_wait_box("reverse_partner: Phase 3 — binary summary …")
        try:
            res, err = _run_ai_thread(
                lambda: provider.analyze_whole_program("\n".join(summary_parts)),
                timeout=cfg.get("timeout_sec", 120)
            )
        finally:
            ida_kernwin.hide_wait_box()

        if err:
            log.warn("Phase 3 error: %s" % err[:200])
        elif res and isinstance(res, dict) and not res.get("_parse_error"):
            log.sep()
            log.info("BINARY SUMMARY (AI)")
            log.info("  Family  : %s" % res.get("malware_family","?"))
            log.info("  Campaign: %s" % res.get("campaign","?"))
            log.info("  Summary : %s" % res.get("summary","")[:300])
            for t in res.get("techniques",[])[:10]:
                log.info("  MITRE   : %s" % t)
            log.sep()
            idaapi.info(
                "Binary Summary\n\n"
                "Family  : %s\nCampaign: %s\n\n%s\n\n"
                "MITRE: %s" % (
                    res.get("malware_family","?"),
                    res.get("campaign","?"),
                    res.get("summary","")[:600],
                    ", ".join(res.get("techniques",[])[:10]),
                )
            )
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionAntiObfuscation
# ---------------------------------------------------------------------------

class ActionAntiObfuscation(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:anti_obfuscation"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not require_static_mode("Anti-Obfuscation Scanner"):
            return 1
        if idaapi.ask_yn(idaapi.ASKBTN_YES,
                "Anti-Obfuscation Scanner v5\n\n"
                "4 passes (STATIC ONLY):\n"
                "  1. Hash API resolution (ROR13 / DJB2 / FNV1a)\n"
                "  2. Indirect / vtable call tracing\n"
                "  3. Dispatcher / switch-table mapping\n"
                "  4. Wrapper rename → resolve_and_call_<API>_aN\n\n"
                "Continue?") != idaapi.ASKBTN_YES:
            return 1

        from anti_obfuscation import run_scanner
        ida_kernwin.show_wait_box("Anti-Obfuscation Scanner v5 …")
        try:
            summary = run_scanner()
        except Exception:
            log.err(traceback.format_exc())
            return 1
        finally:
            ida_kernwin.hide_wait_box()

        idaapi.refresh_idaview_anyway()
        idaapi.info(
            "Anti-Obfuscation Scanner done!\n\n"
            "Hash matches  : %(hash_matches)d\n"
            "Indirect calls: %(indirect_calls)d\n"
            "Dispatchers   : %(dispatchers)d\n"
            "Wrappers named: %(wrappers_named)d\n\n"
            "See Output window for details." % summary
        )
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionExportReport
# ---------------------------------------------------------------------------

class ActionExportReport(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:export_report"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        from report import export_report
        export_report(load_config())
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionReviewQueue  [NEW v5]
# ---------------------------------------------------------------------------

class ActionReviewQueue(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:review_queue"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        show_review_queue_ui()
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionWorkspace
# ---------------------------------------------------------------------------

class ActionWorkspace(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:workspace"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        from workspace import open_workspace
        open_workspace()
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionRollback  [NEW v5]
# ---------------------------------------------------------------------------

class ActionRollback(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:rollback"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        ok, skip, manual = rollback_last_batch()
        if ok + skip + manual > 0:
            idaapi.info("Rollback done.\nRestored: %d | Skipped: %d | Manual skip: %d" % (
                ok, skip, manual))
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionExtractIOCs  [NEW v5]
# ---------------------------------------------------------------------------

class ActionExtractIOCs(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:extract_iocs"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        from ioc_extractor import extract_iocs_from_binary, format_iocs_report
        ida_kernwin.show_wait_box("reverse_partner: Scanning for IOCs …")
        try:
            iocs = extract_iocs_from_binary()
        finally:
            ida_kernwin.hide_wait_box()

        if not iocs:
            idaapi.info("No IOCs found.")
            return 1

        report = format_iocs_report(iocs)
        log.sep()
        log.info("IOC EXTRACTION RESULTS")
        for line in report.split("\n")[:60]:
            log.info("  " + line)
        log.sep()

        total = sum(len(v) for v in iocs.values())
        idaapi.info("IOCs found: %d items across %d categories.\n\n%s" % (
            total, len(iocs), report[:2000]))
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionAnalyzeRange  [NEW v5]
# ---------------------------------------------------------------------------

class ActionAnalyzeRange(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:analyze_range"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        cfg = load_config()
        if not cfg.get("api_keys"):
            idaapi.warning("No API key.")
            return 1

        sel_start = idc.read_selection_start()
        sel_end   = idc.read_selection_end()

        if sel_start == idaapi.BADADDR or sel_end == idaapi.BADADDR or sel_start >= sel_end:
            idaapi.warning(
                "No code selected!\n\n"
                "Instructions:\n"
                "  IDA View: select instructions with mouse/keyboard\n"
                "  Pseudocode: select lines\n"
                "Then press Ctrl+Shift+L again.")
            return 1

        lines = []
        ea = sel_start
        while ea < sel_end and len(lines) < 200:
            d = idc.generate_disasm_line(ea, 0)
            if d:
                lines.append("  %s: %s" % (hex(ea), d))
            ea = idc.next_head(ea, sel_end)
            if ea == idaapi.BADADDR:
                break

        if not lines:
            idaapi.warning("Cannot get disassembly for selected range.")
            return 1

        snippet = "\n".join(lines)
        log.info("Range analysis: %s–%s (%d lines)" % (
            hex(sel_start), hex(sel_end), len(lines)))

        from providers import make_provider
        provider = make_provider(cfg)

        ida_kernwin.show_wait_box("reverse_partner: Analyzing range %s–%s …" % (
            hex(sel_start), hex(sel_end)))
        try:
            res, err = _run_ai_thread(
                lambda: provider.analyze_range(snippet),
                timeout=cfg.get("timeout_sec", 60)
            )
        finally:
            ida_kernwin.hide_wait_box()

        if err:
            idaapi.warning("AI error: %s" % err[:200])
            return 1
        if not res or res.get("_parse_error"):
            idaapi.warning("AI returned no usable result.")
            return 1

        purpose   = res.get("purpose", "")
        comment   = res.get("suggested_comment", "")
        apis      = res.get("interesting_apis", [])
        consts    = res.get("interesting_constants", [])
        conf      = res.get("confidence", 0.0)
        evidence  = res.get("evidence", [])
        warnings  = res.get("warnings", [])

        log.sep()
        log.info("RANGE ANALYSIS: %s–%s" % (hex(sel_start), hex(sel_end)))
        if purpose:  log.info("  Purpose : %s" % purpose)
        if comment:  log.info("  Comment : %s" % comment)
        log.sep()

        popup = [
            "Range  : %s – %s" % (hex(sel_start), hex(sel_end)),
            "Conf   : %.2f" % conf, "",
        ]
        if purpose: popup.append("Purpose: %s" % purpose)
        if apis:    popup.append("APIs   : %s" % ", ".join(apis[:8]))
        if consts:  popup.append("Consts : %s" % ", ".join(consts[:8]))
        if evidence:
            popup.append("\nEvidence:")
            for ev in evidence[:5]: popup.append("  · " + ev)
        if warnings:
            popup.append("\nWarnings:")
            for w in warnings[:3]: popup.append("  [!] " + w)
        if comment: popup.append("\nSuggested comment:\n  " + comment)
        idaapi.info("\n".join(popup))

        if comment and not is_debugger_active():
            if idaapi.ask_yn(idaapi.ASKBTN_YES,
                    "Insert comment at %s?\n\n%s" % (hex(sel_start), comment)) == idaapi.ASKBTN_YES:
                from ida_write import safe_set_cmt
                safe_set_cmt(sel_start, "[AI Range] %s" % comment)
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionStructInference  [NEW v5]
# ---------------------------------------------------------------------------

class ActionStructInference(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:struct_inference"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        cfg = load_config()
        if not cfg.get("api_keys"):
            idaapi.warning("No API key.")
            return 1
        if not cfg.get("enable_struct_inference", True):
            idaapi.warning("Struct inference is disabled in Settings.")
            return 1

        ea = idc.get_screen_ea()
        f  = ida_funcs.get_func(ea)
        if not f:
            idaapi.warning("Cursor is not inside a function.")
            return 1
        ea = f.start_ea
        nm = idc.get_func_name(ea) or ("sub_%x" % ea)

        from struct_inference import run_struct_inference
        ida_kernwin.show_wait_box("reverse_partner: Struct inference for '%s' …" % nm)
        try:
            result = run_struct_inference(ea, cfg)
        finally:
            ida_kernwin.hide_wait_box()

        if not result:
            idaapi.info("No struct accesses detected in '%s'." % nm)
            return 1

        c_def = result.get("_c_definition", "")
        if c_def:
            idaapi.info(
                "Struct Inference — %s\n\nConfidence: %.2f\n\n%s\n\n"
                "(Comment applied to function if confidence ≥ 0.70)" % (
                    nm, result.get("confidence", 0.0), c_def)
            )
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionVariableRenamer
# ---------------------------------------------------------------------------

class ActionVariableRenamer(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:variable_renamer"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        from variable_renamer import run_variable_renamer
        return run_variable_renamer()

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionPrototypeInference
# ---------------------------------------------------------------------------

class ActionPrototypeInference(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:prototype_inference"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        from prototype_inference import run_prototype_inference
        return run_prototype_inference()

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionRunFLOSS
# ---------------------------------------------------------------------------

class ActionRunFLOSS(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:run_floss"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        cfg = load_config()
        path = idc.get_input_file_path() or ""
        if not path:
            idaapi.warning("No input file path is available for FLOSS.")
            return 1
        if idaapi.ask_yn(
                idaapi.ASKBTN_NO,
                "Run external FLOSS string discovery against:\n\n%s\n\n"
                "This runs floss.exe as a static analysis tool. Continue?" % path
        ) != idaapi.ASKBTN_YES:
            return 1

        cfg["_input_path"] = path
        from floss_integration import run_floss_on_input_binary

        ida_kernwin.show_wait_box("reverse_partner: Running FLOSS ...")
        try:
            results, err = _run_ai_thread(
                lambda: run_floss_on_input_binary(cfg),
                timeout=int(cfg.get("floss_timeout_sec", 120)) + 5)
        finally:
            ida_kernwin.hide_wait_box()

        if err:
            idaapi.warning("FLOSS error: %s" % err[:300])
            return 1
        idaapi.info("FLOSS complete.\nDecoded strings: %d" % len(results or []))
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# Static Program Analyzer actions
# ---------------------------------------------------------------------------

def _run_static_program_analyzer(mode):
    cfg = load_config()
    provider = cfg.get("provider", "?")
    model = cfg.get("model", "?")
    max_depth = int(cfg.get("spa_max_depth", 5))
    max_funcs = int(cfg.get("spa_max_functions", 300))
    ai_limit = int(cfg.get("spa_ai_function_limit", 80))
    artifact_dir = cfg.get("spa_artifact_dir", "") or "<near input binary>"
    msg = (
        "Static Program Analyzer\n\n"
        "Mode: %s\n"
        "Max depth: %d\n"
        "Max functions: %d\n"
        "AI function limit: %d\n"
        "Provider/model: %s / %s\n"
        "Cache enabled: %s\n"
        "Artifact dir: %s\n\n"
        "Estimated AI calls: up to %d\n\n"
        "Continue?"
    ) % (
        mode, max_depth, max_funcs, ai_limit,
        provider, model,
        "yes" if cfg.get("spa_use_cache", True) else "no",
        artifact_dir, ai_limit,
    )
    if idaapi.ask_yn(idaapi.ASKBTN_NO, msg) != idaapi.ASKBTN_YES:
        return 1

    from static_program_analyzer import StaticProgramAnalyzer

    analyzer = StaticProgramAnalyzer(cfg=cfg, mode=mode)
    ida_kernwin.show_wait_box("reverse_partner: Static Program Analyzer collecting context ...")
    try:
        analyzer.prepare(mode=mode)
    finally:
        ida_kernwin.hide_wait_box()

    if not analyzer.graph or not analyzer.scored_items:
        idaapi.warning("Static Program Analyzer found no functions for this mode.")
        return 1
    if analyzer.cancelled:
        artifact_dir = analyzer.save_results()
        idaapi.info("Static Program Analyzer cancelled during context collection.\nPartial artifacts: %s" % (
            artifact_dir or "<not saved>"))
        return 1

    ida_kernwin.show_wait_box("reverse_partner: Static Program Analyzer AI stage ...")
    try:
        timeout = max(120, int(cfg.get("timeout_sec", 60)) * max(1, len(analyzer.selected_items)) + 30)
        result, err = _run_ai_thread(
            lambda: analyzer.analyze_selected_functions(analyzer.selected_items),
            timeout=timeout)
    finally:
        ida_kernwin.hide_wait_box()

    if err:
        idaapi.warning("Static Program Analyzer error: %s" % err[:300])
        result = {"results": analyzer.results, "review_suggestions": analyzer.review_suggestions}
    elif result is None:
        analyzer.cancelled = True
        for suggestion in list(analyzer.review_suggestions):
            try:
                add_to_review_queue(
                    int(suggestion["ea"]),
                    suggestion.get("old_name", ""),
                    suggestion.get("ai_result", {}),
                    cfg.get("model", "?"),
                    cfg.get("provider", "?"),
                )
            except Exception as exc:
                log.warn("SPA review suggestion queue failed: %s" % exc)
        artifact_dir = analyzer.save_results()
        idaapi.warning(
            "Static Program Analyzer did not finish before timeout.\n"
            "Cancellation was requested and partial artifacts were saved: %s" % (
                artifact_dir or "<not saved>"))
        return 1

    for suggestion in analyzer.review_suggestions:
        try:
            add_to_review_queue(
                int(suggestion["ea"]),
                suggestion.get("old_name", ""),
                suggestion.get("ai_result", {}),
                cfg.get("model", "?"),
                cfg.get("provider", "?"),
            )
        except Exception as exc:
            log.warn("SPA review suggestion queue failed: %s" % exc)

    artifact_dir = analyzer.save_results()
    info = (
        "Static Program Analyzer complete.\n\n"
        "Functions in scope: %d\n"
        "AI candidates: %d\n"
        "Review suggestions: %d\n"
        "Artifacts: %s"
    ) % (
        len(analyzer.scored_items),
        len(analyzer.selected_items),
        len(analyzer.review_suggestions),
        artifact_dir or "<not saved>",
    )
    idaapi.info(info)
    return 1


class ActionSPACurrentSubgraph(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:spa_current_subgraph"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        return _run_static_program_analyzer("current_function")

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


class ActionSPAEntryPoints(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:spa_entry_points"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        return _run_static_program_analyzer("entry_points")

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


class ActionSPAReviewPriority(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:spa_review_priority"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        return _run_static_program_analyzer("review_priority_only")

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


class ActionSPAOpenLastReport(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:spa_open_last_report"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        from static_program_analyzer import open_last_static_report
        path = open_last_static_report(load_config())
        if not path:
            idaapi.warning("No Static Program Analyzer report found.")
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS


# ---------------------------------------------------------------------------
# ActionSettings
# ---------------------------------------------------------------------------

class ActionSettings(idaapi.action_handler_t):
    ACTION_ID = "gpt_renamer:settings"

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        from settings_ui import show_settings
        show_settings()
        return 1

    def update(self, ctx): return idaapi.AST_ENABLE_ALWAYS
