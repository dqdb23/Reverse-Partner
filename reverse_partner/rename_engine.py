# -*- coding: utf-8 -*-
"""
rename_engine.py — Core rename / analysis orchestration
=========================================================
Handles:
  - Single function rename
  - Batch rename all / rename unnamed
  - Whole-program 3-phase analysis
  - Selected-range analysis
  - Per-function apply logic (review_mode, confidence thresholds)
"""

import time
import threading
import traceback
import queue as queue_module
from collections import defaultdict

from guards import require_static_mode, is_debugger_active
from logger import log
from utils import is_default_name, is_worth_renaming, normalize_ai_result
from ida_read import (
    collect_all_functions, get_code, get_callee_names, get_caller_names,
    get_referenced_strings, get_referenced_apis, build_call_graph, topological_sort,
)
from ida_write import safe_apply_name, safe_set_func_cmt, build_ai_comment
from static_analysis import classify_function_static, build_function_context
from cache import compute_cache_key, cache_get, cache_put
from review_queue import add_to_review_queue
from history import record_rename_batch
from prompts import pack_batches

try:
    import idaapi, idautils, idc, ida_funcs
    import ida_kernwin
    _IN_IDA = True
except ImportError:
    _IN_IDA = False


# ---------------------------------------------------------------------------
# Per-function apply decision
# ---------------------------------------------------------------------------

def decide_and_apply(ea: int, old_name: str, ai_result: dict,
                      cfg: dict, batch_history: list, stats: dict):
    """
    Apply an AI rename result according to review_mode and confidence thresholds.
    Mutates batch_history and stats in place.
    """
    review_mode    = cfg.get("review_mode", True)
    auto_conf      = cfg.get("auto_apply_confidence", 0.85)
    comment_conf   = cfg.get("comment_only_below_confidence", 0.60)
    require_ev     = cfg.get("require_evidence", True)
    provider_name  = cfg.get("provider", "?")
    model          = cfg.get("model", "?")
    prefix         = cfg.get("prefix", "")

    norm = normalize_ai_result(ai_result, old_name, prefix, require_ev)

    if norm.get("_error"):
        stats["failed"] = stats.get("failed", 0) + 1
        add_to_review_queue(ea, old_name, norm, model, provider_name)
        return

    conf      = norm["confidence"]
    new_name  = norm["name"]
    evidence  = norm["evidence"]

    if not new_name or new_name == old_name:
        stats["skipped"] = stats.get("skipped", 0) + 1
        return

    # ── review_mode = True → everything goes to queue ───────────────────
    if review_mode:
        add_to_review_queue(ea, old_name, norm, model, provider_name)
        stats["queued"] = stats.get("queued", 0) + 1
        log.info("  [QUEUE] %s → %s (conf=%.2f)" % (old_name, new_name, conf))
        return

    # ── auto-apply ────────────────────────────────────────────────────────
    if conf >= auto_conf and (not require_ev or evidence):
        applied = safe_apply_name(ea, new_name)
        if applied:
            safe_set_func_cmt(ea, build_ai_comment(norm))
            log.renamed(old_name, applied)
            stats["renamed"] = stats.get("renamed", 0) + 1
            batch_history.append({"ea": ea, "old_name": old_name,
                                   "new_name": applied, "confidence": conf})
        else:
            stats["failed"] = stats.get("failed", 0) + 1

    elif conf >= comment_conf:
        # Medium confidence → queue only, no rename
        add_to_review_queue(ea, old_name, norm, model, provider_name)
        stats["queued"] = stats.get("queued", 0) + 1
        log.info("  [QUEUE] %s → %s (conf=%.2f, below auto_apply)" % (
            old_name, new_name, conf))

    else:
        # Low confidence → optional comment, no rename
        if norm.get("description"):
            safe_set_func_cmt(ea, "[AI?] %s (conf=%.2f)" % (norm["description"], conf))
        stats["skipped"] = stats.get("skipped", 0) + 1
        log.warn("  [LOW] %s conf=%.2f → comment only" % (old_name, conf))


# ---------------------------------------------------------------------------
# Rename all
# ---------------------------------------------------------------------------

def run_rename_all(cfg: dict) -> int:
    """
    Main rename-all workflow (parallel batch).
    Returns 1 always (IDA action protocol).
    """
    if not require_static_mode("Rename All"):
        return 1

    from providers import make_parallel_providers, PerKeyProvider
    from config import mask_key

    n_total   = sum(1 for _ in idautils.Functions())
    n_default = sum(1 for ea in idautils.Functions()
                    if is_default_name(idc.get_func_name(ea) or ""))
    n_keys    = len(cfg.get("api_keys", []))
    batch_sz  = int(cfg.get("batch_size", 50)) or 50

    ans = idaapi.ask_yn(idaapi.ASKBTN_NO,
        "reverse_partner — Rename All\n\n"
        "Binary overview:\n"
        "  Total functions   : %d\n"
        "  Unnamed (sub_*)   : %d\n"
        "  Named             : %d\n\n"
        "Config:\n"
        "  Provider : %s | Model : %s\n"
        "  Keys     : %d  | Batch : %d/req\n"
        "  Review   : %s | AutoConf >= %.2f\n"
        "  Naming   : %s\n\n"
        "Watch Output window (Alt+0).\nContinue?" % (
            n_total, n_default, n_total - n_default,
            cfg["provider"], cfg["model"],
            n_keys, batch_sz,
            "ON → review queue" if cfg.get("review_mode") else "OFF → auto-apply",
            cfg.get("auto_apply_confidence", 0.85),
            cfg.get("naming_mode", "conservative"),
        ))
    if ans != idaapi.ASKBTN_YES:
        return 1

    t_start = time.time()
    ida_kernwin.show_wait_box("reverse_partner: Collecting data …\nPress Cancel to abort.")

    try:
        # ── Step 1: collect functions ────────────────────────────────────
        log.sep()
        log.info("Step 1/4: Collecting functions …")
        all_info = collect_all_functions()

        # ── Step 2: filter + gather code ─────────────────────────────────
        ida_kernwin.replace_wait_box("reverse_partner: Loading code …")
        log.info("Step 2/4: Filtering and loading code …")
        candidates   = []
        skipped      = 0
        failed_code  = 0
        skip_reasons = defaultdict(int)
        use_pseudo   = cfg.get("use_pseudocode", True)
        min_insn     = cfg.get("min_insn", 5)
        skip_named   = cfg.get("skip_named", True)

        for i, info in enumerate(all_info):
            if ida_kernwin.user_cancelled():
                ida_kernwin.hide_wait_box()
                return 1

            ea, name = info["ea"], info["name"]
            should, reason = is_worth_renaming(name, info["n_insn"], skip_named)
            if not should:
                skipped += 1; skip_reasons[reason] += 1; continue
            if info["n_insn"] < min_insn:
                skipped += 1; skip_reasons["min_insn"] += 1; continue

            code, code_type = get_code(ea, use_pseudo)
            if not code:
                failed_code += 1; skip_reasons["no_code"] += 1; continue

            callees  = get_callee_names(ea)
            callers  = get_caller_names(ea)
            strings  = get_referenced_strings(ea, 8)
            decoded_strings = []
            try:
                if cfg.get("enable_floss", False):
                    from floss_integration import get_floss_strings_for_function
                    decoded_strings = get_floss_strings_for_function(ea)
            except Exception:
                decoded_strings = []
            apis     = get_referenced_apis(ea, 12)
            pre_tags, _, mitre = classify_function_static(ea)

            # Check cache
            ck = compute_cache_key(ea, name, code, callers, callees,
                                   strings, apis, cfg.get("model",""), cfg.get("provider",""),
                                   decoded_strings)
            cached = cache_get(cfg, ck)

            candidates.append({
                "ea": ea, "name": name, "code": code, "code_type": code_type,
                "callees": callees, "callers": callers, "strings": strings,
                "decoded_strings": decoded_strings,
                "apis": apis, "pre_tags": pre_tags, "mitre_hints": mitre,
                "_cache_key": ck, "_cached": cached,
            })
            if i % 100 == 0:
                ida_kernwin.replace_wait_box(
                    "reverse_partner: Loading %d/%d … (%d candidates)" % (
                        i, len(all_info), len(candidates)))

        log.info("  → %d candidates | %d skipped | %d no-code" % (
            len(candidates), skipped, failed_code))
        if not candidates:
            ida_kernwin.hide_wait_box()
            return 1

        # Pre-apply cached results immediately
        batch_history: list = []
        stats: dict         = {"renamed": 0, "skipped": 0, "failed": failed_code,
                                "queued": 0, "retry_ok": 0, "retry_fail": 0}
        need_ai = []
        for item in candidates:
            if item["_cached"]:
                log.info("  [CACHE HIT] %s" % item["name"])
                decide_and_apply(item["ea"], item["name"], item["_cached"],
                                 cfg, batch_history, stats)
            else:
                need_ai.append(item)
        log.info("  → %d cache hits | %d need AI" % (
            len(candidates) - len(need_ai), len(need_ai)))

        # ── Step 3: build call graph + sort ──────────────────────────────
        ida_kernwin.replace_wait_box("reverse_partner: Building call graph …")
        log.info("Step 3/4: Building call graph …")
        ceas      = [c["ea"] for c in need_ai]
        cmap      = build_call_graph(ceas)
        sorted_e  = topological_sort(ceas, cmap)
        ea_map    = {c["ea"]: c for c in need_ai}
        sorted_ai = [ea_map[e] for e in sorted_e if e in ea_map]
        batches   = pack_batches(sorted_ai, cfg["model"], batch_sz)
        log.info("  → %d batches (avg %.1f/batch)" % (
            len(batches), len(sorted_ai) / len(batches) if batches else 0))

    except Exception:
        ida_kernwin.hide_wait_box()
        log.err(traceback.format_exc())
        return 1

    # ── Step 4: parallel AI calls ─────────────────────────────────────────
    log.sep()
    log.info("Step 4/4: Parallel AI rename …")
    log.sep()

    main_prov, per_key_provs, rotator = make_parallel_providers(cfg)
    n_workers  = len(per_key_provs)
    total_b    = len(batches)
    processed  = 0
    failed_items: list = []

    bq = queue_module.Queue()
    rq = queue_module.Queue()
    for bi, batch in enumerate(batches):
        bq.put((bi, batch))

    def _worker(pkp):
        while True:
            if _IN_IDA and ida_kernwin.user_cancelled():
                break
            try:
                bi, batch = bq.get_nowait()
            except queue_module.Empty:
                break
            try:
                results = pkp.rename_batch(batch)
                rq.put(("ok", bi, batch, results))
            except Exception as exc:
                if pkp.exhausted:
                    bq.put((bi, batch))   # give batch back
                    break
                log.err("  Worker key#%d batch%d: %s" % (pkp.key_index+1, bi+1, str(exc)[:150]))
                rq.put(("err", bi, batch, {}))
        rq.put(("done", 0, [], {}))

    workers = [threading.Thread(target=_worker, args=(p,), daemon=True)
               for p in per_key_provs]
    for w in workers:
        w.start()

    alive = n_workers
    while alive > 0:
        if _IN_IDA and ida_kernwin.user_cancelled():
            log.warn("User cancelled.")
            break
        try:
            kind, bi, batch, results = rq.get(timeout=0.5)
        except queue_module.Empty:
            continue

        if kind == "done":
            alive -= 1
            continue

        elapsed = time.time() - t_start
        log.progress(bi, total_b, processed, len(sorted_ai),
                     stats["renamed"], stats["skipped"],
                     stats["failed"], rotator.index+1, n_workers, elapsed)

        if kind == "err":
            stats["failed"] += len(batch)
            if cfg.get("retry_failed", True):
                failed_items.extend(batch)
            processed += len(batch)
            continue

        if is_debugger_active():
            log.warn("  Debugger detected mid-run! Stopping writes.")
            break

        for item in batch:
            raw = results.get(item["name"], {})
            if not raw:
                if cfg.get("retry_failed", True):
                    failed_items.append(item)
                else:
                    stats["skipped"] += 1
                continue
            # Store in cache
            cache_put(cfg, item["_cache_key"], raw, item["name"], item.get("code_type",""))
            decide_and_apply(item["ea"], item["name"], raw, cfg, batch_history, stats)

        processed += len(batch)
        if _IN_IDA:
            ida_kernwin.replace_wait_box(
                "Batch %d/%d | %d%%\n%d/%d  OK:%d Q:%d Fail:%d\nWorkers:%d" % (
                    bi+1, total_b,
                    int(processed*100/len(sorted_ai)) if sorted_ai else 0,
                    processed, len(sorted_ai),
                    stats["renamed"], stats.get("queued",0), stats["failed"],
                    alive))

    for w in workers:
        w.join(timeout=5)

    # ── Retry failed ──────────────────────────────────────────────────────
    retry_ok = 0
    if cfg.get("retry_failed", True) and failed_items and not (
            _IN_IDA and ida_kernwin.user_cancelled()):
        if not is_debugger_active():
            log.sep()
            log.info("RETRY: %d functions …" % len(failed_items))
            if _IN_IDA:
                ida_kernwin.replace_wait_box("Retrying %d functions …" % len(failed_items))
            for i, item in enumerate(failed_items):
                if _IN_IDA and ida_kernwin.user_cancelled():
                    break
                if is_debugger_active():
                    break
                current = idc.get_func_name(item["ea"]) or item["name"]
                if not is_default_name(current):
                    continue

                res_box = [None]; err_box = [None]
                ctx_extra = ""
                if item.get("strings"):
                    ctx_extra += "// Strings: %s\n" % "; ".join(item["strings"][:5])
                if item.get("apis"):
                    ctx_extra += "// APIs: %s\n" % ", ".join(item["apis"][:8])

                def _single(it=item, ce=ctx_extra):
                    try:
                        res_box[0] = main_prov.rename_single(
                            it["code"], it["name"],
                            it.get("callees"), it.get("callers"), ce)
                    except Exception as e:
                        err_box[0] = str(e)

                t = threading.Thread(target=_single, daemon=True)
                t.start()
                t.join(timeout=cfg.get("timeout_sec", 60))
                if _IN_IDA:
                    ida_kernwin.replace_wait_box("Retry %d/%d: %s" % (
                        i+1, len(failed_items), item["name"]))

                if err_box[0] or not res_box[0]:
                    stats["retry_fail"] = stats.get("retry_fail", 0) + 1
                    continue
                cache_put(cfg, item["_cache_key"], res_box[0], item["name"], item.get("code_type",""))
                prev = stats.get("renamed", 0)
                decide_and_apply(item["ea"], item["name"], res_box[0],
                                 cfg, batch_history, stats)
                if stats.get("renamed", 0) > prev:
                    retry_ok += 1

    if _IN_IDA:
        ida_kernwin.hide_wait_box()

    if batch_history:
        record_rename_batch(batch_history, cfg.get("provider","?"), cfg.get("model","?"))

    if _IN_IDA:
        idaapi.refresh_idaview_anyway()

    elapsed = time.time() - t_start
    log.sep()
    log.info("DONE (%.1fs)" % elapsed)
    log.info("  Renamed  : %d" % stats["renamed"])
    log.info("  Queued   : %d" % stats.get("queued", 0))
    log.info("  Skipped  : %d" % stats["skipped"])
    log.info("  Failed   : %d" % (stats["failed"] + stats.get("retry_fail", 0)))
    log.sep()

    q_count  = stats.get("queued", 0)
    n_renamed = stats["renamed"] + retry_ok
    if _IN_IDA:
        msg = "Renamed %d functions!" % n_renamed
        if q_count:
            msg += "\n%d suggestions waiting in Review Queue (Ctrl+Shift+Q)." % q_count
        msg += "\n\nExport forensic report?"
        if idaapi.ask_yn(idaapi.ASKBTN_YES, msg) == idaapi.ASKBTN_YES:
            from report import export_report
            export_report(cfg)

    return 1
