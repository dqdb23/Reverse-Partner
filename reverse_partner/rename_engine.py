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
    get_referenced_strings, get_referenced_apis, get_interesting_constants,
    build_call_graph, topological_sort,
)
from ida_write import safe_apply_name, safe_set_func_cmt, build_ai_comment
from static_analysis import classify_function_static, build_function_context
from cache import compute_cache_key, cache_get, cache_put
from review_queue import add_to_review_queue, load_review_queue
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
    for meta_key in (
            "depends_on_pending_suggestions", "confidence_adjustment",
            "dependency_level", "child_support_confidence"):
        if isinstance(ai_result, dict) and meta_key in ai_result:
            norm[meta_key] = ai_result.get(meta_key)

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
# Strict bottom-up Rename All helpers
# ---------------------------------------------------------------------------

_ALLOWED_RENAME_ORDERS = frozenset(("best_effort_bottom_up", "strict_bottom_up", "proposal_aware_bottom_up"))
_LAST_BOTTOM_UP_PLAN = {"levels": [], "cycle_groups": [], "candidates": {}}
_ALLOWED_REQUEST_BUDGET_MODES = frozenset(("fast_low_requests", "free_key_balanced", "quality_strict"))


class _StrictRenameComplete(Exception):
    pass


def _candidate_ea(candidate):
    if isinstance(candidate, dict):
        return candidate.get("ea")
    return candidate


def _explicit_candidate_callees(candidate):
    if not isinstance(candidate, dict):
        return None
    for key in ("callee_eas", "callees_ea", "calls", "callees"):
        value = candidate.get(key)
        if value is None:
            continue
        callees = []
        for item in value:
            if isinstance(item, int):
                callees.append(item)
            elif isinstance(item, dict) and isinstance(item.get("ea"), int):
                callees.append(item["ea"])
        return callees
    return None


def build_candidate_call_graph(candidates):
    """
    Build a candidate-only call graph using caller -> callee edges.

    Imported/external callees and functions outside the candidate set are ignored.
    Tests may provide explicit integer callee lists; IDA runs fall back to the
    existing read-only IDA call-graph helper.
    """
    eas = []
    by_ea = {}
    for candidate in candidates or []:
        ea = _candidate_ea(candidate)
        if isinstance(ea, int):
            eas.append(ea)
            by_ea[ea] = candidate
    candidate_set = set(eas)
    graph = {ea: set() for ea in eas}

    have_explicit_edges = False
    for ea in eas:
        explicit = _explicit_candidate_callees(by_ea[ea])
        if explicit is None:
            continue
        have_explicit_edges = True
        graph[ea] = set(c for c in explicit if c in candidate_set and c != ea)

    if have_explicit_edges:
        return graph

    try:
        return {ea: set(callees or set()) & candidate_set
                for ea, callees in build_call_graph(eas).items()}
    except Exception:
        return graph


def _strongly_connected_components(graph):
    index = [0]
    stack = []
    on_stack = set()
    indices = {}
    lowlinks = {}
    components = []
    nodes = list(graph.keys())

    def strongconnect(node):
        indices[node] = index[0]
        lowlinks[node] = index[0]
        index[0] += 1
        stack.append(node)
        on_stack.add(node)

        for callee in graph.get(node, set()):
            if callee not in graph:
                continue
            if callee not in indices:
                strongconnect(callee)
                lowlinks[node] = min(lowlinks[node], lowlinks[callee])
            elif callee in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[callee])

        if lowlinks[node] == indices[node]:
            comp = []
            while True:
                item = stack.pop()
                on_stack.remove(item)
                comp.append(item)
                if item == node:
                    break
            components.append(sorted(comp))

    for node in nodes:
        if node not in indices:
            strongconnect(node)
    return components


def split_cycles_from_acyclic_graph(graph):
    """
    Return (acyclic_graph, cycle_groups). Cyclic SCCs and self-recursive nodes
    are removed from the acyclic graph so they can be processed last.
    """
    normalized = {ea: set(callees or set()) for ea, callees in (graph or {}).items()}
    components = _strongly_connected_components(normalized)
    cycle_groups = []
    cycle_nodes = set()
    for comp in components:
        if len(comp) > 1 or (len(comp) == 1 and comp[0] in normalized.get(comp[0], set())):
            cycle_groups.append(comp)
            cycle_nodes.update(comp)

    acyclic = {}
    for ea, callees in normalized.items():
        if ea in cycle_nodes:
            continue
        acyclic[ea] = set(c for c in callees if c not in cycle_nodes)
    return acyclic, cycle_groups


def compute_bottom_up_levels(candidates, graph):
    """
    Compute strict callee-before-caller levels.

    Level 0 contains candidate leaves. A caller appears only after every
    candidate callee has appeared in a lower completed level. Cycle groups are
    returned separately for best-effort last processing.
    """
    candidate_eas = [_candidate_ea(c) for c in (candidates or []) if isinstance(_candidate_ea(c), int)]
    graph = {ea: set((graph or {}).get(ea, set())) & set(candidate_eas) for ea in candidate_eas}
    acyclic, cycle_groups = split_cycles_from_acyclic_graph(graph)
    remaining = set(acyclic.keys())
    completed = set()
    levels = []

    while remaining:
        level = sorted(ea for ea in remaining if not (acyclic.get(ea, set()) - completed))
        if not level:
            # Defensive fallback: any unexpected cycle goes last instead of hanging.
            cycle_groups.append(sorted(remaining))
            break
        levels.append(level)
        completed.update(level)
        remaining.difference_update(level)

    plan = {"levels": levels, "cycle_groups": cycle_groups, "graph": acyclic}
    global _LAST_BOTTOM_UP_PLAN
    _LAST_BOTTOM_UP_PLAN = {"levels": levels, "cycle_groups": cycle_groups,
                            "candidates": {ea: ea for ea in candidate_eas}}
    return plan


def get_level_candidates(level_index, levels=None, candidates=None):
    """Return candidate objects for a computed level index."""
    levels = _LAST_BOTTOM_UP_PLAN.get("levels", []) if levels is None else levels
    if level_index < 0 or level_index >= len(levels):
        return []
    level = levels[level_index]
    if candidates is None:
        return list(level)
    by_ea = {_candidate_ea(c): c for c in candidates or []}
    return [by_ea[ea] for ea in level if ea in by_ea]


def _strict_batch_items(items, batch_size):
    size = max(1, int(batch_size or 1))
    for i in range(0, len(items), size):
        yield items[i:i + size]


def refresh_candidate_context(ea, cfg, virtual_names=None, graph=None, proposal_mode=False, dependency_level=0):
    """
    Rebuild a Rename All prompt item from current IDB state.

    This intentionally refreshes names and xrefs immediately before an AI
    request, so parent context sees child names applied by lower levels.
    """
    use_pseudo = cfg.get("use_pseudocode", True)
    name = idc.get_func_name(ea) or ("sub_%X" % ea)
    code, code_type = get_code(ea, use_pseudo)
    if not code:
        return None
    callees = get_callee_names(ea)
    callers = get_caller_names(ea)
    strings = get_referenced_strings(ea, 8)
    decoded_strings = []
    try:
        if cfg.get("enable_floss", False):
            from floss_integration import get_floss_strings_for_function
            decoded_strings = get_floss_strings_for_function(ea)
    except Exception:
        decoded_strings = []
    apis = get_referenced_apis(ea, 12)
    constants = get_interesting_constants(ea, 12)
    pre_tags, _, mitre = classify_function_static(ea)
    static_context = {}
    try:
        static_context = build_function_context(ea) or {}
    except Exception:
        static_context = {}

    proposal_context = ""
    pending_child_deps = []
    if proposal_mode and cfg.get("proposal_use_pending_child_names", True):
        proposal_context, pending_child_deps = build_pending_child_context(ea, virtual_names or {}, graph or {})

    cache_decoded = list(decoded_strings or [])
    if proposal_context:
        cache_decoded.append({"value": proposal_context})
    ck = compute_cache_key(ea, name, code, callers, callees, strings, apis,
                           cfg.get("model", ""), cfg.get("provider", ""),
                           cache_decoded)
    return {
        "ea": ea, "name": name, "code": code, "code_type": code_type,
        "callees": callees, "callers": callers, "strings": strings,
        "decoded_strings": decoded_strings, "apis": apis,
        "constants": constants, "pre_tags": pre_tags, "mitre_hints": mitre,
        "proposal_context": proposal_context,
        "depends_on_pending_suggestions": pending_child_deps,
        "dependency_level": dependency_level,
        "static_context": static_context, "_cache_key": ck,
        "_cached": cache_get(cfg, ck),
    }


def _estimate_strict_requests(levels, cycle_groups, strict_batch_size):
    total = 0
    for level in list(levels or []) + list(cycle_groups or []):
        total += (len(level) + max(1, int(strict_batch_size or 1)) - 1) // max(1, int(strict_batch_size or 1))
    return total


def plan_strict_bottom_up_batches(candidates, cfg, graph=None):
    """Pure planner: return strict levels/cycle groups split into per-level batches."""
    graph = build_candidate_call_graph(candidates) if graph is None else graph
    plan = compute_bottom_up_levels(candidates, graph)
    mode = cfg.get("rename_order", "strict_bottom_up")
    batch_size = get_dynamic_request_batch_size(cfg, mode)
    groups = []
    for idx, level in enumerate(plan.get("levels", [])):
        groups.append({
            "level_index": idx,
            "is_cycle": False,
            "eas": list(level),
            "batches": [list(b) for b in _strict_batch_items(list(level), batch_size)],
        })
    cycle_base = len(groups)
    for idx, group in enumerate(plan.get("cycle_groups", [])):
        groups.append({
            "level_index": cycle_base + idx,
            "is_cycle": True,
            "eas": list(group),
            "batches": [list(b) for b in _strict_batch_items(list(group), batch_size)],
        })
    return {"levels": plan.get("levels", []), "cycle_groups": plan.get("cycle_groups", []), "groups": groups}


def execute_strict_bottom_up_plan(candidates, cfg, send_batch, apply_item, refresh_func, graph=None):
    """
    Pure strict-order executor used by tests and documentation.

    Callbacks perform side effects in callers. This function guarantees that all
    batches for a lower level are sent/applied before any parent level is sent.
    """
    if cfg.get("rename_order", "best_effort_bottom_up") != "strict_bottom_up":
        return {"mode": "best_effort_bottom_up", "processed_levels": [], "paused": False}

    planned = plan_strict_bottom_up_batches(candidates, cfg, graph)
    processed = []
    for group in planned["groups"]:
        level_index = group["level_index"]
        refreshed = [refresh_func(ea, cfg) for ea in group["eas"]]
        refreshed = [item for item in refreshed if item]
        by_ea = {item.get("ea"): item for item in refreshed}
        counts = {"queued": 0, "applied": 0, "skipped": 0, "failed": 0}
        sent_batches = []
        for ea_batch in group["batches"]:
            batch = [by_ea[ea] for ea in ea_batch if ea in by_ea]
            sent_batches.append([item["ea"] for item in batch])
            results = send_batch(batch, level_index) or {}
            for item in batch:
                action = apply_item(item, results.get(item.get("name")))
                if action not in counts:
                    action = "skipped"
                counts[action] += 1
        processed.append({"level_index": level_index, "is_cycle": group["is_cycle"],
                          "batches": sent_batches, "counts": counts})
        if (cfg.get("review_mode", True)
                and cfg.get("strict_pause_for_review", True)
                and counts["queued"]):
            return {"mode": "strict_bottom_up", "processed_levels": processed,
                    "paused": True, "paused_level": level_index,
                    "planned": planned}
    return {"mode": "strict_bottom_up", "processed_levels": processed,
            "paused": False, "planned": planned}


def _ceil_div(n, d):
    d = max(1, int(d or 1))
    return (max(0, int(n or 0)) + d - 1) // d


def get_dynamic_request_batch_size(cfg, mode):
    if mode == "strict_bottom_up":
        base = int(cfg.get("strict_level_batch_size", cfg.get("target_functions_per_request", 40)) or 40)
    elif mode == "proposal_aware_bottom_up":
        base = int(cfg.get("proposal_level_batch_size", cfg.get("target_functions_per_request", 40)) or 50)
    else:
        base = int(cfg.get("target_functions_per_request", cfg.get("batch_size", 50)) or 40)
    target = int(cfg.get("target_functions_per_request", base) or base)
    max_size = int(cfg.get("max_functions_per_request", max(base, target)) or max(base, target))
    min_size = int(cfg.get("min_functions_per_request", 1) or 1)
    size = min(max(base, target, min_size), max_size)
    return max(1, size)


def _pack_level_batches(items, cfg, mode):
    manual = get_dynamic_request_batch_size(cfg, mode)
    batches = pack_batches(items, cfg.get("model", ""), manual)
    if len(batches) > _ceil_div(len(items), manual):
        log.warn("Token budget forced smaller %s batches: %d functions -> %d requests" % (
            mode, len(items), len(batches)))
    return batches


def _candidate_priority(candidate):
    score = 0
    try:
        tags = candidate.get("pre_tags", []) if isinstance(candidate, dict) else []
        score += len(tags or []) * 10
        score += len(candidate.get("apis", []) or [])
        score += len(candidate.get("strings", []) or [])
    except Exception:
        pass
    return score


def reduce_scope_for_budget(candidates, cfg, graph=None):
    limit = int(cfg.get("max_functions_per_rename_run", 250) or 250)
    if len(candidates or []) <= limit:
        return list(candidates or [])
    graph = graph or build_candidate_call_graph(candidates)
    leaves = set(ea for ea, callees in graph.items() if not callees)
    ranked = sorted(candidates or [], key=lambda c: (
        0 if _candidate_ea(c) in leaves else 1,
        -_candidate_priority(c),
        _candidate_ea(c) or 0))
    return ranked[:limit]


def estimate_rename_requests(candidates, cfg, rename_order=None, graph=None):
    rename_order = rename_order or cfg.get("rename_order", "best_effort_bottom_up")
    graph = graph or build_candidate_call_graph(candidates)
    prefer_cache = cfg.get("prefer_cache_before_budget_count", True)
    cached = 0

    def _is_uncached(item):
        return not (prefer_cache and isinstance(item, dict) and item.get("_cached"))

    uncached_candidates = [c for c in (candidates or []) if _is_uncached(c)]
    cached = len(candidates or []) - len(uncached_candidates)
    batch_plan = []

    if rename_order == "best_effort_bottom_up":
        batch_size = int(cfg.get("batch_size", cfg.get("target_functions_per_request", 40)) or 40)
        reqs = _ceil_div(len(uncached_candidates), batch_size)
        batch_plan.append({"mode": rename_order, "count": len(uncached_candidates), "batch_size": batch_size, "requests": reqs})
        levels = 0
        cycle_groups = 0
    else:
        plan = compute_bottom_up_levels(candidates, graph)
        levels = len(plan.get("levels", []))
        cycle_groups = len(plan.get("cycle_groups", []))
        by_ea = {_candidate_ea(c): c for c in uncached_candidates}
        batch_size = get_dynamic_request_batch_size(cfg, rename_order)
        reqs = 0
        groups = list(plan.get("levels", [])) + list(plan.get("cycle_groups", []))
        for i, level in enumerate(groups):
            cnt = len([ea for ea in level if ea in by_ea])
            nreq = _ceil_div(cnt, batch_size)
            reqs += nreq
            batch_plan.append({"level": i, "count": cnt, "batch_size": batch_size, "requests": nreq})

    max_req = int(cfg.get("max_ai_requests_per_run", 25) or 25)
    warn_req = int(cfg.get("warn_if_estimated_requests_above", max_req) or max_req)
    exceeded = reqs > max_req or reqs > warn_req
    rec = "within request budget"
    if exceeded:
        rec = "reduce scope, use cache, or switch to best_effort_bottom_up for fewer requests"
    return {
        "estimated_requests": reqs,
        "estimated_cached": cached,
        "estimated_uncached_functions": len(uncached_candidates),
        "levels": levels,
        "cycle_groups": cycle_groups,
        "batch_plan": batch_plan,
        "budget_exceeded": exceeded,
        "recommendation": rec,
    }


def build_pending_child_context(ea, virtual_names, graph):
    lines = []
    deps = []
    for child_ea in sorted((graph or {}).get(ea, set())):
        info = (virtual_names or {}).get(child_ea)
        if not info or not info.get("suggested_name"):
            continue
        if info.get("status") == "applied" and info.get("suggested_name") == info.get("idb_name"):
            continue
        dep = {
            "ea": "0x%X" % child_ea,
            "idb_name": info.get("idb_name", ""),
            "suggested_name": info.get("suggested_name", ""),
            "confidence": float(info.get("confidence", 0.0) or 0.0),
            "status": info.get("status", "pending_review"),
            "evidence": list(info.get("evidence", []) or [])[:5],
            "level": info.get("level", 0),
        }
        deps.append(dep)
        lines.append("- EA %s" % dep["ea"])
        lines.append("  IDB name: %s" % dep["idb_name"])
        lines.append("  Pending suggested name: %s" % dep["suggested_name"])
        lines.append("  confidence: %.2f" % dep["confidence"])
        lines.append("  status: %s" % dep["status"])
        if dep["evidence"]:
            lines.append("  evidence:")
            for ev in dep["evidence"][:3]:
                lines.append("    - %s" % ev)
    if lines:
        return "Callee context (tentative suggestions, not ground truth):\n" + "\n".join(lines), deps
    return "", []


def apply_proposal_confidence_metadata(ai_result, pending_deps, cfg, dependency_level=0):
    result = dict(ai_result or {})
    deps = list(pending_deps or [])
    result["dependency_level"] = dependency_level
    if not deps or not cfg.get("proposal_propagate_child_confidence", True):
        return result
    child_conf = min(float(d.get("confidence", 0.0) or 0.0) for d in deps)
    original = float(result.get("confidence", result.get("score", 0.5)) or 0.5)
    original = max(0.0, min(1.0, original))
    final = min(original, 0.60 + 0.40 * child_conf)
    result["confidence"] = round(final, 3)
    result["depends_on_pending_suggestions"] = deps
    result["child_support_confidence"] = round(child_conf, 3)
    result["confidence_adjustment"] = {
        "original": round(original, 3),
        "final": round(final, 3),
        "reason": "Parent result depends on pending child suggestions",
    }
    return result


def update_virtual_name_map(virtual_names, item, ai_result, level, status):
    if not item or not isinstance(ai_result, dict):
        return virtual_names
    name = ai_result.get("name") or ai_result.get("function_name") or ai_result.get("suggested_name")
    if not name:
        return virtual_names
    virtual_names[item["ea"]] = {
        "idb_name": item.get("name", ""),
        "suggested_name": name,
        "confidence": float(ai_result.get("confidence", 0.0) or 0.0),
        "status": status,
        "evidence": list(ai_result.get("evidence", []) or [])[:8],
        "level": level,
    }
    return virtual_names


def build_virtual_name_map_from_review_queue(candidates, queue_items=None):
    virtual = {}
    by_ea = {_candidate_ea(c): c for c in candidates or []}
    try:
        queue_items = load_review_queue() if queue_items is None else queue_items
    except Exception:
        queue_items = []
    for ea, item in by_ea.items():
        if isinstance(item, dict):
            virtual[ea] = {"idb_name": item.get("name", ""), "suggested_name": item.get("name", ""),
                           "confidence": 1.0, "status": "applied", "evidence": [], "level": -1}
    for q in queue_items or []:
        if q.get("kind", "function_rename") != "function_rename" or q.get("status") != "pending":
            continue
        try:
            ea = int(str(q.get("ea", "0")), 16)
        except Exception:
            continue
        if ea in by_ea:
            virtual[ea] = {"idb_name": q.get("old_name", ""), "suggested_name": q.get("suggested_name", ""),
                           "confidence": float(q.get("confidence", 0.0) or 0.0),
                           "status": "pending_review", "evidence": q.get("evidence", []) or [],
                           "level": int(q.get("dependency_level", 0) or 0)}
    return virtual


def budget_exceeded_plan(estimate, cfg):
    max_req = int(cfg.get("max_ai_requests_per_run", 25) or 25)
    exceeded = bool((estimate or {}).get("estimated_requests", 0) > max_req)
    return {
        "budget_exceeded": exceeded,
        "message": "Estimated AI requests: %d, configured max: %d. This may consume many free-tier requests." % (
            (estimate or {}).get("estimated_requests", 0), max_req),
        "options": ["continue_anyway", "reduce_scope", "switch_to_best_effort_bottom_up", "cancel"],
    }


def plan_retry_batches(missing_items, cfg):
    max_reqs = int(cfg.get("max_retry_requests_per_run", 5) or 5)
    shrink = max(1, int(cfg.get("retry_batch_shrink_factor", 2) or 2))
    base = max(1, get_dynamic_request_batch_size(cfg, cfg.get("rename_order", "best_effort_bottom_up")) // shrink)
    batches = []
    for batch in _strict_batch_items(list(missing_items or []), base):
        if len(batches) >= max_reqs:
            break
        batches.append(batch)
    return batches


def _confirm_strict_bottom_up(candidates, plan, cfg):
    if not _IN_IDA:
        return True
    level_count = len(plan.get("levels", []))
    cycle_count = len(plan.get("cycle_groups", []))
    strict_batch_size = get_dynamic_request_batch_size(cfg, "strict_bottom_up")
    est = _estimate_strict_requests(plan.get("levels", []), plan.get("cycle_groups", []), strict_batch_size)
    ans = idaapi.ask_yn(idaapi.ASKBTN_NO,
        "reverse_partner — Strict Bottom-Up Rename All\n\n"
        "Candidates: %d\n"
        "Dependency levels: %d\n"
        "Cycle groups: %d\n"
        "Review mode: %s\n"
        "Pause for review: %s\n"
        "Estimated AI requests: %d\n\n"
        "Strict mode may require multiple review/apply passes when review_mode is enabled.\n\n"
        "Continue?" % (
            len(candidates), level_count, cycle_count,
            "ON" if cfg.get("review_mode", True) else "OFF",
            "ON" if cfg.get("strict_pause_for_review", True) else "OFF",
            est))
    return ans == idaapi.ASKBTN_YES


def _show_strict_review_pause(level_index, queued):
    msg = (
        "Strict bottom-up is paused. Review/apply level %d suggestions before continuing.\n\n"
        "Level %d suggestions were queued. Apply/reject them in Review Queue, then rerun "
        "Rename All to continue with updated child names."
    ) % (level_index, level_index)
    log.warn(msg.replace("\n", " "))
    if _IN_IDA:
        try:
            idaapi.info(msg + "\n\nQueued suggestions: %d" % queued)
            from review_queue import show_review_queue_ui
            show_review_queue_ui()
        except Exception:
            pass


def _run_strict_bottom_up_rename(candidates, cfg, batch_history, stats, t_start):
    """Sequential strict-level Rename All path. Default mode does not call this."""
    from providers import make_parallel_providers

    graph = build_candidate_call_graph(candidates)
    plan = compute_bottom_up_levels(candidates, graph)
    if not _confirm_strict_bottom_up(candidates, plan, cfg):
        return 1

    main_prov, _per_key_provs, _rotator = make_parallel_providers(cfg)
    strict_batch_size = get_dynamic_request_batch_size(cfg, "strict_bottom_up")
    failed_items = []
    processed = 0
    total = len(candidates)

    groups = [(idx, False, level) for idx, level in enumerate(plan.get("levels", []))]
    cycle_base = len(groups)
    if cfg.get("strict_process_cycles_last", True):
        for idx, group in enumerate(plan.get("cycle_groups", [])):
            groups.append((cycle_base + idx, True, group))
    else:
        for idx, group in enumerate(plan.get("cycle_groups", [])):
            groups.insert(0, (-(idx + 1), True, group))

    for level_index, is_cycle, level_eas in groups:
        if _IN_IDA and ida_kernwin.user_cancelled():
            log.warn("User cancelled strict bottom-up rename.")
            break
        if is_debugger_active():
            log.warn("  Debugger detected mid-run! Stopping writes.")
            break

        if is_cycle:
            log.warn("Cycle group detected: strict child-before-parent ordering is not possible for these functions.")
        log.sep()
        log.info("Strict bottom-up level %d%s: %d functions" % (
            level_index, " (cycle group)" if is_cycle else "", len(level_eas)))

        if _IN_IDA:
            ida_kernwin.replace_wait_box(
                "reverse_partner: Strict bottom-up level %d\nRefreshing context ..." % level_index)

        refreshed = []
        for ea in level_eas:
            item = refresh_candidate_context(ea, cfg)
            if not item:
                stats["failed"] = stats.get("failed", 0) + 1
                continue
            refreshed.append(item)
        log.info("  Refreshed context after level %d preparation: %d/%d" % (
            level_index, len(refreshed), len(level_eas)))

        queued_before = stats.get("queued", 0)
        renamed_before = stats.get("renamed", 0)
        skipped_before = stats.get("skipped", 0)
        failed_before = stats.get("failed", 0)

        need_ai = []
        for item in refreshed:
            if item.get("_cached"):
                log.info("  [CACHE HIT] %s" % item["name"])
                decide_and_apply(item["ea"], item["name"], item["_cached"], cfg, batch_history, stats)
            else:
                log.info("  [CACHE MISS] %s" % item["name"])
                need_ai.append(item)

        for batch_no, batch in enumerate(_strict_batch_items(need_ai, strict_batch_size), start=1):
            if _IN_IDA and ida_kernwin.user_cancelled():
                break
            if is_debugger_active():
                log.warn("  Debugger detected mid-run! Stopping writes.")
                break
            if _IN_IDA:
                ida_kernwin.replace_wait_box(
                    "reverse_partner: Strict level %d request %d\n%d/%d processed" % (
                        level_index, batch_no, processed, total))
            try:
                results = main_prov.rename_batch(batch, cfg)
            except Exception as exc:
                log.err("  Strict level %d batch %d error: %s" % (
                    level_index, batch_no, str(exc)[:180]))
                stats["failed"] = stats.get("failed", 0) + len(batch)
                if cfg.get("retry_failed", True):
                    failed_items.extend(batch)
                continue

            for item in batch:
                raw = results.get(item["name"], {})
                if not raw:
                    stats["failed"] = stats.get("failed", 0) + 1
                    if cfg.get("retry_failed", True):
                        failed_items.append(item)
                    continue
                cache_put(cfg, item["_cache_key"], raw, item["name"], item.get("code_type", ""))
                decide_and_apply(item["ea"], item["name"], raw, cfg, batch_history, stats)

        processed += len(refreshed)
        level_queued = stats.get("queued", 0) - queued_before
        level_applied = stats.get("renamed", 0) - renamed_before
        level_skipped = stats.get("skipped", 0) - skipped_before
        level_failed = stats.get("failed", 0) - failed_before
        log.info("  Level %d summary: queued=%d applied=%d skipped=%d failed=%d" % (
            level_index, level_queued, level_applied, level_skipped, level_failed))

        if _IN_IDA:
            idaapi.refresh_idaview_anyway()

        if cfg.get("review_mode", True):
            if cfg.get("strict_pause_for_review", True) and level_queued:
                log.warn("  Parent levels blocked until Review Queue suggestions are applied/rejected.")
                _show_strict_review_pause(level_index, level_queued)
                break
            if level_queued:
                log.warn("Continuing with queued child suggestions; parent context may not include child applied names.")

        if cfg.get("strict_refresh_context_after_level", True):
            log.info("  Refreshed context after level %d will be used by subsequent parent levels." % level_index)

    if failed_items:
        log.warn("Strict bottom-up: %d failed items were not retried across levels to preserve ordering." % len(failed_items))
    return 1

def _run_proposal_aware_rename(candidates, cfg, batch_history, stats, t_start):
    """Proposal-aware bottom-up path: child suggestions become tentative parent context."""
    from providers import make_parallel_providers

    graph = build_candidate_call_graph(candidates)
    plan = compute_bottom_up_levels(candidates, graph)
    estimate = estimate_rename_requests(candidates, cfg, "proposal_aware_bottom_up", graph)
    if _IN_IDA:
        ans = idaapi.ask_yn(idaapi.ASKBTN_NO,
            "reverse_partner — Proposal-Aware Bottom-Up Rename All\n\n"
            "Candidates: %d\nUncached: %d\nCache hits: %d\nDependency levels: %d\nCycle groups: %d\n"
            "Estimated AI requests: %d / max %d\nProvider/model: %s / %s\n\n"
            "Pending child suggestions will be included as tentative parent context. Continue?" % (
                len(candidates), estimate["estimated_uncached_functions"], estimate["estimated_cached"],
                estimate["levels"], estimate["cycle_groups"], estimate["estimated_requests"],
                int(cfg.get("max_ai_requests_per_run", 25) or 25), cfg.get("provider", "?"), cfg.get("model", "?")))
        if ans != idaapi.ASKBTN_YES:
            return 1
        if estimate.get("budget_exceeded"):
            warn = ("Estimated AI requests: %d, configured max: %d.\n"
                    "This may consume many free-tier requests.\n\n"
                    "Yes = continue anyway\nNo = reduce scope to %d functions\nCancel = cancel" % (
                        estimate["estimated_requests"], int(cfg.get("max_ai_requests_per_run", 25) or 25),
                        int(cfg.get("max_functions_per_rename_run", 250) or 250)))
            ans2 = idaapi.ask_yn(idaapi.ASKBTN_NO, warn)
            if ans2 == idaapi.ASKBTN_CANCEL:
                return 1
            if ans2 == idaapi.ASKBTN_NO and cfg.get("allow_user_to_reduce_scope_on_budget_exceed", True):
                candidates = reduce_scope_for_budget(candidates, cfg, graph)
                graph = build_candidate_call_graph(candidates)
                plan = compute_bottom_up_levels(candidates, graph)
                log.warn("Reduced proposal-aware scope to %d functions for request budget." % len(candidates))

    main_prov, _per_key_provs, rotator = make_parallel_providers(cfg)
    virtual_names = build_virtual_name_map_from_review_queue(candidates)
    request_count = 0
    retry_request_count = 0
    cache_hit_count = 0
    processed = 0
    total = len(candidates)
    groups = [(idx, False, level) for idx, level in enumerate(plan.get("levels", []))]
    cycle_base = len(groups)
    for idx, group in enumerate(plan.get("cycle_groups", [])):
        groups.append((cycle_base + idx, True, group))

    for level_index, is_cycle, level_eas in groups:
        if _IN_IDA and ida_kernwin.user_cancelled():
            log.warn("User cancelled proposal-aware rename.")
            break
        if is_debugger_active():
            log.warn("  Debugger detected mid-run! Stopping writes.")
            break
        if is_cycle:
            log.warn("Cycle group detected: strict child-before-parent ordering is not possible for these functions.")
        log.sep()
        log.info("Proposal-aware level %d%s: %d functions" % (
            level_index, " (cycle group)" if is_cycle else "", len(level_eas)))

        refreshed = []
        for ea in level_eas:
            item = refresh_candidate_context(ea, cfg, virtual_names, graph, True, level_index)
            if not item:
                stats["failed"] = stats.get("failed", 0) + 1
                continue
            refreshed.append(item)

        need_ai = []
        for item in refreshed:
            if item.get("_cached"):
                cache_hit_count += 1
                log.info("  [CACHE HIT] %s" % item["name"])
                cached = apply_proposal_confidence_metadata(
                    item["_cached"], item.get("depends_on_pending_suggestions", []), cfg, level_index)
                before_renamed = stats.get("renamed", 0)
                before_queued = stats.get("queued", 0)
                decide_and_apply(item["ea"], item["name"], cached, cfg, batch_history, stats)
                status = "applied" if stats.get("renamed", 0) > before_renamed else "pending_review"
                if stats.get("queued", 0) == before_queued and status != "applied":
                    status = "skipped"
                update_virtual_name_map(virtual_names, item, cached, level_index, status)
            else:
                need_ai.append(item)
        batches = _pack_level_batches(need_ai, cfg, "proposal_aware_bottom_up")
        log.info("  Level %d: total=%d cache_hits=%d ai_functions=%d requests=%d" % (
            level_index, len(refreshed), len(refreshed) - len(need_ai), len(need_ai), len(batches)))

        for batch_no, batch in enumerate(batches, start=1):
            if _IN_IDA and ida_kernwin.user_cancelled():
                break
            if is_debugger_active():
                log.warn("  Debugger detected mid-run! Stopping writes.")
                break
            request_count += 1
            log.info("  Request %d (key index %s, retry=%d, cache_hits=%d, remaining_budget=%s)" % (
                request_count, getattr(rotator, "index", 0) + 1, retry_request_count, cache_hit_count,
                max(0, int(cfg.get("max_ai_requests_per_run", 25) or 25) - request_count)))
            try:
                results = main_prov.rename_batch(batch, cfg)
            except Exception as exc:
                log.err("  Proposal level %d batch %d error: %s" % (level_index, batch_no, str(exc)[:180]))
                results = {}

            missing = []
            for item in batch:
                raw = results.get(item["name"], {}) if isinstance(results, dict) else {}
                if not raw:
                    missing.append(item)
                    continue
                raw = apply_proposal_confidence_metadata(raw, item.get("depends_on_pending_suggestions", []), cfg, level_index)
                cache_put(cfg, item["_cache_key"], raw, item["name"], item.get("code_type", ""))
                before_renamed = stats.get("renamed", 0)
                before_queued = stats.get("queued", 0)
                decide_and_apply(item["ea"], item["name"], raw, cfg, batch_history, stats)
                status = "applied" if stats.get("renamed", 0) > before_renamed else "pending_review"
                if stats.get("queued", 0) == before_queued and status != "applied":
                    status = "skipped"
                update_virtual_name_map(virtual_names, item, raw, level_index, status)

            for retry_batch in plan_retry_batches(missing, cfg):
                if retry_request_count >= int(cfg.get("max_retry_requests_per_run", 5) or 5):
                    break
                retry_request_count += 1
                request_count += 1
                try:
                    retry_results = main_prov.rename_batch(retry_batch, cfg)
                except Exception as exc:
                    log.err("  Proposal retry error: %s" % str(exc)[:180])
                    retry_results = {}
                for item in retry_batch:
                    raw = retry_results.get(item["name"], {}) if isinstance(retry_results, dict) else {}
                    if not raw:
                        stats["failed"] = stats.get("failed", 0) + 1
                        continue
                    raw = apply_proposal_confidence_metadata(raw, item.get("depends_on_pending_suggestions", []), cfg, level_index)
                    cache_put(cfg, item["_cache_key"], raw, item["name"], item.get("code_type", ""))
                    before_renamed = stats.get("renamed", 0)
                    before_queued = stats.get("queued", 0)
                    decide_and_apply(item["ea"], item["name"], raw, cfg, batch_history, stats)
                    status = "applied" if stats.get("renamed", 0) > before_renamed else "pending_review"
                    if stats.get("queued", 0) == before_queued and status != "applied":
                        status = "skipped"
                    update_virtual_name_map(virtual_names, item, raw, level_index, status)

        processed += len(refreshed)
        if _IN_IDA:
            ida_kernwin.replace_wait_box("Proposal-aware level %d complete\n%d/%d processed" % (
                level_index, processed, total))
            idaapi.refresh_idaview_anyway()

    log.info("Proposal-aware requests: total=%d retry=%d cache_hits=%d remaining_budget=%s" % (
        request_count, retry_request_count, cache_hit_count,
        max(0, int(cfg.get("max_ai_requests_per_run", 25) or 25) - request_count)))
    return 1


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

        # Pre-apply cached results immediately. Strict mode refreshes context and
        # checks cache per dependency level instead of using this initial snapshot.
        batch_history: list = []
        stats: dict         = {"renamed": 0, "skipped": 0, "failed": failed_code,
                                "queued": 0, "retry_ok": 0, "retry_fail": 0}

        rename_order = cfg.get("rename_order", "best_effort_bottom_up")
        if rename_order not in _ALLOWED_RENAME_ORDERS:
            log.warn("Unknown rename_order '%s'; using best_effort_bottom_up." % rename_order)
            rename_order = "best_effort_bottom_up"
        if rename_order == "strict_bottom_up":
            log.info("Strict bottom-up Rename All enabled: processing callee levels before callers.")
            _run_strict_bottom_up_rename(candidates, cfg, batch_history, stats, t_start)
            raise _StrictRenameComplete
        if rename_order == "proposal_aware_bottom_up":
            log.info("Proposal-aware bottom-up Rename All enabled: using tentative child suggestions as parent context.")
            _run_proposal_aware_rename(candidates, cfg, batch_history, stats, t_start)
            raise _StrictRenameComplete

        estimate = estimate_rename_requests(candidates, cfg, "best_effort_bottom_up")
        log.info("Request estimate: %d AI requests | %d cached | %d uncached" % (
            estimate["estimated_requests"], estimate["estimated_cached"],
            estimate["estimated_uncached_functions"]))

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

    except _StrictRenameComplete:
        if _IN_IDA:
            ida_kernwin.hide_wait_box()
        if batch_history:
            record_rename_batch(batch_history, cfg.get("provider","?"), cfg.get("model","?"))
        if _IN_IDA:
            idaapi.refresh_idaview_anyway()
        elapsed = time.time() - t_start
        log.sep()
        log.info("DONE ordered Rename All (%.1fs)" % elapsed)
        log.info("  Renamed  : %d" % stats.get("renamed", 0))
        log.info("  Queued   : %d" % stats.get("queued", 0))
        log.info("  Skipped  : %d" % stats.get("skipped", 0))
        log.info("  Failed   : %d" % (stats.get("failed", 0) + stats.get("retry_fail", 0)))
        log.sep()
        return 1
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
