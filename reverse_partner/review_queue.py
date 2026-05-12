# -*- coding: utf-8 -*-
"""
review_queue.py — AI suggestion review queue
=============================================
AI suggestions are stored here before being applied.
Users can review, approve, reject, or bulk-apply high-confidence items.

Storage: JSON file next to the IDB (or user idadir as fallback).
One entry per function (deduplicates by ea + pending status).
"""

import os
import json
import time

_IN_IDA = False
try:
    import idaapi
    import idc
    import ida_kernwin
    _IN_IDA = True
except ImportError:
    idaapi = None
    idc = None
    ida_kernwin = None
    _IN_IDA = False

from guards import require_static_mode, is_debugger_active
from logger import log


def _clip(value, limit=120):
    text = str(value or "")
    return text if len(text) <= limit else text[:limit - 3] + "..."


def _as_list(value):
    if isinstance(value, list):
        return value
    if isinstance(value, str) and value:
        return [value]
    return []


def _queue_path() -> str:
    if _IN_IDA:
        idb  = idc.get_input_file_path() or ""
        base = os.path.splitext(idb)[0] if idb else ""
        if base:
            return base + "_gpt_review_queue.json"
        return os.path.join(idaapi.get_user_idadir(), "gpt_review_queue.json")
    return os.path.expanduser("~/.gpt_review_queue.json")


def load_review_queue() -> list:
    try:
        p = _queue_path()
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
    except Exception:
        pass
    return []


def save_review_queue(queue: list):
    try:
        p = _queue_path()
        with open(p, "w", encoding="utf-8") as f:
            json.dump(queue, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        log.err("Cannot save review queue: %s" % exc)


def add_to_review_queue(ea: int, old_name: str, ai_result: dict,
                         model: str, provider: str):
    """
    Add one AI suggestion to the queue.
    Deduplicates: removes existing pending entry for same ea before adding.
    ai_result: normalized result from normalize_ai_result().
    """
    queue = load_review_queue()
    # remove existing pending entry for this ea
    queue = [q for q in queue
             if not (q.get("kind", "function_rename") == "function_rename"
                     and q.get("ea") == hex(ea)
                     and q.get("status") == "pending")]

    entry = {
        "kind":           "function_rename",
        "ea":             hex(ea),
        "old_name":       old_name,
        "suggested_name": ai_result.get("name", ""),
        "confidence":     ai_result.get("confidence", 0.0),
        "category":       ai_result.get("category", "UNKNOWN"),
        "tags":           ai_result.get("tags", []),
        "description":    ai_result.get("description", ""),
        "evidence":       ai_result.get("evidence", []),
        "warnings":       ai_result.get("warnings", []),
        "depends_on_pending_suggestions": ai_result.get("depends_on_pending_suggestions", []),
        "confidence_adjustment": ai_result.get("confidence_adjustment", {}),
        "dependency_level": ai_result.get("dependency_level", 0),
        "child_support_confidence": ai_result.get("child_support_confidence", None),
        "model":          model,
        "provider":       provider,
        "timestamp":      time.strftime("%Y-%m-%d %H:%M:%S"),
        "status":         "pending",   # pending | applied | rejected
    }
    queue.append(entry)
    queue = sort_review_queue_dependencies(queue)
    save_review_queue(queue)


def add_variable_rename_to_review_queue(ea: int, func_name: str,
                                        old_var: str, new_var: str,
                                        confidence: float, reason: str,
                                        model: str, provider: str):
    queue = load_review_queue()
    queue = [q for q in queue if not (
        q.get("kind") == "variable_rename"
        and q.get("ea") == hex(ea)
        and q.get("old_var") == old_var
        and q.get("status") == "pending")]
    queue.append({
        "kind":       "variable_rename",
        "ea":         hex(ea),
        "func_name":  func_name,
        "old_var":    old_var,
        "new_var":    new_var,
        "confidence": round(float(confidence), 3),
        "reason":     reason,
        "model":      model,
        "provider":   provider,
        "timestamp":  time.strftime("%Y-%m-%d %H:%M:%S"),
        "status":     "pending",
    })
    save_review_queue(queue)


def add_prototype_to_review_queue(ea: int, func_name: str, old_prototype: str,
                                  new_prototype: str, confidence: float,
                                  evidence: list, warnings: list,
                                  model: str, provider: str):
    queue = load_review_queue()
    queue = [q for q in queue if not (
        q.get("kind") == "prototype_change"
        and q.get("ea") == hex(ea)
        and q.get("status") == "pending")]
    queue.append({
        "kind":          "prototype_change",
        "ea":            hex(ea),
        "func_name":     func_name,
        "old_prototype": old_prototype or "",
        "new_prototype": new_prototype,
        "confidence":    round(float(confidence), 3),
        "evidence":      evidence or [],
        "warnings":      warnings or [],
        "model":         model,
        "provider":      provider,
        "timestamp":     time.strftime("%Y-%m-%d %H:%M:%S"),
        "status":        "pending",
    })
    save_review_queue(queue)


def sort_review_queue_dependencies(queue: list) -> list:
    """Sort pending dependency-aware suggestions before parents; pure helper."""
    def _key(item):
        deps = item.get("depends_on_pending_suggestions") or []
        dep_count = len(deps) if isinstance(deps, list) else 0
        try:
            level = int(item.get("dependency_level", 0) or 0)
        except Exception:
            level = 0
        return (1 if dep_count else 0, level, dep_count, item.get("timestamp", ""))
    return sorted(queue or [], key=_key)


def _dependency_lines(item: dict) -> list:
    deps = item.get("depends_on_pending_suggestions") or []
    lines = []
    if isinstance(deps, list):
        for dep in deps:
            if isinstance(dep, dict):
                lines.append("%s %s -> %s conf=%.2f status=%s" % (
                    dep.get("ea", "?"), dep.get("idb_name", ""),
                    dep.get("suggested_name", ""),
                    float(dep.get("confidence", 0.0) or 0.0),
                    dep.get("status", "pending_review")))
            else:
                lines.append(str(dep))
    return lines


def choose_dependency_apply_action(item: dict) -> str:
    """
    Return apply_dependencies_first | apply_only | cancel.
    In tests/non-IDA this safely defaults to cancel for dependency-bearing parents.
    """
    lines = _dependency_lines(item)
    if not lines:
        return "apply_only"
    if not _IN_IDA:
        return "cancel"
    msg = (
        "This suggestion depends on pending child rename suggestions.\n\n"
        + "\n".join(lines[:12])
        + "\n\nApply dependencies first?\n"
        "Yes = apply dependencies first\nNo = apply only this item\nCancel = cancel"
    )
    try:
        ans = idaapi.ask_yn(idaapi.ASKBTN_CANCEL, msg)
        if ans == idaapi.ASKBTN_YES:
            return "apply_dependencies_first"
        if ans == idaapi.ASKBTN_NO:
            return "apply_only"
    except Exception:
        pass
    return "cancel"


def _find_pending_dependency_items(parent_item: dict) -> list:
    deps = parent_item.get("depends_on_pending_suggestions") or []
    wanted = set()
    if isinstance(deps, list):
        for dep in deps:
            if isinstance(dep, dict):
                wanted.add((str(dep.get("ea", "")).lower(), dep.get("suggested_name", "")))
    if not wanted:
        return []
    matches = []
    for q in load_review_queue():
        key = (str(q.get("ea", "")).lower(), q.get("suggested_name", ""))
        if q.get("status") == "pending" and key in wanted:
            matches.append(q)
    return sort_review_queue_dependencies(matches)


def apply_queue_item(item: dict) -> bool:
    """
    Apply one review queue item (rename + comment).
    Returns True on success.
    """
    if not require_static_mode("Apply Queue Item"):
        return False

    from ida_write import safe_apply_name, safe_set_func_cmt, build_ai_comment
    from ida_write import safe_rename_lvar, safe_apply_func_type
    from history import record_rename_batch

    try:
        ea   = int(item["ea"], 16)
        kind = item.get("kind", "function_rename")

        if kind == "variable_rename":
            if safe_rename_lvar(ea, item.get("old_var", ""), item.get("new_var", "")):
                record_rename_batch([{
                    "kind": "variable_rename",
                    "ea": ea,
                    "old_var": item.get("old_var", ""),
                    "new_var": item.get("new_var", ""),
                    "confidence": item.get("confidence", 0.0),
                }], item.get("provider", "?"), item.get("model", "?"))
                log.ok("Variable renamed: %s -> %s" % (
                    item.get("old_var", ""), item.get("new_var", "")))
                return True
            return False

        if kind == "prototype_change":
            if safe_apply_func_type(ea, item.get("new_prototype", "")):
                record_rename_batch([{
                    "kind": "prototype_change",
                    "ea": ea,
                    "old_prototype": item.get("old_prototype", ""),
                    "new_prototype": item.get("new_prototype", ""),
                    "confidence": item.get("confidence", 0.0),
                }], item.get("provider", "?"), item.get("model", "?"))
                log.ok("Prototype applied at %s" % hex(ea))
                return True
            return False

        dep_action = choose_dependency_apply_action(item)
        if dep_action == "cancel":
            log.warn("Apply cancelled: parent suggestion depends on pending child suggestions.")
            return False
        if dep_action == "apply_dependencies_first":
            dep_items = _find_pending_dependency_items(item)
            applied_deps = 0
            for dep_item in dep_items:
                if _same_queue_item(dep_item, item):
                    continue
                if apply_queue_item(dep_item):
                    applied_deps += 1
                    _update_queue_status(dep_item, "applied")
            if applied_deps < len(dep_items) and _IN_IDA:
                try:
                    ans = idaapi.ask_yn(idaapi.ASKBTN_NO,
                        "Only %d/%d dependencies applied. Apply parent anyway?" % (
                            applied_deps, len(dep_items)))
                    if ans != idaapi.ASKBTN_YES:
                        return False
                except Exception:
                    return False

        name = item["suggested_name"]
        applied = safe_apply_name(ea, name)
        if applied:
            # Build and set comment
            comment = build_ai_comment(item)
            safe_set_func_cmt(ea, comment)
            log.renamed(item["old_name"], applied)

            # Record in history for rollback
            record_rename_batch(
                [{"ea": ea, "old_name": item["old_name"],
                  "new_name": applied,
                  "confidence": item.get("confidence", 0.0)}],
                item.get("provider", "?"),
                item.get("model", "?"),
            )
            return True
    except Exception as exc:
        log.err("apply_queue_item error: %s" % exc)
    return False


def _same_queue_item(left: dict, right: dict) -> bool:
    kind = left.get("kind", "function_rename")
    if kind != right.get("kind", "function_rename"):
        return False
    if left.get("ea") != right.get("ea"):
        return False
    if kind == "variable_rename":
        return left.get("old_var") == right.get("old_var")
    if kind == "prototype_change":
        return left.get("new_prototype") == right.get("new_prototype")
    return left.get("suggested_name") == right.get("suggested_name")


def _update_queue_status(item: dict, new_status: str):
    """Helper to set status of a specific pending queue entry."""
    queue = load_review_queue()
    for q in queue:
        if q.get("status") == "pending" and _same_queue_item(q, item):
            q["status"] = new_status
    save_review_queue(queue)


# ---------------------------------------------------------------------------
# IDA chooser UI
# ---------------------------------------------------------------------------

def show_review_queue_ui():
    """
    Show the review queue in an IDA chooser dialog.
    Allows the user to:
      - View details of each suggestion (single-click)
      - Apply individual suggestions
      - Bulk-apply all high-confidence pending items
    """
    if not _IN_IDA:
        log.warn("Review queue UI requires IDA.")
        return

    pending = sort_review_queue_dependencies([q for q in load_review_queue() if q.get("status") == "pending"])
    if not pending:
        idaapi.info("Review Queue is empty.\nNo pending AI suggestions.")
        return

    class _Chooser(ida_kernwin.Choose):
        def __init__(self, items):
            ida_kernwin.Choose.__init__(
                self,
                "reverse_partner — Review Queue (%d pending)" % len(items),
                [
                    ["EA",        8],
                    ["Old Name",  26],
                    ["Suggested", 26],
                    ["Conf",       6],
                    ["Cat",       10],
                    ["Tags",      15],
                    ["Provider",  10],
                ],
                flags=ida_kernwin.Choose.CH_MULTI,
            )
            self.items = items

        def OnGetSize(self):
            return len(self.items)

        def OnGetLine(self, n):
            it = self.items[n]
            kind = it.get("kind", "function_rename")
            if kind == "variable_rename":
                old_name = "%s:%s" % (it.get("func_name", ""), it.get("old_var", ""))
                suggested = it.get("new_var", "")
                category = "LVAR"
                tags = "variable"
            elif kind == "prototype_change":
                old_name = it.get("func_name", "")
                suggested = _clip(it.get("new_prototype", ""), 120)
                category = "PROTO"
                tags = "prototype"
            else:
                old_name = it.get("old_name", "")
                suggested = it.get("suggested_name", "")
                category = it.get("category", "?")
                tags = ", ".join(it.get("tags", []))
            return [
                it.get("ea", "?"),
                old_name,
                suggested,
                "%.2f" % it.get("confidence", 0.0),
                category,
                tags,
                it.get("provider", "?"),
            ]

        def OnSelectLine(self, n):
            idx = n[0] if isinstance(n, (list, tuple)) else n
            it  = self.items[idx]
            kind = it.get("kind", "function_rename")
            if kind == "variable_rename":
                detail = (
                    "Variable Rename\n"
                    "EA        : %s\n"
                    "Function  : %s\n"
                    "Old Var   : %s\n"
                    "New Var   : %s\n"
                    "Confidence: %.2f\n"
                    "Provider  : %s / %s\n"
                    "Timestamp : %s\n\n"
                    "Reason:\n  %s"
                ) % (
                    it.get("ea", "?"), it.get("func_name", ""),
                    it.get("old_var", ""), it.get("new_var", ""),
                    it.get("confidence", 0.0),
                    it.get("provider", "?"), it.get("model", "?"),
                    it.get("timestamp", "?"), it.get("reason", "-"))
            elif kind == "prototype_change":
                detail = (
                    "Prototype Change\n"
                    "EA        : %s\n"
                    "Function  : %s\n"
                    "Confidence: %.2f\n"
                    "Provider  : %s / %s\n"
                    "Timestamp : %s\n\n"
                    "Old prototype:\n  %s\n\n"
                    "New prototype:\n  %s\n\n"
                    "Evidence:\n  %s\n\n"
                    "Warnings:\n  %s"
                ) % (
                    it.get("ea", "?"), it.get("func_name", ""),
                    it.get("confidence", 0.0),
                    it.get("provider", "?"), it.get("model", "?"),
                    it.get("timestamp", "?"),
                    it.get("old_prototype", "-") or "-",
                    it.get("new_prototype", ""),
                    "\n  ".join(_as_list(it.get("evidence", []))[:8]) or "-",
                    "\n  ".join(_as_list(it.get("warnings", []))[:4]) or "-")
            else:
                detail = (
                    "EA        : %s\n"
                    "Old Name  : %s\n"
                    "Suggested : %s\n"
                    "Confidence: %.2f\n"
                    "Category  : %s\n"
                    "Tags      : %s\n"
                    "Provider  : %s / %s\n"
                    "Timestamp : %s\n\n"
                    "Description:\n  %s\n\n"
                    "Evidence:\n  %s\n\n"
                    "Warnings:\n  %s"
                ) % (
                    it.get("ea", "?"),
                    it.get("old_name", ""),
                    it.get("suggested_name", ""),
                    it.get("confidence", 0.0),
                    it.get("category", ""),
                    ", ".join(it.get("tags", [])),
                    it.get("provider", "?"), it.get("model", "?"),
                    it.get("timestamp", "?"),
                    it.get("description", "-"),
                    "\n  ".join(_as_list(it.get("evidence", []))[:8]) or "-",
                    "\n  ".join(_as_list(it.get("warnings", []))[:4]) or "-",
                )
            ans = idaapi.ask_yn(idaapi.ASKBTN_YES,
                detail + "\n\nApply this suggestion?")
            if ans == idaapi.ASKBTN_YES:
                if apply_queue_item(it):
                    it["status"] = "applied"
                    _update_queue_status(it, "applied")
                    idaapi.refresh_idaview_anyway()
            elif ans == idaapi.ASKBTN_NO:
                # Offer reject
                ans2 = idaapi.ask_yn(idaapi.ASKBTN_NO, "Reject this suggestion?")
                if ans2 == idaapi.ASKBTN_YES:
                    it["status"] = "rejected"
                    _update_queue_status(it, "rejected")
            return (ida_kernwin.Choose.NOTHING_CHANGED,)

    if ida_kernwin is None:
        log.warn("Review queue UI requires ida_kernwin.")
        return

    try:
        c = _Chooser(pending)
        c.Show()
    except Exception as exc:
        log.err("Chooser error: %s" % exc)
        return

    # Bulk apply offer after chooser closes
    from config import load_config
    cfg   = load_config()
    ans   = idaapi.ask_yn(idaapi.ASKBTN_NO,
        "Bulk-apply ALL pending items with confidence ≥ %.2f?" %
        cfg.get("auto_apply_confidence", 0.85))
    if ans != idaapi.ASKBTN_YES:
        return
    if not require_static_mode("Bulk Apply Queue"):
        return

    fresh     = [q for q in load_review_queue() if q.get("status") == "pending"]
    threshold = cfg.get("auto_apply_confidence", 0.85)
    n_applied = 0
    for it in fresh:
        if it.get("kind", "function_rename") != "function_rename":
            continue
        if it.get("confidence", 0.0) >= threshold:
            if apply_queue_item(it):
                it["status"] = "applied"
                _update_queue_status(it, "applied")
                n_applied += 1

    idaapi.refresh_idaview_anyway()
    idaapi.info("Bulk applied %d suggestion(s) from the review queue." % n_applied)
