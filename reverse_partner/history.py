# -*- coding: utf-8 -*-
"""
history.py — Rename history & rollback
=========================================
Before every rename batch, old names are saved here.
Rollback restores old names using safe_apply_name().
Stored as a JSON file next to the IDB (or in user idadir as fallback).

Data format:
{
  "batches": [
    {
      "batch_id":  "batch_20250505_123456",
      "timestamp": "2025-05-05 12:34:56",
      "provider":  "gemini",
      "model":     "gemini-2.5-flash",
      "items": [
        {"ea": "0x401000", "old_name": "sub_401000",
         "new_name": "parse_config", "confidence": 0.91}
      ]
    }
  ]
}
"""

import os
import json
import time

_IN_IDA = False
try:
    import idaapi
    import idc
    _IN_IDA = True
except ImportError:
    pass

from guards import require_static_mode, is_debugger_active
from utils import is_default_name
from logger import log


def _history_path() -> str:
    if _IN_IDA:
        idb = idc.get_input_file_path() or ""
        base = os.path.splitext(idb)[0] if idb else ""
        if base:
            return base + "_gpt_rename_history.json"
        return os.path.join(idaapi.get_user_idadir(), "gpt_rename_history.json")
    return os.path.expanduser("~/.gpt_rename_history.json")


def load_rename_history() -> dict:
    try:
        p = _history_path()
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {"batches": []}


def save_rename_history(history: dict):
    try:
        p = _history_path()
        with open(p, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        log.err("Cannot save rename history: %s" % exc)


def record_rename_batch(items: list, provider: str, model: str) -> str:
    """
    items: list of rollback records. Function rename records use
    {ea: int, old_name: str, new_name: str, confidence: float}. Newer records
    may include kind=variable_rename or prototype_change.
    Returns batch_id string.
    """
    history  = load_rename_history()
    batch_id = "batch_%s" % time.strftime("%Y%m%d_%H%M%S")
    entry    = {
        "batch_id":  batch_id,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "provider":  provider,
        "model":     model,
        "items": [],
    }
    for it in items:
        rec = {
            "kind":       it.get("kind", "function_rename"),
            "ea":         hex(it["ea"]),
            "confidence": round(float(it.get("confidence", 0.0)), 3),
        }
        for key in (
            "old_name", "new_name", "old_var", "new_var",
            "old_prototype", "new_prototype",
        ):
            if key in it:
                rec[key] = it.get(key, "")
        entry["items"].append(rec)
    history["batches"].append(entry)
    history["batches"] = history["batches"][-50:]   # keep last 50 batches
    save_rename_history(history)
    return batch_id


def rollback_last_batch() -> tuple:
    """
    Roll back the most recent rename batch.
    Returns (n_ok, n_skipped, n_manual_skipped).
    """
    if not require_static_mode("Rollback Last Batch"):
        return 0, 0, 0

    history = load_rename_history()
    batches = history.get("batches", [])
    if not batches:
        if _IN_IDA:
            idaapi.warning("No rename batch found to roll back.")
        return 0, 0, 0

    batch = batches[-1]
    items = batch.get("items", [])
    if not items:
        if _IN_IDA:
            idaapi.warning("Last batch is empty.")
        return 0, 0, 0

    if _IN_IDA:
        msg = (
            "Rollback batch: %s\n"
            "Provider : %s | Model: %s\n"
            "Timestamp: %s\n"
            "%d item(s) will be restored.\n\n"
            "Continue?" % (
                batch["batch_id"], batch.get("provider", "?"),
                batch.get("model", "?"), batch.get("timestamp", "?"),
                len(items)
            )
        )
        if idaapi.ask_yn(idaapi.ASKBTN_NO, msg) != idaapi.ASKBTN_YES:
            return 0, 0, 0

    n_ok = n_skip = n_manual = 0
    from ida_write import safe_apply_name, safe_rename_lvar, safe_apply_func_type

    for it in items:
        try:
            ea = int(it["ea"], 16)
        except (ValueError, KeyError):
            n_skip += 1
            continue

        kind = it.get("kind", "function_rename")

        if kind == "variable_rename":
            old_var = it.get("old_var", "")
            new_var = it.get("new_var", "")
            if old_var and new_var and safe_rename_lvar(ea, new_var, old_var):
                log.ok("Rollback lvar: %s -> %s" % (new_var, old_var))
                n_ok += 1
            else:
                n_skip += 1
            continue

        if kind == "prototype_change":
            old_proto = it.get("old_prototype", "")
            if old_proto and safe_apply_func_type(ea, old_proto):
                log.ok("Rollback prototype at %s" % hex(ea))
                n_ok += 1
            else:
                n_skip += 1
            continue

        old_name = it.get("old_name", "")
        new_name = it.get("new_name", "")
        if not old_name:
            n_skip += 1
            continue

        # Check for manual renames since our batch
        current = (idc.get_func_name(ea) if _IN_IDA else "") or ""
        if current and current != new_name and not is_default_name(current):
            if _IN_IDA:
                ans = idaapi.ask_yn(idaapi.ASKBTN_NO,
                    "Function at %s has been manually renamed to '%s'\n"
                    "(AI had set it to '%s').\n\n"
                    "Overwrite with original name '%s'?" % (
                        hex(ea), current, new_name, old_name))
                if ans != idaapi.ASKBTN_YES:
                    n_manual += 1
                    continue
            else:
                n_manual += 1
                continue

        applied = safe_apply_name(ea, old_name)
        if applied:
            log.ok("Rollback: %s → %s" % (new_name, old_name))
            n_ok += 1
        else:
            n_skip += 1

    # Remove rolled-back batch
    history["batches"] = batches[:-1]
    save_rename_history(history)

    if _IN_IDA:
        idaapi.refresh_idaview_anyway()

    log.sep()
    log.info("ROLLBACK DONE: ok=%d  skip=%d  manual_skip=%d" % (n_ok, n_skip, n_manual))
    log.sep()
    return n_ok, n_skip, n_manual
