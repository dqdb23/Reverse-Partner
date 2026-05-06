# -*- coding: utf-8 -*-
"""
reverse_partner/__init__.py — IDA Pro 9.0 plugin entry point
=============================================================
IDA loads this via PLUGIN_ENTRY() when the .py file (or the folder's
__init__.py) is placed in  <IDA>/plugins/reverse_partner/

CHANGELOG v5 (summary):
  [FIX]  Ctrl+Shift+R registered (was listed in header, never wired up)
  [FIX]  show_wait_box / hide_wait_box always matched via try/finally
  [FIX]  Debugger guard on every write path (preserved from v4)
  [NEW]  New AI schema: confidence, category, evidence, warnings
  [NEW]  JSON repair + multi-attempt parser
  [NEW]  normalize_ai_result / validate_ai_result
  [NEW]  Review Queue  (Ctrl+Shift+Q)
  [NEW]  Rollback last batch  (Ctrl+Alt+Z)
  [NEW]  Analysis cache (SHA-256, TTL, hit/miss log)
  [NEW]  openai_compatible / ollama / lmstudio providers
  [NEW]  KeyRotator v2: quota/rate/auth/safety/timeout error classification
  [NEW]  Naming modes: conservative | malware | blog
  [NEW]  Richer static context: strings, APIs, constants, pre-tags, MITRE hints
  [NEW]  Struct inference  (Ctrl+Shift+X)
  [NEW]  IOC extractor  (Ctrl+Shift+I)
  [NEW]  Selected-range analysis  (Ctrl+Shift+L)
  [NEW]  Whole-program 3-phase analysis  (Ctrl+Shift+R)
  [NEW]  Upgraded HTML forensic report (sortable table, IOCs, queue, history)
  [NEW]  Wrapper resolver naming: resolve_and_call_<API>_aN
  [NEW]  Standalone test harness (python tests.py)
  [NEW]  Full modular layout (one concern per file)
"""

import sys
import os

# ── make sibling modules importable when IDA loads the package ───────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    import idaapi
    import idautils
    import idc
    import ida_kernwin
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

if _IN_IDA:
    from logger import log
    from config import load_config
    from guards import is_debugger_active

    from actions import (
        ActionRenameCurrent,
        ActionRenameUnnamed,
        ActionRenameAll,
        ActionAnalyzeCurrent,
        ActionAnalyzeProgram,
        ActionAntiObfuscation,
        ActionExportReport,
        ActionReviewQueue,
        ActionWorkspace,
        ActionRollback,
        ActionExtractIOCs,
        ActionAnalyzeRange,
        ActionStructInference,
        ActionVariableRenamer,
        ActionPrototypeInference,
        ActionRunFLOSS,
        ActionSPACurrentSubgraph,
        ActionSPAEntryPoints,
        ActionSPAReviewPriority,
        ActionSPAOpenLastReport,
        ActionSettings,
    )

# ---------------------------------------------------------------------------
# Action registry
# ---------------------------------------------------------------------------

PLUGIN_NAME = "GPT Function Renamer v5"
MENU_ROOT   = "Edit/GPT Renamer/"

# (action_id, hotkey, label, tooltip, handler_class)
_ACTIONS = [
    (ActionRenameCurrent.ACTION_ID,   "Shift+G",
     "Rename Current Function",
     "AI rename the function under cursor",
     ActionRenameCurrent),

    (ActionRenameUnnamed.ACTION_ID,   "Ctrl+Shift+U",
     "Rename Unnamed Functions",
     "AI rename only sub_XXXX / default-named functions",
     ActionRenameUnnamed),

    (ActionRenameAll.ACTION_ID,       "Ctrl+Shift+G",
     "Rename All Functions",
     "AI rename all functions per config",
     ActionRenameAll),

    (ActionAnalyzeCurrent.ACTION_ID,  "Ctrl+Shift+A",
     "Analyze Current Function (AI)",
     "Deep AI analysis of the function under cursor",
     ActionAnalyzeCurrent),

    (ActionAnalyzeProgram.ACTION_ID,  "Ctrl+Shift+R",   # [FIX v5]
     "Analyze Whole Program (3-phase AI)",
     "Phase 1: pre-tag  Phase 2: batch rename  Phase 3: binary summary",
     ActionAnalyzeProgram),

    (ActionAntiObfuscation.ACTION_ID, "Ctrl+Shift+O",
     "Anti-Obfuscation Scanner [static]",
     "4-pass: hash API / indirect calls / dispatchers / wrapper rename",
     ActionAntiObfuscation),

    (ActionExportReport.ACTION_ID,    "Ctrl+Shift+E",
     "Export Forensic Report",
     "Export JSON + HTML report (functions, IOCs, queue, history)",
     ActionExportReport),

    (ActionReviewQueue.ACTION_ID,     "Ctrl+Shift+Q",   # [NEW v5]
     "Review Queue",
     "View / approve / reject AI rename suggestions",
     ActionReviewQueue),

    (ActionWorkspace.ACTION_ID,       "Ctrl+Alt+G",
     "Open Workspace",
     "Open the GPT Renamer workspace pane",
     ActionWorkspace),

    (ActionRollback.ACTION_ID,        "Ctrl+Alt+Z",     # [NEW v5]
     "Rollback Last Rename Batch",
     "Undo the last AI rename batch",
     ActionRollback),

    (ActionExtractIOCs.ACTION_ID,     "Ctrl+Shift+I",   # [NEW v5]
     "Extract IOCs",
     "Rule-based IOC scan of all binary strings",
     ActionExtractIOCs),

    (ActionAnalyzeRange.ACTION_ID,    "Ctrl+Shift+L",   # [NEW v5]
     "Analyze Selected Range",
     "AI analysis of the selected instruction range",
     ActionAnalyzeRange),

    (ActionStructInference.ACTION_ID, "Ctrl+Shift+X",   # [NEW v5]
     "Struct Inference (AI)",
     "Infer struct layout from field accesses in current function",
     ActionStructInference),

    (ActionVariableRenamer.ACTION_ID, "Ctrl+Alt+V",
     "Variable Rename Suggestions",
     "Suggest Hex-Rays local variable renames and queue them for review",
     ActionVariableRenamer),

    (ActionPrototypeInference.ACTION_ID, "Ctrl+Alt+P",
     "Prototype Inference",
     "Suggest a function prototype and queue it for review",
     ActionPrototypeInference),

    (ActionRunFLOSS.ACTION_ID,       "Ctrl+Shift+F",
     "Run FLOSS String Discovery",
     "Run optional FLOSS decoded string discovery against the input file",
     ActionRunFLOSS),

    (ActionSPACurrentSubgraph.ACTION_ID, "Ctrl+Alt+D",
     "Static Program Analyzer/Analyze Current Subgraph",
     "Static program analysis for current function and reachable callees",
     ActionSPACurrentSubgraph),

    (ActionSPAEntryPoints.ACTION_ID, "",
     "Static Program Analyzer/Analyze Entry Points",
     "Static program analysis for entry points and reachable functions",
     ActionSPAEntryPoints),

    (ActionSPAReviewPriority.ACTION_ID, "",
     "Static Program Analyzer/Analyze Review-Priority Functions",
     "Static program analysis for statically notable functions",
     ActionSPAReviewPriority),

    (ActionSPAOpenLastReport.ACTION_ID, "",
     "Static Program Analyzer/Open Last Report",
     "Open the last Static Program Analyzer HTML report",
     ActionSPAOpenLastReport),

    (ActionSettings.ACTION_ID,        "Ctrl+Shift+S",
     "Settings",
     "Configure provider, keys, naming mode, review queue, cache …",
     ActionSettings),
]


# ---------------------------------------------------------------------------
# Plugin class
# ---------------------------------------------------------------------------

class GPTRenamerPlugin(idaapi.plugin_t):
    flags       = idaapi.PLUGIN_KEEP
    comment     = "AI-powered function renamer — IDA 9.0 debug-safe v5"
    help        = "Edit > GPT Renamer"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""

    # ── init ────────────────────────────────────────────────────────────────

    def init(self):
        for action_id, hotkey, label, tooltip, cls in _ACTIONS:
            desc = idaapi.action_desc_t(
                action_id, label, cls(), hotkey, tooltip, -1)
            if not idaapi.register_action(desc):
                log.err("Failed to register action: %s" % action_id)
                continue
            idaapi.attach_action_to_menu(
                MENU_ROOT + label, action_id, idaapi.SETMENU_APP)
            if action_id == ActionWorkspace.ACTION_ID:
                idaapi.attach_action_to_menu(
                    "Edit/Plugins/GPT Renamer/" + label,
                    action_id, idaapi.SETMENU_APP)
            if action_id in (
                    ActionSPACurrentSubgraph.ACTION_ID,
                    ActionSPAEntryPoints.ACTION_ID,
                    ActionSPAReviewPriority.ACTION_ID,
                    ActionSPAOpenLastReport.ACTION_ID):
                idaapi.attach_action_to_menu(
                    "Edit/Plugins/GPT Renamer/" + label,
                    action_id, idaapi.SETMENU_APP)

        cfg        = load_config()
        n_keys     = len(cfg.get("api_keys", []))
        dbg_status = ("ACTIVE — writes BLOCKED!" if is_debugger_active() else "off")

        log.sep()
        log.ok("%s loaded — IDA 9.0 debug-safe" % PLUGIN_NAME)
        log.info("Provider : %s | Model : %s" % (cfg["provider"], cfg["model"]))
        log.info("Keys     : %d | Batch : %d | Naming : %s" % (
            n_keys, cfg.get("batch_size", 50), cfg.get("naming_mode","conservative")))
        log.info("Review   : %s | AutoConf >= %.2f | Cache : %s" % (
            cfg.get("review_mode", True),
            cfg.get("auto_apply_confidence", 0.85),
            cfg.get("enable_cache", True)))
        log.info("Debugger : %s" % dbg_status)
        log.info("Shift+G=Rename Cur  Ctrl+Shift+U=Rename Unnamed  Ctrl+Shift+G=Rename All")
        log.info("Ctrl+Shift+A=Analyze  Ctrl+Shift+R=Analyze Program  Ctrl+Shift+O=Anti-Obfus")
        log.info("Ctrl+Shift+Q=Queue  Ctrl+Alt+Z=Rollback  Ctrl+Shift+I=IOC  Ctrl+Shift+L=Range")
        log.info("Ctrl+Shift+X=Struct  Ctrl+Shift+E=Report  Ctrl+Alt+G=Workspace  Ctrl+Alt+V=Vars  Ctrl+Alt+P=Proto")
        log.info("Ctrl+Shift+F=FLOSS")
        log.info("Ctrl+Alt+D=Static Program Analyzer")
        log.info("Ctrl+Shift+S=Settings")
        if not cfg.get("api_keys"):
            log.warn("No API key configured — open Settings (Ctrl+Shift+S) first.")
        log.sep()

        return idaapi.PLUGIN_KEEP

    # ── run (menu trigger — not used) ───────────────────────────────────────

    def run(self, arg):
        log.info("Use the menu  Edit > GPT Renamer  or the hotkeys listed above.")

    # ── term ────────────────────────────────────────────────────────────────

    def term(self):
        for action_id, _, label, _, _ in _ACTIONS:
            try:
                idaapi.detach_action_from_menu(MENU_ROOT + label, action_id)
                if action_id == ActionWorkspace.ACTION_ID:
                    idaapi.detach_action_from_menu(
                        "Edit/Plugins/GPT Renamer/" + label, action_id)
                if action_id in (
                        ActionSPACurrentSubgraph.ACTION_ID,
                        ActionSPAEntryPoints.ACTION_ID,
                        ActionSPAReviewPriority.ACTION_ID,
                        ActionSPAOpenLastReport.ACTION_ID):
                    idaapi.detach_action_from_menu(
                        "Edit/Plugins/GPT Renamer/" + label, action_id)
                idaapi.unregister_action(action_id)
            except Exception:
                pass
        log.info("%s unloaded." % PLUGIN_NAME)


# ---------------------------------------------------------------------------
# IDA plugin entry point
# ---------------------------------------------------------------------------

def PLUGIN_ENTRY():
    return GPTRenamerPlugin()
