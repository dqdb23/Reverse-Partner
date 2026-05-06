# -*- coding: utf-8 -*-
"""
workspace.py - GPT Renamer dockable workspace pane
==================================================
PseudoNote-style workspace implemented for reverse_partner.

The pane is intentionally conservative:
  - context collection is read-only
  - notes/analysis are saved as plugin metadata in idb_storage
  - renames/comments continue through existing safe wrappers and review queue
"""

import json
import os
import tempfile
import time

try:
    import idaapi
    import ida_funcs
    import ida_kernwin
    import idc
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

try:
    from PyQt5 import QtCore, QtWidgets
except ImportError:
    try:
        from PySide2 import QtCore, QtWidgets
    except ImportError:
        QtCore = None
        QtWidgets = None

from cache import cache_get, cache_put, compute_cache_key
from config import MAX_FUNC_SIZE_FOR_DECOMPILE, load_config
from history import load_rename_history
from idb_storage import load_blob, save_blob
from ida_read import get_assembly
from logger import log
from review_queue import add_to_review_queue, load_review_queue, show_review_queue_ui
from static_analysis import build_function_context
from utils import normalize_ai_result


_FORM = None
_PluginFormBase = ida_kernwin.PluginForm if _IN_IDA else object


def _current_function_ea():
    if not _IN_IDA:
        return None
    ea = idc.get_screen_ea()
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    return func.start_ea


def _join(values, limit=20):
    values = values or []
    return "\n".join(str(v) for v in values[:limit]) if values else "-"


def _pending_queue_item(ea, kind="function_rename"):
    ea_hex = hex(ea)
    for item in load_review_queue():
        if (item.get("ea") == ea_hex
                and item.get("status") == "pending"
                and item.get("kind", "function_rename") == kind):
            return item
    return None


def _rename_history_for(ea):
    result = []
    try:
        for batch in load_rename_history().get("batches", []):
            for item in batch.get("items", []):
                try:
                    item_ea = item.get("ea", -1)
                    if isinstance(item_ea, str):
                        item_ea = int(item_ea, 16 if item_ea.lower().startswith("0x") else 10)
                    if int(item_ea) == int(ea):
                        result.append({
                            "timestamp": batch.get("timestamp", ""),
                            "provider": batch.get("provider", "?"),
                            "model": batch.get("model", "?"),
                            "old_name": item.get("old_name", ""),
                            "new_name": item.get("new_name", ""),
                            "confidence": float(item.get("confidence", 0.0)),
                        })
                except Exception:
                    pass
    except Exception:
        pass
    return result[-10:]


class GPTRenamerWorkspace(_PluginFormBase):
    """Dockable GPT Renamer workspace."""

    def __init__(self):
        if _IN_IDA:
            ida_kernwin.PluginForm.__init__(self)
        self.parent = None
        self.current_ea = None
        self.context = {}
        self.last_analysis = None
        self._loading_notes = False

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self._build_ui()
        self.refresh_context(force=True)
        self.timer = QtCore.QTimer(self.parent)
        self.timer.timeout.connect(self._poll_current_function)
        self.timer.start(1000)

    def OnClose(self, form):
        global _FORM
        _FORM = None

    def _build_ui(self):
        root = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(root)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        self.func_label = QtWidgets.QLabel("Function: -")
        self.func_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        layout.addWidget(self.func_label)

        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs, 1)

        self.overview = QtWidgets.QWidget()
        ov = QtWidgets.QVBoxLayout(self.overview)
        self.summary = QtWidgets.QTextEdit()
        self.summary.setReadOnly(True)
        self.suggestion = QtWidgets.QLabel("Suggested: -")
        self.suggestion.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        self.evidence = QtWidgets.QTextEdit()
        self.evidence.setReadOnly(True)
        ov.addWidget(QtWidgets.QLabel("AI Summary"))
        ov.addWidget(self.summary, 2)
        ov.addWidget(self.suggestion)
        ov.addWidget(QtWidgets.QLabel("Evidence"))
        ov.addWidget(self.evidence, 1)
        self.tabs.addTab(self.overview, "Overview")

        self.static_tab = QtWidgets.QWidget()
        st = QtWidgets.QGridLayout(self.static_tab)
        self.tags = QtWidgets.QTextEdit(); self.tags.setReadOnly(True)
        self.apis = QtWidgets.QTextEdit(); self.apis.setReadOnly(True)
        self.strings = QtWidgets.QTextEdit(); self.strings.setReadOnly(True)
        self.decoded_strings = QtWidgets.QTextEdit(); self.decoded_strings.setReadOnly(True)
        self.constants = QtWidgets.QTextEdit(); self.constants.setReadOnly(True)
        self.callers = QtWidgets.QTextEdit(); self.callers.setReadOnly(True)
        self.callees = QtWidgets.QTextEdit(); self.callees.setReadOnly(True)
        st.addWidget(QtWidgets.QLabel("Static Tags"), 0, 0)
        st.addWidget(QtWidgets.QLabel("APIs"), 0, 1)
        st.addWidget(self.tags, 1, 0)
        st.addWidget(self.apis, 1, 1)
        st.addWidget(QtWidgets.QLabel("IDA Strings"), 2, 0)
        st.addWidget(QtWidgets.QLabel("FLOSS Decoded Strings"), 2, 1)
        st.addWidget(self.strings, 3, 0)
        st.addWidget(self.decoded_strings, 3, 1)
        st.addWidget(QtWidgets.QLabel("Constants"), 4, 0)
        st.addWidget(QtWidgets.QLabel("Callers"), 4, 1)
        st.addWidget(self.constants, 5, 0)
        st.addWidget(self.callers, 5, 1)
        st.addWidget(QtWidgets.QLabel("Callees"), 6, 0)
        st.addWidget(self.callees, 7, 0, 1, 2)
        self.tabs.addTab(self.static_tab, "Context")

        self.notes_tab = QtWidgets.QWidget()
        nt = QtWidgets.QVBoxLayout(self.notes_tab)
        self.notes = QtWidgets.QTextEdit()
        self.chat = QtWidgets.QTextEdit()
        self.chat.setReadOnly(True)
        nt.addWidget(QtWidgets.QLabel("Analyst Notes"))
        nt.addWidget(self.notes, 3)
        nt.addWidget(QtWidgets.QLabel("Chat / History"))
        nt.addWidget(self.chat, 2)
        self.tabs.addTab(self.notes_tab, "Notes")

        self.spa_tab = QtWidgets.QWidget()
        sp = QtWidgets.QVBoxLayout(self.spa_tab)
        self.spa_result = QtWidgets.QTextEdit()
        self.spa_result.setReadOnly(True)
        spa_buttons = QtWidgets.QHBoxLayout()
        btn_spa_analyze = QtWidgets.QPushButton("Analyze Current Subgraph")
        btn_spa_view = QtWidgets.QPushButton("View Stored Analysis")
        btn_spa_report = QtWidgets.QPushButton("Open Last Report")
        btn_spa_analyze.clicked.connect(self.analyze_static_subgraph)
        btn_spa_view.clicked.connect(self.view_static_analysis)
        btn_spa_report.clicked.connect(self.open_static_report)
        spa_buttons.addWidget(btn_spa_analyze)
        spa_buttons.addWidget(btn_spa_view)
        spa_buttons.addWidget(btn_spa_report)
        sp.addLayout(spa_buttons)
        sp.addWidget(self.spa_result, 1)
        self.tabs.addTab(self.spa_tab, "Static Program Analysis")

        buttons = QtWidgets.QGridLayout()
        specs = [
            ("Refresh Context", self.refresh_context),
            ("Analyze Current", self.analyze_current),
            ("Queue Rename", self.queue_rename),
            ("Open Review Queue", show_review_queue_ui),
            ("Apply High Confidence", self.apply_high_confidence),
            ("Save Notes", self.save_notes),
            ("Export Function JSON", self.export_function_json),
        ]
        for i, (text, cb) in enumerate(specs):
            btn = QtWidgets.QPushButton(text)
            btn.clicked.connect(cb)
            buttons.addWidget(btn, i // 2, i % 2)
        layout.addLayout(buttons)

        outer = QtWidgets.QVBoxLayout(self.parent)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(root)

    def _poll_current_function(self):
        ea = _current_function_ea()
        if ea is None and self.current_ea is not None:
            self.refresh_context(force=True)
        elif ea is not None and ea != self.current_ea:
            self.refresh_context(force=True)

    def _set_status(self, text):
        self.func_label.setText(text)

    def _clear_fields(self):
        for widget in (
            self.summary, self.evidence, self.tags, self.apis,
            self.strings, self.decoded_strings, self.constants, self.callers, self.callees,
            self.chat, self.spa_result,
        ):
            widget.setPlainText("-")
        self.suggestion.setText("Suggested: -")

    def refresh_context(self, checked=False, force=False):
        cfg = load_config()
        ea = _current_function_ea()
        if ea is None:
            self.current_ea = None
            self.context = {}
            self._set_status("Function: <cursor is not inside a function>")
            self._clear_fields()
            return

        if not force and ea == self.current_ea and self.context:
            return

        self.current_ea = ea
        try:
            func = ida_funcs.get_func(ea)
            if func and (func.end_ea - func.start_ea) > MAX_FUNC_SIZE_FOR_DECOMPILE:
                name = idc.get_func_name(ea) or ("sub_%x" % ea)
                self.context = {
                    "ea": hex(ea),
                    "name": name,
                    "size_bytes": func.end_ea - func.start_ea,
                    "n_insn": 0,
                    "code_type": "assembly",
                    "code": get_assembly(ea, max_lines=80) or "",
                    "callers": [],
                    "callees": [],
                    "strings": [],
                    "decoded_strings": [],
                    "apis": [],
                    "constants": [],
                    "pre_tags": ["LARGE_FUNCTION"],
                    "pre_reasons": ["workspace_lightweight_context"],
                    "mitre_hints": [],
                    "n_callers": 0,
                    "n_callees": 0,
                    "local_vars": [],
                    "struct_accesses": [],
                }
            else:
                self.context = build_function_context(ea, cfg)
            save_blob(ea, "function_context", self._context_for_storage(self.context))
        except Exception as exc:
            self.context = {"ea": hex(ea), "name": idc.get_func_name(ea) or ("sub_%x" % ea)}
            log.warn("Workspace context refresh failed: %s" % exc)

        name = self.context.get("name", idc.get_func_name(ea) or "")
        self._set_status("Function: %s  %s" % (hex(ea), name))

        self.last_analysis = load_blob(ea, "last_analysis")
        saved_summary = load_blob(ea, "ai_summary") or ""
        notes = load_blob(ea, "analyst_notes") or ""
        readable_c = load_blob(ea, "readable_c")
        spa = load_blob(ea, "static_program_analysis")

        qitem = _pending_queue_item(ea)
        shown = qitem or (normalize_ai_result(self.last_analysis, name, cfg.get("prefix", ""))
                          if isinstance(self.last_analysis, dict) else None)

        self.summary.setPlainText(saved_summary or (shown or {}).get("description", "") or "-")
        if shown:
            self.suggestion.setText("Suggested: %s  confidence=%.2f  category=%s" % (
                shown.get("suggested_name") or shown.get("name", "-"),
                shown.get("confidence", 0.0),
                shown.get("category", "UNKNOWN"),
            ))
            self.evidence.setPlainText(_join(shown.get("evidence", []), 15))
        else:
            self.suggestion.setText("Suggested: -")
            self.evidence.setPlainText("-")

        self.tags.setPlainText(_join(self.context.get("pre_tags", [])))
        self.apis.setPlainText(_join(self.context.get("apis", [])))
        self.strings.setPlainText(_join(self.context.get("strings", [])))
        dec_vals = []
        for s in self.context.get("decoded_strings", []):
            dec_vals.append(s.get("value", "") if isinstance(s, dict) else str(s))
        self.decoded_strings.setPlainText(_join([s for s in dec_vals if s]))
        self.constants.setPlainText(_join(self.context.get("constants", [])))
        self.callers.setPlainText(_join(self.context.get("callers", [])))
        self.callees.setPlainText(_join(self.context.get("callees", [])))

        self._loading_notes = True
        self.notes.setPlainText(notes if isinstance(notes, str) else json.dumps(notes, indent=2))
        self._loading_notes = False

        history = _rename_history_for(ea)
        chat_lines = []
        if qitem:
            chat_lines.append("Pending queue item: %s (conf=%.2f)" % (
                qitem.get("suggested_name", ""), qitem.get("confidence", 0.0)))
        if readable_c:
            chat_lines.append("Saved readable_c is available for this function.")
        if history:
            chat_lines.append("Rename history:")
            for h in history:
                chat_lines.append("  %(timestamp)s %(old_name)s -> %(new_name)s conf=%(confidence).2f" % h)
        self.chat.setPlainText("\n".join(chat_lines) if chat_lines else "Chat/history placeholder.")
        self._show_static_analysis(spa)

    def _show_static_analysis(self, spa):
        if not isinstance(spa, dict):
            self.spa_result.setPlainText("No stored Static Program Analysis for this function.")
            return
        analysis = spa.get("analysis", {}) if isinstance(spa.get("analysis", {}), dict) else {}
        score = spa.get("static_score", {}) if isinstance(spa.get("static_score", {}), dict) else {}
        rec = analysis.get("rename_recommendation", {}) if isinstance(analysis.get("rename_recommendation", {}), dict) else {}
        lines = [
            "Priority: %s  score=%s" % (analysis.get("priority", score.get("priority", "-")), score.get("score", "-")),
            "Category: %s" % analysis.get("category", "-"),
            "Suggested rename: %s" % (rec.get("name") or "-"),
            "",
            "Summary:",
            analysis.get("summary", "-"),
            "",
            "Evidence:",
        ]
        for ev in analysis.get("evidence", [])[:12]:
            lines.append("  - " + str(ev))
        if analysis.get("called_behaviors"):
            lines.append("")
            lines.append("Called behaviors:")
            for item in analysis.get("called_behaviors", [])[:8]:
                lines.append("  - " + str(item))
        self.spa_result.setPlainText("\n".join(lines))

    def analyze_static_subgraph(self, checked=False):
        if not _IN_IDA:
            return
        try:
            idaapi.process_ui_action("gpt_renamer:spa_current_subgraph")
        except Exception:
            idaapi.warning("Static Program Analyzer action is unavailable.")

    def view_static_analysis(self, checked=False):
        ea = self._require_function()
        if ea is None:
            return
        self._show_static_analysis(load_blob(ea, "static_program_analysis"))

    def open_static_report(self, checked=False):
        try:
            from static_program_analyzer import open_last_static_report
            path = open_last_static_report(load_config())
            if not path:
                idaapi.warning("No Static Program Analyzer report found.")
        except Exception as exc:
            idaapi.warning("Cannot open Static Program Analyzer report: %s" % str(exc)[:200])

    def _context_for_storage(self, ctx):
        keep = dict(ctx)
        code = keep.get("code", "")
        if isinstance(code, str) and len(code) > 12000:
            keep["code"] = code[:12000] + "\n/* truncated for IDB metadata */"
        return keep

    def _require_function(self):
        if self.current_ea is None:
            idaapi.warning("Cursor is not inside a function.")
            return None
        return self.current_ea

    def analyze_current(self, checked=False):
        ea = self._require_function()
        if ea is None:
            return
        cfg = load_config()
        if not cfg.get("api_keys") and cfg.get("provider") not in ("ollama", "lmstudio"):
            idaapi.warning("No API key configured.")
            return
        ctx = self.context or build_function_context(ea, cfg)
        name = ctx.get("name", idc.get_func_name(ea) or ("sub_%x" % ea))
        code = ctx.get("code", "")
        if not code:
            idaapi.warning("Cannot get code for '%s'." % name)
            return

        ck = compute_cache_key(
            ea, name, code, ctx.get("callers", []), ctx.get("callees", []),
            ctx.get("strings", []), ctx.get("apis", []),
            cfg.get("model", ""), cfg.get("provider", ""),
            ctx.get("decoded_strings", []))
        raw = cache_get(cfg, ck)

        if not raw:
            from actions import _run_ai_thread
            from providers import make_provider
            try:
                provider = make_provider(cfg)
            except Exception as exc:
                idaapi.warning("Provider is not available: %s" % str(exc)[:300])
                return
            ctx_extra = self._prompt_extra(ctx)
            ida_kernwin.show_wait_box("reverse_partner: Workspace analyzing '%s' ..." % name)
            try:
                raw, err = _run_ai_thread(
                    lambda: provider.analyze(code, name, ctx.get("callees", []),
                                             ctx.get("callers", []), ctx_extra),
                    timeout=cfg.get("timeout_sec", 90))
            finally:
                ida_kernwin.hide_wait_box()
            if err:
                idaapi.warning("AI error: %s" % err[:300])
                return
            if not raw:
                idaapi.warning("AI returned no result.")
                return
            cache_put(cfg, ck, raw, name, ctx.get("code_type", ""))

        self.last_analysis = raw
        norm = normalize_ai_result(raw, name, cfg.get("prefix", ""))
        save_blob(ea, "last_analysis", raw)
        save_blob(ea, "ai_summary", norm.get("description", ""))
        self.refresh_context(force=True)

    def _prompt_extra(self, ctx):
        lines = []
        if ctx.get("strings"):
            lines.append("// Strings: %s" % "; ".join(ctx.get("strings", [])[:8]))
        if ctx.get("decoded_strings"):
            decoded = []
            for s in ctx.get("decoded_strings", [])[:6]:
                decoded.append(s.get("value", "") if isinstance(s, dict) else str(s))
            decoded = [s for s in decoded if s]
            if decoded:
                lines.append("// Decoded strings (FLOSS): %s" % "; ".join(decoded))
        if ctx.get("apis"):
            lines.append("// APIs: %s" % ", ".join(ctx.get("apis", [])[:12]))
        if ctx.get("pre_tags"):
            lines.append("// Static pre-tags: %s" % ", ".join(ctx.get("pre_tags", [])))
        if ctx.get("constants"):
            lines.append("// Constants: %s" % ", ".join(ctx.get("constants", [])[:12]))
        return "\n".join(lines)

    def _normalized_current_analysis(self):
        ea = self._require_function()
        if ea is None:
            return None
        raw = self.last_analysis or load_blob(ea, "last_analysis")
        if not isinstance(raw, dict):
            idaapi.warning("No saved analysis for this function. Run Analyze Current first.")
            return None
        cfg = load_config()
        name = (self.context or {}).get("name", idc.get_func_name(ea) or ("sub_%x" % ea))
        return normalize_ai_result(raw, name, cfg.get("prefix", ""))

    def queue_rename(self, checked=False):
        ea = self._require_function()
        if ea is None:
            return
        norm = self._normalized_current_analysis()
        if not norm:
            return
        cfg = load_config()
        old_name = (self.context or {}).get("name", idc.get_func_name(ea) or "")
        add_to_review_queue(ea, old_name, norm, cfg.get("model", "?"), cfg.get("provider", "?"))
        idaapi.info("Queued rename suggestion for %s." % old_name)
        self.refresh_context(force=True)

    def apply_high_confidence(self, checked=False):
        ea = self._require_function()
        if ea is None:
            return
        qitem = _pending_queue_item(ea)
        if qitem:
            show_review_queue_ui()
            return

        norm = self._normalized_current_analysis()
        if not norm:
            return
        cfg = load_config()
        threshold = cfg.get("auto_apply_confidence", 0.85)
        if norm.get("confidence", 0.0) < threshold:
            idaapi.warning("Suggestion confidence %.2f is below threshold %.2f." % (
                norm.get("confidence", 0.0), threshold))
            return
        old_name = (self.context or {}).get("name", idc.get_func_name(ea) or "")
        add_to_review_queue(ea, old_name, norm, cfg.get("model", "?"), cfg.get("provider", "?"))
        idaapi.info("High-confidence suggestion queued for review.")
        show_review_queue_ui()
        self.refresh_context(force=True)

    def save_notes(self, checked=False):
        ea = self._require_function()
        if ea is None:
            return
        if save_blob(ea, "analyst_notes", self.notes.toPlainText()):
            idaapi.info("Saved analyst notes for %s." % (self.context.get("name", hex(ea))))

    def export_function_json(self, checked=False):
        ea = self._require_function()
        if ea is None:
            return
        data = {
            "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "context": self._context_for_storage(self.context or {}),
            "ai_summary": load_blob(ea, "ai_summary"),
            "last_analysis": load_blob(ea, "last_analysis"),
            "analyst_notes": load_blob(ea, "analyst_notes"),
            "readable_c": load_blob(ea, "readable_c"),
            "pending_queue_item": _pending_queue_item(ea),
            "rename_history": _rename_history_for(ea),
        }
        default = os.path.join(tempfile.gettempdir(), "gpt_renamer_%X.json" % ea)
        path = ida_kernwin.ask_file(True, default, "Export function JSON")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            idaapi.info("Exported function JSON:\n%s" % path)
        except Exception as exc:
            idaapi.warning("Export failed: %s" % exc)


def open_workspace():
    """Open or focus the GPT Renamer workspace."""
    global _FORM
    if not _IN_IDA:
        log.warn("Workspace requires IDA.")
        return
    if QtWidgets is None or QtCore is None:
        idaapi.warning("Qt workspace is not available in this IDA session.")
        return
    if _FORM is None:
        _FORM = GPTRenamerWorkspace()
        try:
            _FORM.Show("GPT Renamer Workspace",
                       options=ida_kernwin.PluginForm.WOPN_PERSIST)
        except TypeError:
            _FORM.Show("GPT Renamer Workspace")
    else:
        try:
            _FORM.Show("GPT Renamer Workspace")
        except Exception:
            pass
        _FORM.refresh_context(force=True)
