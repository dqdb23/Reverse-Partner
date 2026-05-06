# -*- coding: utf-8 -*-
"""
static_program_analyzer.py - contained static program analysis pipeline
=======================================================================
Offline, static-only analysis for binaries already opened in IDA.

This pipeline does not patch bytes, execute the input, or auto-apply names.
IDA symbol/comment/type/name writes remain outside this module and must go
through existing safe wrappers. Per-function analysis metadata is stored via
idb_storage helpers only.
"""

import hashlib
import json
import os
import re
import time
import webbrowser
from collections import deque

try:
    import idaapi
    import idautils
    import idc
    import ida_entry
    import ida_funcs
    import ida_kernwin
    import ida_xref
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

from cache import cache_get, cache_put
from config import DEFAULT_CONFIG, MAX_CHARS_PER_FUNC, MAX_FUNC_SIZE_FOR_DECOMPILE, load_config
from idb_storage import load_blob, save_blob
from logger import log
from utils import parse_json_response_v5, repair_json_response, sanitize_name


SPA_METADATA_KEY = "static_program_analysis"
SPA_REPORT_MARKER = "_gpt_spa_last_report.json"
SPA_CACHE_VERSION = "spa_v1"

SPA_CATEGORIES = frozenset({
    "MEMORY", "NETWORK", "CRYPTO", "FILE", "DISPATCH", "WRAPPER",
    "INIT", "UTIL", "UNKNOWN",
})
SPA_PRIORITIES = ("low", "medium", "high", "critical")


def _hex(ea):
    return "0x%X" % int(ea)


def _parse_ea(value):
    if isinstance(value, int):
        return value
    try:
        text = str(value)
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except Exception:
        return None


def _input_path():
    if not _IN_IDA:
        return ""
    try:
        return idc.get_input_file_path() or ""
    except Exception:
        return ""


def _base_output_dir(cfg=None, input_path=None):
    cfg = cfg or {}
    if cfg.get("spa_artifact_dir"):
        return cfg.get("spa_artifact_dir")
    path = input_path or _input_path()
    if path:
        return os.path.dirname(path) or os.getcwd()
    return os.getcwd()


def make_artifact_dir(cfg=None, timestamp=None, input_path=None):
    ts = timestamp or time.strftime("%Y%m%d_%H%M%S")
    return os.path.join(_base_output_dir(cfg, input_path), "gpt_renamer_static_analysis_%s" % ts)


def _cache_cfg(cfg):
    local = dict(cfg or {})
    local["enable_cache"] = bool(local.get("spa_use_cache", True))
    if not local.get("cache_file"):
        if _IN_IDA:
            try:
                local["cache_file"] = os.path.join(idaapi.get_user_idadir(), "reverse_partner_cache.json")
            except Exception:
                pass
    return local


def get_current_function_ea():
    if not _IN_IDA:
        return None
    try:
        func = ida_funcs.get_func(idc.get_screen_ea())
        return func.start_ea if func else None
    except Exception:
        return None


def get_entry_points():
    if not _IN_IDA:
        return []
    roots = []
    try:
        qty = ida_entry.get_entry_qty()
        for i in range(qty):
            ea = ida_entry.get_entry(ida_entry.get_entry_ordinal(i))
            if ea != idaapi.BADADDR and ida_funcs.get_func(ea):
                roots.append(ida_funcs.get_func(ea).start_ea)
    except Exception:
        pass
    try:
        start = idc.get_inf_attr(idc.INF_START_EA)
        if start and start != idaapi.BADADDR and ida_funcs.get_func(start):
            roots.append(ida_funcs.get_func(start).start_ea)
    except Exception:
        pass
    return sorted(set(roots))


def is_library_or_thunk_function(ea):
    if not _IN_IDA:
        return False
    try:
        func = ida_funcs.get_func(ea)
        if not func:
            return False
        flags = int(func.flags)
        return bool(flags & ida_funcs.FUNC_LIB) or bool(flags & ida_funcs.FUNC_THUNK)
    except Exception:
        return False


def _is_thunk(ea):
    if not _IN_IDA:
        return False
    try:
        func = ida_funcs.get_func(ea)
        return bool(func and (int(func.flags) & ida_funcs.FUNC_THUNK))
    except Exception:
        return False


def get_callers_callees(ea):
    callers, callees = set(), set()
    if not _IN_IDA:
        return [], []
    try:
        func = ida_funcs.get_func(ea)
        if not func:
            return [], []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            ref = ida_xref.get_first_cref_from(head)
            while ref != idaapi.BADADDR:
                callee = ida_funcs.get_func(ref)
                if callee and callee.start_ea != func.start_ea:
                    callees.add(callee.start_ea)
                ref = ida_xref.get_next_cref_from(head, ref)
        ref = ida_xref.get_first_cref_to(func.start_ea)
        while ref != idaapi.BADADDR:
            caller = ida_funcs.get_func(ref)
            if caller and caller.start_ea != func.start_ea:
                callers.add(caller.start_ea)
            ref = ida_xref.get_next_cref_to(func.start_ea, ref)
    except Exception:
        pass
    return sorted(callers), sorted(callees)


def build_call_graph_from_roots(roots, max_depth=5, max_functions=300,
                                include_library_funcs=False):
    graph = {
        "roots": [_hex(r) for r in roots or [] if r is not None],
        "nodes": {},
        "edges": [],
        "cycles": [],
        "skipped": {},
    }
    if not _IN_IDA:
        return graph

    def skip(reason):
        graph["skipped"][reason] = graph["skipped"].get(reason, 0) + 1

    queue = deque((int(r), 0) for r in roots or [] if r is not None)
    seen_edges = set()
    while queue:
        ea, depth = queue.popleft()
        if depth > max_depth:
            skip("max_depth")
            continue
        if len(graph["nodes"]) >= max_functions and _hex(ea) not in graph["nodes"]:
            skip("max_functions")
            continue
        func = ida_funcs.get_func(ea)
        if not func:
            skip("no_function")
            continue
        ea = func.start_ea
        if is_library_or_thunk_function(ea) and not include_library_funcs:
            skip("library/thunk")
            continue
        key = _hex(ea)
        if key in graph["nodes"]:
            skip("duplicate")
            if depth < graph["nodes"][key].get("depth", depth):
                graph["nodes"][key]["depth"] = depth
            continue

        callers, callees = get_callers_callees(ea)
        graph["nodes"][key] = {
            "ea": ea,
            "name": idc.get_func_name(ea) or ("sub_%x" % ea),
            "depth": depth,
            "callers": [_hex(c) for c in callers],
            "callees": [],
            "is_library": is_library_or_thunk_function(ea),
            "is_thunk": _is_thunk(ea),
        }

        for callee in callees:
            callee_func = ida_funcs.get_func(callee)
            if not callee_func:
                skip("external/import")
                continue
            callee_ea = callee_func.start_ea
            if is_library_or_thunk_function(callee_ea) and not include_library_funcs:
                skip("library/thunk")
                continue
            edge = (key, _hex(callee_ea))
            if edge not in seen_edges:
                seen_edges.add(edge)
                graph["edges"].append({"caller": edge[0], "callee": edge[1]})
            graph["nodes"][key]["callees"].append(edge[1])
            if depth + 1 <= max_depth:
                queue.append((callee_ea, depth + 1))
            else:
                skip("max_depth")

    graph["cycles"] = detect_cycles(graph)
    return graph


def detect_cycles(graph):
    adjacency = {}
    for edge in graph.get("edges", []):
        adjacency.setdefault(edge["caller"], []).append(edge["callee"])

    cycles = []
    stack = []
    visiting = set()
    visited = set()

    def dfs(node):
        visiting.add(node)
        stack.append(node)
        for child in adjacency.get(node, []):
            if child in visiting:
                try:
                    cycles.append(stack[stack.index(child):] + [child])
                except ValueError:
                    cycles.append([node, child, node])
            elif child not in visited:
                dfs(child)
        stack.pop()
        visiting.discard(node)
        visited.add(node)

    for node in graph.get("nodes", {}):
        if node not in visited:
            dfs(node)
    return cycles


def topological_order_bottom_up(graph):
    adjacency = {key: [] for key in graph.get("nodes", {})}
    for edge in graph.get("edges", []):
        if edge.get("caller") in adjacency and edge.get("callee") in adjacency:
            adjacency[edge["caller"]].append(edge["callee"])

    ordered = []
    temp = set()
    perm = set()

    def visit(node):
        if node in perm:
            return
        if node in temp:
            return
        temp.add(node)
        for child in adjacency.get(node, []):
            visit(child)
        temp.discard(node)
        perm.add(node)
        ordered.append(node)

    for root in graph.get("nodes", {}):
        visit(root)
    return ordered


def _all_context_strings(context):
    values = list(context.get("strings", []) or [])
    for item in context.get("decoded_strings", []) or []:
        values.append(item.get("value", "") if isinstance(item, dict) else str(item))
    return [v for v in values if v]


def score_function_for_review(context):
    apis = [str(a) for a in context.get("apis", []) + context.get("callees", [])]
    strings = _all_context_strings(context)
    tags = set(context.get("pre_tags", []) or [])
    reasons = []
    score = 0

    joined_api = " ".join(apis).lower()
    joined_str = " ".join(strings).lower()

    def add(points, reason, tag=None):
        nonlocal score
        score += points
        reasons.append(reason)
        if tag:
            tags.add(tag)

    if any(k in joined_api for k in ("internet", "winhttp", "socket", "connect", "recv", "send")) or re.search(r"https?://|ftp://|\b[a-z0-9.-]+\.(com|net|org|ru|cn|io)\b", joined_str):
        add(3, "network-related API or URL-like string", "NETWORK")
    if any(k in joined_api for k in ("crypt", "bcrypt", "decompress", "rtlcompress")) or any("xor" in s.lower() for s in strings):
        add(2, "encryption/compression/static transform hint", "CRYPTO")
    if any(k in joined_api for k in ("virtualalloc", "virtualprotect", "heapalloc", "memcpy", "memmove", "rtldecompressbuffer")):
        add(3, "memory allocation/protection/copy API", "MEMORY")
    if any(k in joined_api for k in ("openprocess", "writeprocessmemory", "createremotethread", "ntcreatethreadex", "createthread")):
        add(3, "process/thread interaction API", "PROCESS")
    if any(k in joined_api for k in ("regsetvalue", "regcreatekey", "createservice", "schtasks", "taskschd")):
        add(3, "registry/service/task related API", "PERSISTENCE")
    if any(k in joined_api for k in ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "gettickcount")):
        add(2, "anti-debug or environment-check API", "EVASION")
    if any(k in joined_api for k in ("createfile", "writefile", "deletefile", "movefile")) and re.search(r"\.(exe|dll|sys|ps1|bat|vbs|tmp)|appdata|temp|system32", joined_str):
        add(2, "file API with notable path or extension", "FILE")
    if context.get("decoded_strings"):
        add(2, "decoded strings available from optional string discovery", "DECODED_STRINGS")
    if "DISPATCH" in tags or len(context.get("callees", []) or []) >= 15:
        add(2, "dispatcher-like or high fan-out structure", "DISPATCH")
    name = str(context.get("name", "")).lower()
    if "wrapper" in name or "resolve" in name or name.startswith("j_"):
        add(1, "wrapper/resolver naming hint", "WRAPPER")
    n_insn = int(context.get("n_insn", 0) or 0)
    if n_insn and n_insn <= 4 and not apis and not strings:
        add(-2, "tiny function with no useful references", None)
    if any(k in name for k in ("memcpy", "strlen", "strcmp", "free", "malloc")) and score <= 2:
        add(-1, "known utility/library-like wrapper", "UTIL")

    if score >= 9:
        priority = "critical"
    elif score >= 6:
        priority = "high"
    elif score >= 3:
        priority = "medium"
    else:
        priority = "low"

    return {
        "score": score,
        "priority": priority,
        "reasons": reasons,
        "tags": sorted(tags),
        "interesting": score >= 3,
    }


def _listify(value):
    if isinstance(value, list):
        return [str(v)[:300] for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value[:300]]
    return []


def repair_spa_json_response(text):
    return repair_json_response(text)


def parse_spa_result(text, original_name="", cfg=None):
    return normalize_spa_result(parse_json_response_v5(repair_spa_json_response(text)),
                                original_name=original_name, cfg=cfg)


def normalize_spa_result(raw, original_name="", cfg=None):
    cfg = cfg or {}
    if not isinstance(raw, dict) or raw.get("_parse_error"):
        raw = {}
    evidence = _listify(raw.get("evidence", []))
    try:
        confidence = max(0.0, min(1.0, float(raw.get("confidence", 0.0))))
    except Exception:
        confidence = 0.0
    if not evidence:
        confidence = min(confidence, 0.5)

    category = str(raw.get("category", "UNKNOWN")).upper()
    if category not in SPA_CATEGORIES:
        category = "UNKNOWN"
    priority = str(raw.get("priority", "low")).lower()
    if priority not in SPA_PRIORITIES:
        priority = "low"

    rec = raw.get("rename_recommendation", {})
    if not isinstance(rec, dict):
        rec = {}
    threshold = float(cfg.get("auto_apply_confidence", DEFAULT_CONFIG.get("auto_apply_confidence", 0.85)))
    rec_name = sanitize_name(str(rec.get("name") or raw.get("function_name") or original_name or "")).lower()
    rec_apply = bool(rec.get("apply")) and confidence >= threshold and rec_name

    return {
        "function_name": sanitize_name(str(raw.get("function_name") or original_name or "unknown_func")).lower(),
        "confidence": round(confidence, 3),
        "priority": priority,
        "category": category,
        "summary": str(raw.get("summary", ""))[:800],
        "technical_behavior": str(raw.get("technical_behavior", ""))[:1800],
        "evidence": evidence[:15],
        "data_flows": _listify(raw.get("data_flows", []))[:12],
        "called_behaviors": _listify(raw.get("called_behaviors", []))[:12],
        "warnings": _listify(raw.get("warnings", []))[:10],
        "rename_recommendation": {
            "apply": rec_apply,
            "name": rec_name,
            "reason": str(rec.get("reason", ""))[:500],
        },
        "analyst_notes": _listify(raw.get("analyst_notes", []))[:10],
    }


def validate_spa_result(result):
    issues = []
    if not isinstance(result, dict):
        return False, ["result is not a dict"]
    if not result.get("evidence"):
        issues.append("evidence missing")
    conf = result.get("confidence")
    if not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        issues.append("confidence out of range")
    if result.get("priority") not in SPA_PRIORITIES:
        issues.append("invalid priority")
    if result.get("category") not in SPA_CATEGORIES:
        issues.append("invalid category")
    rec = result.get("rename_recommendation", {})
    if rec.get("apply") and not rec.get("name"):
        issues.append("rename recommendation missing name")
    return not issues, issues


def _score_sort_key(item):
    priority_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    score = item.get("static_score", item.get("score", {}))
    if isinstance(score, dict):
        return (priority_rank.get(score.get("priority", "low"), 0), score.get("score", 0))
    return (0, 0)


def sort_by_priority(scored_items):
    return sorted(scored_items, key=_score_sort_key, reverse=True)


def select_ai_candidates_for_review(scored_items, limit=80, min_score=3,
                                    include_named=True, roots=None):
    roots = set(roots or [])
    selected = []
    seen = set()
    for item in sort_by_priority(scored_items):
        key = item.get("ea_hex") or _hex(item.get("ea", 0))
        score = item.get("static_score", item.get("score", {}))
        numeric = score.get("score", 0) if isinstance(score, dict) else 0
        if key not in roots and numeric < min_score:
            continue
        if not include_named and not str(item.get("name", "")).startswith(("sub_", "loc_", "fn_", "func_")):
            continue
        if key in seen:
            continue
        selected.append(item)
        seen.add(key)
        if len(selected) >= limit:
            break
    return selected


def truncate_child_summaries(summaries, limit=12, char_limit=350):
    result = []
    for item in summaries[:limit]:
        if isinstance(item, dict):
            text = item.get("summary") or item.get("technical_behavior") or ""
            result.append({"ea": item.get("ea", ""), "name": item.get("name", ""), "summary": str(text)[:char_limit]})
        else:
            result.append(str(item)[:char_limit])
    return result


def compute_spa_input_hash(context, child_summaries=None):
    h = hashlib.sha256()
    payload = {
        "version": SPA_CACHE_VERSION,
        "ea": context.get("ea"),
        "name": context.get("name"),
        "code": context.get("code", ""),
        "apis": context.get("apis", []),
        "strings": context.get("strings", []),
        "decoded_strings": context.get("decoded_strings", []),
        "constants": context.get("constants", []),
        "children": child_summaries or [],
    }
    h.update(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8", errors="replace"))
    return "spa_" + h.hexdigest()


def _esc(text):
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _user_cancelled():
    if not _IN_IDA:
        return False
    try:
        return bool(ida_kernwin.user_cancelled())
    except Exception:
        return False


class StaticProgramAnalyzer(object):
    def __init__(self, cfg=None, mode="current_function", roots=None):
        self.cfg = load_config() if cfg is None else dict(cfg)
        self.cache_cfg = _cache_cfg(self.cfg)
        self.mode = mode
        self.roots = roots or []
        self.graph = None
        self.contexts = {}
        self.scored_items = []
        self.selected_items = []
        self.results = {}
        self.review_suggestions = []
        self.artifact_dir = make_artifact_dir(self.cfg, input_path=_input_path())
        self.last_report_path = ""
        self.cancelled = False

    def collect_scope(self, mode, roots=None):
        if roots:
            return sorted(set(int(r) for r in roots))
        if mode == "current_function":
            ea = get_current_function_ea()
            return [ea] if ea is not None else []
        if mode == "entry_points":
            return get_entry_points()
        if mode in ("review_priority_only", "limited_program"):
            if not _IN_IDA:
                return []
            try:
                funcs = list(idautils.Functions())
                return funcs[:int(self.cfg.get("spa_max_functions", 300))]
            except Exception:
                return []
        return []

    def build_call_graph(self, roots, max_depth=None, max_functions=None):
        self.graph = build_call_graph_from_roots(
            roots,
            max_depth=int(max_depth if max_depth is not None else self.cfg.get("spa_max_depth", 5)),
            max_functions=int(max_functions if max_functions is not None else self.cfg.get("spa_max_functions", 300)),
            include_library_funcs=bool(self.cfg.get("spa_include_library_funcs", False)),
        )
        return self.graph

    def collect_function_contexts(self, graph):
        from static_analysis import build_function_context
        for key, node in graph.get("nodes", {}).items():
            if _user_cancelled():
                self.cancelled = True
                log.warn("Static Program Analyzer context collection cancelled; saving partial results.")
                break
            ea = int(node["ea"])
            try:
                ctx = build_function_context(ea, self.cfg)
            except Exception as exc:
                ctx = {
                    "ea": key,
                    "name": node.get("name", "sub_%x" % ea),
                    "code": "",
                    "code_type": "",
                    "apis": [],
                    "strings": [],
                    "decoded_strings": [],
                    "constants": [],
                    "callers": node.get("callers", []),
                    "callees": node.get("callees", []),
                    "pre_tags": [],
                    "pre_reasons": ["context_error:%s" % str(exc)[:80]],
                    "n_insn": 0,
                }
            self.contexts[key] = ctx
        return self.contexts

    def score_functions(self, contexts):
        self.scored_items = []
        for key, ctx in contexts.items():
            score = score_function_for_review(ctx)
            item = {
                "ea_hex": key,
                "ea": _parse_ea(ctx.get("ea")) or _parse_ea(key),
                "name": ctx.get("name", ""),
                "context": ctx,
                "static_score": score,
            }
            self.scored_items.append(item)
        self.scored_items = sort_by_priority(self.scored_items)
        return self.scored_items

    def select_ai_candidates(self, scored_items):
        roots = set((self.graph or {}).get("roots", []))
        self.selected_items = select_ai_candidates_for_review(
            scored_items,
            limit=int(self.cfg.get("spa_ai_function_limit", 80)),
            min_score=int(self.cfg.get("spa_min_priority_score", 3)),
            include_named=bool(self.cfg.get("spa_include_named_funcs", True)),
            roots=roots,
        )
        return self.selected_items

    def _child_summaries_for(self, key):
        children = []
        for edge in (self.graph or {}).get("edges", []):
            if edge.get("caller") != key:
                continue
            child_key = edge.get("callee")
            result = self.results.get(child_key)
            if result:
                children.append({
                    "ea": child_key,
                    "name": (self.contexts.get(child_key) or {}).get("name", ""),
                    "summary": result.get("summary", ""),
                    "technical_behavior": result.get("technical_behavior", ""),
                })
        return truncate_child_summaries(
            children,
            limit=int(self.cfg.get("spa_child_summary_limit", 12)),
        )

    def _build_prompt(self, item, child_summaries):
        ctx = item["context"]
        score = item["static_score"]
        decoded = [
            s.get("value", "") if isinstance(s, dict) else str(s)
            for s in (ctx.get("decoded_strings", []) or [])[:8]
        ]
        prompt = {
            "address": ctx.get("ea"),
            "current_name": ctx.get("name"),
            "static_priority_score": score,
            "callers": ctx.get("callers", [])[:12],
            "callees": ctx.get("callees", [])[:20],
            "apis": ctx.get("apis", [])[:24],
            "strings": ctx.get("strings", [])[:16],
            "decoded_strings": [s for s in decoded if s],
            "constants": ctx.get("constants", [])[:16],
            "static_tags": ctx.get("pre_tags", [])[:12],
            "child_summaries": child_summaries,
            "code_type": ctx.get("code_type", ""),
            "code": (ctx.get("code", "") or "")[:min(int(self.cfg.get("spa_prompt_char_budget", 48000)), MAX_CHARS_PER_FUNC * 4)],
        }
        try:
            notes = load_blob(_parse_ea(ctx.get("ea")) or item["ea"], "analyst_notes")
            if notes:
                prompt["analyst_notes"] = str(notes)[:1200]
        except Exception:
            pass
        return json.dumps(prompt, indent=2, ensure_ascii=False)

    def analyze_selected_functions(self, selected_items):
        from providers import make_provider
        from prompts import STATIC_PROGRAM_FUNCTION_SYSTEM_PROMPT

        try:
            provider = make_provider(self.cfg)
        except Exception as exc:
            log.warn("Static Program Analyzer provider unavailable: %s" % str(exc)[:300])
            for item in self.scored_items:
                key = item["ea_hex"]
                if key not in self.results:
                    result = self._static_only_result(
                        item,
                        "provider_unavailable:%s" % str(exc)[:120],
                        mode="provider_unavailable")
                    self.results[key] = result
                    self._save_function_result(key, item, result)
            return {"results": self.results, "review_suggestions": self.review_suggestions, "error": str(exc)}

        selected_by_key = {item["ea_hex"]: item for item in selected_items}
        order = topological_order_bottom_up(self.graph or {})
        order = [k for k in order if k in selected_by_key]
        log.info("Static Program Analyzer: %d AI candidate(s)." % len(order))

        for idx, key in enumerate(order, 1):
            if self.cancelled:
                break
            item = selected_by_key[key]
            ctx = item["context"]
            child_summaries = self._child_summaries_for(key)
            cache_key = compute_spa_input_hash(ctx, child_summaries)
            cached = cache_get(self.cache_cfg, cache_key) if self.cfg.get("spa_use_cache", True) else None
            if cached:
                result = cached
                if isinstance(result, dict):
                    result.setdefault("_analysis_mode", "ai")
                log.info("[SPA CACHE HIT] %s" % ctx.get("name", key))
            else:
                log.info("[SPA CACHE MISS] %s" % ctx.get("name", key))
                prompt = self._build_prompt(item, child_summaries)
                try:
                    raw = provider._call(STATIC_PROGRAM_FUNCTION_SYSTEM_PROMPT, prompt, max_tokens=1000)
                    result = parse_spa_result(raw, original_name=ctx.get("name", ""), cfg=self.cfg)
                    result["_analysis_mode"] = "ai"
                    cache_put(self.cache_cfg, cache_key, result, ctx.get("name", ""), ctx.get("code_type", ""))
                except Exception as exc:
                    log.warn("SPA AI error for %s: %s" % (ctx.get("name", key), str(exc)[:250]))
                    result = self._static_only_result(item, "ai_error:%s" % str(exc)[:120], mode="ai_error")
            self.results[key] = result
            self._save_function_result(key, item, result)
            self._collect_review_suggestion(key, item, result)
            log.info("Static Program Analyzer: %d/%d %s" % (idx, len(order), ctx.get("name", key)))

        for item in self.scored_items:
            key = item["ea_hex"]
            if key not in self.results:
                result = self._static_only_result(item, "static_only", mode="static_only")
                self.results[key] = result
                self._save_function_result(key, item, result)
        return {"results": self.results, "review_suggestions": self.review_suggestions}

    def _static_only_result(self, item, note, mode="static_only"):
        score = item.get("static_score", {})
        return {
            "function_name": sanitize_name(item.get("name", "unknown_func")).lower(),
            "confidence": 0.0,
            "priority": score.get("priority", "low"),
            "category": "UNKNOWN",
            "summary": "Static-only review item.",
            "technical_behavior": "No AI analysis was performed for this function.",
            "evidence": score.get("reasons", [])[:8] or [note],
            "data_flows": [],
            "called_behaviors": [],
            "warnings": [note],
            "rename_recommendation": {"apply": False, "name": "", "reason": ""},
            "analyst_notes": [],
            "_analysis_mode": mode,
        }

    def _save_function_result(self, key, item, result):
        ea = item.get("ea")
        if ea is None:
            return
        payload = {
            "ea": key,
            "name": item.get("name", ""),
            "static_score": item.get("static_score", {}),
            "analysis": result,
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        save_blob(ea, SPA_METADATA_KEY, payload)

    def _collect_review_suggestion(self, key, item, result):
        rec = result.get("rename_recommendation", {})
        if not rec.get("apply") or not rec.get("name"):
            return
        self.review_suggestions.append({
            "ea": item.get("ea"),
            "old_name": item.get("name", ""),
            "ai_result": {
                "name": rec.get("name"),
                "confidence": result.get("confidence", 0.0),
                "category": result.get("category", "UNKNOWN"),
                "description": result.get("summary", ""),
                "evidence": result.get("evidence", []),
                "warnings": result.get("warnings", []),
                "tags": [result.get("category", "UNKNOWN")],
            },
        })

    def save_artifacts(self, results):
        if not self.cfg.get("spa_save_artifacts", True):
            return ""
        try:
            os.makedirs(os.path.join(self.artifact_dir, "functions"), exist_ok=True)
        except Exception as exc:
            log.warn("SPA artifact directory error: %s" % exc)
            return ""

        def write_json(name, data):
            try:
                path = os.path.join(self.artifact_dir, name)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                return path
            except Exception as exc:
                log.warn("SPA artifact write failed (%s): %s" % (name, exc))
                return ""

        write_json("summary.json", self.update_summary_data(results))
        write_json("call_graph.json", self.graph or {})
        score_rows = [
            {
                "ea": item.get("ea_hex"),
                "name": item.get("name", ""),
                "static_score": item.get("static_score", {}),
            }
            for item in self.scored_items
        ]
        write_json("function_scores.json", score_rows)
        write_json("review_suggestions.json", self.review_suggestions)
        try:
            from ioc_extractor import extract_iocs_from_binary
            write_json("iocs.json", extract_iocs_from_binary())
        except Exception:
            write_json("iocs.json", {})

        for item in self.scored_items:
            key = item["ea_hex"].replace("0x", "").zfill(8).upper()
            ctx = item.get("context", {})
            write_json(os.path.join("functions", "%s_context.json" % key), ctx)
            write_json(os.path.join("functions", "%s_analysis.json" % key), self.results.get(item["ea_hex"], {}))
            try:
                with open(os.path.join(self.artifact_dir, "functions", "%s_code.txt" % key), "w", encoding="utf-8") as f:
                    f.write(ctx.get("code", "") or "")
            except Exception:
                pass

        report = self.generate_html_report(results)
        if report:
            self.last_report_path = report
            self._save_last_report_path(report)
        return self.artifact_dir

    def update_summary_data(self, results):
        result_map = results.get("results", results) if isinstance(results, dict) else self.results
        if not isinstance(result_map, dict):
            result_map = self.results
        analyzed = [r for r in result_map.values()
                    if isinstance(r, dict) and r.get("_analysis_mode") == "ai"]
        high = [i for i in self.scored_items if i.get("static_score", {}).get("priority") in ("high", "critical")]
        return {
            "schema": "gpt_renamer_static_program_analysis_v1",
            "binary": _input_path(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "mode": self.mode,
            "total_functions": len(self.scored_items),
            "ai_analyzed": len(analyzed),
            "static_only": max(0, len(self.scored_items) - len(analyzed)),
            "high_or_critical": len(high),
            "review_suggestions": len(self.review_suggestions),
            "artifact_dir": self.artifact_dir,
        }

    update_report_data = update_summary_data

    def generate_html_report(self, results):
        try:
            os.makedirs(self.artifact_dir, exist_ok=True)
            path = os.path.join(self.artifact_dir, "report_static.html")
            summary = self.update_summary_data(results)
            rows = []
            for item in self.scored_items:
                res = self.results.get(item["ea_hex"], {})
                score = item.get("static_score", {})
                rows.append(
                    "<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                        _esc(item["ea_hex"]), _esc(item.get("name", "")),
                        score.get("score", 0), _esc(score.get("priority", "")),
                        _esc(res.get("category", "")), _esc("; ".join(score.get("reasons", [])[:4]))))
            analyses = []
            for item in self.scored_items:
                res = self.results.get(item["ea_hex"], {})
                ctx = item.get("context", {})
                decoded = [
                    s.get("value", "") if isinstance(s, dict) else str(s)
                    for s in (ctx.get("decoded_strings", []) or [])[:8]
                ]
                analyses.append(
                    "<h3>%s %s</h3><p><b>Suggested:</b> %s conf=%.2f priority=%s category=%s</p>"
                    "<p>%s</p><pre>%s</pre><p><b>APIs:</b> %s</p><p><b>Strings:</b> %s</p>"
                    "<p><b>Decoded:</b> %s</p>" % (
                        _esc(item["ea_hex"]), _esc(item.get("name", "")),
                        _esc(res.get("rename_recommendation", {}).get("name", "")),
                        res.get("confidence", 0.0), _esc(res.get("priority", "")),
                        _esc(res.get("category", "")), _esc(res.get("summary", "")),
                        _esc("\n".join(res.get("evidence", [])[:8])),
                        _esc(", ".join(ctx.get("apis", [])[:12])),
                        _esc("; ".join(ctx.get("strings", [])[:8])),
                        _esc("; ".join([d for d in decoded if d]))))
            html = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>GPT Renamer Static Program Analysis</title>
<style>body{font-family:Consolas,monospace;background:#101218;color:#d8dbea;padding:16px}
table{border-collapse:collapse;width:100%%}td,th{border:1px solid #2a2d3d;padding:4px 6px}
th{color:#75a7ff;background:#171a24}h1,h2{color:#75a7ff}.section{margin:12px 0;padding:10px;border:1px solid #2a2d3d}
pre{white-space:pre-wrap;background:#0b0d12;padding:8px}</style></head><body>
<h1>GPT Renamer Static Program Analysis</h1>
<div class="section"><b>Binary:</b> %(binary)s<br><b>Mode:</b> %(mode)s<br>
<b>Functions:</b> %(total)d <b>AI analyzed:</b> %(ai)d <b>Review suggestions:</b> %(suggestions)d</div>
<h2>Function Priority Summary</h2><div class="section"><table><tr><th>EA</th><th>Name</th><th>Score</th><th>Priority</th><th>Category</th><th>Reasons</th></tr>%(rows)s</table></div>
<h2>Call Graph Summary</h2><div class="section"><pre>Roots: %(roots)s\nCycles: %(cycles)s</pre></div>
<h2>Function Analyses</h2><div class="section">%(analyses)s</div>
<h2>Pending Rename Suggestions</h2><div class="section"><pre>%(suggestions_json)s</pre></div>
</body></html>""" % {
                "binary": _esc(summary.get("binary", "")),
                "mode": _esc(summary.get("mode", "")),
                "total": summary.get("total_functions", 0),
                "ai": summary.get("ai_analyzed", 0),
                "suggestions": summary.get("review_suggestions", 0),
                "rows": "\n".join(rows),
                "roots": _esc(", ".join((self.graph or {}).get("roots", []))),
                "cycles": _esc(json.dumps((self.graph or {}).get("cycles", []))),
                "analyses": "\n".join(analyses),
                "suggestions_json": _esc(json.dumps(self.review_suggestions, indent=2)),
            }
            with open(path, "w", encoding="utf-8") as f:
                f.write(html)
            return path
        except Exception as exc:
            log.warn("SPA HTML report failed: %s" % exc)
            return ""

    def _save_last_report_path(self, path):
        try:
            marker = os.path.join(_base_output_dir(self.cfg), SPA_REPORT_MARKER)
            with open(marker, "w", encoding="utf-8") as f:
                json.dump({"path": path, "saved_at": time.strftime("%Y-%m-%d %H:%M:%S")}, f)
        except Exception:
            pass

    def prepare(self, mode=None, roots=None):
        self.mode = mode or self.mode
        self.roots = self.collect_scope(self.mode, roots or self.roots)
        self.build_call_graph(self.roots)
        self.collect_function_contexts(self.graph)
        self.score_functions(self.contexts)
        self.select_ai_candidates(self.scored_items)
        return self

    def save_results(self):
        return self.save_artifacts({"results": self.results, "review_suggestions": self.review_suggestions})


def open_last_static_report(cfg=None):
    cfg = cfg or load_config()
    try:
        marker = os.path.join(_base_output_dir(cfg), SPA_REPORT_MARKER)
        with open(marker, "r", encoding="utf-8") as f:
            path = json.load(f).get("path", "")
        if path and os.path.exists(path):
            webbrowser.open("file://" + os.path.abspath(path))
            return path
    except Exception as exc:
        log.warn("Open last SPA report failed: %s" % exc)
    return ""
