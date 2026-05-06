# -*- coding: utf-8 -*-
"""
ida_read.py — IDA read-only data collection
=============================================
ALL functions here are READ-ONLY.
Safe to call in any mode including while debugger is attached.
MAIN THREAD ONLY (IDA API requirement).
"""

import re
from collections import deque, defaultdict
from config import MAX_FUNC_SIZE_FOR_DECOMPILE

try:
    import idaapi
    import idautils
    import idc
    import ida_funcs
    import ida_xref
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

from guards import is_debugger_active
from logger import log


# ── Decompiler / assembly ────────────────────────────────────────────────────

def safe_decompile(ea: int):
    """
    Decompile a function safely.
    Skips when: debugger active, function too large, Hex-Rays unavailable.
    Returns pseudocode string or None.
    [FIX v4 preserved] No timeout crash; execute_sync for thread safety.
    """
    if is_debugger_active():
        return None
    func = ida_funcs.get_func(ea)
    if not func:
        return None
    func_size = func.end_ea - func.start_ea
    if func_size > MAX_FUNC_SIZE_FOR_DECOMPILE:
        log.warn("  Skip decompile (size=0x%x > limit): %s" % (
            func_size, idc.get_func_name(ea) or hex(ea)))
        return None

    result = [None]

    def _do():
        try:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                return
            try:
                cfunc = ida_hexrays.decompile(ea, flags=ida_hexrays.DECOMP_NO_WAIT)
            except (AttributeError, TypeError):
                cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                result[0] = str(cfunc)
        except Exception:
            pass

    try:
        idaapi.execute_sync(_do, idaapi.MFF_READ)
    except TypeError:
        _do()
    except Exception:
        _do()

    return result[0]


def get_assembly(ea: int, max_lines: int = 80) -> str:
    """Return disassembly text for a function. Safe in all modes."""
    lines = []
    func  = ida_funcs.get_func(ea)
    if not func:
        return ""
    try:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            disasm = idc.generate_disasm_line(head, 0)
            if disasm:
                lines.append("  %s: %s" % (hex(head), disasm))
            if len(lines) >= max_lines:
                lines.append("  ...")
                break
    except Exception:
        pass
    return "\n".join(lines)


def get_code(ea: int, use_pseudocode: bool) -> tuple:
    """
    Return (code_text, code_type) for a function.
    Prefers pseudocode when use_pseudocode=True AND debugger is not active.
    Falls back to assembly.
    """
    if use_pseudocode:
        code = safe_decompile(ea)
        if code:
            return code, "pseudocode"
    asm = get_assembly(ea)
    return (asm or None), "assembly"


# ── Cross-references ─────────────────────────────────────────────────────────

def get_callee_names(ea: int, limit: int = 20) -> list:
    """Names of functions called by ea. READ-ONLY."""
    names = []
    func  = ida_funcs.get_func(ea)
    if not func:
        return names
    seen = set()
    try:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            ref = ida_xref.get_first_cref_from(head)
            while ref != idaapi.BADADDR:
                callee = ida_funcs.get_func(ref)
                if callee and callee.start_ea not in seen and callee.start_ea != ea:
                    seen.add(callee.start_ea)
                    nm = idc.get_func_name(callee.start_ea) or ""
                    if nm:
                        names.append(nm)
                        if len(names) >= limit:
                            return names
                ref = ida_xref.get_next_cref_from(head, ref)
    except Exception:
        pass
    return names


def get_caller_names(ea: int, limit: int = 10) -> list:
    """Names of functions that call ea. READ-ONLY."""
    names = []
    seen  = set()
    try:
        ref = ida_xref.get_first_cref_to(ea)
        while ref != idaapi.BADADDR:
            caller = ida_funcs.get_func(ref)
            if caller and caller.start_ea not in seen and caller.start_ea != ea:
                seen.add(caller.start_ea)
                nm = idc.get_func_name(caller.start_ea) or ""
                if nm:
                    names.append(nm)
                    if len(names) >= limit:
                        break
            ref = ida_xref.get_next_cref_to(ea, ref)
    except Exception:
        pass
    return names


# ── String / API / constant collection ───────────────────────────────────────

def get_referenced_strings(ea: int, limit: int = 20) -> list:
    """
    String literals referenced by function at ea.
    READ-ONLY. Used for AI context and IOC detection.
    """
    strings = []
    func    = ida_funcs.get_func(ea)
    if not func:
        return strings
    seen = set()
    try:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            ref = idc.get_first_dref_from(head)
            while ref != idaapi.BADADDR and len(strings) < limit:
                if ref not in seen:
                    seen.add(ref)
                    raw = idc.get_strlit_contents(ref, -1, -1)
                    if raw:
                        try:
                            s = raw.decode("utf-8", errors="replace")
                            if len(s) >= 3:
                                strings.append(s[:150])
                        except Exception:
                            pass
                ref = idc.get_next_dref_from(head, ref)
    except Exception:
        pass
    return strings


def get_referenced_apis(ea: int, limit: int = 30) -> list:
    """
    Import names called from function at ea (entries without a function body).
    READ-ONLY.
    """
    apis = []
    func = ida_funcs.get_func(ea)
    if not func:
        return apis
    seen = set()
    try:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            ref = ida_xref.get_first_cref_from(head)
            while ref != idaapi.BADADDR and len(apis) < limit:
                nm = idc.get_name(ref, 0) or ""
                if nm and nm not in seen and not ida_funcs.get_func(ref):
                    seen.add(nm)
                    apis.append(nm)
                ref = ida_xref.get_next_cref_from(head, ref)
    except Exception:
        pass
    return apis


def get_interesting_constants(ea: int, limit: int = 30) -> list:
    """
    Collect integer immediates > 0xFFFF that are not all-F masks.
    Used for AI context (crypto constants, port numbers, magic values).
    READ-ONLY.
    """
    constants = []
    func = ida_funcs.get_func(ea)
    if not func:
        return constants
    seen = set()
    try:
        import ida_ua
        for head in idautils.Heads(func.start_ea, func.end_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) == 0:
                continue
            for op in insn.ops:
                if op.type == ida_ua.o_imm:
                    val = op.value & 0xFFFFFFFFFFFFFFFF
                    if (val > 0xFFFF
                            and val not in (0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)
                            and val not in seen):
                        seen.add(val)
                        constants.append(hex(val))
                        if len(constants) >= limit:
                            return constants
    except Exception:
        pass
    return constants


# ── Struct / context inference ────────────────────────────────────────────────

def get_local_var_types(ea: int) -> list:
    """
    [v5] Extract local variable names and types from Hex-Rays cfunc if available.
    Returns list of {"name": str, "type": str, "offset": int}.
    READ-ONLY.
    """
    if is_debugger_active():
        return []
    func = ida_funcs.get_func(ea)
    if not func:
        return []
    if (func.end_ea - func.start_ea) > MAX_FUNC_SIZE_FOR_DECOMPILE:
        return []
    vars_info = []

    def _do():
        try:
            import ida_hexrays
            if not ida_hexrays.init_hexrays_plugin():
                return
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return
            for lv in cfunc.get_lvars():
                tinfo = lv.type()
                vars_info.append({
                    "name":   lv.name,
                    "type":   str(tinfo) if tinfo else "unknown",
                    "offset": lv.location.stkoff() if lv.is_stk_var() else -1,
                })
        except Exception:
            pass

    try:
        idaapi.execute_sync(_do, idaapi.MFF_READ)
    except TypeError:
        _do()
    except Exception:
        _do()
    return vars_info[:32]


def infer_struct_access(ea: int) -> list:
    """
    [v5] Detect struct field accesses (reg+offset patterns).
    Returns list of {"base_reg": str, "offset": int, "access_ea": hex_str}.
    READ-ONLY. Useful for guessing struct layouts referenced by the function.
    """
    accesses = []
    func = ida_funcs.get_func(ea)
    if not func:
        return accesses
    try:
        import ida_ua
        for head in idautils.Heads(func.start_ea, func.end_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) == 0:
                continue
            for op in insn.ops:
                if op.type == ida_ua.o_displ and 0 < op.addr < 0x1000:
                    accesses.append({
                        "base_reg":  op.reg,
                        "offset":    op.addr,
                        "access_ea": hex(head),
                    })
    except Exception:
        pass
    # Deduplicate by (reg, offset)
    seen  = set()
    dedup = []
    for a in accesses:
        key = (a["base_reg"], a["offset"])
        if key not in seen:
            seen.add(key)
            dedup.append(a)
    return dedup[:48]


def get_xref_counts(ea: int) -> dict:
    """[v5] Count callers and callees for a function. READ-ONLY."""
    n_callers = 0
    n_callees = 0
    try:
        ref = ida_xref.get_first_cref_to(ea)
        while ref != idaapi.BADADDR:
            n_callers += 1
            ref = ida_xref.get_next_cref_to(ea, ref)
    except Exception:
        pass
    func = ida_funcs.get_func(ea)
    if func:
        seen = set()
        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                ref = ida_xref.get_first_cref_from(head)
                while ref != idaapi.BADADDR:
                    if ref not in seen:
                        seen.add(ref)
                        n_callees += 1
                    ref = ida_xref.get_next_cref_from(head, ref)
        except Exception:
            pass
    return {"n_callers": n_callers, "n_callees": n_callees}


# ── Call graph utilities ──────────────────────────────────────────────────────

def collect_all_functions() -> list:
    """Collect basic info for every function in the IDB. READ-ONLY."""
    result = []
    for ea in idautils.Functions():
        name  = idc.get_func_name(ea) or ""
        func  = ida_funcs.get_func(ea)
        n_insn = (sum(1 for _ in idautils.Heads(func.start_ea, func.end_ea))
                  if func else 0)
        result.append({"ea": ea, "name": name, "n_insn": n_insn})
    return result


def build_call_graph(func_eas: list) -> dict:
    """Build a callee map {ea: set(callee_ea)}. READ-ONLY."""
    func_set   = set(func_eas)
    callee_map = {ea: set() for ea in func_set}
    for caller_ea in func_set:
        func = ida_funcs.get_func(caller_ea)
        if not func:
            continue
        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                ref = ida_xref.get_first_cref_from(head)
                while ref != idaapi.BADADDR:
                    cf = ida_funcs.get_func(ref)
                    if cf and cf.start_ea in func_set and cf.start_ea != caller_ea:
                        callee_map[caller_ea].add(cf.start_ea)
                    ref = ida_xref.get_next_cref_from(head, ref)
        except Exception:
            pass
    return callee_map


def topological_sort(func_eas: list, callee_map: dict) -> list:
    """Topological sort of functions (callees before callers)."""
    func_set  = set(func_eas)
    in_degree = {ea: len(callee_map.get(ea, set()) & func_set) for ea in func_eas}
    queue     = deque(ea for ea in func_eas if in_degree[ea] == 0)
    result, visited = [], set()

    while queue:
        ea = queue.popleft()
        if ea in visited:
            continue
        visited.add(ea)
        result.append(ea)
        for caller in func_eas:
            if ea in callee_map.get(caller, set()) and caller not in visited:
                in_degree[caller] -= 1
                if in_degree[caller] == 0:
                    queue.append(caller)

    remaining = [ea for ea in func_eas if ea not in visited]
    if remaining:
        log.warn("%d recursive/cyclic functions — appended at end." % len(remaining))
    result.extend(remaining)
    return result
