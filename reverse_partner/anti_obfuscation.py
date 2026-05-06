# -*- coding: utf-8 -*-
"""
anti_obfuscation.py — 4-pass static anti-obfuscation scanner
=============================================================
STATIC ONLY — never touches a running process.
All write operations route through ida_write.safe_apply_name / safe_set_cmt.

Pass 1 — Hash-based API resolution (ROR13, DJB2, FNV1a)
Pass 2 — Indirect / vtable call tracing
Pass 3 — Dispatcher / switch-table mapping
Pass 4 — Wrapper rename with v5 naming (resolve_and_call_<API>_aN)
"""

import re
from collections import defaultdict
from guards import require_static_mode, is_debugger_active
from ida_write import safe_apply_name, safe_set_cmt, safe_set_func_cmt
from utils import sanitize_name, is_default_name
from logger import log

try:
    import idaapi, idautils, idc, ida_funcs, ida_segment
    import ida_bytes, ida_ua, ida_name, ida_xref
    _HAVE_IDA = True
except ImportError:
    _HAVE_IDA = False

# ---------------------------------------------------------------------------
# Hash tables — ROR13 (PEB walk), DJB2, FNV1a
# ---------------------------------------------------------------------------

_WINAPI_NAMES = [
    "VirtualAlloc","VirtualAllocEx","VirtualFree","VirtualProtect","VirtualProtectEx",
    "WriteProcessMemory","ReadProcessMemory","CreateRemoteThread","NtCreateThreadEx",
    "OpenProcess","CreateProcessA","CreateProcessW","ShellExecuteA","ShellExecuteW",
    "LoadLibraryA","LoadLibraryW","GetProcAddress","GetModuleHandleA","GetModuleHandleW",
    "CreateFileA","CreateFileW","ReadFile","WriteFile","CloseHandle",
    "DeleteFileA","DeleteFileW","MoveFileA","MoveFileW","CopyFileA","CopyFileW",
    "RegOpenKeyExA","RegOpenKeyExW","RegQueryValueExA","RegQueryValueExW",
    "RegSetValueExA","RegSetValueExW","RegCreateKeyA","RegCreateKeyW",
    "WSAStartup","socket","connect","send","recv","closesocket","bind","listen","accept",
    "gethostbyname","gethostbyaddr",
    "InternetOpenA","InternetOpenW","InternetConnectA","InternetConnectW",
    "InternetReadFile","InternetWriteFile","HttpSendRequestA","HttpSendRequestW",
    "HttpOpenRequestA","HttpOpenRequestW",
    "WinHttpOpen","WinHttpConnect","WinHttpSendRequest","WinHttpReadData",
    "URLDownloadToFileA","URLDownloadToFileW",
    "CreateThread","ExitProcess","ExitThread","TerminateProcess","TerminateThread",
    "SuspendThread","ResumeThread","GetTickCount","GetTickCount64",
    "Sleep","SleepEx","WaitForSingleObject","WaitForMultipleObjects",
    "CreateMutexA","CreateMutexW","OpenMutexA","OpenMutexW",
    "CreateEventA","CreateEventW","OpenEventA","OpenEventW",
    "SetFileAttributesA","SetFileAttributesW","GetTempPathA","GetTempPathW",
    "CryptAcquireContextA","CryptAcquireContextW","CryptCreateHash","CryptHashData",
    "CryptEncrypt","CryptDecrypt","CryptGenKey","CryptDeriveKey","CryptGenRandom",
    "BCryptEncrypt","BCryptDecrypt","BCryptGenerateSymmetricKey","BCryptOpenAlgorithmProvider",
    "NtAllocateVirtualMemory","NtWriteVirtualMemory","NtMapViewOfSection",
    "NtQueryInformationProcess","NtSetInformationThread","NtResumeThread",
    "RtlDecompressBuffer","RtlCompressBuffer","RtlAllocateHeap",
    "IsDebuggerPresent","CheckRemoteDebuggerPresent","DbgBreakPoint",
    "CreateServiceA","CreateServiceW","OpenSCManagerA","OpenSCManagerW",
    "StartServiceA","StartServiceW","DeleteService",
    "SetWindowsHookExA","SetWindowsHookExW","CallNextHookEx","UnhookWindowsHookEx",
    "EnumProcesses","Process32First","Process32Next","CreateToolhelp32Snapshot",
    "Module32First","Module32Next","Thread32First","Thread32Next",
    "GetComputerNameA","GetComputerNameW","GetUserNameA","GetUserNameW",
    "GetSystemInfo","GetAdaptersInfo","GetAdaptersAddresses",
    "QueueUserAPC","ZwCreateSection","RtlCreateUserThread",
    "CoCreateInstance","OleInitialize","CoInitialize",
]


def _ror32(v: int, n: int) -> int:
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF


def hash_ror13(name: str) -> int:
    h = 0
    for c in (name + "\x00"):
        h = (_ror32(h, 13) + ord(c)) & 0xFFFFFFFF
    return h


def hash_djb2(name: str) -> int:
    h = 5381
    for c in name:
        h = ((h << 5) + h + ord(c)) & 0xFFFFFFFF
    return h


def hash_fnv1a(name: str) -> int:
    h = 0x811c9dc5
    for c in name:
        h = ((h ^ ord(c)) * 0x01000193) & 0xFFFFFFFF
    return h


_ROR13_TABLE:  dict = {}
_CUSTOM_TABLE: dict = {}


def _build_tables():
    for name in _WINAPI_NAMES:
        _ROR13_TABLE[hash_ror13(name)]  = name
        _CUSTOM_TABLE[hash_djb2(name)]  = name
        _CUSTOM_TABLE[hash_fnv1a(name)] = name


_build_tables()


def lookup_hash(val: int) -> str:
    return _ROR13_TABLE.get(val) or _CUSTOM_TABLE.get(val) or ""


# ---------------------------------------------------------------------------
# Pass 1 — Hash API resolution
# ---------------------------------------------------------------------------

def pass1_resolve_hashes() -> dict:
    """
    Scan all code segments for integer immediates that match known API hashes.
    Annotates matching instructions with comments.
    READ/WRITE — write path goes through safe_set_cmt().
    """
    if not _HAVE_IDA:
        return {}
    if is_debugger_active():
        log.warn("Pass1 skipped: debugger active.")
        return {}

    results = {}
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if not seg or seg.type != ida_segment.SEG_CODE:
            continue
        ea = seg.start_ea
        while ea < seg.end_ea:
            try:
                insn = ida_ua.insn_t()
                size = ida_ua.decode_insn(insn, ea)
                if size == 0:
                    ea += 1
                    continue
                mnem = insn.get_canon_mnem()
                if mnem in ("mov", "push"):
                    for op in insn.ops:
                        if op.type == ida_ua.o_imm:
                            val = op.value & 0xFFFFFFFF
                            if val > 0xFFFF:
                                api = lookup_hash(val)
                                if api:
                                    results[ea] = (val, api)
                                    existing = idc.get_cmt(ea, 0) or ""
                                    if api not in existing:
                                        safe_set_cmt(ea, "HASH→%s" % api)
                ea += max(size, 1)
            except Exception:
                ea += 1
    log.ok("Pass1: %d hash matches annotated." % len(results))
    return results


# ---------------------------------------------------------------------------
# Pass 2 — Indirect / vtable call tracing
# ---------------------------------------------------------------------------

def pass2_trace_indirect_calls() -> list:
    """
    Track register values to resolve indirect calls (vtable, thunk tables).
    Returns list of (call_ea, caller_func_ea, target_ea, target_name).
    Annotates call sites with comments.
    """
    if not _HAVE_IDA:
        return []
    if is_debugger_active():
        log.warn("Pass2 skipped: debugger active.")
        return []

    results = []
    try:
        ptr_size = 8 if idaapi.inf_is_64bit() else 4
    except AttributeError:
        ptr_size = 8 if idaapi.get_inf_structure().is_64bit() else 4

    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        reg_vals: dict = {}
        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, head) == 0:
                    continue
                mnem = insn.get_canon_mnem()

                # Track: mov reg, [mem] or lea reg, [mem]
                if mnem in ("mov", "lea") and insn.ops[0].type == ida_ua.o_reg:
                    if insn.ops[1].type == ida_ua.o_mem:
                        addr = insn.ops[1].addr
                        try:
                            val = (ida_bytes.get_qword(addr) if ptr_size == 8
                                   else ida_bytes.get_dword(addr))
                            if val and val != idaapi.BADADDR:
                                reg_vals[insn.ops[0].reg] = val
                        except Exception:
                            pass

                if mnem == "call":
                    op        = insn.ops[0]
                    target_ea = idaapi.BADADDR

                    if op.type in (ida_ua.o_phrase, ida_ua.o_displ):
                        base_val = reg_vals.get(op.reg, idaapi.BADADDR)
                        offset   = op.addr if op.type == ida_ua.o_displ else 0
                        if base_val and base_val != idaapi.BADADDR:
                            ptr_ea = (base_val + offset) & 0xFFFFFFFFFFFFFFFF
                            try:
                                target_ea = (ida_bytes.get_qword(ptr_ea) if ptr_size == 8
                                             else ida_bytes.get_dword(ptr_ea))
                            except Exception:
                                pass
                    elif op.type == ida_ua.o_mem:
                        try:
                            target_ea = (ida_bytes.get_qword(op.addr) if ptr_size == 8
                                         else ida_bytes.get_dword(op.addr))
                        except Exception:
                            pass

                    if target_ea and target_ea != idaapi.BADADDR:
                        if ida_funcs.get_func(target_ea):
                            tname = idc.get_func_name(target_ea) or hex(target_ea)
                            results.append((head, func_ea, target_ea, tname))
                            safe_set_cmt(head, "→ %s" % tname)
        except Exception:
            continue

    log.ok("Pass2: %d indirect calls resolved." % len(results))
    return results


# ---------------------------------------------------------------------------
# Pass 3 — Dispatcher / switch table mapping
# ---------------------------------------------------------------------------

def pass3_analyze_dispatchers() -> dict:
    """
    Find dispatcher functions (by name pattern) and map their
    hash→target tables by tracking cmp/jcc pairs.
    Annotates dispatchers with function comments.
    """
    if not _HAVE_IDA:
        return {}
    if is_debugger_active():
        log.warn("Pass3 skipped: debugger active.")
        return {}

    results     = {}
    disp_re     = re.compile(
        r"dispatch|resolver|wrapper|indirect|vtable|thunk|trampoline|gateway",
        re.IGNORECASE
    )

    for func_ea in idautils.Functions():
        name = idc.get_func_name(func_ea) or ""
        if not disp_re.search(name):
            continue
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue

        hash_map:     dict = {}
        prev_cmp_val: int  = 0

        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, head) == 0:
                    continue
                mnem = insn.get_canon_mnem()

                if mnem == "cmp":
                    for op in insn.ops:
                        if op.type == ida_ua.o_imm and op.value > 0xFFFF:
                            prev_cmp_val = op.value & 0xFFFFFFFFFFFFFFFF

                elif mnem in ("je","jz","jne","jnz","jg","jl","jge","jle"):
                    if prev_cmp_val and insn.ops[0].type == ida_ua.o_near:
                        hash_map[prev_cmp_val] = insn.ops[0].addr
                    prev_cmp_val = 0
                else:
                    prev_cmp_val = 0
        except Exception:
            pass

        if hash_map:
            results[func_ea] = hash_map
            summary = "DISPATCH MAP: " + ", ".join(
                "0x%x→%s" % (h, hex(b)) for h, b in list(hash_map.items())[:8]
            )
            safe_set_func_cmt(func_ea, summary)

    log.ok("Pass3: %d dispatchers mapped." % len(results))
    return results


# ---------------------------------------------------------------------------
# Pass 4 — Wrapper rename (v5 naming)
# ---------------------------------------------------------------------------

def _estimate_arg_count(ea: int) -> int:
    """Heuristic: count push instructions before the first call."""
    func = ida_funcs.get_func(ea)
    if not func:
        return 0
    push_count = 0
    try:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            insn = ida_ua.insn_t()
            if ida_ua.decode_insn(insn, head) == 0:
                continue
            mnem = insn.get_canon_mnem()
            if mnem == "push":
                push_count += 1
            elif mnem == "call":
                return push_count
    except Exception:
        pass
    return 0


def pass4_rename_wrappers(indirect_results: list) -> list:
    """
    v5 wrapper naming:
      resolve_and_call_<API>_aN   if function has default name + single target
      wrap_<API>                  if already named wrapper-style
      indirect_call_<API>         fallback

    Skips: multiple unrelated targets, low-confidence, already meaningful names.
    """
    if not _HAVE_IDA:
        return []
    if not require_static_mode("Pass4 wrapper rename"):
        return []

    renamed            = []
    call_counter: dict = defaultdict(lambda: defaultdict(int))

    for call_ea, caller_ea, target_ea, target_name in indirect_results:
        call_counter[caller_ea][target_ea] += 1

    for caller_ea, target_counts in call_counter.items():
        old_name = idc.get_func_name(caller_ea) or ""

        # Only rename wrapper-looking or default-named functions
        is_default   = is_default_name(old_name)
        is_wrapper_ish = bool(re.search(
            r"(wrapper|indirect|dynamic|dispatch|thunk|sub_)", old_name, re.I))
        if not is_default and not is_wrapper_ish:
            continue

        # Must resolve to exactly one target
        if len(target_counts) != 1:
            continue

        target_ea  = list(target_counts.keys())[0]
        target_name = idc.get_func_name(target_ea) or ""
        if not target_name or is_default_name(target_name):
            continue

        n_args   = _estimate_arg_count(caller_ea)
        stripped = re.sub(r"^(j_|_+)", "", target_name)   # strip j_ prefix

        if is_default:
            new_name = ("resolve_and_call_%s_a%d" % (stripped, n_args)
                        if n_args > 0
                        else "resolve_and_call_%s" % stripped)
        elif "indirect" in old_name.lower():
            new_name = "indirect_call_%s" % stripped
        else:
            new_name = "wrap_%s" % stripped

        new_name = sanitize_name(new_name)

        # Avoid collision with existing name
        if idc.get_name_ea_simple(new_name) not in (idaapi.BADADDR, caller_ea):
            new_name = "%s_%x" % (new_name, caller_ea & 0xFFF)

        applied = safe_apply_name(caller_ea, new_name)
        if applied:
            renamed.append((old_name, applied, caller_ea))
            log.ok("Deobfus wrapper: %s → %s" % (old_name, applied))

    log.ok("Pass4: %d wrappers renamed." % len(renamed))
    return renamed


# ---------------------------------------------------------------------------
# Top-level scanner
# ---------------------------------------------------------------------------

def run_scanner() -> dict:
    """
    Run all 4 passes. Returns summary dict.
    """
    if not require_static_mode("Anti-Obfuscation Scanner"):
        return {}

    log.sep()
    log.info("ANTI-OBFUSCATION SCANNER v5 — static only")

    log.info("Pass 1: Hash API resolution …")
    h = pass1_resolve_hashes()

    log.info("Pass 2: Indirect call tracing …")
    i = pass2_trace_indirect_calls()

    log.info("Pass 3: Dispatcher mapping …")
    d = pass3_analyze_dispatchers()

    log.info("Pass 4: Wrapper rename …")
    r = pass4_rename_wrappers(i)

    log.sep()
    log.info("SCANNER DONE: hashes=%d  indirect=%d  dispatchers=%d  wrappers=%d" % (
        len(h), len(i), len(d), len(r)))
    log.sep()

    return {
        "hash_matches":   len(h),
        "indirect_calls": len(i),
        "dispatchers":    len(d),
        "wrappers_named": len(r),
    }
