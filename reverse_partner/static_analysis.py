# -*- coding: utf-8 -*-
"""
static_analysis.py — Rule-based static pre-tagger & context builder
=====================================================================
No AI calls. Pure static analysis of functions:
  - API-based category tagging
  - MITRE ATT&CK pre-hints
  - Struct field access inference
  - Interesting constant detection
  - Full function context builder (used in AI prompts)
"""

import re
from ida_read import (
    get_callee_names, get_referenced_apis, get_referenced_strings,
    get_interesting_constants, get_code, get_local_var_types,
    infer_struct_access, get_xref_counts,
)

try:
    import idaapi
    import idautils
    import idc
    import ida_funcs
    import ida_ua
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

# ---------------------------------------------------------------------------
# API → category map
# ---------------------------------------------------------------------------

_API_CATEGORY_MAP: dict = {
    "MEMORY": [
        "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
        "HeapAlloc", "LocalAlloc", "GlobalAlloc", "memcpy", "memmove",
        "RtlDecompressBuffer", "RtlAllocateHeap", "NtAllocateVirtualMemory",
    ],
    "PERSIST": [
        "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx", "CreateService",
        "OpenSCManager", "StartService", "sc_create", "NtSetValueKey",
        "WritePrivateProfileString", "SetFileAttributes",
    ],
    "NETWORK": [
        "socket", "connect", "send", "recv", "WSAStartup", "closesocket",
        "InternetOpen", "InternetConnect", "InternetReadFile", "InternetWriteFile",
        "HttpSendRequest", "HttpOpenRequest", "WinHttpOpen", "WinHttpConnect",
        "WinHttpSendRequest", "WinHttpReadData", "URLDownloadToFile",
        "URLDownloadToCacheFile", "FtpPutFile", "FtpGetFile",
    ],
    "CRYPTO": [
        "CryptEncrypt", "CryptDecrypt", "CryptGenKey", "CryptDeriveKey",
        "CryptAcquireContext", "CryptCreateHash", "CryptHashData",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateSymmetricKey",
        "BCryptOpenAlgorithmProvider", "BCryptImportKey",
        "RC4Init", "RC4", "AESInit",
    ],
    "EVASION": [
        "IsDebuggerPresent", "NtQueryInformationProcess", "CheckRemoteDebuggerPresent",
        "GetTickCount", "GetTickCount64", "NtSetInformationThread",
        "DbgBreakPoint", "OutputDebugString", "FindWindow",
        "NtQuerySystemInformation", "SetThreadContext",
    ],
    "INJECT": [
        "WriteProcessMemory", "CreateRemoteThread", "NtCreateThreadEx",
        "VirtualAllocEx", "NtMapViewOfSection", "QueueUserAPC",
        "SetWindowsHookEx", "NtWriteVirtualMemory", "ZwCreateSection",
        "RtlCreateUserThread", "NtResumeThread",
    ],
    "RECON": [
        "GetComputerName", "GetUserName", "GetSystemInfo", "EnumProcesses",
        "CreateToolhelp32Snapshot", "Process32First", "Process32Next",
        "GetAdaptersInfo", "GetAdaptersAddresses", "GetVolumeInformation",
        "RegOpenKeyEx", "RegQueryValueEx", "WNetGetConnection",
    ],
    "FILE": [
        "CreateFile", "ReadFile", "WriteFile", "DeleteFile", "MoveFile",
        "CopyFile", "FindFirstFile", "FindNextFile", "GetTempPath",
        "GetTempFileName", "SetFilePointer", "FlushFileBuffers",
    ],
    "EXEC": [
        "CreateProcess", "ShellExecute", "ShellExecuteEx", "WinExec",
        "CreateProcessWithToken", "CreateProcessAsUser",
        "system", "_popen", "execv",
    ],
    "LOADER": [
        "LoadLibrary", "LoadLibraryEx", "GetProcAddress",
        "GetModuleHandle", "LdrLoadDll", "NtMapViewOfSection",
    ],
}

# Flat lookup: lowercase api name → category
_API_FLAT: dict = {}
for _cat, _apis in _API_CATEGORY_MAP.items():
    for _api in _apis:
        _API_FLAT[_api.lower()] = _cat
        _API_FLAT[(_api + "A").lower()] = _cat
        _API_FLAT[(_api + "W").lower()] = _cat
        _API_FLAT[(_api + "Ex").lower()] = _cat
        _API_FLAT[(_api + "ExA").lower()] = _cat
        _API_FLAT[(_api + "ExW").lower()] = _cat

# MITRE ATT&CK hints (informational only)
_MITRE_HINTS: dict = {
    "INJECT":  "T1055 Process Injection",
    "PERSIST": "T1547 Boot/Logon Autostart | T1543 Create/Modify System Process",
    "EVASION": "T1497 Virtualization/Sandbox Evasion | T1562 Impair Defenses",
    "RECON":   "T1082 System Information Discovery",
    "CRYPTO":  "T1027 Obfuscated Files or Information",
    "NETWORK": "T1071 Application Layer Protocol",
    "EXEC":    "T1059 Command and Scripting Interpreter",
    "LOADER":  "T1574 Hijack Execution Flow | T1055 Process Injection",
}


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------

def classify_function_static(ea: int) -> tuple:
    """
    Rule-based pre-tagger.
    Returns (tags: list[str], reasons: list[str], mitre_hints: list[str]).
    READ-ONLY. Safe in all modes.
    """
    if not _IN_IDA:
        return [], [], []

    tags    = set()
    reasons = []

    # API-based tagging
    try:
        callees = get_callee_names(ea) + get_referenced_apis(ea)
        for api in callees:
            cat = _API_FLAT.get(api.lower().lstrip("_"))
            if cat:
                tags.add(cat)
                reasons.append("api:%s→%s" % (api, cat))
    except Exception:
        pass

    # Structural DISPATCH detection: many indirect calls
    try:
        func = ida_funcs.get_func(ea)
        if func:
            n_insn = sum(1 for _ in idautils.Heads(func.start_ea, func.end_ea))
            if n_insn > 80:
                indirect = 0
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    insn = ida_ua.insn_t()
                    if ida_ua.decode_insn(insn, head) == 0:
                        continue
                    if insn.get_canon_mnem() == "call":
                        op = insn.ops[0]
                        if op.type in (ida_ua.o_reg, ida_ua.o_phrase, ida_ua.o_displ):
                            indirect += 1
                if indirect >= 3:
                    tags.add("DISPATCH")
                    reasons.append("indirect_calls=%d" % indirect)
    except Exception:
        pass

    # String-based hints
    try:
        strings = get_referenced_strings(ea, limit=15)
        combined = " ".join(strings).lower()
        if any(kw in combined for kw in ("http://", "https://", ".onion", "ftp://")):
            tags.add("NETWORK")
            reasons.append("string:url_pattern")
        if any(kw in combined for kw in ("software\\", "hklm", "hkcu", "registry")):
            tags.add("PERSIST")
            reasons.append("string:registry_path")
        if any(kw in combined for kw in (".exe", ".dll", ".bat", ".ps1", ".vbs")):
            tags.add("FILE")
            reasons.append("string:executable_extension")
        if any(kw in combined for kw in ("aes", "rc4", "chacha", "salsa", "xor")):
            tags.add("CRYPTO")
            reasons.append("string:crypto_keyword")
    except Exception:
        pass

    # MITRE hints based on detected tags
    mitre_hints = []
    for tag in tags:
        hint = _MITRE_HINTS.get(tag)
        if hint:
            mitre_hints.append(hint)

    return list(tags), reasons, mitre_hints


# ---------------------------------------------------------------------------
# Full function context builder (used for AI prompts and cache keys)
# ---------------------------------------------------------------------------

def build_function_context(ea: int, cfg: dict) -> dict:
    """
    [v5] Build a rich context dict for a function EA.
    Collects everything needed for AI prompt construction.
    READ-ONLY.
    """
    use_pseudo = cfg.get("use_pseudocode", True)

    func = ida_funcs.get_func(ea)
    name = idc.get_func_name(ea) or ("sub_%x" % ea)
    code, code_type = get_code(ea, use_pseudo)
    callees  = get_callee_names(ea)
    callers  = get_caller_names_safe(ea)
    strings  = get_referenced_strings(ea)
    decoded_strings = []
    try:
        if cfg.get("enable_floss", False):
            from floss_integration import get_floss_strings_for_function
            ida_seen = set(strings)
            for item in get_floss_strings_for_function(ea):
                value = item.get("value", "") if isinstance(item, dict) else str(item)
                if value and value not in ida_seen:
                    decoded_strings.append({
                        "value": value,
                        "source": "floss",
                        "kind": item.get("kind", "") if isinstance(item, dict) else "",
                    })
                    ida_seen.add(value)
    except Exception:
        decoded_strings = []
    apis     = get_referenced_apis(ea)
    consts   = get_interesting_constants(ea)
    pre_tags, pre_reasons, mitre = classify_function_static(ea)
    xrefs    = get_xref_counts(ea)

    # v5: struct-level context
    local_vars   = get_local_var_types(ea) if cfg.get("enable_struct_inference", True) else []
    struct_accesses = infer_struct_access(ea) if cfg.get("enable_struct_inference", True) else []

    n_insn = 0
    size   = 0
    if func:
        n_insn = sum(1 for _ in idautils.Heads(func.start_ea, func.end_ea))
        size   = func.end_ea - func.start_ea

    return {
        "ea":              hex(ea),
        "name":            name,
        "size_bytes":      size,
        "n_insn":          n_insn,
        "code_type":       code_type,
        "code":            code or "",
        "callers":         callers,
        "callees":         callees,
        "strings":         strings,
        "decoded_strings": decoded_strings,
        "apis":            apis,
        "constants":       consts,
        "pre_tags":        pre_tags,
        "pre_reasons":     pre_reasons,
        "mitre_hints":     mitre,
        "n_callers":       xrefs["n_callers"],
        "n_callees":       xrefs["n_callees"],
        "local_vars":      local_vars,
        "struct_accesses": struct_accesses,
    }


def get_caller_names_safe(ea: int) -> list:
    """Wrapper around get_caller_names that never raises."""
    try:
        from ida_read import get_caller_names
        return get_caller_names(ea)
    except Exception:
        return []
