# -*- coding: utf-8 -*-
"""
ioc_extractor.py — Standalone IOC extraction engine
======================================================
Completely independent of AI — pure regex + IDA string scan.

Extracts:
  IPv4 / IPv6 addresses
  Domains (by TLD list)
  URLs (http/https/ftp)
  Windows filesystem paths
  UNC paths
  Registry paths (HKEY_* / HKLM / HKCU / …)
  Global mutex names (Global\\…)
  User-Agent strings
  Base64-looking blobs (>= 40 chars)
  PE-related file extensions
  Hardcoded port numbers (heuristic)
  Suspicious strings (format strings, env vars)
  Crypto magic constants (hardcoded key-like hex)

All patterns are testable outside IDA.
"""

import re
from collections import defaultdict

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_PATTERNS: dict = {
    "ipv4": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "ipv6": re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
        r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b|"
        r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9\-]+\.)+(?:"
        r"com|net|org|io|ru|cn|de|uk|onion|xyz|top|info|cc|tk|"
        r"biz|site|club|online|tech|pro|pw|me|in|fr|jp|br|au|"
        r"gov|edu|mil|int|arpa|mobi|name|travel|coop|aero|museum"
        r")\b",
        re.IGNORECASE
    ),
    "url": re.compile(
        r"(?:https?|ftp)://[^\s\"'<>\x00-\x1f]{5,250}",
        re.IGNORECASE
    ),
    "win_path": re.compile(
        r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*"
    ),
    "unc_path": re.compile(
        r"\\\\[a-zA-Z0-9\-_\.]+(?:\\[^\\\s]+)+"
    ),
    "registry": re.compile(
        r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|"
        r"HKEY_USERS|HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU|HKCC)"
        r"\\[^\s\"'\x00-\x1f]{3,200}",
        re.IGNORECASE
    ),
    "mutex": re.compile(
        r"\bGlobal\\[a-zA-Z0-9_\-\{\}]{4,80}\b"
    ),
    "user_agent": re.compile(
        r"Mozilla/[0-9]\.[0-9][^\r\n\"]{10,150}",
        re.IGNORECASE
    ),
    "base64": re.compile(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"
    ),
    "pe_artifact": re.compile(
        r"\b[^\s\"']{3,80}\.(?:exe|dll|sys|drv|ocx|scr|bat|cmd|ps1|vbs|vbe|js|"
        r"jse|wsf|wsh|msi|cab|inf|reg)\b",
        re.IGNORECASE
    ),
    "env_var": re.compile(
        r"%(?:APPDATA|LOCALAPPDATA|TEMP|TMP|WINDIR|SYSTEMROOT|PROGRAMFILES|"
        r"USERPROFILE|COMSPEC|PUBLIC|ALLUSERSPROFILE|USERNAME|USERDOMAIN|"
        r"COMPUTERNAME|SystemDrive|SystemRoot)%?",
        re.IGNORECASE
    ),
    "email": re.compile(
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
}

# Known-false-positive IPv4 prefixes to filter
_IPV4_FILTER_PREFIXES = ("0.0.0.", "127.0.", "255.255.", "169.254.")

# Strings that look like base64 but are clearly not (common false positives)
_BASE64_FP_STARTS = ("AAAA", "////", "MMMM")


def _filter_iocs(ioc_type: str, values: set) -> list:
    """Post-filter to remove obvious false positives."""
    result = []
    for v in values:
        v = v.strip()
        if not v:
            continue

        if ioc_type == "ipv4":
            if any(v.startswith(p) for p in _IPV4_FILTER_PREFIXES):
                continue
            # Filter all-zero octets
            parts = v.split(".")
            if all(p == "0" for p in parts):
                continue

        elif ioc_type == "base64":
            if any(v.startswith(p) for p in _BASE64_FP_STARTS):
                continue
            # Must have some entropy — reject repetitive strings
            if len(set(v)) < 6:
                continue

        elif ioc_type == "domain":
            # Filter single-label results that slipped through
            if v.count(".") < 1:
                continue
            # Filter obvious code/version strings (e.g. "1.2.3.com")
            if re.match(r"^\d+\.\d+\.", v):
                continue

        result.append(v)

    return sorted(set(result))


def extract_iocs_from_text(corpus: str) -> dict:
    """
    Extract IOCs from a text corpus.
    Pure Python — testable outside IDA.
    Returns dict: {ioc_type: [match, ...]}
    """
    raw: dict = defaultdict(set)
    for ioc_type, pattern in _PATTERNS.items():
        try:
            for m in pattern.findall(corpus):
                raw[ioc_type].add(m.strip())
        except Exception:
            pass
    return {t: _filter_iocs(t, v) for t, v in raw.items() if v}


def _entry_value(entry):
    return entry.get("value", "") if isinstance(entry, dict) else str(entry)


def ioc_values(entries: list) -> list:
    """Return raw IOC values from either source-aware entries or legacy strings."""
    return [_entry_value(v) for v in (entries or []) if _entry_value(v)]


def _merge_iocs(target: dict, iocs: dict, source: str):
    for ioc_type, values in (iocs or {}).items():
        bucket = target.setdefault(ioc_type, {})
        for value in ioc_values(values):
            item = bucket.setdefault(value, {"value": value, "sources": set()})
            item["sources"].add(source)


def _finalize_iocs(target: dict, include_sources: bool) -> dict:
    result = {}
    for ioc_type, bucket in target.items():
        values = []
        for item in sorted(bucket.values(), key=lambda x: x["value"]):
            sources = sorted(item["sources"])
            if include_sources:
                values.append({
                    "value": item["value"],
                    "source": sources[0] if sources else "",
                    "sources": sources,
                })
            else:
                values.append(item["value"])
        if values:
            result[ioc_type] = values
    return result


def extract_iocs_from_binary(include_sources: bool = True) -> dict:
    """
    [v5] Scan the entire IDB for IOCs.
    Collects: all string literals, function names, comments, optional FLOSS
    decoded strings, and saved AI summaries/analyst notes.
    READ-ONLY.
    """
    try:
        import idautils
        import idc
        import ida_funcs
        _IN_IDA = True
    except ImportError:
        return {}

    merged = {}
    ida_parts = []

    # All string literals in the binary
    try:
        for s in idautils.Strings():
            content = str(s)
            if content:
                ida_parts.append(content)
    except Exception:
        pass

    # Function names and comments
    ai_summary_parts = []
    analyst_note_parts = []
    try:
        for ea in idautils.Functions():
            nm = idc.get_func_name(ea) or ""
            if nm:
                ida_parts.append(nm)
            cmt = idc.get_func_cmt(ea, 0) or ""
            if cmt:
                ida_parts.append(cmt)
            # Also grab instruction comments
            import ida_funcs as _if
            func = _if.get_func(ea)
            if func:
                import idautils as _iu
                for head in _iu.Heads(func.start_ea, func.end_ea):
                    c = idc.get_cmt(head, 0) or ""
                    if c:
                        ida_parts.append(c)
            try:
                from idb_storage import load_blob
                summary = load_blob(ea, "ai_summary")
                notes = load_blob(ea, "analyst_notes")
                if summary:
                    ai_summary_parts.append(str(summary))
                if notes:
                    analyst_note_parts.append(str(notes))
            except Exception:
                pass
    except Exception:
        pass

    _merge_iocs(merged, extract_iocs_from_text("\n".join(ida_parts)), "ida_string")
    _merge_iocs(merged, extract_iocs_from_text("\n".join(ai_summary_parts)), "ai_summary")
    _merge_iocs(merged, extract_iocs_from_text("\n".join(analyst_note_parts)), "analyst_note")

    try:
        from floss_integration import extract_iocs_from_floss_results
        floss_iocs = extract_iocs_from_floss_results()
        for ioc_type, values in floss_iocs.items():
            bucket = merged.setdefault(ioc_type, {})
            for entry in values:
                value = _entry_value(entry)
                if not value:
                    continue
                item = bucket.setdefault(value, {"value": value, "sources": set()})
                for src in entry.get("sources", [entry.get("source", "floss_decoded")]):
                    item["sources"].add(src)
    except Exception:
        pass

    return _finalize_iocs(merged, include_sources)


def format_iocs_report(iocs: dict) -> str:
    """Format IOC dict into a human-readable text report."""
    if not iocs:
        return "No IOCs found."
    lines = []
    order = ["url", "domain", "ipv4", "ipv6", "win_path", "unc_path",
             "registry", "mutex", "user_agent", "pe_artifact",
             "email", "env_var", "base64"]
    for t in order:
        if t in iocs:
            lines.append("[%s] (%d)" % (t.upper(), len(iocs[t])))
            for v in iocs[t][:30]:
                if isinstance(v, dict):
                    src = ",".join(v.get("sources", [v.get("source", "")]))
                    lines.append("  %s  [%s]" % (v.get("value", ""), src))
                else:
                    lines.append("  %s" % v)
            if len(iocs[t]) > 30:
                lines.append("  ... (%d more)" % (len(iocs[t]) - 30))
            lines.append("")
    for t in sorted(iocs):
        if t not in order:
            lines.append("[%s] (%d)" % (t.upper(), len(iocs[t])))
            for v in iocs[t][:10]:
                if isinstance(v, dict):
                    src = ",".join(v.get("sources", [v.get("source", "")]))
                    lines.append("  %s  [%s]" % (v.get("value", ""), src))
                else:
                    lines.append("  %s" % v)
    return "\n".join(lines)
