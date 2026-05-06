# -*- coding: utf-8 -*-
"""
floss_integration.py - Optional FLOSS decoded string integration
================================================================
FLOSS is treated as an optional external static-analysis tool. This module
never executes the analyzed binary and never writes IDB symbols, comments,
types, or bytes. Results are cached as JSON next to the IDB/input file.
"""

import json
import os
import shutil
import subprocess
import time

try:
    import idaapi
    import idc
    import ida_funcs
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

from logger import log


STRING_KINDS = ("static_strings", "stack_strings", "tight_strings", "decoded_strings")


def _input_path():
    if not _IN_IDA:
        return ""
    try:
        return idc.get_input_file_path() or ""
    except Exception:
        return ""


def _cache_path(input_path=None):
    path = input_path or _input_path()
    if path:
        return os.path.splitext(path)[0] + "_gpt_floss_strings.json"
    if _IN_IDA:
        try:
            return os.path.join(idaapi.get_user_idadir(), "gpt_floss_strings.json")
        except Exception:
            pass
    return os.path.expanduser("~/.gpt_floss_strings.json")


def _parse_int(value):
    if value in (None, ""):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    try:
        return int(text, 16 if text.lower().startswith("0x") else 10)
    except Exception:
        return None


def _coerce_string(record):
    if isinstance(record, str):
        return record
    if not isinstance(record, dict):
        return ""
    for key in ("string", "decoded_string", "value", "s"):
        value = record.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, dict):
            nested = _coerce_string(value)
            if nested:
                return nested
    return ""


def _coerce_address(record):
    if not isinstance(record, dict):
        return None
    for key in (
        "address", "ea", "offset", "va", "virtual_address", "string_va",
        "decoded_at", "decoding_routine", "function", "function_va",
        "function_address",
    ):
        value = _parse_int(record.get(key))
        if value is not None:
            return value
    return None


def _normalize_record(record, kind, min_length):
    value = _coerce_string(record)
    if len(value) < min_length:
        return None
    item = {
        "string": value,
        "source": "floss_decoded",
        "kind": kind,
    }
    addr = _coerce_address(record)
    if addr is not None:
        item["address"] = addr
    if isinstance(record, dict):
        func_addr = _parse_int(record.get("function") or record.get("function_va")
                               or record.get("function_address"))
        if func_addr is not None:
            item["function_ea"] = func_addr
        decoder = record.get("decoder") or record.get("encoding") or record.get("location_type")
        if decoder:
            item["detail"] = str(decoder)[:80]
    return item


def find_floss_executable():
    """Return a FLOSS executable path if one is discoverable, else empty string."""
    for name in ("floss", "floss.exe"):
        found = shutil.which(name)
        if found:
            return found
    return ""


def parse_floss_json(output, min_length=4):
    """
    Parse FLOSS JSON output into normalized records.
    Falls back to best-effort text parsing when output is not JSON.
    """
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    if not output:
        return []

    try:
        data = json.loads(output)
    except Exception:
        return parse_floss_text(output, min_length=min_length)

    raw_records = []
    if isinstance(data, list):
        raw_records.extend(("decoded_strings", item) for item in data)
    elif isinstance(data, dict):
        strings_obj = data.get("strings") if isinstance(data.get("strings"), dict) else data
        for kind in STRING_KINDS:
            values = strings_obj.get(kind, []) if isinstance(strings_obj, dict) else []
            if isinstance(values, dict):
                values = values.values()
            for item in values or []:
                raw_records.append((kind, item))
        if not raw_records:
            for key in ("decoded", "results", "strings"):
                values = data.get(key, [])
                if isinstance(values, list):
                    for item in values:
                        raw_records.append(("decoded_strings", item))

    seen = set()
    records = []
    for kind, record in raw_records:
        item = _normalize_record(record, kind, min_length)
        if not item:
            continue
        dedupe = (item.get("string"), item.get("address"), item.get("kind"))
        if dedupe in seen:
            continue
        seen.add(dedupe)
        records.append(item)
    return records


def parse_floss_text(output, min_length=4):
    """Best-effort parser for non-JSON FLOSS text output."""
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    records = []
    seen = set()
    for line in (output or "").splitlines():
        text = line.strip()
        if not text or text.startswith(("#", "FLOSS", "WARNING", "INFO")):
            continue
        lower = text.lower()
        if lower.endswith(":") or "strings:" in lower:
            continue
        addr = None
        parts = text.split(None, 1)
        if len(parts) == 2:
            possible = _parse_int(parts[0].rstrip(":"))
            if possible is not None:
                addr = possible
                text = parts[1].strip()
        text = text.strip(" \"'")
        if len(text) < min_length:
            continue
        key = (text, addr)
        if key in seen:
            continue
        seen.add(key)
        rec = {"string": text, "source": "floss_decoded", "kind": "text_output"}
        if addr is not None:
            rec["address"] = addr
        records.append(rec)
    return records


def load_cached_floss_results(input_path=None):
    """Load cached FLOSS records; returns [] on missing/corrupt cache."""
    try:
        path = _cache_path(input_path)
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            records = data.get("strings", data if isinstance(data, list) else [])
            return records if isinstance(records, list) else []
    except Exception as exc:
        log.warn("FLOSS cache load failed: %s" % exc)
    return []


def save_floss_results(results=None, input_path=None):
    """Save FLOSS records to JSON cache near the input file."""
    try:
        path = _cache_path(input_path)
        payload = {
            "schema": "reverse_partner_floss_strings_v1",
            "input": input_path or _input_path(),
            "saved_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "strings": results or [],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        log.ok("FLOSS cache saved: %s" % path)
        return True
    except Exception as exc:
        log.warn("FLOSS cache save failed: %s" % exc)
        return False


def run_floss_on_input_binary(cfg):
    """
    Run FLOSS against the current input file or cfg['_input_path'].
    Returns normalized records. Never raises.
    """
    cfg = cfg or {}
    input_path = cfg.get("_input_path") or _input_path()
    if not input_path or not os.path.exists(input_path):
        log.warn("FLOSS input file is unavailable.")
        return []

    floss = cfg.get("floss_path") or find_floss_executable()
    if not floss:
        log.warn("FLOSS executable not found. Configure floss_path or add FLOSS to PATH.")
        return []

    timeout = int(cfg.get("floss_timeout_sec", 120) or 120)
    min_len = int(cfg.get("floss_min_length", 4) or 4)

    commands = [
        [floss, "--json", input_path],
        [floss, input_path],
    ]
    last_error = ""
    for cmd in commands:
        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                shell=False,
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            if proc.returncode != 0:
                last_error = stderr.strip() or ("return code %d" % proc.returncode)
                continue
            records = parse_floss_json(stdout, min_length=min_len)
            if records:
                save_floss_results(records, input_path=input_path)
                log.ok("FLOSS decoded %d string(s)." % len(records))
                return records
            last_error = stderr.strip() or "no decoded strings"
        except subprocess.TimeoutExpired:
            log.warn("FLOSS timed out after %d seconds." % timeout)
            return []
        except Exception as exc:
            last_error = str(exc)

    if last_error:
        log.warn("FLOSS failed: %s" % last_error[:300])
    return []


def get_floss_strings_for_function(ea):
    """Return cached FLOSS strings associated with a function EA."""
    records = load_cached_floss_results()
    if not records or not _IN_IDA:
        return []
    try:
        func = ida_funcs.get_func(ea)
        if not func:
            return []
        result = []
        seen = set()
        for rec in records:
            text = rec.get("string") if isinstance(rec, dict) else str(rec)
            if not text or text in seen:
                continue
            func_ea = _parse_int(rec.get("function_ea")) if isinstance(rec, dict) else None
            addr = _parse_int(rec.get("address")) if isinstance(rec, dict) else None
            if func_ea == func.start_ea or (addr is not None and func.start_ea <= addr < func.end_ea):
                result.append({"value": text, "source": "floss", "kind": rec.get("kind", "")})
                seen.add(text)
        return result[:30]
    except Exception:
        return []


def extract_iocs_from_floss_results(results=None):
    """Extract source-tagged IOCs from cached or supplied FLOSS records."""
    from ioc_extractor import extract_iocs_from_text

    records = results if results is not None else load_cached_floss_results()
    merged = {}
    for rec in records or []:
        text = rec.get("string", "") if isinstance(rec, dict) else str(rec)
        for ioc_type, values in extract_iocs_from_text(text).items():
            bucket = merged.setdefault(ioc_type, {})
            for value in values:
                item = bucket.setdefault(value, {"value": value, "sources": set()})
                item["sources"].add("floss_decoded")

    return {
        ioc_type: [
            {"value": item["value"], "source": sorted(item["sources"])[0],
             "sources": sorted(item["sources"])}
            for item in sorted(bucket.values(), key=lambda x: x["value"])
        ]
        for ioc_type, bucket in merged.items()
    }
