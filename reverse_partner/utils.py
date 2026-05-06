# -*- coding: utf-8 -*-
"""
utils.py — Name sanitization, JSON repair, AI result normalization
===================================================================
All functions here are pure Python and testable outside IDA.
"""

import re
import json

# ---------------------------------------------------------------------------
# Name helpers
# ---------------------------------------------------------------------------

def sanitize_name(name: str, prefix: str = "") -> str:
    """
    Sanitize a string into a valid IDA function name (snake_case).
    Pure Python — testable outside IDA.
    """
    name = name.strip()
    name = re.sub(r"`+", "", name)
    name = re.split(r"[/#]", name)[0].strip()
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    if name and name[0].isdigit():
        name = "_" + name
    name = name[:64]
    if prefix:
        clean_prefix = re.sub(r"[^a-zA-Z0-9_]", "", prefix)
        name = clean_prefix + name
    return name if name else "unknown_func"


_DEFAULT_NAME_RE = re.compile(
    r"^(sub_|loc_|nullsub_|j_|unknown_libname_|fn_|func_|"
    r"_[0-9a-fA-F]{4,}|[?@]sub_|wrap_sub_)",
    re.IGNORECASE
)


def is_default_name(name: str) -> bool:
    """Return True if name is an auto-generated IDA default (sub_XXXX, etc.)."""
    if not name:
        return True
    if _DEFAULT_NAME_RE.match(name):
        return True
    if re.match(r"^(sub|loc|nullsub|fn|func)_[0-9a-fA-F]+(_\d+)?$", name, re.IGNORECASE):
        return True
    return False


def is_worth_renaming(name: str, n_insn: int, use_skip_named: bool) -> tuple:
    """Returns (should_rename: bool, reason: str)."""
    if not name:
        return False, "no_name"
    if is_default_name(name):
        return True, "default"
    if use_skip_named:
        return False, "named"
    return True, "force"


# ---------------------------------------------------------------------------
# JSON repair
# ---------------------------------------------------------------------------

def repair_json_response(text: str) -> str:
    """
    Attempt to repair common AI JSON output defects:
    - Markdown code fences
    - Leading/trailing prose
    - Smart / curly quotes
    - Trailing commas before } or ]
    - Conservative single-quote → double-quote conversion

    Returns best-effort repaired string ready for json.loads().
    Testable outside IDA.
    """
    if not text:
        return "{}"
    s = text

    # 1. Strip markdown fences
    s = re.sub(r"```(?:json)?\s*", "", s)
    s = re.sub(r"```", "", s)

    # 2. Trim to first { or [ ... last } or ]
    m = re.search(r"[\[{]", s)
    if m:
        s = s[m.start():]
    m2 = re.search(r"[}\]](?=[^}\]]*$)", s)
    if m2:
        s = s[:m2.end()]

    # 3. Smart / curly quotes → straight
    s = (s.replace("\u201c", '"').replace("\u201d", '"')
          .replace("\u2018", "'").replace("\u2019", "'"))

    # 4. Trailing commas before ] or }
    s = re.sub(r",\s*([}\]])", r"\1", s)

    # 5. Conservative single-quote JSON repair
    if s.count("'") >= 2 and '"' not in s[:20]:
        try:
            s2 = re.sub(r"(?<!\\)'", '"', s)
            json.loads(s2)
            s = s2
        except Exception:
            pass

    return s


# ---------------------------------------------------------------------------
# JSON parsing — v5 multi-attempt
# ---------------------------------------------------------------------------

def parse_json_response_v5(text: str) -> dict:
    """
    Multi-attempt JSON parser.
    Returns parsed dict/list or a structured error dict on failure.
    Testable outside IDA.
    """
    if not text:
        return {"_parse_error": "empty response"}

    for attempt in (text, repair_json_response(text)):
        # a) direct parse
        try:
            return json.loads(attempt)
        except Exception:
            pass
        # b) first {...} block
        try:
            m = re.search(r"\{.*\}", attempt, re.DOTALL)
            if m:
                return json.loads(m.group())
        except Exception:
            pass
        # c) ```json ... ``` block
        try:
            m = re.search(r"```json\s*(\{.*?\})\s*```", attempt, re.DOTALL)
            if m:
                return json.loads(m.group(1))
        except Exception:
            pass

    from logger import log
    log.warn("parse_json_response_v5 failed. raw=%r" % text[:200])
    return {"_parse_error": "all parse attempts failed", "_raw": text[:500]}


# Backward-compat alias
def parse_json_response(text: str) -> dict:
    result = parse_json_response_v5(text)
    return {} if "_parse_error" in result else result


# ---------------------------------------------------------------------------
# AI result normalization & validation
# ---------------------------------------------------------------------------

VALID_CATEGORIES = frozenset({
    "WRAPPER", "NETWORK", "CRYPTO", "INJECT", "PERSIST", "EVASION",
    "RECON", "EXEC", "FILE", "MEMORY", "DISPATCH", "CTOR", "INIT",
    "LOADER", "CONFIG", "UTIL", "UNKNOWN"
})
VALID_TAGS = VALID_CATEGORIES

# Names that imply serious malicious capability — require strong evidence
_OVERCLAIM_WORDS = (
    "exfiltrate", "steal", "backdoor", "c2", "c&c",
    "keylog", "rootkit", "bootkit", "ransom",
)


def normalize_ai_result(raw: dict, original_name: str,
                         prefix: str = "", require_evidence: bool = True) -> dict:
    """
    Convert raw AI response into a normalized v5 result.
    Applies conservative naming policy and evidence-based confidence clamping.
    Testable outside IDA.
    """
    if not isinstance(raw, dict) or "_parse_error" in raw:
        return {
            "name":        sanitize_name(original_name, prefix) or "unknown_func",
            "confidence":  0.0,
            "category":    "UNKNOWN",
            "description": "Parse error — AI response could not be decoded.",
            "evidence":    [],
            "warnings":    ["parse_error"],
            "tags":        [],
            "_error":      True,
        }

    # ── name ────────────────────────────────────────────────────────────────
    raw_name = raw.get("name") or raw.get("function_name") or ""
    name     = sanitize_name(str(raw_name), prefix)
    if not name or name == "unknown_func":
        name = sanitize_name(original_name, prefix) or "unknown_func"

    # ── confidence ──────────────────────────────────────────────────────────
    try:
        conf = float(raw.get("confidence", raw.get("score", 0.5)))
        conf = max(0.0, min(1.0, conf))
    except (TypeError, ValueError):
        conf = 0.5

    # ── evidence ────────────────────────────────────────────────────────────
    evidence = raw.get("evidence", raw.get("evidence_list", []))
    if isinstance(evidence, str):
        evidence = [evidence] if evidence else []
    elif not isinstance(evidence, list):
        evidence = []
    evidence = [str(e)[:300] for e in evidence if str(e).strip()]

    if require_evidence and not evidence:
        conf = min(conf, 0.5)

    # ── category ────────────────────────────────────────────────────────────
    category = str(raw.get("category", "UNKNOWN")).upper()
    if category not in VALID_CATEGORIES:
        # try to inherit from tags
        for t in (raw.get("tags", []) or []):
            if str(t).upper() in VALID_CATEGORIES:
                category = str(t).upper()
                break
        else:
            category = "UNKNOWN"

    # ── tags ────────────────────────────────────────────────────────────────
    tags_raw = raw.get("tags", [])
    if isinstance(tags_raw, str):
        tags_raw = re.split(r"[,;\s]+", tags_raw)
    tags = [t.upper() for t in (tags_raw or []) if str(t).upper() in VALID_TAGS]

    # ── description ─────────────────────────────────────────────────────────
    desc = str(raw.get("description", raw.get("summary", ""))).strip()[:600]

    # ── warnings ────────────────────────────────────────────────────────────
    warnings_raw = raw.get("warnings", raw.get("analyst_warnings", []))
    if isinstance(warnings_raw, str):
        warnings_raw = [warnings_raw]
    warnings = [str(w)[:200] for w in (warnings_raw or [])[:10]]

    # ── conservative overclaim guard ────────────────────────────────────────
    if any(w in name.lower() for w in _OVERCLAIM_WORDS) and len(evidence) < 2:
        conf = min(conf, 0.55)
        warnings.append("overclaim_name_without_sufficient_evidence: %s" % name)

    return {
        "name":        name,
        "confidence":  round(conf, 3),
        "category":    category,
        "description": desc,
        "evidence":    evidence[:15],
        "warnings":    warnings,
        "tags":        tags,
    }


def validate_ai_result(result: dict) -> tuple:
    """
    Validate a normalized result dict.
    Returns (is_valid: bool, issues: list[str]).
    Testable outside IDA.
    """
    issues = []
    if not isinstance(result, dict):
        return False, ["result is not a dict"]
    if "_parse_error" in result:
        return False, ["parse error: %s" % result.get("_parse_error")]

    name = result.get("name", "")
    if not name or not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$", name):
        issues.append("invalid name: %r" % name)

    conf = result.get("confidence", None)
    if conf is None or not isinstance(conf, (int, float)) or not (0.0 <= conf <= 1.0):
        issues.append("confidence out of range: %r" % conf)

    cat = result.get("category", "")
    if cat not in VALID_CATEGORIES:
        issues.append("unknown category: %r" % cat)

    if not isinstance(result.get("evidence", []), list) or not result.get("evidence"):
        issues.append("evidence missing or empty")

    return len(issues) == 0, issues


# ---------------------------------------------------------------------------
# Backward-compat helper
# ---------------------------------------------------------------------------

def extract_name_from_result(result_val, prefix: str = "") -> tuple:
    """v4 compat: returns (name, description, tags)."""
    if isinstance(result_val, dict):
        name = sanitize_name(result_val.get("name", ""), prefix)
        desc = str(result_val.get("description", ""))[:500]
        tags = result_val.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        return name, desc, tags
    if isinstance(result_val, str):
        return sanitize_name(result_val, prefix), "", []
    return "", "", []
