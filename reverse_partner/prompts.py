# -*- coding: utf-8 -*-
"""
prompts.py — AI prompt templates
===================================
Centralizes all system prompts and batch prompt construction.
Naming-mode instructions are injected at call time.
"""

from config import MAX_CHARS_PER_FUNC

# ---------------------------------------------------------------------------
# Naming mode instructions (injected into every prompt)
# ---------------------------------------------------------------------------

_NAMING_MODE_INSTRUCTIONS: dict = {
    "conservative": (
        "NAMING RULES (conservative mode):\n"
        "- Use behavior-faithful names: xor_transform_buffer, "
        "resolve_and_call_virtualalloc, decompress_buffer_rtl.\n"
        "- Do NOT use 'steal', 'exfiltrate', 'backdoor', 'c2' unless "
        "CLEAR, SPECIFIC evidence exists in the code.\n"
        "- When unsure, prefix name with 'likely_' or use a generic conservative name.\n"
        "- confidence must reflect your certainty (0.0 = wild guess, 1.0 = certain).\n"
    ),
    "malware": (
        "NAMING RULES (malware mode):\n"
        "- Stronger names are allowed when evidence is clear:\n"
        "  decrypt_embedded_config, build_c2_http_request, "
        "install_service_persistence, inject_payload_into_process.\n"
        "- Still require at least 2 pieces of evidence for strong names.\n"
        "- confidence must reflect your certainty.\n"
    ),
    "blog": (
        "NAMING RULES (blog mode):\n"
        "- Analyst-friendly, descriptive names: "
        "stage4_loader_entry, config_decoder_dispatcher, polymorphic_chunk_generator.\n"
        "- Names should be evidence-based and publication-ready.\n"
        "- confidence must reflect your certainty.\n"
    ),
}


def get_naming_instruction(cfg: dict) -> str:
    """Return the naming mode instruction for the current config."""
    mode = cfg.get("naming_mode", "conservative")
    return _NAMING_MODE_INSTRUCTIONS.get(mode, _NAMING_MODE_INSTRUCTIONS["conservative"])


# ---------------------------------------------------------------------------
# v5 JSON schema description (injected into every prompt)
# ---------------------------------------------------------------------------

_V5_SCHEMA = (
    "Respond ONLY with a JSON object (no markdown, no prose) matching this schema:\n"
    "{\n"
    '  "name": "snake_case_name",\n'
    '  "confidence": 0.0,\n'
    '  "category": "WRAPPER|NETWORK|CRYPTO|INJECT|PERSIST|EVASION|RECON|'
    'EXEC|FILE|MEMORY|DISPATCH|CTOR|INIT|LOADER|CONFIG|UTIL|UNKNOWN",\n'
    '  "description": "1-3 concise sentences",\n'
    '  "evidence": ["specific evidence: API call, constant, string, pattern"],\n'
    '  "warnings": ["optional analyst notes"],\n'
    '  "tags": ["TAG1", "TAG2"]\n'
    "}\n"
    "Rules:\n"
    "- name: snake_case, max 64 chars, [a-z0-9_], must start with letter.\n"
    "- confidence: float 0.0-1.0.\n"
    "- evidence: mandatory — list at least 1 item. "
    "Empty evidence forces confidence ≤ 0.5.\n"
    "- Do NOT invent capabilities not visible in the code.\n"
    "- If uncertain, lower confidence and use conservative name.\n"
)

_BATCH_SCHEMA = (
    "Map each original function name to its result object:\n"
    '{"original_name": {<v5 schema>}, ...}\n'
    "No markdown. No prose. Only the JSON object.\n"
)

# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

BATCH_SYSTEM_PROMPT_V5 = (
    "You are an expert malware reverse engineer analyzing decompiled binary code.\n"
    "Analyze EACH function listed below.\n\n"
    + _V5_SCHEMA
    + "\n"
    + _BATCH_SCHEMA
)

SINGLE_SYSTEM_PROMPT_V5 = (
    "You are an expert malware reverse engineer.\n"
    + _V5_SCHEMA
)

ANALYZE_SYSTEM_PROMPT_V5 = (
    "You are an expert malware reverse engineer performing deep static analysis.\n"
    "Analyze the given function thoroughly.\n\n"
    + _V5_SCHEMA
    + "\nAlso include key 'behavior': detailed technical analysis — "
    "data structures, algorithms, notable constants, IOCs, obfuscation patterns.\n"
)

RANGE_SYSTEM_PROMPT = (
    "You are an expert malware reverse engineer analyzing a code snippet.\n"
    "Respond ONLY with JSON:\n"
    "{\n"
    '  "purpose": "1-2 sentences describing what this code block does",\n'
    '  "suggested_comment": "1 sentence block comment suitable for IDA",\n'
    '  "interesting_apis": ["API1", ...],\n'
    '  "interesting_constants": ["0xDEAD", ...],\n'
    '  "confidence": 0.0,\n'
    '  "evidence": ["..."],\n'
    '  "warnings": ["..."]\n'
    "}\n"
    "No markdown. No prose.\n"
)

WHOLE_PROGRAM_PROMPT = (
    "You are an expert malware reverse engineer.\n"
    "Given a summary of a binary, produce a JSON object:\n"
    "{\n"
    '  "malware_family": "best guess or UNKNOWN",\n'
    '  "campaign": "best guess or UNKNOWN",\n'
    '  "techniques": ["T1055 Process Injection", ...],\n'
    '  "high_interest_functions": ["func_name", ...],\n'
    '  "summary": "3-5 sentences about the binary",\n'
    '  "iocs": {"ips": [], "domains": [], "urls": [], "paths": [], "registry": []}\n'
    "}\n"
    "No markdown outside JSON.\n"
)

STRUCT_INFERENCE_PROMPT = (
    "You are an expert reverse engineer specializing in data structure recovery.\n"
    "Given struct field accesses and function context, infer struct layout.\n"
    "Respond ONLY with JSON:\n"
    "{\n"
    '  "struct_name": "inferred_struct_name",\n'
    '  "fields": [\n'
    '    {"offset": 0, "name": "field_name", "type": "DWORD", "purpose": "..."},\n'
    '    ...\n'
    '  ],\n'
    '  "confidence": 0.0,\n'
    '  "evidence": ["..."]\n'
    "}\n"
    "No markdown. No prose.\n"
)

VARIABLE_RENAME_PROMPT = (
    "You are an expert reverse engineer improving local variable names in "
    "Hex-Rays pseudocode.\n"
    "Suggest variable renames only when supported by visible use in the code.\n"
    "Respond ONLY with JSON:\n"
    "{\n"
    '  "variables": [\n'
    '    {"old_name": "v1", "new_name": "buffer_len", "confidence": 0.0, '
    '"reason": "specific code evidence"},\n'
    "    ...\n"
    "  ],\n"
    '  "warnings": ["optional analyst warnings"]\n'
    "}\n"
    "Rules:\n"
    "- new_name must be snake_case, max 64 chars, start with a letter or underscore.\n"
    "- Do not suggest names for variables you cannot justify.\n"
    "- Do not invent malware capabilities not visible in the code.\n"
    "- No markdown. No prose.\n"
)

PROTOTYPE_INFERENCE_PROMPT = (
    "You are an expert reverse engineer inferring C function prototypes from "
    "Hex-Rays pseudocode and call context.\n"
    "Respond ONLY with JSON:\n"
    "{\n"
    '  "prototype": "int __fastcall function_name(int arg1, char *buf)",\n'
    '  "confidence": 0.0,\n'
    '  "calling_convention": "__fastcall|__cdecl|__stdcall|unknown",\n'
    '  "return_type": "int",\n'
    '  "arguments": [{"name": "arg1", "type": "int", "evidence": "..."}],\n'
    '  "evidence": ["specific code evidence"],\n'
    '  "warnings": ["optional analyst warnings"]\n'
    "}\n"
    "Rules:\n"
    "- Prototype must be a single C declaration for the current function.\n"
    "- Prefer conservative types when evidence is incomplete.\n"
    "- Do not invent parameters that are not visible in pseudocode/call sites.\n"
    "- No markdown. No prose.\n"
)

STATIC_PROGRAM_FUNCTION_SYSTEM_PROMPT = (
    "You are an expert reverse engineer performing conservative static program analysis.\n"
    "Analyze only the provided static context. Do not infer runtime behavior beyond visible evidence.\n"
    "Treat static tags, priority scores, and child summaries as hints, not facts.\n"
    "Use neutral wording such as notable behavior, review priority, evidence, and static hints.\n"
    "Respond ONLY with JSON matching this schema:\n"
    "{\n"
    '  "function_name": "suggested_name",\n'
    '  "confidence": 0.0,\n'
    '  "priority": "low|medium|high|critical",\n'
    '  "category": "MEMORY|NETWORK|CRYPTO|FILE|DISPATCH|WRAPPER|INIT|UTIL|UNKNOWN",\n'
    '  "summary": "short summary",\n'
    '  "technical_behavior": "concise explanation",\n'
    '  "evidence": ["specific static evidence"],\n'
    '  "data_flows": [],\n'
    '  "called_behaviors": [],\n'
    '  "warnings": [],\n'
    '  "rename_recommendation": {"apply": false, "name": "snake_case_name", "reason": "why this name fits"},\n'
    '  "analyst_notes": []\n'
    "}\n"
    "Rules:\n"
    "- evidence is mandatory.\n"
    "- confidence must be 0.0 to 1.0.\n"
    "- If evidence is weak, lower confidence.\n"
    "- Never claim malicious intent as fact.\n"
    "- rename_recommendation.apply should only be true for high-confidence names.\n"
    "- No markdown. No prose outside JSON.\n"
)


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------

def build_prompt(batch: list, cfg: dict = None) -> str:
    """
    Build the user-side prompt for a batch of functions.
    Includes naming mode instructions and all available context.
    """
    cfg = cfg or {}
    naming = get_naming_instruction(cfg)
    parts  = [naming]

    for item in batch:
        header  = "--- %s ---" % item["name"]
        callees = item.get("callees", [])
        callers = item.get("callers", [])
        strings = item.get("strings", [])
        decoded = item.get("decoded_strings", [])
        apis    = item.get("apis", [])
        consts  = item.get("constants", [])
        pre_tags = item.get("pre_tags", [])
        mitre   = item.get("mitre_hints", [])
        proposal_context = item.get("proposal_context", "")
        structs = item.get("struct_accesses", [])
        lvars   = item.get("local_vars", [])

        def _named(lst):
            from utils import is_default_name
            return [c for c in lst if not is_default_name(c)]

        if callees:
            n = _named(callees)
            if n:
                header += "\n// Calls: %s" % ", ".join(n[:10])
        if callers:
            n = _named(callers)
            if n:
                header += "\n// Called by: %s" % ", ".join(n[:5])
        if strings:
            header += "\n// Strings: %s" % "; ".join(strings[:8])
        if decoded:
            dec_vals = []
            for s in decoded[:6]:
                dec_vals.append(s.get("value", "") if isinstance(s, dict) else str(s))
            dec_vals = [s for s in dec_vals if s]
            if dec_vals:
                header += "\n// Decoded strings (FLOSS): %s" % "; ".join(dec_vals)
        if apis:
            header += "\n// APIs: %s" % ", ".join(apis[:14])
        if consts:
            header += "\n// Constants: %s" % ", ".join(consts[:8])
        if pre_tags:
            header += "\n// Static pre-tags (informational): %s" % ", ".join(pre_tags)
        if mitre:
            header += "\n// MITRE hints: %s" % "; ".join(mitre[:3])
        if proposal_context:
            header += "\n// Tentative callee rename context (not ground truth):\n%s" % proposal_context
        if lvars:
            lv_strs = ["%s:%s" % (v["name"], v["type"]) for v in lvars[:8]]
            header += "\n// Local vars: %s" % ", ".join(lv_strs)
        if structs:
            sa_strs = ["off+%d" % s["offset"] for s in structs[:6]]
            header += "\n// Struct offsets accessed: %s" % ", ".join(sa_strs)

        code = item.get("code", "")[:MAX_CHARS_PER_FUNC]
        parts.append("%s\n```\n%s\n```" % (header, code))

    return "\n\n".join(parts)


def pack_batches(items: list, model: str, manual_limit: int = 0) -> list:
    """Pack function items into token-budgeted batches."""
    from config import get_budget_chars
    budget  = get_budget_chars(model)
    slot    = budget - len(BATCH_SYSTEM_PROMPT_V5) - 200
    batches, current, chars = [], [], 0
    for item in items:
        entry = len("--- %s ---\n```\n%s\n```\n" % (
            item["name"], item.get("code", "")[:MAX_CHARS_PER_FUNC]))
        full = manual_limit > 0 and len(current) >= manual_limit
        if current and (chars + entry > slot or full):
            batches.append(current)
            current, chars = [], 0
        current.append(item)
        chars += entry
    if current:
        batches.append(current)
    return batches
