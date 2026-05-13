# -*- coding: utf-8 -*-
"""
config.py — Plugin configuration
==================================
Loads / saves JSON config. Migrates v4 → v5 fields automatically.
Config file is stored next to the IDA user dir.
"""

import json
import os
import re

_IN_IDA = False
try:
    import idaapi
    _IN_IDA = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Token budgets (chars) per model
# ---------------------------------------------------------------------------
TOKEN_BUDGETS: dict = {
    "gemini-1.5-flash":               {"input": 800_000, "cpt": 4},
    "gemini-1.5-pro":                 {"input": 800_000, "cpt": 4},
    "gemini-2.0-flash":               {"input": 800_000, "cpt": 4},
    "gemini-2.5-flash":               {"input": 800_000, "cpt": 4},
    "gemini-2.5-flash-preview-04-17": {"input": 800_000, "cpt": 4},
    "gemini-2.5-pro":                 {"input": 800_000, "cpt": 4},
    "llama3-70b-8192":                {"input":   6_000, "cpt": 4},
    "llama3-8b-8192":                 {"input":   6_000, "cpt": 4},
    "mixtral-8x7b-32768":             {"input":  28_000, "cpt": 4},
    "gpt-4o":                         {"input": 100_000, "cpt": 4},
    "gpt-4-turbo":                    {"input": 100_000, "cpt": 4},
    "gpt-3.5-turbo":                  {"input":  14_000, "cpt": 4},
}

MAX_CHARS_PER_FUNC          = 3000
INPUT_USAGE_RATIO           = 0.80
MAX_FUNC_SIZE_FOR_DECOMPILE = 0x8000   # 32 KB — skip decompile for huge funcs

# ---------------------------------------------------------------------------
# Default configuration
# ---------------------------------------------------------------------------
DEFAULT_CONFIG: dict = {
    # Provider
    "provider":       "gemini",      # gemini|groq|openai|openai_compatible|ollama|lmstudio
    "base_url":       "",            # for openai_compatible / ollama / lmstudio
    "api_keys":       [],
    "model":          "gemini-2.5-flash-preview-04-17",
    "timeout_sec":    60,
    "temperature":    0.1,
    # Rename behaviour
    "skip_named":     True,
    "use_pseudocode": True,
    "prefix":         "",
    "min_insn":       5,
    "batch_size":     50,
    "keys_file":      "",
    "retry_failed":   True,
    "export_html":    True,
    # Rename All ordering
    "rename_order":                      "best_effort_bottom_up",
    "strict_refresh_context_after_level": True,
    "strict_pause_for_review":           True,
    "strict_process_cycles_last":        True,
    "strict_level_batch_size":           40,
    "strict_second_pass_parent_refine":  False,
    # Proposal-aware bottom-up context
    "proposal_use_pending_child_names":     True,
    "proposal_propagate_child_confidence":  True,
    "proposal_dependency_review_sort":      True,
    "proposal_max_parent_confidence_boost": 0.10,
    # Rename All request budgeting
    "request_budget_mode":                  "free_key_balanced",
    "max_ai_requests_per_run":              25,
    "max_functions_per_rename_run":         250,
    "target_functions_per_request":         40,
    "max_functions_per_request":            60,
    "min_functions_per_request":            8,
    "proposal_level_batch_size":            50,
    "warn_if_estimated_requests_above":     25,
    "allow_user_to_reduce_scope_on_budget_exceed": True,
    "prefer_cache_before_budget_count":     True,
    "max_retry_requests_per_run":           5,
    "retry_batch_shrink_factor":            2,
    # Naming policy
    "naming_mode":    "conservative",  # conservative | malware | blog
    # Review queue
    "review_mode":                   True,
    "auto_apply_confidence":         0.85,
    "comment_only_below_confidence": 0.60,
    "require_evidence":              True,
    # Analysis cache
    "enable_cache":   True,
    "cache_file":     "",
    "cache_ttl_days": 90,
    # Struct inference (v5)
    "enable_struct_inference": True,
    "max_struct_fields":       24,
    # Optional FLOSS decoded string discovery
    "floss_path":              "",
    "enable_floss":            False,
    "floss_timeout_sec":       120,
    "floss_min_length":        4,
    # Deep Analyzer
    "deep_max_depth":          5,
    "deep_max_functions":      300,
    "deep_ai_function_limit":  80,
    "deep_include_library_funcs": False,
    "deep_include_named_funcs":   True,
    "deep_min_static_score":   3,
    "deep_use_cache":          True,
    "deep_save_artifacts":     True,
    "deep_artifact_dir":       "",
    "deep_child_summary_limit": 12,
    "deep_prompt_token_budget": 12000,
    # Static Program Analyzer
    "spa_max_depth":          5,
    "spa_max_functions":      300,
    "spa_ai_function_limit":  80,
    "spa_include_named_funcs": True,
    "spa_include_library_funcs": False,
    "spa_min_priority_score": 3,
    "spa_use_cache":          True,
    "spa_save_artifacts":     True,
    "spa_artifact_dir":       "",
    "spa_child_summary_limit": 12,
    "spa_prompt_char_budget": 48000,
}

DEFAULT_MODEL_MAP: dict = {
    "gemini":            "gemini-2.5-flash-preview-04-17",
    "groq":              "llama3-70b-8192",
    "openai":            "gpt-4o",
    "openai_compatible": "local-model",
    "ollama":            "llama3",
    "lmstudio":          "local-model",
}

VALID_PROVIDERS   = ("gemini", "groq", "openai", "openai_compatible", "ollama", "lmstudio")
VALID_NAMING_MODES = ("conservative", "malware", "blog")
VALID_RENAME_ORDERS = ("best_effort_bottom_up", "strict_bottom_up", "proposal_aware_bottom_up")
VALID_REQUEST_BUDGET_MODES = ("fast_low_requests", "free_key_balanced", "quality_strict")



def normalize_rename_order(value: str) -> str:
    value = str(value or "best_effort_bottom_up").strip().lower()
    if value in VALID_RENAME_ORDERS:
        return value
    try:
        from logger import log
        log.warn("Invalid rename_order '%s'; using best_effort_bottom_up." % value)
    except Exception:
        pass
    return "best_effort_bottom_up"


def normalize_request_budget_mode(value: str) -> str:
    value = str(value or "free_key_balanced").strip().lower()
    return value if value in VALID_REQUEST_BUDGET_MODES else "free_key_balanced"

def _config_path() -> str:
    if _IN_IDA:
        return os.path.join(idaapi.get_user_idadir(), "reverse_partner_config.json")
    return os.path.expanduser("~/.reverse_partner_config.json")


def _migrate(data: dict) -> dict:
    """Migrate v4 fields → v5 without data loss."""
    # old single-key field
    if "api_key" in data and isinstance(data["api_key"], str) and data["api_key"]:
        if not data.get("api_keys"):
            data["api_keys"] = [data["api_key"]]
        del data["api_key"]
    # inject missing v5 defaults
    for k, v in DEFAULT_CONFIG.items():
        if k not in data:
            data[k] = v
    data["rename_order"] = normalize_rename_order(data.get("rename_order"))
    data["request_budget_mode"] = normalize_request_budget_mode(data.get("request_budget_mode"))
    return data


def load_config() -> dict:
    try:
        with open(_config_path(), "r", encoding="utf-8") as f:
            data   = json.load(f)
            merged = DEFAULT_CONFIG.copy()
            merged.update(data)
            return _migrate(merged)
    except Exception:
        return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    try:
        cfg.pop("api_key", None)  # never save legacy field
        cfg["rename_order"] = normalize_rename_order(cfg.get("rename_order"))
        cfg["request_budget_mode"] = normalize_request_budget_mode(cfg.get("request_budget_mode"))
        with open(_config_path(), "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
    except Exception as exc:
        from logger import log
        log.err("Cannot save config: %s" % exc)


def load_keys_from_file(path: str) -> list:
    keys = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    keys.append(line)
    except Exception as exc:
        from logger import log
        log.err("Cannot read keys file: %s" % exc)
    return keys


def get_budget_chars(model: str) -> int:
    b = TOKEN_BUDGETS.get(model, {"input": 10_000, "cpt": 4})
    return int(b["input"] * b["cpt"] * INPUT_USAGE_RATIO)


def mask_key(key: str) -> str:
    """Mask API key for logging — never print full keys."""
    if not key or len(key) < 12:
        return "***"
    return key[:6] + "..." + key[-4:]
