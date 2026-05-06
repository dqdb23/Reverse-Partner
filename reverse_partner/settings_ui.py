# -*- coding: utf-8 -*-
"""
settings_ui — Settings wizard (IDA ask_str / ask_yn dialogs)
=============================================================
Covers all v5 config fields. Migrates old config gracefully.
Never stores duplicate keys. Never shows full API keys.
"""

import re
from config import (
    load_config, save_config, load_keys_from_file, mask_key,
    VALID_PROVIDERS, VALID_NAMING_MODES, DEFAULT_MODEL_MAP,
)
from logger import log

try:
    import idaapi
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

_KEY_GUIDE = {
    "gemini":            "Free tier: https://aistudio.google.com/apikey",
    "groq":              "Free tier: https://console.groq.com/keys",
    "openai":            "Paid: https://platform.openai.com/api-keys",
    "openai_compatible": "API key for the compatible server (or 'none' if not required)",
    "ollama":            "No key required — leave blank.",
    "lmstudio":          "No key required — leave blank.",
}

_MODEL_GUIDE = {
    "gemini":            "gemini-2.5-flash-preview-04-17 | gemini-1.5-flash | gemini-2.5-pro",
    "groq":              "llama3-70b-8192 | llama3-8b-8192 | mixtral-8x7b-32768",
    "openai":            "gpt-4o | gpt-4-turbo | gpt-3.5-turbo",
    "openai_compatible": "Model name served by your endpoint (e.g. mistral-7b)",
    "ollama":            "llama3 | mistral | codellama | phi3",
    "lmstudio":          "Name of the model loaded in LM Studio",
}


def _yn(label: str, current: bool) -> bool:
    """Show YES/NO dialog; return bool result. Returns current on Cancel."""
    if not _IN_IDA:
        return current
    ans = idaapi.ask_yn(
        idaapi.ASKBTN_YES if current else idaapi.ASKBTN_NO,
        label)
    if ans == idaapi.ASKBTN_CANCEL:
        return current
    return ans == idaapi.ASKBTN_YES


def _ask(label: str, default: str) -> str:
    """Show string input dialog; return default on Cancel."""
    if not _IN_IDA:
        return default
    result = idaapi.ask_str(default, 0, label)
    return result.strip() if result is not None else default


def show_settings():
    if not _IN_IDA:
        log.warn("Settings UI requires IDA.")
        return

    cfg = load_config()

    # ── [1] Provider ────────────────────────────────────────────────────
    prov_raw = _ask(
        "Settings [1/10] — Provider\n\n"
        "  gemini           ← free (recommended)\n"
        "  groq             ← free, fast\n"
        "  openai           ← paid\n"
        "  openai_compatible← any OpenAI-compat server (vLLM, LiteLLM, …)\n"
        "  ollama           ← local, no key\n"
        "  lmstudio         ← local, no key\n\n"
        "Enter provider:",
        cfg.get("provider", "gemini")
    )
    provider = prov_raw.lower()
    if provider not in VALID_PROVIDERS:
        provider = "gemini"

    # ── [2] base_url (local providers) ──────────────────────────────────
    base_url = cfg.get("base_url", "")
    if provider in ("openai_compatible", "ollama", "lmstudio"):
        defaults = {
            "openai_compatible": "",
            "ollama":            "http://127.0.0.1:11434",
            "lmstudio":          "http://127.0.0.1:1234/v1",
        }
        base_url = _ask(
            "Settings [2/10] — Base URL (%s)\n\nServer URL:" % provider,
            base_url or defaults.get(provider, "")
        )
    else:
        base_url = ""

    # ── [3] API keys ─────────────────────────────────────────────────────
    current_keys = cfg.get("api_keys", [])
    masked_list  = [mask_key(k) for k in current_keys[:5]]
    key_summary  = (", ".join(masked_list) + (" …" if len(current_keys) > 5 else "")
                    if current_keys else "none")

    ans3 = idaapi.ask_yn(idaapi.ASKBTN_YES,
        "Settings [3/10] — API Keys\n\n"
        "Provider : %s\n"
        "Current  : %s (%d key%s)\n\n"
        "%s\n\n"
        "YES    = Load keys from file\n"
        "NO     = Type / add one key\n"
        "Cancel = Keep current keys" % (
            provider, key_summary, len(current_keys),
            "s" if len(current_keys) != 1 else "",
            _KEY_GUIDE.get(provider, "")
        ))

    if ans3 == idaapi.ASKBTN_CANCEL:
        new_keys, new_keys_file = current_keys, cfg.get("keys_file", "")
    elif ans3 == idaapi.ASKBTN_YES:
        path = idaapi.ask_file(0, "*.txt", "Select API keys file (one key per line):")
        if path:
            loaded = load_keys_from_file(path)
            if loaded:
                new_keys, new_keys_file = loaded, path
                log.ok("Loaded %d keys from: %s" % (len(loaded), path))
            else:
                idaapi.warning("File is empty — keeping current keys.")
                new_keys, new_keys_file = current_keys, cfg.get("keys_file", "")
        else:
            new_keys, new_keys_file = current_keys, cfg.get("keys_file", "")
    else:
        if provider in ("ollama", "lmstudio"):
            new_keys, new_keys_file = ["local"], ""
        else:
            raw = _ask(
                "Settings [3/10] — Enter API key\n\n%s\n\nPaste key:" % (
                    _KEY_GUIDE.get(provider, "")),
                ""
            )
            if raw and raw.strip() and raw.strip() not in current_keys:
                new_keys = current_keys + [raw.strip()]
            else:
                new_keys = current_keys
            new_keys_file = cfg.get("keys_file", "")

    if not new_keys and provider not in ("ollama", "lmstudio"):
        idaapi.warning("No API keys set — plugin won't be able to call AI.")

    # ── [4] Model ────────────────────────────────────────────────────────
    model = _ask(
        "Settings [4/10] — Model\n\n%s\n\nEnter model name:" % (
            _MODEL_GUIDE.get(provider, "")),
        cfg.get("model", DEFAULT_MODEL_MAP.get(provider, ""))
    ) or DEFAULT_MODEL_MAP.get(provider, "")

    # ── [5] Batch size ────────────────────────────────────────────────────
    batch_raw = _ask(
        "Settings [5/10] — Batch Size\n\n"
        "Functions per AI request (recommended: 50).\n"
        "Lower = more requests but smaller prompts.\n\nEnter:",
        str(cfg.get("batch_size", 50))
    )
    try:
        batch_size = max(1, int(batch_raw))
    except ValueError:
        batch_size = 50

    # ── [6] Naming mode ───────────────────────────────────────────────────
    nm_raw = _ask(
        "Settings [6/10] — Naming Mode\n\n"
        "  conservative  ← safe, no overclaiming (recommended)\n"
        "  malware       ← stronger names allowed with evidence\n"
        "  blog          ← analyst-friendly descriptive names\n\nEnter:",
        cfg.get("naming_mode", "conservative")
    ).lower()
    naming_mode = nm_raw if nm_raw in VALID_NAMING_MODES else "conservative"

    # ── [7] Review mode ───────────────────────────────────────────────────
    review_mode = _yn(
        "Settings [7/10] — Review Mode\n\n"
        "YES = Store AI results in review queue before applying\n"
        "      (safer — you approve each rename)\n"
        "NO  = Auto-apply when confidence ≥ threshold",
        cfg.get("review_mode", True)
    )
    ac_raw = _ask(
        "Settings [7/10] — Auto-Apply Confidence Threshold\n\n"
        "(Only used when Review Mode = OFF.)\n"
        "Range 0.0–1.0. Recommended: 0.85\n\nEnter:",
        "%.2f" % cfg.get("auto_apply_confidence", 0.85)
    )
    try:
        auto_conf = max(0.0, min(1.0, float(ac_raw)))
    except ValueError:
        auto_conf = 0.85

    # ── [8] Prefix ────────────────────────────────────────────────────────
    prefix_raw = _ask(
        "Settings [8/10] — Prefix (optional)\n\n"
        "Prepended to every AI-suggested name.\n"
        "Example: 'mal_' → mal_decrypt_config\n"
        "Leave blank for none.\n\nEnter:",
        cfg.get("prefix", "")
    )
    prefix = re.sub(r"[^a-zA-Z0-9_]", "", prefix_raw.strip())

    # ── [9] Struct inference + cache ──────────────────────────────────────
    enable_struct = _yn(
        "Settings [9/10] — Struct Inference\n\n"
        "YES = Infer struct layouts for functions with heavy field accesses\n"
        "NO  = Disable (faster)",
        cfg.get("enable_struct_inference", True)
    )
    enable_cache = _yn(
        "Settings [9/10] — Analysis Cache\n\n"
        "YES = Cache AI results to avoid repeated calls for unchanged functions\n"
        "NO  = Always call AI",
        cfg.get("enable_cache", True)
    )

    # ── [10] Misc ─────────────────────────────────────────────────────────
    skip_named   = _yn(
        "Settings [10/10] — Skip Named Functions\n\n"
        "YES = Only rename sub_XXXX / default names\n"
        "NO  = Rename all functions",
        cfg.get("skip_named", True)
    )
    use_pseudo   = _yn(
        "Settings [10/10] — Use Pseudocode\n\n"
        "YES = Use Hex-Rays decompiler output (more accurate)\n"
        "NO  = Use assembly only",
        cfg.get("use_pseudocode", True)
    )
    retry_failed = _yn(
        "Settings [10/10] — Retry Failed\n\n"
        "YES = Single-call retry for functions that failed batch processing\n"
        "NO  = Skip failed functions",
        cfg.get("retry_failed", True)
    )

    # ── Save ─────────────────────────────────────────────────────────────
    cfg.update({
        "provider":              provider,
        "base_url":              base_url,
        "api_keys":              new_keys,
        "keys_file":             new_keys_file,
        "model":                 model,
        "prefix":                prefix,
        "batch_size":            batch_size,
        "naming_mode":           naming_mode,
        "review_mode":           review_mode,
        "auto_apply_confidence": auto_conf,
        "skip_named":            skip_named,
        "use_pseudocode":        use_pseudo,
        "retry_failed":          retry_failed,
        "enable_struct_inference": enable_struct,
        "enable_cache":          enable_cache,
    })
    save_config(cfg)

    log.sep()
    log.ok("Config saved (v5)!")
    log.info("  Provider : %s | Model: %s" % (provider, model))
    if base_url: log.info("  Base URL : %s" % base_url)
    log.info("  Keys     : %d | Batch: %d" % (len(new_keys), batch_size))
    log.info("  Naming   : %s | Review: %s | AutoConf: %.2f" % (
        naming_mode, review_mode, auto_conf))
    log.info("  Prefix   : '%s' | Struct: %s | Cache: %s" % (
        prefix, enable_struct, enable_cache))
    log.sep()
