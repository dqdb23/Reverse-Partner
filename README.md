# Reverse Partner— IDA Pro 9.0

AI-powered function renamer for authorized malware reverse engineering.  
Modular, debug-safe, supports local and cloud AI providers.

---

## File layout

```
reverse_partner/
├── __init__.py          IDA plugin entry point  (PLUGIN_ENTRY)
├── guards.py            Debugger safety guards  (preserved from v4)
├── logger.py            Output-window logger
├── config.py            Load / save / migrate config
├── utils.py             Name sanitization, JSON repair, AI result normalization
├── ida_read.py          All IDA read-only operations
├── ida_write.py         All IDA write operations  (all guarded)
├── static_analysis.py   Rule-based pre-tagger, context builder
├── prompts.py           AI prompt templates, batch packer
├── providers.py         AI provider abstraction (Gemini/Groq/OpenAI/Ollama/LMStudio)
├── cache.py             SHA-256 analysis cache with TTL
├── history.py           Rename history + rollback
├── review_queue.py      Review queue storage + chooser UI
├── anti_obfuscation.py  4-pass static anti-obfuscation scanner
├── struct_inference.py  AI-powered struct layout recovery
├── ioc_extractor.py     Standalone rule-based IOC extractor
├── report.py            HTML forensic report generator
├── rename_engine.py     Core rename / analysis orchestration
├── actions.py           IDA action handler classes
├── settings_ui.py       Settings wizard dialogs
└── tests.py             Standalone test harness (no IDA required)
```

---

## Installation

### 1. Install Python dependencies

```bash
# Gemini (free tier — recommended)
pip install google-generativeai

# Groq (free tier, fast)
pip install groq

# OpenAI / openai_compatible / LM Studio
pip install openai

# Ollama — no pip package needed; install Ollama separately
# https://ollama.com/download
```

### 2. Copy plugin folder to IDA

```
<IDA install dir>/plugins/reverse_partner/   ← copy entire folder here
```

### 3. Restart IDA

The plugin loads automatically.  
Watch the **Output window** (Alt+0) for the startup banner.

---

## First run

1. Press **Ctrl+Shift+S** → Settings
2. Select provider (e.g. `gemini`)
3. Enter or load your API key
4. Enter model name (e.g. `gemini-2.5-flash-preview-04-17`)
5. Choose naming mode: `conservative` / `malware` / `blog`
6. Leave **Review Mode = YES** (safer — you approve each rename)
7. Save

Then press **Ctrl+Shift+U** to rename unnamed functions only.

---

## Hotkeys

| Hotkey | Action |
|--------|--------|
| `Shift+G` | Rename function under cursor |
| `Ctrl+Shift+U` | Rename unnamed (sub_XXXX) functions |
| `Ctrl+Shift+G` | Rename all functions |
| `Ctrl+Shift+A` | Deep AI analysis of current function |
| `Ctrl+Shift+R` | Analyze whole program (3-phase) |
| `Ctrl+Shift+O` | Anti-obfuscation scanner (static only) |
| `Ctrl+Shift+E` | Export forensic report (JSON + HTML) |
| `Ctrl+Shift+Q` | Review Queue — approve / reject suggestions |
| `Ctrl+Alt+Z` | Rollback last rename batch |
| `Ctrl+Shift+I` | Extract IOCs from binary |
| `Ctrl+Shift+L` | Analyze selected instruction range |
| `Ctrl+Shift+X` | Struct inference for current function |
| `Ctrl+Shift+S` | Settings |

All actions are also in **Edit > GPT Renamer**.

---

## Providers

| Provider | Key required | Notes |
|----------|-------------|-------|
| `gemini` | Yes (free tier) | Recommended default |
| `groq` | Yes (free tier) | Fastest for batch |
| `openai` | Yes (paid) | GPT-4o recommended |
| `openai_compatible` | Optional | Any vLLM / LiteLLM endpoint |
| `ollama` | No | Set base_url to `http://127.0.0.1:11434` |
| `lmstudio` | No | Set base_url to `http://127.0.0.1:1234/v1` |

API keys file format (one key per line):
```
AIzaSyABC...key1
AIzaSyDEF...key2
```

---

## Review Queue workflow

With `review_mode = true` (default):

1. AI results are stored in the queue — **no automatic rename**.
2. Press **Ctrl+Shift+Q** to open the chooser.
3. Click a row to see full details and choose **Apply** or **Reject**.
4. Or click **"Apply all ≥ 0.85 confidence"** to bulk-apply high-confidence items.

With `review_mode = false`:

| Confidence | Action |
|------------|--------|
| `>= auto_apply_confidence (0.85)` | Auto-rename + comment |
| `0.60 – 0.84` | Added to review queue, not renamed |
| `< 0.60` | Comment only, not renamed |

---

## Rollback

Every rename batch is saved to `<binary_name>_gpt_rename_history.json`.

Press **Ctrl+Alt+Z** to roll back the last batch.  
The plugin asks for confirmation and handles manually-changed names gracefully.

---

## Analysis Cache

Cache file: `<IDA user dir>/reverse_partner_cache.json`  
Cache key: SHA-256 of `(ea, name, code, callers, callees, strings, apis, model, provider, prompt_version)`

Functions with unchanged code reuse cached results — no AI call needed.  
TTL default: 90 days.  Cache is pruned to 5000 entries automatically.

---

## Naming Modes

| Mode | Description |
|------|-------------|
| `conservative` | Behavior-faithful names; no overclaiming (`xor_transform_buffer`) |
| `malware` | Stronger names with evidence (`install_service_persistence`) |
| `blog` | Analyst-friendly descriptive names (`stage4_loader_entry`) |

Overclaim guard: names containing `steal`, `exfiltrate`, `backdoor`, `c2`, etc.
are automatically confidence-capped at 0.55 if evidence count < 2.

---

## IOC Extractor

**Ctrl+Shift+I** scans all binary strings for:

IPv4 · IPv6 · Domains · URLs · Windows paths · UNC paths · Registry paths  
Global mutexes · User-Agent strings · Base64 blobs · PE artifacts · Emails · Env vars

Results are also included in the HTML forensic report.

---

## Struct Inference

**Ctrl+Shift+X** on a function:

1. Detects `reg+offset` field accesses statically.
2. Sends offsets + code context to AI.
3. AI suggests field names, types, and purposes.
4. Output: C struct definition in Output window + function comment if confidence ≥ 0.70.

---

## HTML Forensic Report

**Ctrl+Shift+E** exports:

- Binary overview stats + rename coverage bar
- Full sortable function table (filterable)
- Suspicious / high-risk functions (INJECT/PERSIST/EVASION/CRYPTO/LOADER/MEMORY)
- Review queue pending items
- IOC section (all types)
- Top called APIs
- Top referenced strings
- Rename history summary

Fully self-contained HTML — no external JS/CSS.

---

## Config migration from v4

Config is auto-migrated on first load:

| v4 field | v5 field | Note |
|----------|----------|------|
| `api_key` (str) | `api_keys` (list) | Moved into list |
| *(missing)* | `naming_mode` | Default: `conservative` |
| *(missing)* | `review_mode` | Default: `true` |
| *(missing)* | `auto_apply_confidence` | Default: `0.85` |
| *(missing)* | `enable_cache` | Default: `true` |
| *(missing)* | `enable_struct_inference` | Default: `true` |

Config file: `<IDA user dir>/reverse_partner_config.json`

---

## Running tests (outside IDA)

```bash
cd plugins/reverse_partner
python tests.py
# or
python -m pytest tests.py -v
```

Tests cover: sanitize_name, is_default_name, JSON repair, parse_json_response_v5,
normalize_ai_result, validate_ai_result, classify_provider_error, mask_key,
compute_cache_key, IOC patterns, build_prompt, format_struct_c.

---

## Safety guarantees

- **No IDB write while debugger is active** — every write path checks `is_debugger_active()`.
- Avoids IDA's unsafe no-check name flag; preserved from v4 to prevent crashes on duplicate names.
- **No binary patching** — plugin never writes to the binary file.
- **API keys never printed in full** — masked as `AIzaSy...WXYZ` in all logs.
- **No malware execution / injection / persistence** — static analysis only.
- **All network traffic = AI provider calls only**.
