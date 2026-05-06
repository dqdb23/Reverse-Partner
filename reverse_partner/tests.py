# -*- coding: utf-8 -*-
"""
tests.py — Standalone test harness
=====================================
Tests pure-Python helpers.  Run outside IDA:
    python tests.py
or via unittest:
    python -m pytest tests.py -v

IDA modules are never imported here.
"""

import sys
import os

# Allow importing sibling modules without IDA
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _pass(name):
    print("PASS  %s" % name)


def _fail(name, got, expected="", note=""):
    print("FAIL  %s  got=%r  expected=%r  %s" % (name, got, expected, note))


def check(name, got, expected):
    if got == expected:
        _pass(name)
        return True
    _fail(name, got, expected)
    return False


def check_true(name, cond, note=""):
    if cond:
        _pass(name)
        return True
    _fail(name, cond, True, note)
    return False


# ---------------------------------------------------------------------------

def test_sanitize_name():
    from utils import sanitize_name
    check("basic",        sanitize_name("parse_http_response"), "parse_http_response")
    check("prefix",       sanitize_name("foo", "mal_"),          "mal_foo")
    check("special_chars",sanitize_name("foo bar!"),              "foo_bar")
    check("digit_start",  sanitize_name("123abc"),                "_123abc")
    check("empty",        sanitize_name(""),                      "unknown_func")
    check_true("max_len", len(sanitize_name("a" * 200)) <= 64)
    check("backtick",     sanitize_name("`name`"),                "name")
    check("slash",        sanitize_name("foo/bar"),               "foo")


def test_is_default_name():
    from utils import is_default_name
    check("sub_",    is_default_name("sub_401000"),  True)
    check("nullsub", is_default_name("nullsub_1"),   True)
    check("loc_",    is_default_name("loc_4010AB"),  True)
    check("j_",      is_default_name("j_printf"),    True)
    check("named",   is_default_name("parse_config"),False)
    check("named2",  is_default_name("create_socket"),False)
    check("empty",   is_default_name(""),            True)


def test_repair_json():
    from utils import repair_json_response
    # Markdown fences
    r = repair_json_response('```json\n{"name": "foo"}\n```')
    check_true("fence_removed", '"name"' in r)

    # Trailing commas
    r = repair_json_response('{"name": "bar",}')
    check_true("trailing_comma", '"name"' in r and '"bar"' in r)

    # Smart quotes
    r = repair_json_response('\u201cname\u201d: \u201cfoo\u201d')
    check_true("smart_quotes", '"name"' in r or "name" in r)

    # Leading prose
    r = repair_json_response('Here is the result: {"x": 1}')
    check_true("leading_prose", '"x"' in r)


def test_parse_json():
    from utils import parse_json_response_v5
    # Direct
    r = parse_json_response_v5('{"name": "foo", "confidence": 0.9}')
    check("direct_name",  r.get("name"), "foo")
    check("direct_conf",  r.get("confidence"), 0.9)

    # Fenced
    r = parse_json_response_v5('```json\n{"name": "bar"}\n```')
    check("fenced",       r.get("name"), "bar")

    # Trailing comma
    r = parse_json_response_v5('{"name": "baz",}')
    check("trailing_comma", r.get("name"), "baz")

    # Error case
    r = parse_json_response_v5("this is not json {{{{")
    check_true("error_dict", "_parse_error" in r)

    # Empty
    r = parse_json_response_v5("")
    check_true("empty_error", "_parse_error" in r)


def test_normalize_ai_result():
    from utils import normalize_ai_result

    raw = {
        "name": "decrypt_config",
        "confidence": 0.92,
        "category": "CRYPTO",
        "description": "Decrypts embedded config.",
        "evidence": ["calls CryptDecrypt", "allocs output buffer"],
        "warnings": [],
        "tags": ["CRYPTO", "CONFIG"],
    }
    n = normalize_ai_result(raw, "sub_401000", "", require_evidence=True)
    check("norm_name",       n["name"],        "decrypt_config")
    check("norm_conf",       n["confidence"],  0.92)
    check("norm_cat",        n["category"],    "CRYPTO")
    check_true("norm_ev",    len(n["evidence"]) == 2)
    check_true("no_error",   not n.get("_error"))

    # Overclaim without evidence
    raw2 = {"name": "steal_credentials", "confidence": 0.9,
            "category": "RECON", "description": "", "evidence": [],
            "warnings": [], "tags": []}
    n2 = normalize_ai_result(raw2, "sub_401000", "", require_evidence=True)
    check_true("overclaim_conf_capped", n2["confidence"] <= 0.5)
    check_true("overclaim_warning", any("overclaim" in w for w in n2["warnings"]))

    # Parse error raw
    n3 = normalize_ai_result({"_parse_error": "fail"}, "sub_401000")
    check_true("parse_error_flag", n3.get("_error"))

    # Prefix
    n4 = normalize_ai_result(raw, "sub_401000", prefix="mal_")
    check_true("prefix_applied", n4["name"].startswith("mal_"))


def test_validate_ai_result():
    from utils import validate_ai_result

    good = {"name": "parse_config", "confidence": 0.88, "category": "CONFIG",
            "description": "x", "evidence": ["something"], "warnings": [], "tags": []}
    ok, issues = validate_ai_result(good)
    check("valid_ok", ok, True)
    check("valid_no_issues", issues, [])

    bad = {"name": "123bad!", "confidence": 2.0, "category": "NOPE",
           "description": "", "evidence": [], "warnings": [], "tags": []}
    ok2, issues2 = validate_ai_result(bad)
    check("invalid_ok", ok2, False)
    check_true("invalid_has_issues", len(issues2) > 0)

    check("non_dict_invalid", validate_ai_result("notadict")[0], False)


def test_classify_provider_error():
    from providers import classify_provider_error
    check("quota",   classify_provider_error("quota exceeded"),        "quota_exhausted")
    check("rate",    classify_provider_error("429 too many requests"), "rate_limited")
    check("auth",    classify_provider_error("401 unauthorized"),      "auth_error")
    check("model",   classify_provider_error("model not found"),       "model_not_found")
    check("safety",  classify_provider_error("safety blocked"),        "safety_block")
    check("timeout", classify_provider_error("connection timed out"),  "network_timeout")
    check("unknown", classify_provider_error("segfault"),              "unknown_error")


def test_mask_key():
    from config import mask_key
    check("mask_long",  mask_key("AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ"), "AIzaSy...WXYZ")
    check("mask_short", mask_key("abc"),                                "***")
    check("mask_empty", mask_key(""),                                   "***")


def test_cache_key():
    from cache import compute_cache_key
    k1 = compute_cache_key(0x401000, "sub_401000", "push ebp",
                           [], [], [], [], "model", "gemini")
    k2 = compute_cache_key(0x401000, "sub_401000", "push ebp",
                           [], [], [], [], "model", "gemini")
    k3 = compute_cache_key(0x401000, "sub_401000", "push eax",
                           [], [], [], [], "model", "gemini")
    check("stable",  k1, k2)
    check_true("differs_on_code",    k1 != k3)

    k4 = compute_cache_key(0x401000, "sub_401000", "push ebp",
                           [], [], [], [], "gpt-4o", "openai")
    check_true("differs_on_model",   k1 != k4)


def test_ioc_patterns():
    from ioc_extractor import extract_iocs_from_text

    corpus = (
        "http://evil.com/payload.exe\n"
        "192.168.1.100\n"
        "HKEY_LOCAL_MACHINE\\Software\\evil\n"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Appl\n"
        "C:\\Windows\\System32\\cmd.exe\n"
        "user@evil.com\n"
    )
    iocs = extract_iocs_from_text(corpus)
    check_true("url_found",    bool(iocs.get("url")))
    check_true("ipv4_found",   bool(iocs.get("ipv4")))
    check_true("reg_found",    bool(iocs.get("registry")))
    check_true("path_found",   bool(iocs.get("win_path")))
    check_true("email_found",  bool(iocs.get("email")))
    check_true("pe_found",     bool(iocs.get("pe_artifact")))


def test_build_prompt_no_crash():
    from prompts import build_prompt
    batch = [
        {"name": "sub_401000", "code": "mov eax, 1\nret",
         "callees": ["CreateFile"], "callers": [],
         "strings": ["evil.dll"], "apis": ["CreateFile"],
         "constants": ["0xDEAD"], "pre_tags": ["FILE"],
         "mitre_hints": ["T1055"], "local_vars": [], "struct_accesses": []},
    ]
    cfg  = {"naming_mode": "conservative"}
    text = build_prompt(batch, cfg)
    check_true("prompt_has_name",   "sub_401000" in text)
    check_true("prompt_has_api",    "CreateFile" in text)
    check_true("prompt_has_tag",    "FILE" in text)


def test_format_struct_c():
    from struct_inference import format_struct_c
    result = {
        "struct_name": "context_t",
        "confidence":  0.82,
        "fields": [
            {"offset": 0,  "name": "size",    "type": "DWORD",  "purpose": "allocation size"},
            {"offset": 4,  "name": "flags",   "type": "DWORD",  "purpose": "control flags"},
            {"offset": 8,  "name": "buffer",  "type": "LPVOID", "purpose": "data pointer"},
        ],
    }
    c_def = format_struct_c(result)
    check_true("struct_typedef",  "typedef struct" in c_def)
    check_true("struct_name",     "context_t" in c_def)
    check_true("field_size",      "size" in c_def)
    check_true("field_offset",    "+0x00" in c_def or "+0x04" in c_def)


def test_variable_suggestion_validation():
    from variable_renamer import _validate_suggestions
    raw = {
        "variables": [
            {"old_name": "v1", "new_name": "Buffer Length", "confidence": 1.5, "reason": "used as size"},
            {"old_name": "missing", "new_name": "bad", "confidence": 0.9, "reason": "not known"},
            {"old_name": "v2", "new_name": "v2", "confidence": 0.9, "reason": "same"},
        ]
    }
    result = _validate_suggestions(raw, {"v1", "v2"})
    check("var_valid_count", len(result), 1)
    check("var_name_sanitized", result[0]["new_name"], "buffer_length")
    check("var_conf_clamped", result[0]["confidence"], 1.0)


def test_prototype_validation():
    from prototype_inference import _validate_prototype
    good = _validate_prototype("int __fastcall sub_401000(int a1)", "sub_401000")
    bad_multiline = _validate_prototype("int sub_401000()\n{ return 0; }", "sub_401000")
    bad_name = _validate_prototype("int other_name(void)", "sub_401000")
    check_true("proto_accepts_decl", good.endswith(";"))
    check("proto_rejects_multiline", bad_multiline, "")
    check("proto_rejects_wrong_name", bad_name, "")


def test_idb_storage_chunk_helpers():
    import idb_storage

    class FakeNode:
        def __init__(self):
            self.data = {}

        def hashset(self, key, value, tag=None):
            self.data[key] = value
            return True

        def hashstr(self, key, tag=None):
            return self.data.get(key)

        def hashval(self, key, tag=None):
            return self.data.get(key)

        def hashdel(self, key, tag=None):
            return self.data.pop(key, None) is not None

        def hdel(self, key):
            return self.hashdel(key)

    node = FakeNode()
    payload = idb_storage._json_pack({"text": "A" * (idb_storage.CHUNK_SIZE + 20)})
    idb_storage._store_value(node, "k", payload)
    loaded = idb_storage._load_value(node, "k")
    check("idb_chunk_roundtrip", loaded["text"], "A" * (idb_storage.CHUNK_SIZE + 20))
    check("idb_corrupt_json_text", idb_storage._json_unpack("{not-json"), "{not-json")


def test_floss_json_parser():
    from floss_integration import parse_floss_json
    raw = '{"strings": {"decoded_strings": [{"string": "http://evil.example.com/a", "address": "0x401000"}]}}'
    result = parse_floss_json(raw)
    check("floss_json_count", len(result), 1)
    check("floss_json_string", result[0]["string"], "http://evil.example.com/a")
    check("floss_json_addr", result[0]["address"], 0x401000)


def test_floss_text_parser():
    from floss_integration import parse_floss_json
    result = parse_floss_json("0x401000 decoded.example.net\nshort\nplain-string-value")
    values = [r["string"] for r in result]
    check_true("floss_text_addr_value", "decoded.example.net" in values)
    check_true("floss_text_plain_value", "plain-string-value" in values)


def test_floss_ioc_extraction_dedup():
    from floss_integration import extract_iocs_from_floss_results
    records = [
        {"string": "connect http://dup.example.com/a"},
        {"string": "backup http://dup.example.com/a"},
    ]
    iocs = extract_iocs_from_floss_results(records)
    check("floss_ioc_dedup", len(iocs.get("url", [])), 1)
    check("floss_ioc_source", iocs["url"][0]["source"], "floss_decoded")


def test_floss_timeout_handling():
    import os
    import tempfile
    import subprocess
    import floss_integration

    fd, path = tempfile.mkstemp()
    os.close(fd)
    old_run = floss_integration.subprocess.run
    try:
        def _raise_timeout(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], kwargs.get("timeout", 1))
        floss_integration.subprocess.run = _raise_timeout
        result = floss_integration.run_floss_on_input_binary({
            "_input_path": path,
            "floss_path": "floss",
            "floss_timeout_sec": 1,
        })
        check("floss_timeout_empty", result, [])
    finally:
        floss_integration.subprocess.run = old_run
        try:
            os.remove(path)
        except Exception:
            pass


def test_spa_topological_sort_cycles():
    from static_program_analyzer import detect_cycles, topological_order_bottom_up
    graph = {
        "nodes": {"A": {}, "B": {}, "C": {}},
        "edges": [{"caller": "A", "callee": "B"}, {"caller": "B", "callee": "C"}, {"caller": "C", "callee": "B"}],
    }
    order = topological_order_bottom_up(graph)
    cycles = detect_cycles(graph)
    check_true("spa_order_has_all", set(order) == {"A", "B", "C"})
    check_true("spa_cycle_detected", len(cycles) >= 1)


def test_spa_priority_scoring():
    from static_program_analyzer import score_function_for_review
    ctx = {
        "name": "sub_401000",
        "apis": ["InternetOpenA", "VirtualAlloc", "WriteFile"],
        "callees": [],
        "strings": ["http://example.com/a", "C:\\Temp\\dropper.exe"],
        "decoded_strings": [{"value": "HKCU\\Software\\Test"}],
        "pre_tags": [],
        "n_insn": 50,
    }
    score = score_function_for_review(ctx)
    check_true("spa_score_interesting", score["interesting"])
    check_true("spa_score_medium_plus", score["score"] >= 8)


def test_spa_candidate_selection():
    from static_program_analyzer import select_ai_candidates_for_review
    items = [
        {"ea_hex": "0x1", "name": "sub_1", "static_score": {"score": 1, "priority": "low"}},
        {"ea_hex": "0x2", "name": "sub_2", "static_score": {"score": 7, "priority": "high"}},
        {"ea_hex": "0x3", "name": "sub_3", "static_score": {"score": 4, "priority": "medium"}},
    ]
    selected = select_ai_candidates_for_review(items, limit=2, min_score=3)
    check("spa_selected_count", len(selected), 2)
    check("spa_selected_first", selected[0]["ea_hex"], "0x2")


def test_spa_result_normalization():
    from static_program_analyzer import normalize_spa_result, validate_spa_result
    raw = {
        "function_name": "Do Thing",
        "confidence": 1.2,
        "priority": "HIGH",
        "category": "NETWORK",
        "summary": "Uses visible network APIs.",
        "evidence": ["InternetOpenA"],
        "rename_recommendation": {"apply": True, "name": "Network Init", "reason": "API evidence"},
    }
    norm = normalize_spa_result(raw, original_name="sub_1", cfg={"auto_apply_confidence": 0.85})
    ok, issues = validate_spa_result(norm)
    check_true("spa_norm_valid", ok)
    check("spa_norm_conf", norm["confidence"], 1.0)
    check("spa_norm_name", norm["rename_recommendation"]["name"], "network_init")


def test_spa_json_repair():
    from static_program_analyzer import parse_spa_result
    text = '```json\n{"confidence": 0.5, "evidence": ["x"], "category": "UTIL",}\n```'
    result = parse_spa_result(text, original_name="sub_1")
    check("spa_repair_category", result["category"], "UTIL")


def test_spa_artifact_path_and_child_truncation():
    from static_program_analyzer import make_artifact_dir, truncate_child_summaries
    path = make_artifact_dir({"spa_artifact_dir": "D:\\out"}, timestamp="20260101_000000", input_path="D:\\a.exe")
    children = truncate_child_summaries(
        [{"ea": "0x1", "name": "a", "summary": "A" * 100}],
        limit=1, char_limit=10)
    check_true("spa_artifact_suffix", path.endswith("gpt_renamer_static_analysis_20260101_000000"))
    check("spa_child_truncated", children[0]["summary"], "A" * 10)


def test_spa_priority_sorting():
    from static_program_analyzer import sort_by_priority
    items = [
        {"ea_hex": "0x1", "static_score": {"score": 3, "priority": "medium"}},
        {"ea_hex": "0x2", "static_score": {"score": 9, "priority": "critical"}},
        {"ea_hex": "0x3", "static_score": {"score": 6, "priority": "high"}},
    ]
    sorted_items = sort_by_priority(items)
    check("spa_sort_first", sorted_items[0]["ea_hex"], "0x2")


def test_spa_summary_accounting():
    from static_program_analyzer import StaticProgramAnalyzer
    analyzer = StaticProgramAnalyzer(cfg={"spa_use_cache": False}, mode="current_function")
    analyzer.scored_items = [{"ea_hex": "0x1"}, {"ea_hex": "0x2"}, {"ea_hex": "0x3"}]
    analyzer.results = {
        "0x1": {"_analysis_mode": "ai"},
        "0x2": {"_analysis_mode": "static_only"},
        "0x3": {"_analysis_mode": "ai_error"},
    }
    summary = analyzer.update_summary_data({"results": analyzer.results})
    check("spa_summary_ai_count", summary["ai_analyzed"], 1)
    check("spa_summary_static_count", summary["static_only"], 2)


# ---------------------------------------------------------------------------

def run_all():
    tests = [
        test_sanitize_name,
        test_is_default_name,
        test_repair_json,
        test_parse_json,
        test_normalize_ai_result,
        test_validate_ai_result,
        test_classify_provider_error,
        test_mask_key,
        test_cache_key,
        test_ioc_patterns,
        test_build_prompt_no_crash,
        test_format_struct_c,
        test_variable_suggestion_validation,
        test_prototype_validation,
        test_idb_storage_chunk_helpers,
        test_floss_json_parser,
        test_floss_text_parser,
        test_floss_ioc_extraction_dedup,
        test_floss_timeout_handling,
        test_spa_topological_sort_cycles,
        test_spa_priority_scoring,
        test_spa_candidate_selection,
        test_spa_result_normalization,
        test_spa_json_repair,
        test_spa_artifact_path_and_child_truncation,
        test_spa_priority_sorting,
        test_spa_summary_accounting,
    ]

    import io
    from contextlib import redirect_stdout
    passed = failed = 0
    for t in tests:
        buf = io.StringIO()
        print("\n-- %s" % t.__name__)
        try:
            with redirect_stdout(buf):
                t()
        except Exception as exc:
            print("  ERROR: %s" % exc)
            failed += 1
            continue
        output = buf.getvalue()
        for line in output.splitlines():
            print("  " + line)
        f = output.count("\nFAIL")
        p = output.count("\nPASS")
        passed += p
        failed += f

    print("\n" + "=" * 50)
    print("Results: %d passed, %d failed" % (passed, failed))
    return failed == 0


if __name__ == "__main__":
    ok = run_all()
    sys.exit(0 if ok else 1)
