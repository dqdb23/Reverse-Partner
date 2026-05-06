# -*- coding: utf-8 -*-
"""
report.py — HTML forensic report generator
============================================
Produces a self-contained single-file HTML report with:
  - Binary overview stats
  - Full function table (sortable)
  - Suspicious / tagged functions section
  - High-confidence AI-renamed functions
  - Review queue pending items
  - IOC section (all types)
  - Rename history summary
  - Static behavior tags summary
  - Top called APIs
  - Top referenced strings
  - Call graph summary (top callers/callees)

No external JS/CSS — fully self-contained.
"""

import os
import time
import json
from collections import Counter

try:
    import idaapi, idautils, idc, ida_funcs, ida_xref
    _IN_IDA = True
except ImportError:
    _IN_IDA = False

from logger import log
from utils import is_default_name
from ioc_extractor import extract_iocs_from_binary, format_iocs_report
from history import load_rename_history
from review_queue import load_review_queue
from ida_read import get_referenced_apis, get_referenced_strings, safe_decompile, get_code
from static_analysis import classify_function_static
from ioc_extractor import ioc_values

try:
    from idb_storage import load_blob
except Exception:
    load_blob = None


# ---------------------------------------------------------------------------
# HTML skeleton
# ---------------------------------------------------------------------------

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0b0c12;color:#cdd1e8;font-family:'Consolas','Courier New',monospace;
     font-size:12px;padding:16px 20px}
h1{color:#5b8af0;font-size:18px;margin:12px 0 4px}
h2{color:#7c6bf5;font-size:14px;margin:18px 0 6px;border-bottom:1px solid #22233a;
   padding-bottom:4px}
h3{color:#5b8af0;font-size:12px;margin:10px 0 4px}
a{color:#5b8af0;text-decoration:none}
.stat-bar{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
.stat{background:#161720;border:1px solid #22233a;border-radius:4px;
      padding:6px 14px;color:#6b6f9a}
.stat b{color:#dde1f5}
.section{background:#0f1020;border:1px solid #22233a;border-radius:6px;
         padding:12px;margin:10px 0}
table{border-collapse:collapse;width:100%}
th{background:#161720;color:#5b8af0;padding:5px 8px;text-align:left;
   border:1px solid #22233a;cursor:pointer;user-select:none}
th:hover{background:#1c1d30}
td{padding:4px 7px;border:1px solid #181928;font-size:11px;
   max-width:380px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
tr:hover td{background:#11121a}
.r{color:#3ecf8e}.u{color:#f0a855}.w{color:#f06060}.dim{color:#444}
.tag{display:inline-block;padding:1px 5px;border-radius:2px;font-size:9px;
     font-weight:700;margin:1px 0;background:#1e1f32;color:#7c6bf5}
.ioc{font-family:monospace;background:#161720;padding:2px 7px;border-radius:3px;
     margin:2px;display:inline-block;font-size:10px;color:#3ecf8e;
     border:1px solid #1e2e1e}
pre{background:#0a0b10;padding:8px;border-radius:4px;overflow-x:auto;
    white-space:pre-wrap;word-break:break-all;font-size:10px;color:#9ba3c0}
.q-item{background:#0f1020;border-left:3px solid #7c6bf5;
        padding:6px 10px;margin:4px 0;border-radius:0 4px 4px 0}
.prog{height:8px;background:#22233a;border-radius:4px;margin:6px 0}
.prog-fill{height:8px;border-radius:4px}
input#search{background:#161720;border:1px solid #22233a;color:#cdd1e8;
             padding:4px 8px;font-family:inherit;font-size:11px;
             border-radius:3px;width:260px;margin-bottom:6px}
"""

_SORT_JS = """
function sortTable(tbl,col){
  var rows=Array.from(tbl.querySelectorAll('tbody tr'));
  var asc=tbl._sort_col===col?!tbl._sort_asc:true;
  tbl._sort_col=col; tbl._sort_asc=asc;
  rows.sort(function(a,b){
    var av=a.cells[col]?a.cells[col].innerText:'';
    var bv=b.cells[col]?b.cells[col].innerText:'';
    var an=parseFloat(av),bn=parseFloat(bv);
    if(!isNaN(an)&&!isNaN(bn))return asc?an-bn:bn-an;
    return asc?av.localeCompare(bv):bv.localeCompare(av);
  });
  var tb=tbl.querySelector('tbody');
  rows.forEach(function(r){tb.appendChild(r)});
}
document.querySelectorAll('th[data-col]').forEach(function(th){
  th.addEventListener('click',function(){
    sortTable(th.closest('table'),parseInt(th.dataset.col));
  });
});
function filterTable(){
  var q=document.getElementById('search').value.toLowerCase();
  document.querySelectorAll('#func-table tbody tr').forEach(function(tr){
    tr.style.display=tr.innerText.toLowerCase().includes(q)?'':'none';
  });
}
"""


def _tag_html(tags: list) -> str:
    return "".join("<span class='tag'>%s</span>" % t for t in (tags or []))


def _bar(pct: int, color: str = "#3ecf8e") -> str:
    return ("<div class='prog'><div class='prog-fill' "
            "style='width:%d%%;background:%s'></div></div>" % (min(pct, 100), color))


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------

def collect_report_data(cfg: dict = None) -> dict:
    """
    Gather everything needed for the report. READ-ONLY.
    """
    cfg = cfg or {}
    all_eas = list(idautils.Functions())
    nodes   = {}
    api_counter   = Counter()
    string_counter = Counter()
    decoded_counter = Counter()

    for i, ea in enumerate(all_eas):
        name  = idc.get_func_name(ea) or ("sub_%x" % ea)
        func  = ida_funcs.get_func(ea)
        size  = (func.end_ea - func.start_ea) if func else 0
        n_ins = sum(1 for _ in idautils.Heads(func.start_ea, func.end_ea)) if func else 0
        pre_tags, _, mitre = classify_function_static(ea)
        apis    = get_referenced_apis(ea, 12)
        strs    = get_referenced_strings(ea, 8)
        decoded = []
        try:
            from floss_integration import get_floss_strings_for_function
            for item in get_floss_strings_for_function(ea):
                value = item.get("value", "") if isinstance(item, dict) else str(item)
                if value and value not in strs:
                    decoded.append(value)
                    decoded_counter[value] += 1
        except Exception:
            decoded = []
        cmt     = idc.get_func_cmt(ea, 0) or ""
        idb_meta = {}
        if load_blob:
            try:
                for meta_key in ("analyst_notes", "ai_summary", "readable_c"):
                    value = load_blob(ea, meta_key)
                    if value:
                        idb_meta[meta_key] = value
            except Exception:
                idb_meta = {}
        n_callers = 0
        ref = ida_xref.get_first_cref_to(ea)
        while ref != idaapi.BADADDR:
            n_callers += 1
            ref = ida_xref.get_next_cref_to(ea, ref)

        for a in apis:
            api_counter[a] += 1
        for s in strs:
            if len(s) >= 6:
                string_counter[s] += 1

        nodes[hex(ea)] = {
            "ea":        hex(ea),
            "name":      name,
            "size":      size,
            "n_insn":    n_ins,
            "renamed":   not is_default_name(name),
            "tags":      pre_tags,
            "mitre":     mitre,
            "apis":      apis,
            "strings":   strs,
            "decoded_strings": decoded,
            "comment":   cmt,
            "idb_meta":  idb_meta,
            "n_callers": n_callers,
        }

        if i % 200 == 0 and _IN_IDA:
            try:
                import ida_kernwin
                ida_kernwin.replace_wait_box("Building report data … %d/%d" % (i, len(all_eas)))
            except Exception:
                pass

    n_renamed = sum(1 for n in nodes.values() if n["renamed"])
    iocs      = extract_iocs_from_binary()
    history   = load_rename_history()
    queue     = [q for q in load_review_queue() if q.get("status") == "pending"]
    try:
        from floss_integration import load_cached_floss_results
        for rec in load_cached_floss_results():
            value = rec.get("string", "") if isinstance(rec, dict) else str(rec)
            if value:
                decoded_counter[value] += 1
    except Exception:
        pass

    return {
        "binary":        idc.get_input_file_path() or "unknown",
        "exported_at":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "n_funcs":       len(nodes),
        "n_renamed":     n_renamed,
        "n_unnamed":     len(nodes) - n_renamed,
        "nodes":         nodes,
        "iocs":          iocs,
        "history":       history,
        "queue":         queue,
        "top_apis":      api_counter.most_common(30),
        "top_strings":   string_counter.most_common(20),
        "top_decoded_strings": decoded_counter.most_common(40),
    }


# ---------------------------------------------------------------------------
# HTML builder
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _ioc_text(entry):
    return entry.get("value", "") if isinstance(entry, dict) else str(entry)


def _ioc_sources(entry):
    if isinstance(entry, dict):
        return ", ".join(entry.get("sources", [entry.get("source", "")]))
    return ""


def build_html(data: dict) -> str:
    n_f = data["n_funcs"]
    n_r = data["n_renamed"]
    n_u = data["n_unnamed"]
    pct = int(n_r * 100 / n_f) if n_f else 0

    # ── stat bar ──────────────────────────────────────────────────────────
    stat_bar = (
        "<div class='stat-bar'>"
        "<div class='stat'>Binary: <b>%s</b></div>"
        "<div class='stat'>Functions: <b>%d</b></div>"
        "<div class='stat'>Renamed: <b class='r'>%d</b></div>"
        "<div class='stat'>Unnamed: <b class='u'>%d</b></div>"
        "<div class='stat'>Coverage: <b>%d%%</b></div>"
        "<div class='stat'>Exported: <b>%s</b></div>"
        "</div>" % (
            _esc(os.path.basename(data["binary"])),
            n_f, n_r, n_u, pct, _esc(data["exported_at"])
        )
    )
    stat_bar += _bar(pct)

    # ── function table ────────────────────────────────────────────────────
    rows = []
    for addr, n in sorted(data["nodes"].items(), key=lambda x: int(x[0], 16)):
        status   = "<span class='r'>✓ Renamed</span>" if n["renamed"] else "<span class='u'>unnamed</span>"
        tags_h   = _tag_html(n.get("tags", []))
        cmt      = _esc((n.get("comment") or "")[:100])
        rows.append(
            "<tr><td><a href='#'>%s</a></td><td>%s</td><td>%s</td>"
            "<td>%d</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td></tr>" % (
                _esc(addr), _esc(n["name"]), status,
                n["n_insn"], n["size"], n["n_callers"],
                tags_h, cmt
            )
        )
    func_table = (
        "<input id='search' oninput='filterTable()' placeholder='Filter functions…'>"
        "<table id='func-table'>"
        "<thead><tr>"
        "<th data-col='0'>EA</th>"
        "<th data-col='1'>Name</th>"
        "<th data-col='2'>Status</th>"
        "<th data-col='3'>Insns</th>"
        "<th data-col='4'>Bytes</th>"
        "<th data-col='5'>Callers</th>"
        "<th data-col='6'>Tags</th>"
        "<th data-col='7'>Comment</th>"
        "</tr></thead><tbody>" +
        "\n".join(rows) +
        "</tbody></table>"
    )

    # ── suspicious / tagged ───────────────────────────────────────────────
    HIGH_RISK = {"INJECT", "PERSIST", "EVASION", "CRYPTO", "LOADER", "MEMORY"}
    susp_rows = []
    for addr, n in sorted(data["nodes"].items(), key=lambda x: int(x[0], 16)):
        tags_set = set(n.get("tags", []))
        if tags_set & HIGH_RISK:
            tags_h = _tag_html(n.get("tags", []))
            mitre_h = ", ".join(n.get("mitre", []))[:100]
            susp_rows.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td class='dim'>%s</td></tr>" % (
                    _esc(addr), _esc(n["name"]), tags_h, _esc(mitre_h))
            )
    susp_table = (
        "<table><thead><tr>"
        "<th>EA</th><th>Name</th><th>Tags</th><th>MITRE hints</th>"
        "</tr></thead><tbody>" +
        ("".join(susp_rows) if susp_rows else "<tr><td colspan='4' class='dim'>None found.</td></tr>") +
        "</tbody></table>"
    )

    # ── review queue ──────────────────────────────────────────────────────
    q_items = []
    for q in data["queue"][:50]:
        conf_color = "#3ecf8e" if q.get("confidence", 0) >= 0.85 else "#f0a855"
        q_items.append(
            "<div class='q-item'>"
            "<b>%s</b> → <span style='color:%s'>%s</span> "
            "<span class='dim'>(conf=%.2f, %s, %s)</span><br>"
            "<span class='dim'>%s</span>"
            "</div>" % (
                _esc(q.get("old_name", "")),
                conf_color, _esc(q.get("suggested_name", "")),
                q.get("confidence", 0.0),
                _esc(q.get("category", "")),
                _esc(q.get("provider", "")),
                _esc((q.get("description") or "")[:120])
            )
        )
    queue_html = ("".join(q_items) if q_items
                  else "<span class='dim'>Queue is empty.</span>")

    note_rows = []
    for addr, n in sorted(data["nodes"].items(), key=lambda x: int(x[0], 16)):
        meta = n.get("idb_meta") or {}
        if not meta:
            continue
        note_rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _esc(addr),
                _esc(n.get("name", "")),
                _esc((meta.get("ai_summary") or "")[:180]),
                _esc((meta.get("analyst_notes") or "")[:220]),
                _esc((meta.get("readable_c") or "")[:220]),
            )
        )
    notes_html = (
        "<table><thead><tr>"
        "<th>EA</th><th>Name</th><th>Saved AI Summary</th>"
        "<th>Analyst Notes</th><th>Readable C</th>"
        "</tr></thead><tbody>%s</tbody></table>" %
        ("".join(note_rows) if note_rows else
         "<tr><td colspan='5' class='dim'>No saved IDB notes or summaries.</td></tr>")
    )

    # ── IOCs ──────────────────────────────────────────────────────────────
    ioc_sections = []
    ioc_order    = ["url", "domain", "ipv4", "ipv6", "registry", "mutex",
                    "win_path", "unc_path", "user_agent", "pe_artifact",
                    "email", "env_var", "base64"]
    for t in ioc_order:
        vals = data["iocs"].get(t, [])
        if not vals:
            continue
        items_html = " ".join(
            "<span class='ioc' title='%s'>%s</span>" % (
                _esc(_ioc_sources(v)), _esc(_ioc_text(v)))
            for v in vals[:40]
        )
        extra = (" <span class='dim'>… +%d more</span>" % (len(vals) - 40)
                 if len(vals) > 40 else "")
        ioc_sections.append(
            "<h3>%s <span class='dim'>(%d)</span></h3>%s%s" % (
                t.upper(), len(vals), items_html, extra)
        )
    iocs_html = ("\n".join(ioc_sections) if ioc_sections
                 else "<span class='dim'>No IOCs found.</span>")

    decoded_ioc_sections = []
    for t in ioc_order:
        vals = [
            v for v in data["iocs"].get(t, [])
            if isinstance(v, dict) and "floss_decoded" in v.get("sources", [])
        ]
        if not vals:
            continue
        decoded_ioc_sections.append(
            "<h3>%s <span class='dim'>(%d)</span></h3>%s" % (
                t.upper(), len(vals),
                " ".join("<span class='ioc'>%s</span>" % _esc(_ioc_text(v)) for v in vals[:40]))
        )
    decoded_iocs_html = ("\n".join(decoded_ioc_sections) if decoded_ioc_sections
                         else "<span class='dim'>No FLOSS decoded-string IOCs found.</span>")

    # ── rename history ────────────────────────────────────────────────────
    hist_lines = []
    for b in data["history"].get("batches", [])[-15:]:
        hist_lines.append("[%s] %s  provider=%s  model=%s  items=%d" % (
            b.get("timestamp", ""), b.get("batch_id", ""),
            b.get("provider", "?"), b.get("model", "?"),
            len(b.get("items", []))))
    hist_html = "<pre>%s</pre>" % _esc("\n".join(hist_lines) if hist_lines else "No history.")

    # ── top APIs ──────────────────────────────────────────────────────────
    api_rows = "".join(
        "<tr><td>%s</td><td>%d</td></tr>" % (_esc(a), c)
        for a, c in data["top_apis"][:30]
    )
    api_table = (
        "<table><thead><tr><th data-col='0'>API</th>"
        "<th data-col='1'>Call count</th></tr></thead><tbody>"
        + api_rows + "</tbody></table>"
    )

    # ── top strings ───────────────────────────────────────────────────────
    str_items = " ".join(
        "<span class='ioc'>%s</span>" % _esc(s)
        for s, _ in data["top_strings"][:30]
    )

    decoded_items = " ".join(
        "<span class='ioc'>%s</span>" % _esc(s)
        for s, _ in data.get("top_decoded_strings", [])[:40]
    ) or "<span class='dim'>No cached FLOSS decoded strings mapped to functions.</span>"

    # ── assemble full page ────────────────────────────────────────────────
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>reverse_partner — Forensic Report</title>
<style>
%(css)s
</style>
</head>
<body>
<h1>&#9670; reverse_partner — Forensic Report</h1>
%(stat_bar)s

<h2>&#9654; Function Overview</h2>
<div class="section">%(func_table)s</div>

<h2>&#9888; Suspicious / High-Risk Functions</h2>
<div class="section">%(susp_table)s</div>

<h2>&#8987; Review Queue (%(q_count)d pending)</h2>
<div class="section">%(queue_html)s</div>

<h2>&#9998; IDB Notes / Saved Summaries</h2>
<div class="section">%(notes_html)s</div>

<h2>&#128270; IOCs</h2>
<div class="section">%(iocs_html)s</div>

<h2>&#128270; IOCs from Decoded Strings</h2>
<div class="section">%(decoded_iocs_html)s</div>

<h2>&#128202; Top Called APIs</h2>
<div class="section">%(api_table)s</div>

<h2>&#128100; Top Referenced Strings</h2>
<div class="section">%(str_items)s</div>

<h2>&#128196; Decoded Strings</h2>
<div class="section">%(decoded_items)s</div>

<h2>&#128196; Rename History</h2>
<div class="section">%(hist_html)s</div>

<script>%(js)s</script>
</body>
</html>""" % {
        "css":        _CSS,
        "stat_bar":   stat_bar,
        "func_table": func_table,
        "susp_table": susp_table,
        "q_count":    len(data["queue"]),
        "queue_html": queue_html,
        "notes_html": notes_html,
        "iocs_html":  iocs_html,
        "decoded_iocs_html": decoded_iocs_html,
        "api_table":  api_table,
        "str_items":  str_items,
        "decoded_items": decoded_items,
        "hist_html":  hist_html,
        "js":         _SORT_JS,
    }
    return html


# ---------------------------------------------------------------------------
# Export entry point
# ---------------------------------------------------------------------------

def export_report(cfg: dict = None):
    """
    Build and write the full forensic report (JSON + HTML).
    Called from ActionExportFlow.
    """
    cfg = cfg or {}
    binary = idc.get_input_file_path() or ""

    if binary.lower().endswith((".i64", ".idb", ".id0", ".id1")):
        out_dir  = os.path.dirname(binary)
        raw_base = os.path.splitext(os.path.basename(binary))[0]
        base     = os.path.splitext(raw_base)[0] or raw_base
    else:
        out_dir = os.path.dirname(binary) or os.getcwd()
        base    = os.path.splitext(os.path.basename(binary))[0] or "report"

    if not out_dir or not os.path.isdir(out_dir):
        out_dir = os.getcwd()

    ts        = time.strftime("%Y%m%d_%H%M%S")
    json_path = os.path.join(out_dir, "%s_report_%s.json" % (base, ts))
    html_path = os.path.join(out_dir, "%s_report_%s.html" % (base, ts))

    import ida_kernwin
    ida_kernwin.show_wait_box("reverse_partner: Building forensic report …")
    try:
        data = collect_report_data(cfg)
    finally:
        ida_kernwin.hide_wait_box()

    # Write JSON
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            # Strip code blobs from JSON to keep it manageable
            slim = {k: v for k, v in data.items() if k != "nodes"}
            slim["nodes_count"] = data["n_funcs"]
            slim["nodes_sample"] = {k: v for k, v in list(data["nodes"].items())[:200]}
            json.dump(slim, f, indent=2, ensure_ascii=False)
        log.ok("JSON: %s" % json_path)
    except Exception as exc:
        log.err("JSON write error: %s" % exc)

    # Write HTML
    try:
        html = build_html(data)
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)
        log.ok("HTML: %s" % html_path)
    except Exception as exc:
        log.err("HTML write error: %s" % exc)
        html_path = ""

    idaapi.info(
        "Forensic report exported!\n\n"
        "JSON : %s\nHTML : %s\n\n"
        "Functions : %d  |  Renamed: %d  |  IOC types: %d" % (
            json_path, html_path,
            data["n_funcs"], data["n_renamed"], len(data["iocs"])
        )
    )
