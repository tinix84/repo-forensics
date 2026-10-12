"""Self-contained HTML report.

Visual grammar borrowed from technical drawing (ISO 128 line types):
continuous line = measured fact (CONFIRMED/SUPPORTED), dashed "hidden" line = inference,
dotted "phantom" line = unknown. The same encoding is used on every element, so the
fact/inference boundary is visible without reading labels.
"""

from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from html import escape
from pathlib import Path

STATUS_CLASS = {"CONFIRMED": "fact", "SUPPORTED": "fact-weak", "INFERRED": "infer", "UNKNOWN": "unknown"}
LADDER = ["DECLARED", "IMPORTED", "CALLED", "CENTRAL"]


def e(x) -> str:
    return escape("" if x is None else str(x))


class Ctx:
    """Rendering context: evidence index and source-link builder."""

    def __init__(self, report: dict, evidence: list[dict]):
        self.report = report
        self.ev = {x["id"]: x for x in evidence}
        p = report["provenance"]
        m = re.match(r"^(?:https://github\.com/|git@github\.com:)([^/]+/[^/.]+?)(?:\.git)?/?$", p.get("url") or "")
        self.gh = m.group(1) if m else None
        self.sha = p.get("commit_sha")

    def src(self, file: str | None, line: int | None = None, label: str | None = None) -> str:
        if not file:
            return ""
        text = e(label or (f"{file}:{line}" if line else file))
        if self.gh and self.sha:
            url = f"https://github.com/{self.gh}/blob/{self.sha}/{file}" + (f"#L{line}" if line else "")
            return f'<a class="path" href="{e(url)}" target="_blank" rel="noopener">{text}</a>'
        return f'<span class="path">{text}</span>'

    def chip(self, eid: str | None) -> str:
        if not eid:
            return ""
        st = self.ev.get(eid, {}).get("status", "UNKNOWN")
        title = self.ev.get(eid, {}).get("claim", "")
        return (f'<a class="chip {STATUS_CLASS.get(st, "unknown")}" href="#{e(eid)}" '
                f'title="{e(st)}: {e(title)}">{e(eid)}</a>')

    def chips(self, ids) -> str:
        return " ".join(self.chip(i) for i in ids or [])


def short(name: str, main: str | None) -> str:
    if main and name.startswith(main + "."):
        return name[len(main) + 1:]
    return name


# ---------------------------------------------------------------- component map (SVG)
def component_svg(report: dict, hyp_names: set[str]) -> str:
    items = report["components"]["items"]
    if not items:
        return '<p class="muted">No production Python components found.</p>'
    main = report["components"]["method"].get("main_package")
    cyc = {m for c in report["components"].get("import_time_cycles", []) for m in c}
    layers: dict[int, list[dict]] = defaultdict(list)
    for c in items:
        layers[c.get("dependency_depth") or 0].append(c)
    depths = sorted(layers, reverse=True)           # highest depth (top of the stack) first
    bw, bh, gx, gy, pad = 168, 54, 22, 96, 24
    cols = max(len(v) for v in layers.values())
    width = max(cols * (bw + gx) - gx + 2 * pad, 360)
    height = len(depths) * (bh + gy) - gy + 2 * pad + 18 + 60   # room for arcs above and below rows
    pos = {}
    for row, d in enumerate(depths):
        row_items = sorted(layers[d], key=lambda c: -c["code_lines"])
        row_w = len(row_items) * (bw + gx) - gx
        x0 = (width - row_w) / 2
        for i, c in enumerate(row_items):
            pos[c["name"]] = (x0 + i * (bw + gx), pad + 48 + row * (bh + gy))
    out = [f'<svg class="map" viewBox="0 0 {width:.0f} {height:.0f}" style="min-width:min({width:.0f}px,640px)" role="img" '
           f'aria-label="Component dependency map">',
           '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="9" markerHeight="9" '
           'markerUnits="userSpaceOnUse" orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="arrowhead"/></marker></defs>']
    for row, d in enumerate(depths):
        y = pad + 48 + row * (bh + gy) - 34
        out.append(f'<text class="layer" x="{pad}" y="{y:.0f}">depth {d}</text>')
    for c in items:
        x1, y1 = pos[c["name"]]
        for dst, n in c["depends_on"].items():
            if dst not in pos:
                continue
            x2, y2 = pos[dst]
            sx, sy = x1 + bw / 2, y1 + bh
            tx, ty = x2 + bw / 2, y2
            if y2 == y1:  # same layer: rightward edges arc above the row, leftward edges below
                above = x2 > x1
                off = 10 if above else -10
                sx, tx = x1 + bw / 2 + off, x2 + bw / 2 + off
                sy = ty = y1 if above else y1 + bh
                lift = min(14 + 0.06 * abs(tx - sx), 46)
                mid = sy - lift if above else sy + lift
                path = f"M{sx:.0f},{sy:.0f} C{sx:.0f},{mid:.0f} {tx:.0f},{mid:.0f} {tx:.0f},{ty:.0f}"
            elif y2 < y1:  # upward edge (against the layering): from top of source to bottom of target
                sx, sy, tx, ty = x1 + bw / 2 - 14, y1, x2 + bw / 2 - 14, y2 + bh
                path = f"M{sx:.0f},{sy:.0f} C{sx:.0f},{(sy + ty) / 2:.0f} {tx:.0f},{(sy + ty) / 2:.0f} {tx:.0f},{ty:.0f}"
            else:
                path = f"M{sx:.0f},{sy:.0f} C{sx:.0f},{(sy + ty) / 2:.0f} {tx:.0f},{(sy + ty) / 2:.0f} {tx:.0f},{ty:.0f}"
            w = 1 + 0.8 * math.log2(n)
            back = " back" if (c["name"] in cyc and dst in cyc) else ""
            out.append(f'<path class="edge{back}" d="{path}" stroke-width="{w:.1f}" marker-end="url(#arr)">'
                       f'<title>{e(c["name"])} imports {e(dst)} ({n} module edges)</title></path>')
    for c in items:
        x, y = pos[c["name"]]
        cls = ["node"]
        if c.get("synthetic"):
            cls.append("synthetic")
        if c["entrypoints"]:
            cls.append("entry")
        if c["name"] in hyp_names:
            cls.append("explained")
        label = short(c["name"], main)
        if len(label) > 22:
            label = label[:21] + "…"
        sub = f'{c["code_lines"]:,} LOC' + (f' · {", ".join(c["entrypoints"])}' if c["entrypoints"] else "")
        out.append(f'<a href="#comp-{slug(c["name"])}"><g class="{" ".join(cls)}">'
                   f'<rect x="{x:.0f}" y="{y:.0f}" width="{bw}" height="{bh}" rx="3"/>'
                   f'<text class="n" x="{x + 10:.0f}" y="{y + 22:.0f}">{e(label)}</text>'
                   f'<text class="s" x="{x + 10:.0f}" y="{y + 40:.0f}">{e(sub)}</text>'
                   f'<title>{e(c["name"])}</title></g></a>')
    out.append("</svg>")
    return "".join(out)


def slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()


def histogram_svg(ccs: list[int], threshold: int) -> str:
    if not ccs:
        return ""
    edges = [1, 2, 3, 5, 8, 13, 21, 34, 55, 10**9]
    labels = ["1", "2", "3–4", "5–7", "8–12", "13–20", "21–33", "34–54", "55+"]
    counts = [sum(1 for c in ccs if lo <= c < hi) for lo, hi in zip(edges, edges[1:], strict=False)]
    w, h, pad, bw = 520, 150, 28, 46
    mx = max(counts) or 1
    out = [f'<svg class="hist" viewBox="0 0 {w} {h + 40}" role="img" aria-label="Distribution of cyclomatic complexity">']
    for i, (n, lab) in enumerate(zip(counts, labels, strict=False)):
        bh = (h - pad) * n / mx
        x = pad + i * (bw + 8)
        hot = " hot" if edges[i] > threshold else ""
        out.append(f'<rect class="bar{hot}" x="{x}" y="{h - bh:.1f}" width="{bw}" height="{bh:.1f}"/>'
                   f'<text class="v" x="{x + bw / 2}" y="{h - bh - 5:.1f}">{n}</text>'
                   f'<text class="l" x="{x + bw / 2}" y="{h + 16}">{lab}</text>')
    out.append(f'<text class="l" x="{w / 2}" y="{h + 34}">cyclomatic complexity per function</text></svg>')
    return "".join(out)


# ---------------------------------------------------------------- sections
def sec_header(r: dict, hyp: dict | None, ctx: Ctx) -> str:
    p, f = r["provenance"], r["fingerprint"]
    name = ctx.gh or (p.get("url") or "local repository")
    shape = r["repo_shape"]["hypothesis"]
    mg = r["module_graph"]
    lede = (f'{len(r["components"]["items"])} components, {mg["production_modules"]} production modules, '
            f'{len(r["entrypoints"])} entry points, {len(r["unknowns"]) + len((hyp or {}).get("unknowns", []))} open questions.')
    shape_html = (f'<p class="shape infer-text">Reads as {e(" and ".join(shape))} '
                  f'{ctx.chip(r["repo_shape"].get("evidence_id"))}</p>') if shape else ""
    langs = ", ".join(f'{k} {v["source_share"]:.0%}' for k, v in f["languages"].items()
                      if v["kind"] == "programming" and v.get("source_share"))
    sha = p.get("commit_sha") or "not pinned"
    rows = [("Commit", f'<span class="path">{e(sha[:12])}</span>' + ("" if p.get("pinned") else " (not pinned)")),
            ("Analyzed", e(p["analyzed_at"][:16].replace("T", " ")) + " UTC"),
            ("Tool", f'repo-forensics {e(r["tool"]["version"])}, tier {r["tool"]["tier"]}'),
            ("Evidence", f'<span class="path">{e(r.get("evidence_digest", "")[7:19])}</span> '
                         f'({sum(r["evidence_summary"].values())} items)'),
            ("Inference", "validated hypotheses.json" if hyp else "none yet"),
            ("License", e(p.get("license") or "unknown")),
            ("Languages", e(langs or "n/a"))]
    tb = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in rows)
    src = (f'<a href="https://github.com/{e(ctx.gh)}/tree/{e(p.get("commit_sha"))}" target="_blank" rel="noopener">'
           f'{e(name)}</a>') if ctx.gh else e(name)
    return f"""
<header class="sheet">
  <div class="headline">
    <p class="kicker">Repository forensics report</p>
    <h1>{src}</h1>
    <p class="lede">{lede}</p>
    {shape_html}
  </div>
  <table class="titleblock" aria-label="Title block">{tb}</table>
</header>
<aside class="legend" aria-label="Line types">
  <span><i class="ln fact"></i>Measured fact</span>
  <span><i class="ln infer"></i>Inference</span>
  <span><i class="ln unknown"></i>Unknown</span>
  <span class="note">Line types follow technical-drawing convention: visible, hidden, phantom.</span>
</aside>"""


def sec_hypotheses(hyp: dict | None, ctx: Ctx) -> str:
    if not hyp:
        return ('<section id="inference"><h2>Inference</h2><div class="unknown-box"><p>No inference layer yet. '
                'Run the Claude Code skill to write <span class="path">hypotheses.json</span>, then '
                '<span class="path">repo-forensics validate</span> and <span class="path">repo-forensics render</span>.'
                '</p></div></section>')
    a = hyp.get("ai_assessment") or {}
    ai = ""
    if a:
        core = "".join(f"<li>{e(x)}</li>" for x in a.get("deterministic_core", []))
        label = {"AI_CORE": "AI is the core of the product", "AI_SUPPORTING": "AI supports a deterministic core",
                 "NO_AI_FOUND": "No AI found", "UNKNOWN": "AI role unknown"}.get(a["classification"], a["classification"])
        ai = (f'<div class="card infer"><h3>{e(label)}</h3>'
              f'<p>{e(a.get("rationale"))}</p>'
              + (f'<p class="sub">What the system does without a model</p><ul class="tight">{core}</ul>' if core else "")
              + f'<p class="cite">{ctx.chips(a.get("evidence_ids"))}</p></div>')
    cards = []
    for h in hyp.get("architecture_hypotheses", []):
        conf = h.get("confidence") or 0
        counters = "".join(f"<li>{e(n)}</li>" for n in h.get("counter_evidence_notes", []))
        cards.append(f"""
<div class="card infer hyp">
  <div class="hyp-head"><h3>{e(h["pattern"])}</h3>
    <span class="conf" title="confidence {conf:.2f}"><span class="track"><span class="fill" style="width:{conf * 100:.0f}%"></span></span>
    {conf:.2f} · {e(h["status"].lower())}</span></div>
  <p>{e(h["claim"])}</p>
  <p class="cite">For: {ctx.chips(h.get("evidence_ids"))}</p>
  <div class="against"><p class="sub">Against, or searched for and not found</p><ul class="tight">{counters}</ul>
  <p class="cite">{ctx.chips(h.get("counter_evidence_ids"))}</p></div>
  <p class="falsify"><span class="sub">Falsify by</span> {e(h["how_to_falsify"])}</p>
</div>""")
    return f'<section id="inference"><h2>Inference</h2>{ai}{"".join(cards)}</section>'


def sec_components(r: dict, hyp: dict | None, ctx: Ctx) -> str:
    hmap = {c["name"]: c for c in (hyp or {}).get("components", [])}
    main = r["components"]["method"].get("main_package")
    rows = []
    for c in r["components"]["items"]:
        h = hmap.get(c["name"])
        resp = ""
        if h:
            reads = ", ".join(ctx.src(f) for f in h.get("files_read", []))
            io = ""
            if h.get("inputs") or h.get("outputs"):
                io = (f'<p class="sub">In: {e(", ".join(h.get("inputs", [])) or "n/a")}. '
                      f'Out: {e(", ".join(h.get("outputs", [])) or "n/a")}.</p>')
            resp = (f'<div class="resp infer"><p>{e(h["responsibility"])}</p>{io}'
                    f'<p class="sub">Read: {reads} · confidence {h.get("confidence")}</p></div>')
        deps = ", ".join(f'{e(short(d, main))} ({n})' for d, n in c["depends_on"].items()) or "nothing internal"
        flags = []
        if c.get("synthetic"):
            flags.append('<span class="tag infer">merged bucket</span>')
        if c.get("in_component_cycle"):
            flags.append('<span class="tag">in a cycle</span>')
        for t in c["entrypoints"]:
            flags.append(f'<span class="tag strong">{e(t)} entry</span>')
        sig = ", ".join(e(s) for s in c["signals"]) or "none"
        paths = ", ".join(ctx.src(pth) for pth in c["paths"][:4])
        rows.append(f"""
<article class="comp fact{" synthetic" if c.get("synthetic") else ""}" id="comp-{slug(c["name"])}">
  <div class="comp-head"><h3>{e(short(c["name"], main))}</h3><span class="nums">{c["code_lines"]:,} LOC, {c["modules"]} modules,
  depth {c["dependency_depth"]}</span></div>
  <p class="flags">{" ".join(flags)}</p>
  <dl><dt>Depends on</dt><dd>{deps}</dd><dt>Signals</dt><dd>{sig}</dd>
  <dt>Tests importing it</dt><dd>{c["imported_by_tests"]}</dd><dt>Where</dt><dd>{paths}</dd></dl>
  {resp}<p class="cite">{ctx.chip(c["evidence_id"])}</p>
</article>""")
    return f'<section id="components"><h2>Components</h2><p class="muted">Grouped by directory ' \
           f'(rule: depth {r["components"]["method"]["depth"]}). Dashed boxes are merged buckets of small modules.</p>' \
           f'{"".join(rows)}</section>'


def sec_primitives(r: dict, hyp: dict | None, ctx: Ctx) -> str:
    roles = {x["signature"]: x for x in (hyp or {}).get("primitive_roles", [])}
    rows = []
    for s in r["signals"]:
        lvl = s["usage_level"]
        role = roles.get(s["signature"])
        on_steps = {"DECLARED": s["declared"], "IMPORTED": lvl in ("IMPORTED", "CALLED"), "CALLED": lvl == "CALLED"}
        steps = []
        for step in LADDER:
            if step == "CENTRAL":
                on = role and role["role"] == "CENTRAL"
                cls = "infer on" if on else "infer"
                lab = role["role"].lower() if role else "central?"
                steps.append(f'<span class="step {cls}" title="role decided by inference">{e(lab)}</span>')
            else:
                steps.append(f'<span class="step fact{" on" if on_steps[step] else ""}">{step.lower()}</span>')
        extra = ""
        if s["refined_primitives"]:
            extra = '<span class="sub"> → ' + ", ".join(e(k) for k in s["refined_primitives"]) + "</span>"
        reach = {True: "reachable from an entry point", False: "not statically reachable", None: ""}[s["reachable_from_entrypoint"]]
        np_ = ' <span class="tag">tests/examples only</span>' if lvl == "NON_PRODUCTION_ONLY" else ""
        rationale = f'<p class="sub infer-text">{e(role["rationale"])}</p>' if role else ""
        rows.append(f"""<tr><td><b>{e(s["library"])}</b><br><span class="sub">{e(s["primitive"])}</span>{extra}{np_}</td>
<td><span class="cat">{e(s["category"])}</span></td><td class="ladder">{"".join(steps)}{rationale}</td>
<td class="sub">{e(reach)}</td><td>{ctx.chip(s["evidence_id"])}</td></tr>""")
    if not rows:
        return '<section id="primitives"><h2>Primitives and boundaries</h2><p class="muted">No signature matched.</p></section>'
    return (f'<section id="primitives"><h2>Primitives and boundaries</h2><p class="muted">How far each library is '
            f'actually used: declared in a manifest, imported, or called by production code. Whether it is '
            f'central is an inference.</p><div class="scroll"><table class="grid"><thead><tr><th>Library</th>'
            f'<th>Kind</th><th>Usage</th><th>Reach</th><th>Ev.</th></tr></thead><tbody>{"".join(rows)}</tbody></table>'
            f'</div></section>')


VERDICT_LABEL = {
    "refuted": "refuted by execution", "likely-dead": "likely dead (2 methods)", "possibly-dead": "possibly dead",
    "public-api": "public API, unused internally", "unverified": "unverified (no run data)",
}


def sec_tooling(r: dict, ctx: Ctx) -> str:
    tc = r.get("toolchain") or []
    dyn = r.get("dynamic") or {"status": "not_run"}
    fus = r.get("fusion") or {}
    if not tc and dyn.get("status") == "not_run":
        return ""
    rows = "".join(
        f'<tr><td><b>{e(t["tool"])}</b><br><span class="sub">{e(t.get("version") or "")}</span></td><td>{e(t["question"])}</td>'
        f'<td class="num">{t["tier"]}</td><td>{e(t["status"])}</td><td class="num">{t["findings"]}</td>'
        f'<td class="num">{e(t.get("duration_s"))}</td></tr>' for t in tc)
    parts = [f'<section id="tooling"><h2>Analyzers and run</h2><p class="muted">Each finding below is first a fact about '
             f'the tool\'s output; what it means for the code is decided by fusing independent methods.</p>'
             f'<div class="scroll"><table class="grid"><thead><tr><th>Tool</th><th>Question</th><th>Tier</th><th>Status</th>'
             f'<th>Findings</th><th>s</th></tr></thead><tbody>{rows}</tbody></table></div>']
    if dyn.get("status") != "not_run":
        iso = dyn["isolation"]
        t = dyn.get("tests") or {}
        cov = t.get("coverage_percent")
        tests_line = (f'{t.get("tests", "?")} tests, {t.get("failures", "?")} failures, {t.get("errors", "?")} errors; '
                      f'line coverage {cov:.1f}%; {t.get("callgraph_edges", 0):,} runtime call edges') if t.get("ran") else "not run"
        probes = ", ".join(f'{e(p["spec"])} ({e(p["status"])}, {p["loaded_files"]} modules)' for p in dyn.get("entry_probes", []))
        my = dyn.get("mypy") or {}
        inst = dyn["install"]
        comp_cov = ((fus.get("rules") or {}).get("tests_types") or {}).get("coverage_by_component") or {}
        cc = ", ".join(f"{e(k.split('.')[-1])} {v:.0f}%" for k, v in sorted(comp_cov.items(), key=lambda kv: kv[1]))
        parts.append(f"""<div class="card"><h3>Tier 2 run: {e(dyn["status"])}</h3>
<dl><dt>Python</dt><dd>{e(dyn["python"])}, {e(dyn["elapsed_s"])} s</dd>
<dt>Install</dt><dd>{len(inst["requested"])} requirements as wheels only (no build scripts executed); failed: {e(", ".join(inst["failed"]) or "none")}</dd>
<dt>Tests</dt><dd>{tests_line}</dd><dt>Coverage by component</dt><dd>{cc or "n/a"}</dd>
<dt>Entry probes</dt><dd>{probes or "none"}</dd>
<dt>mypy</dt><dd>{e(my.get("errors", "n/a"))} errors with dependencies installed</dd></dl></div>
<div class="unknown-box"><p><b>Isolation:</b> {e(iso["level"])}-level, {"in a container" if iso["container"] else "no container"}, network {e(iso["network"])}.
{e(iso["environment"])}; {e(iso["limits"])}. {e(iso["note"])}. Observations hold for this run only: code that did not
run here may still run elsewhere.</p></div>""")
    claims = fus.get("claims") or []
    if claims:
        dc = ((fus.get("rules") or {}).get("dead_code") or {}).get("verdicts") or {}
        dc_line = ", ".join(f"{VERDICT_LABEL.get(k, k)}: {v}" for k, v in sorted(dc.items(), key=lambda kv: -kv[1]))
        by_rule = defaultdict(list)
        for c in claims:
            by_rule[c["rule"]].append(c)
        blocks = []
        order = {"likely-dead": 0, "likely-unused-module": 0, "possibly-dead": 1, "public-api": 2, "refuted": 3}
        for rule, cs in by_rule.items():
            per_verdict: dict = defaultdict(list)
            for c in sorted(cs, key=lambda c: order.get(c["verdict"], 1)):
                per_verdict[c["verdict"]].append(c)
            shown = [c for v in per_verdict.values() for c in v[:4]]
            items = "".join(f'<li><span class="tag {STATUS_CLASS.get(c["status"], "unknown")}">{e(c["status"].lower())}</span> '
                            f'{e(c["claim"])} {ctx.chip(c["evidence_id"])}</li>' for c in shown)
            more = (f'<li class="sub">+{len(cs) - len(shown)} more in the evidence register</li>'
                    if len(cs) > len(shown) else "")
            blocks.append(f'<h3>{e(rule.replace("_", " "))}</h3><ul class="fused">{items}{more}</ul>')
        parts.append(f'<h3>Fused findings</h3><p class="muted">Dead-code verdicts for vulture\'s callable findings: '
                     f'{e(dc_line or "n/a")}.</p>{"".join(blocks)}')
    parts.append("</section>")
    return "".join(parts)


def sec_entry(r: dict, ctx: Ctx) -> str:
    rows = "".join(f'<tr><td><b>{e(x["type"])}</b>{(" " + e(x["name"])) if x.get("name") else ""}</td>'
                   f'<td>{ctx.src(x.get("path")) if x.get("path") else e(x.get("module"))}</td><td class="sub">{e(x["detection"])}</td>'
                   f'<td>{ctx.chip(x["evidence_id"])}</td></tr>' for x in r["entrypoints"])
    return (f'<section id="entry"><h2>Entry points</h2><div class="scroll"><table class="grid"><thead><tr><th>Type</th>'
            f'<th>Where</th><th>Detected by</th><th>Ev.</th></tr></thead><tbody>{rows}</tbody></table></div></section>')


def sec_structure(r: dict, ctx: Ctx) -> str:
    mg = r["module_graph"]
    cyc = "".join(f'<li>{e(" → ".join(c))}</li>' for c in mg["cycles"]) or "<li>none</li>"
    smells = "".join(f'<tr><td>{e(s["rule"].replace("_", " "))}</td><td>{e(s["target"])}</td>'
                     f'<td class="sub">{e(s["detail"])}</td><td><span class="sev {e(s["severity"])}">{e(s["severity"])}</span></td>'
                     f'<td>{ctx.chip(s["evidence_id"])}</td></tr>' for s in r["smells"])
    hubs = ", ".join(f'{e(h["module"])} ({h["fan_in"]})' for h in mg["hubs"]) or "none above threshold"
    return f"""<section id="structure"><h2>Structure</h2>
<dl class="facts"><dt>Module import cycles</dt><dd>{len(mg["cycles"])} total, {len(mg["import_time_cycles"])} at import time
<ul class="tight">{cyc}</ul></dd><dt>Hubs (high fan-in)</dt><dd>{hubs}</dd>
<dt>Fan-in / fan-out P95</dt><dd>{mg["fan_in"].get("p95")} / {mg["fan_out"].get("p95")}</dd>
<dt>Orphan modules</dt><dd>{len(mg["orphans"])}</dd></dl>
<h3>Signals worth reading</h3><p class="muted">Thresholds mark places to look, not defects.</p>
<div class="scroll"><table class="grid"><thead><tr><th>Rule</th><th>Target</th><th>Detail</th><th>Level</th><th>Ev.</th></tr></thead>
<tbody>{smells or '<tr><td colspan="5">none</td></tr>'}</tbody></table></div></section>"""


def sec_complexity(r: dict, funcs: list[dict], ctx: Ctx, threshold: int) -> str:
    cx = r["complexity"]
    if cx["status"] != "measured":
        return '<section id="complexity"><h2>Complexity</h2><div class="unknown-box"><p>Not measured (tier 0).</p></div></section>'
    hot = "".join(f'<tr><td>{e(h["function"])}</td><td>{ctx.src(h["file"], h["line"])}</td><td class="num">{h["cc"]}</td>'
                  f'<td class="num">{h["nloc"]}</td></tr>' for h in cx["hotspots"][:8])
    c = cx["cyclomatic"]
    return f"""<section id="complexity"><h2>Complexity</h2>
<p class="muted">{cx["functions"]} functions measured with {e(cx.get("tool"))}. Median {c.get("median")}, P95 {c.get("p95")},
max {c.get("max")}. Bars right of the threshold ({threshold}) are drawn hatched.</p>
<div class="scroll">{histogram_svg([f["cc"] for f in funcs], threshold)}</div>
<div class="scroll"><table class="grid"><thead><tr><th>Function</th><th>Location</th><th>CC</th><th>NLOC</th></tr></thead>
<tbody>{hot}</tbody></table></div></section>"""


def sec_unknowns(r: dict, hyp: dict | None, ctx: Ctx) -> str:
    items = [f'<li><b>{e(u["question"])}</b><br><span class="sub">{e(u["reason"])}</span> {ctx.chip(u["evidence_id"])}</li>'
             for u in r["unknowns"]]
    items += [f'<li><b>{e(u["question"])}</b><br><span class="sub">{e(u["reason"])}</span> '
              f'<span class="tag infer">from inference</span></li>' for u in (hyp or {}).get("unknowns", [])]
    return (f'<section id="unknowns"><h2>Open questions</h2><div class="unknown-box"><ul class="qs">{"".join(items)}</ul>'
            f'</div></section>')


def sec_checklist(r: dict) -> str:
    sym = {"done": "●", "partial": "◐", "not_done": "○", "deferred_to_inference": "◌"}
    rows = "".join(f'<li class="{e(c["status"])}"><span aria-hidden="true">{sym.get(c["status"], "?")}</span> {e(c["gate"])}'
                   f'{(" <span class=sub>(" + e(c["note"]) + ")</span>") if c.get("note") else ""}</li>' for c in r["checklist"])
    return (f'<section id="checklist"><h2>Checklist</h2><p class="muted">● done ◐ partial ○ not done ◌ left to inference</p>'
            f'<ul class="check">{rows}</ul></section>')


def sec_evidence(evidence: list[dict], ctx: Ctx) -> str:
    out = []
    for x in evidence:
        locs = "".join(f'<li>{ctx.src(lc.get("file"), lc.get("line")) if lc.get("file") else ""} '
                       f'{e(lc.get("symbol") or "")} <span class="sub">{e(lc.get("detail") or "")}</span></li>'
                       for lc in x["evidence"])
        cnt = "".join(f'<li>{e(lc.get("detail") or lc.get("file") or "")}</li>' for lc in x["counter_evidence"])
        more = x.get("data", {}).get("locations_total")
        out.append(f"""<details class="ev {STATUS_CLASS[x["status"]]}" id="{e(x["id"])}"><summary><span class="eid">{e(x["id"])}</span>
<span class="st">{e(x["status"].lower())}</span> {e(x["claim"])}</summary>
<div class="evbody"><p class="sub">{e(x["phase"])} · {e(x["kind"])} · {e(x["tool"])}{f" · confidence {x['confidence']}" if x["confidence"] is not None else ""}</p>
{f'<ul class="locs">{locs}</ul>' if locs else ""}{f'<p class="sub">showing {len(x["evidence"])} of {more} locations</p>' if more else ""}
{f'<p class="sub">Counter-evidence</p><ul class="locs">{cnt}</ul>' if cnt else ""}</div></details>""")
    return (f'<section id="evidence"><h2>Evidence register</h2><p class="muted">Every id cited above. Source links point '
            f'to the pinned commit.</p>{"".join(out)}</section>')


CSS = """
:root{--paper:#F7F8F6;--ink:#17233A;--ink-2:#4A5568;--rule:#C9D1D9;--grid:#E6EAEE;--hidden:#6A4BA8;
--hidden-bg:#F3EFFA;--phantom:#9A6B00;--phantom-bg:#FBF6E6;--red:#B4232A;--card:#FFFFFF;--link:#1F4FA8}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--paper:#11161E;--ink:#E3E8EF;--ink-2:#A3AEBD;
--rule:#334050;--grid:#1C2430;--hidden:#B49BEA;--hidden-bg:#1E1A2B;--phantom:#E2B54A;--phantom-bg:#241F12;
--red:#F07178;--card:#161C26;--link:#8DB4FF}}
:root[data-theme="dark"]{--paper:#11161E;--ink:#E3E8EF;--ink-2:#A3AEBD;--rule:#334050;--grid:#1C2430;--hidden:#B49BEA;
--hidden-bg:#1E1A2B;--phantom:#E2B54A;--phantom-bg:#241F12;--red:#F07178;--card:#161C26;--link:#8DB4FF}
:root{box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
*,*::before,*::after{box-sizing:inherit}
body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 "Barlow",system-ui,-apple-system,"Segoe UI",sans-serif;
background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);
background-size:24px 24px;background-attachment:fixed}
main{max-width:980px;margin:0 auto;padding:20px 16px 64px}
a{color:var(--link)}a:focus-visible,summary:focus-visible{outline:2px solid var(--link);outline-offset:2px}
h1,h2,h3{font-family:"Barlow Condensed","Barlow",system-ui,sans-serif;font-weight:600;line-height:1.15;margin:0}
h1{font-size:clamp(2rem,6vw,3.1rem);letter-spacing:-.01em}h1 a{color:inherit;text-decoration:none}
h2{font-size:1.6rem;margin:0 0 10px;padding-top:6px;border-top:2px solid var(--ink)}
h3{font-size:1.2rem}
section{margin-top:40px}
.sheet{display:grid;grid-template-columns:1fr auto;gap:20px;align-items:end;border:2px solid var(--ink);background:var(--card);padding:18px}
@media (max-width:720px){.sheet{grid-template-columns:1fr}}
.kicker{margin:0 0 4px;color:var(--ink-2);font-size:.95rem}
.lede{margin:10px 0 0;font-size:1.1rem;max-width:60ch}
.shape{margin:8px 0 0}
.titleblock{border-collapse:collapse;font-size:.85rem;min-width:260px}
.titleblock th,.titleblock td{border:1px solid var(--ink);padding:3px 8px;text-align:left;vertical-align:top}
.titleblock th{font-weight:600;white-space:nowrap;background:var(--paper)}
.legend{display:flex;flex-wrap:wrap;gap:8px 20px;align-items:center;margin:14px 0 0;font-size:.92rem}
.legend .note{color:var(--ink-2);flex-basis:100%}
.ln{display:inline-block;width:36px;height:0;margin-right:8px;vertical-align:middle;border-top:2.5px solid var(--ink)}
.ln.infer{border-top:2.5px dashed var(--hidden)}.ln.unknown{border-top:2.5px dotted var(--phantom)}
nav.toc{position:sticky;top:env(safe-area-inset-top,0px);z-index:5;background:var(--paper);border-bottom:1px solid var(--rule);
margin:18px -16px 0;padding:8px 16px;display:flex;gap:16px;overflow-x:auto;white-space:nowrap;font-size:.95rem}
nav.toc a{text-decoration:none;color:var(--ink)}nav.toc a:hover{text-decoration:underline}
.muted,.sub{color:var(--ink-2)}.sub{font-size:.88rem}
.path{font-family:"JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;font-size:.84em;word-break:break-all}
.scroll{overflow-x:auto;max-width:100%}
.map{display:block;margin:6px auto;width:100%;height:auto}
.map .layer{fill:var(--ink-2);font-size:11px}
.map .node rect{fill:var(--card);stroke:var(--ink);stroke-width:1.5}
.map .node.entry rect{stroke-width:3}
.map .node.synthetic rect{stroke-dasharray:6 4;stroke:var(--hidden)}
.map .node.explained rect{fill:var(--hidden-bg)}
.map .node text.n{fill:var(--ink);font:600 14px "Barlow Condensed",system-ui,sans-serif}
.map .node text.s{fill:var(--ink-2);font-size:11px}
.map a:hover rect{stroke:var(--link)}
.map .edge{fill:none;stroke:var(--ink-2);opacity:.7}.map .edge.back{stroke:var(--red);opacity:.75}
.map .arrowhead{fill:var(--ink-2)}
.caption{font-size:.88rem;color:var(--ink-2);margin:4px 0 0}
.card{background:var(--card);padding:14px 16px;margin:12px 0;border:2px solid var(--ink)}
.card.infer,.resp.infer{border:2px dashed var(--hidden)}
.card.infer{background:var(--hidden-bg)}
.infer-text{color:var(--hidden)}
.hyp-head{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:baseline}
.conf{font-size:.88rem;color:var(--ink-2);display:inline-flex;gap:8px;align-items:center}
.track{display:inline-block;width:90px;height:8px;border:1.5px dashed var(--hidden);padding:1px}
.fill{display:block;height:100%;background:var(--hidden)}
.against{border-left:3px solid var(--red);padding-left:10px;margin:8px 0}
.falsify{margin:8px 0 0}
.cite{margin:8px 0 0}
ul.tight{margin:4px 0;padding-left:20px}
.comp{background:var(--card);border:2px solid var(--ink);padding:12px 16px;margin:12px 0}
.comp.synthetic{border-style:dashed;border-color:var(--hidden)}
.comp-head{display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px;align-items:baseline}
.nums{color:var(--ink-2);font-size:.92rem}
.flags{margin:6px 0}
.tag{display:inline-block;border:1px solid var(--ink-2);padding:0 6px;font-size:.8rem;margin-right:4px}
.tag.strong{border:2px solid var(--ink);font-weight:600}.tag.infer{border:1px dashed var(--hidden);color:var(--hidden)}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 14px;margin:6px 0}
dt{color:var(--ink-2)}dd{margin:0}
.resp{padding:10px 12px;margin-top:10px;background:var(--hidden-bg)}
.resp p{margin:0 0 4px}
table.grid{border-collapse:collapse;width:100%;font-size:.93rem;background:var(--card)}
table.grid th,table.grid td{border:1px solid var(--rule);padding:6px 8px;text-align:left;vertical-align:top}
table.grid th{border-bottom:2px solid var(--ink);font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.cat{font-size:.85rem;color:var(--ink-2)}
.ladder{min-width:250px}
.step{display:inline-block;padding:1px 7px;margin:0 3px 3px 0;font-size:.8rem;border:1px solid var(--rule);color:var(--ink-2)}
.step.fact.on{border:1.5px solid var(--ink);color:var(--ink);background:var(--grid)}
.step.infer{border:1.5px dashed var(--hidden);color:var(--hidden)}
.step.infer.on{background:var(--hidden);color:var(--card)}
.chip{display:inline-block;font-size:.78rem;padding:0 6px;margin:1px 2px;text-decoration:none;color:var(--ink);
border:1.5px solid var(--ink);background:var(--card);white-space:nowrap}
.chip.fact-weak{border-width:1px}.chip.infer{border:1.5px dashed var(--hidden);color:var(--hidden)}
.chip.unknown{border:1.5px dotted var(--phantom);color:var(--phantom)}
.sev{font-size:.8rem}.sev.warn{color:var(--red);font-weight:600}
.unknown-box{border:2.5px dotted var(--phantom);background:var(--phantom-bg);padding:10px 16px}
ul.qs{padding-left:18px;margin:6px 0}ul.qs li{margin:0 0 10px}
.facts dd ul{margin:2px 0}
.hist{width:100%;max-width:560px;display:block}
.hist .bar{fill:var(--ink)}.hist .bar.hot{fill:url(#hatch)}
.hist .v,.hist .l{fill:var(--ink-2);font-size:11px;text-anchor:middle}
ul.check{list-style:none;padding:0;columns:2 280px;column-gap:28px;margin:0}
ul.check li{break-inside:avoid;margin:0 0 4px}
ul.check li.done span{color:var(--ink)}ul.check li.partial span{color:var(--ink-2)}
ul.check li.deferred_to_inference span{color:var(--hidden)}ul.check li.not_done span{color:var(--phantom)}
details.ev{background:var(--card);border:1.5px solid var(--ink);margin:6px 0;padding:6px 10px}
details.ev.fact-weak{border-width:1px}details.ev.infer{border:1.5px dashed var(--hidden)}
details.ev.unknown{border:1.5px dotted var(--phantom)}
details.ev:target{outline:3px solid var(--link)}
details.ev summary{cursor:pointer}
.eid{font-weight:600;margin-right:6px}.st{font-size:.8rem;color:var(--ink-2);margin-right:6px}
ul.locs{margin:4px 0;padding-left:18px;font-size:.9rem}
ul.fused{list-style:none;padding:0;margin:6px 0 14px}ul.fused li{margin:0 0 6px}
.tag.fact{border:1.5px solid var(--ink)}.tag.fact-weak{border:1px solid var(--ink)}.tag.unknown{border:1.5px dotted var(--phantom);color:var(--phantom)}
footer{margin-top:48px;color:var(--ink-2);font-size:.85rem;border-top:1px solid var(--rule);padding-top:10px}
[id]{scroll-margin-top:calc(env(safe-area-inset-top,0px) + 56px)}
@media (prefers-reduced-motion:no-preference){html{scroll-behavior:smooth}}
"""

JS = """
function openTarget(){var id=location.hash.slice(1);if(!id)return;var el=document.getElementById(id);
if(el&&el.tagName==='DETAILS'){el.open=true;}}
window.addEventListener('hashchange',openTarget);openTarget();
"""


def render_html(out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    report = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    evidence = [json.loads(x) for x in (out_dir / "evidence.jsonl").read_text(encoding="utf-8").splitlines() if x]
    funcs_p = out_dir / "metrics" / "complexity.json"
    funcs = json.loads(funcs_p.read_text(encoding="utf-8")) if funcs_p.exists() else []
    hyp = None
    hp = out_dir / "hypotheses.json"
    if hp.exists():
        from .validate import validate_bundle
        if not validate_bundle(out_dir):          # only a validated inference layer is rendered
            hyp = json.loads(hp.read_text(encoding="utf-8"))
    ctx = Ctx(report, evidence)
    threshold = 15
    hyp_names = {c["name"] for c in (hyp or {}).get("components", [])}
    title = f"{ctx.gh or 'Repository'} — repo-forensics report"
    body = "".join([
        sec_header(report, hyp, ctx),
        '<nav class="toc" aria-label="Sections"><a href="#map">Map</a><a href="#inference">Inference</a>'
        '<a href="#components">Components</a><a href="#primitives">Primitives</a><a href="#tooling">Analyzers</a><a href="#entry">Entry points</a>'
        '<a href="#structure">Structure</a><a href="#complexity">Complexity</a><a href="#unknowns">Open questions</a>'
        '<a href="#evidence">Evidence</a></nav>',
        f'<section id="map"><h2>Component map</h2><div class="scroll">{component_svg(report, hyp_names)}</div>'
        '<p class="caption">Arrows point from importer to imported; width grows with the number of module edges. '
        'Red arrows close an import-time cycle. Thick boxes hold entry points, dashed boxes are merged buckets, '
        'tinted boxes have an inferred responsibility.</p></section>',
        sec_hypotheses(hyp, ctx),
        sec_components(report, hyp, ctx),
        sec_primitives(report, hyp, ctx),
        sec_tooling(report, ctx),
        sec_entry(report, ctx),
        sec_structure(report, ctx),
        sec_complexity(report, funcs, ctx, threshold),
        sec_unknowns(report, hyp, ctx),
        sec_checklist(report),
        sec_evidence(evidence, ctx),
        f'<footer>Generated by repo-forensics {e(report["tool"]["version"])}. Facts come from static analysis at '
        f'the pinned commit; inferences come from a validated <span class="path">hypotheses.json</span> bound to '
        f'evidence digest <span class="path">{e(report.get("evidence_digest"))}</span>.</footer>',
    ])
    hatch = ('<svg width="0" height="0" style="position:absolute" aria-hidden="true"><defs><pattern id="hatch" width="6" '
             'height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="6" height="6" '
             'fill="var(--paper)"/><line x1="0" y1="0" x2="0" y2="6" stroke="var(--red)" stroke-width="3"/></pattern>'
             '</defs></svg>')
    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>{e(title)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;600&family=Barlow+Condensed:wght@600&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>{CSS}</style></head>
<body>{hatch}<main>{body}</main><script>{JS}</script></body></html>
"""
    path = out_dir / "report.html"
    path.write_text(html_doc, encoding="utf-8")
    return path
