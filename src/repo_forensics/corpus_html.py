"""Corpus comparison page: same visual grammar as report.html (continuous = fact,
dashed = inference, dotted = unknown), plus a usage-level glyph for the primitive matrix."""

from __future__ import annotations

from html import escape
from pathlib import Path

from .html import CSS, JS

STATUS_CLASS = {"CONFIRMED": "fact", "SUPPORTED": "fact-weak", "INFERRED": "infer", "UNKNOWN": "unknown"}
GLYPH_TITLE = {"CALLED": "called by production code", "IMPORTED": "imported by production code",
               "DECLARED": "declared, not imported", "NON_PRODUCTION_ONLY": "tests/examples only"}


def e(x) -> str:
    return escape("" if x is None else str(x))


def anchor(ref: str) -> str:
    return "ev-" + "".join(ch if ch.isalnum() else "-" for ch in ref)


class Cites:
    """Collects every cited global evidence reference for the register at the bottom of the page."""

    def __init__(self, lookup: dict):
        self.lookup, self.used = lookup, []

    def chip(self, ref: str) -> str:
        info = self.lookup.get(ref)
        st = info["item"]["status"] if info else "UNKNOWN"
        if ref not in self.used:
            self.used.append(ref)
        short = ref.split("#", 1)[1]
        repo = ref.split("@", 1)[0].split("/")[-1]
        title = info["item"]["claim"] if info else "missing evidence"
        return (f'<a class="chip {STATUS_CLASS.get(st, "unknown")}" href="#{anchor(ref)}" title="{e(repo)}: {e(title)}">'
                f'{e(repo)}·{e(short)}</a>')

    def chips(self, refs, limit: int = 4) -> str:
        refs = list(dict.fromkeys(refs or []))
        more = f' <span class="sub">+{len(refs) - limit}</span>' if len(refs) > limit else ""
        return " ".join(self.chip(r) for r in refs[:limit]) + more


def short_repo(r: str) -> str:
    return r.split("/")[-1]


def glyph(level: str | None, role: str | None) -> str:
    if not level:
        return '<span class="g none" title="not found">·</span>'
    ring = " central" if role == "CENTRAL" else (" supporting" if role in ("SUPPORTING", "INCIDENTAL") else "")
    t = GLYPH_TITLE[level] + (f"; role inferred: {role.lower()}" if role else "")
    return f'<span class="g {level.lower()}{ring}" title="{e(t)}"></span>'


def sec_head(res: dict) -> str:
    repos = res["repos"]
    rows = "".join(f'<tr><th>{e(short_repo(p["repo"]))}</th><td><span class="path">{e(p["ref"].split("@")[1])}</span>'
                   f'{"" if p["inference"] else " (facts only)"}</td></tr>' for p in repos)
    return f"""
<header class="sheet">
  <div class="headline"><p class="kicker">Repository forensics: corpus comparison</p>
  <h1>{len(repos)} repositories, one vocabulary</h1>
  <p class="lede">Common ground by primitive, by role and by pattern, built from {res["facts"]} facts. A statement that
  spans repositories takes the weakest status of its inputs.</p></div>
  <table class="titleblock" aria-label="Title block"><tr><th>Generated</th><td>{e(res["generated_at"][:16].replace("T", " "))} UTC</td></tr>{rows}</table>
</header>
<aside class="legend" aria-label="Line types">
  <span><i class="ln fact"></i>Measured fact</span><span><i class="ln infer"></i>Inference</span>
  <span><i class="ln unknown"></i>Unknown</span>
  <span><span class="g called"></span> called <span class="g imported"></span> imported <span class="g declared"></span> declared only
  <span class="g called central"></span> inferred central</span>
</aside>"""


def sec_profiles(res: dict) -> str:
    rows = "".join(
        f'<tr><td><b>{e(p["repo"])}</b><br><span class="sub">{e(", ".join(p["shape"]))}</span></td>'
        f'<td class="num">{p["code_lines"]:,}</td><td class="num">{p["components"]}</td>'
        f'<td>{e(", ".join(p["entry_types"]))}</td><td class="num">{e(p["test_ratio"])}</td><td class="num">{e(p["cc_p95"])}</td>'
        f'<td class="infer-text">{e(p["ai"].replace("_", " ").lower())}'
        f'{("<br><span class=sub>without a model: " + e(", ".join(p["deterministic_core"])) + "</span>") if p["deterministic_core"] else ""}</td></tr>'
        for p in res["repos"])
    return (f'<section id="profiles"><h2>Profiles</h2><p class="muted">Ratios and percentiles, not raw sizes, are the '
            f'comparable numbers. The AI column is an inference.</p><div class="scroll"><table class="grid"><thead><tr>'
            f'<th>Repository</th><th>Code lines</th><th>Comp.</th><th>Entry types</th><th>Test/prod</th><th>CC P95</th>'
            f'<th>AI role</th></tr></thead><tbody>{rows}</tbody></table></div></section>')


def sec_primitives(res: dict, cites: Cites) -> str:
    repos = [p["repo"] for p in res["repos"]]
    head = "".join(f'<th class="rc" title="{e(r)}">{e(short_repo(r))}</th>' for r in repos)
    body = []
    for row in res["primitives"]:
        cells = []
        for r in repos:
            c = row["cells"].get(r)
            if not c:
                cells.append(f'<td class="rc">{glyph(None, None)}</td>')
                continue
            lv = c.get("library_levels", {})
            extra = [f"{lib} (declared only)" for lib, lvl in sorted(lv.items())
                     if lvl in ("DECLARED", "NON_PRODUCTION_ONLY") and lib not in c["libraries"]]
            libs = e(", ".join(c["libraries"])) + (f'<br><span class="sub">{e(", ".join(extra))}</span>' if extra else "")
            ref = f'<br><span class="sub">{e(", ".join(c.get("refined") or []))}</span>' if c.get("refined") else ""
            cells.append(f'<td class="rc">{glyph(c["usage_level"], c.get("role"))}<br><span class="sub">{libs}</span>{ref}'
                         f'<div class="mini">{cites.chips(c["evidence"], 1)}</div></td>')
        cls = ' class="shared"' if row["shared"] else ""
        body.append(f'<tr{cls}><td><b>{e(row["primitive"])}</b><br><span class="sub">{e(row["category"])}; '
                    f'used by {row["used_by"]}</span></td>{"".join(cells)}</tr>')
    shared = [r for r in res["primitives"] if r["shared"]]
    summary = "".join(f'<li>{e(r["claim"])}.</li>' for r in shared) or "<li>No primitive is shared yet.</li>"
    return f"""<section id="primitives"><h2>Shared primitives</h2>
<p class="muted">What each repository computes with, named by the abstraction rather than the library. Rows used by two or
more repositories are drawn heavier.</p><div class="card"><ul class="tight">{summary}</ul></div>
<div class="scroll"><table class="grid matrix"><thead><tr><th>Primitive</th>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>
</section>"""


def sec_similarity(res: dict) -> str:
    rows = []
    for s in res["similarity"]:
        j = s["jaccard"] or 0
        rows.append(f'<tr><td>{e(short_repo(s["a"]))} ↔ {e(short_repo(s["b"]))}</td>'
                    f'<td><span class="track solid"><span class="fill solid" style="width:{j * 100:.0f}%"></span></span> {j:.2f}</td>'
                    f'<td class="sub">{e(", ".join(s["shared"]) or "nothing")}</td></tr>')
    return (f'<section id="similarity"><h2>Overlap</h2><p class="muted">Jaccard index on the sets of primitives each '
            f'repository imports or calls (1 = identical toolbox, 0 = nothing in common).</p><div class="scroll">'
            f'<table class="grid"><thead><tr><th>Pair</th><th>Overlap</th><th>In common</th></tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div></section>')


def sec_roles(res: dict, cites: Cites) -> str:
    repos = [p["repo"] for p in res["repos"]]
    cards = []
    for r in res["roles"]:
        cols = []
        for repo in repos:
            x = r["repos"].get(repo)
            if not x:
                cols.append(f'<div class="rcol absent"><p class="sub">{e(short_repo(repo))}: no component assigned this role</p></div>')
                continue
            comps = "".join(f'<li><b>{e(c["name"].split(".")[-1])}</b> <span class="sub">({e(c["confidence"])})</span><br>'
                            f'<span class="sub">{e(c["responsibility"])}</span></li>' for c in x["components"])
            impl = e(", ".join(x["implementations"])) or "own code (no matching library signal)"
            cols.append(f'<div class="rcol"><h4>{e(short_repo(repo))}</h4><ul class="tight">{comps}</ul>'
                        f'<p class="sub">Built with: {impl}</p><p class="cite">{cites.chips(x["evidence"], 2)}</p></div>')
        badge = '<span class="tag infer">implementations differ</span>' if r["differs"] else ""
        cards.append(f'<div class="card infer role"><div class="hyp-head"><h3 title="{e(r.get("definition"))}">{e(r["role"])}</h3>'
                     f'<span class="sub">{r["in_repos"]} of {len(repos)} repositories {badge}</span></div>'
                     f'<p class="sub">{e(r.get("definition"))}</p><div class="rgrid">{"".join(cols)}</div></div>')
    return (f'<section id="roles"><h2>Same role, different implementation</h2><p class="muted">Roles come from the '
            f'controlled vocabulary and are assigned by inference, so every card is dashed. "Built with" lists the '
            f'measured library signals inside those components that can implement the role (per the vocabulary).</p>{"".join(cards)}</section>')


def sec_patterns(res: dict, cites: Cites) -> str:
    repos = [p["repo"] for p in res["repos"]]
    head = "".join(f'<th class="rc">{e(short_repo(r))}</th>' for r in repos)
    rows = []
    for p in res["patterns"]:
        cells = []
        for repo in repos:
            x = p["repos"].get(repo)
            if not x:
                cells.append('<td class="rc"><span class="sub">not proposed</span></td>')
                continue
            conf = x["confidence"] or 0
            cells.append(f'<td class="rc" title="{e(x["claim"])}"><span class="track"><span class="fill" style="width:{conf * 100:.0f}%">'
                         f'</span></span><br><span class="sub">{conf:.2f} {e(x["status"].lower())}</span>'
                         f'<div class="mini">{cites.chips(x["evidence"], 1)}</div></td>')
        rows.append(f'<tr><td><b>{e(p["pattern"])}</b></td>{"".join(cells)}</tr>')
    fams = "".join(
        f'<li><b>{e(f["family"])}</b> family ({e(", ".join(f["members"]))}): {f["in_repos"]} of {len(repos)} repositories, '
        + ", ".join(f'{e(short_repo(r))} as {e(x["pattern"])} {x["confidence"]:.2f}' for r, x in sorted(f["repos"].items()))
        + f' <span class="sub">({e(f["status"].lower())}: weakest input)</span></li>' for f in res.get("pattern_families", []))
    fam_html = f'<div class="card infer"><p class="sub">Pattern families</p><ul class="tight">{fams}</ul></div>' if fams else ""
    return (f'<section id="patterns"><h2>Architecture patterns</h2>{fam_html}<p class="muted">Confidence of each pattern hypothesis '
            f'per repository; "not proposed" means no hypothesis was written, not that the pattern is absent.</p>'
            f'<div class="scroll"><table class="grid matrix"><thead><tr><th>Pattern</th>{head}</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div></section>')


def sec_register(cites: Cites) -> str:
    out = []
    for ref in cites.used:
        info = cites.lookup.get(ref)
        if not info:
            out.append(f'<details class="ev unknown" id="{anchor(ref)}"><summary>{e(ref)}: missing</summary></details>')
            continue
        x = info["item"]
        locs = []
        for lc in x["evidence"][:6]:
            f, ln = lc.get("file"), lc.get("line")
            link = ""
            if f:
                url = f'https://github.com/{info["repo"]}/blob/{info["sha"]}/{f}' + (f"#L{ln}" if ln else "")
                link = f'<a class="path" href="{e(url)}" target="_blank" rel="noopener">{e(f)}{f":{ln}" if ln else ""}</a>'
            locs.append(f'<li>{link} {e(lc.get("symbol") or "")} <span class="sub">{e(lc.get("detail") or "")}</span></li>')
        out.append(f'<details class="ev {STATUS_CLASS[x["status"]]}" id="{anchor(ref)}"><summary><span class="eid">{e(ref)}</span>'
                   f'<span class="st">{e(x["status"].lower())}</span> {e(x["claim"])}</summary><div class="evbody">'
                   f'<ul class="locs">{"".join(locs)}</ul></div></details>')
    return (f'<section id="evidence"><h2>Evidence register</h2><p class="muted">Global references '
            f'(<span class="path">owner/repo@commit#EV-id</span>) to every bundle cited on this page; source links '
            f'point to each pinned commit.</p>{"".join(out)}</section>')


EXTRA_CSS = """
.matrix th.rc,.matrix td.rc{text-align:center;min-width:110px}
.matrix tr.shared td:first-child{border-left:4px solid var(--ink)}
.g{display:inline-block;width:16px;height:16px;vertical-align:middle;margin:0 2px;border:2px solid var(--ink)}
.g.called{background:var(--ink)}.g.imported{background:linear-gradient(135deg,var(--ink) 50%,transparent 50%)}
.g.declared{background:transparent}.g.non_production_only{border-style:dotted;border-color:var(--phantom)}
.g.none{border:none;width:auto;height:auto;color:var(--ink-2)}
.g.central{outline:2.5px dashed var(--hidden);outline-offset:3px}
.g.supporting{outline:1.5px dashed var(--rule);outline-offset:3px}
.mini{margin-top:4px}.mini .chip{font-size:.7rem}
.rgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:8px}
.rcol{background:var(--card);border:1px solid var(--rule);padding:8px 10px}.rcol.absent{border-style:dotted;border-color:var(--phantom);background:transparent}
.rcol h4{margin:0 0 4px;font-family:"Barlow Condensed",system-ui,sans-serif;font-size:1.05rem}
.track.solid{border:1.5px solid var(--ink)}.fill.solid{background:var(--ink)}
"""


def render_compare(res: dict, path: Path, lookup: dict) -> Path:
    cites = Cites(lookup)
    parts = [sec_head(res),
             '<nav class="toc" aria-label="Sections"><a href="#primitives">Primitives</a><a href="#similarity">Overlap</a>'
             '<a href="#roles">Roles</a><a href="#patterns">Patterns</a><a href="#profiles">Profiles</a>'
             '<a href="#evidence">Evidence</a></nav>',
             sec_primitives(res, cites), sec_similarity(res), sec_roles(res, cites), sec_patterns(res, cites),
             sec_profiles(res)]
    parts.append(sec_register(cites))
    parts.append(f'<footer>Generated by repo-forensics corpus compare from {res["facts"]} facts across '
                 f'{len(res["repos"])} validated bundles. {e(res["rule"])}</footer>')
    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>Corpus comparison: repo-forensics</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Barlow:wght@400;600&family=Barlow+Condensed:wght@600&family=JetBrains+Mono&display=swap" rel="stylesheet">
<style>{CSS}{EXTRA_CSS}</style></head><body><main>{"".join(parts)}</main><script>{JS}</script></body></html>
"""
    path.write_text(doc, encoding="utf-8")
    return path
