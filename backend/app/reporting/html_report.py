"""Self-contained HTML developer report.

This is the developer-facing artifact described in the report-design doc: the
same findings as the JSON / SARIF / Markdown outputs, rendered as readable
remediation cards for review, marking, and demonstration. It is a single file
with embedded CSS and no external assets, so it opens in any browser offline and
prints cleanly to PDF (File -> Print -> Save as PDF).

Safety: like every other report, it shows only **masked** values -- the
``redacted_secret`` and the already-masked source context. The raw secret is
never read here and never reaches the page. All finding-derived text is
HTML-escaped so file contents cannot break or inject into the markup.
"""

from __future__ import annotations

from html import escape

from app.ci.decision import CIDecision, FindingDecision
from app.reporting.markdown import (
    _DEFAULT_SAFE_PATTERN,
    _SAFE_PATTERNS,
    _SECRET_TITLES,
    _classification_label,
    llm_engine_banner,
)

# Severity rendered high-first, matching the doc's "Findings by severity".
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

_STYLE = """
:root {
  --bg: #f6f8fa; --card: #ffffff; --ink: #1f2328; --muted: #57606a;
  --border: #d0d7de; --code-bg: #f6f8fa;
  --critical: #b30000; --high: #d1242f; --medium: #bf8700; --low: #2da44e;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1rem; background: var(--bg); color: var(--ink);
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
}
.wrap { max-width: 920px; margin: 0 auto; }
h1 { font-size: 1.7rem; margin: 0 0 .25rem; }
h2 { font-size: 1.2rem; margin: 2rem 0 .75rem; border-bottom: 1px solid var(--border); padding-bottom: .35rem; }
.engine { color: var(--muted); margin: 0 0 1rem; }
.summary { display: flex; flex-wrap: wrap; gap: .5rem; margin: 1rem 0; }
.stat {
  background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  padding: .5rem .9rem; min-width: 92px;
}
.stat .n { font-size: 1.5rem; font-weight: 700; display: block; }
.stat .l { color: var(--muted); font-size: .8rem; text-transform: uppercase; letter-spacing: .03em; }
.card {
  background: var(--card); border: 1px solid var(--border); border-left-width: 6px;
  border-radius: 8px; padding: 1rem 1.2rem; margin: 1rem 0; overflow-wrap: anywhere;
}
.card.critical { border-left-color: var(--critical); }
.card.high { border-left-color: var(--high); }
.card.medium { border-left-color: var(--medium); }
.card.low { border-left-color: var(--low); }
.card h3 { margin: 0 0 .6rem; font-size: 1.1rem; }
.badge {
  display: inline-block; color: #fff; font-size: .72rem; font-weight: 700;
  padding: .12rem .5rem; border-radius: 999px; text-transform: uppercase;
  letter-spacing: .04em; vertical-align: middle; margin-right: .5rem;
}
.badge.critical { background: var(--critical); }
.badge.high { background: var(--high); }
.badge.medium { background: var(--medium); }
.badge.low { background: var(--low); }
.meta { list-style: none; padding: 0; margin: 0 0 .75rem;
  display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: .15rem .5rem; }
.meta li { color: var(--muted); font-size: .9rem; }
.meta b { color: var(--ink); }
.label { font-weight: 700; margin: .75rem 0 .25rem; }
ol.steps { margin: .25rem 0 .25rem 1.2rem; padding: 0; }
code, pre { font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace; }
code { background: var(--code-bg); padding: .1rem .35rem; border-radius: 4px; font-size: .88em; }
pre {
  background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px;
  padding: .75rem .9rem; overflow-x: auto; font-size: .85rem; margin: .25rem 0;
}
pre.context .target { background: #fff3cd; display: block; }
.empty { background: var(--card); border: 1px solid var(--border); border-radius: 8px;
  padding: 1.5rem; text-align: center; color: var(--low); font-weight: 600; }
.appendix { color: var(--muted); font-size: .9rem; }
.appendix code { font-size: .85em; }
footer { margin-top: 2rem; color: var(--muted); font-size: .8rem; border-top: 1px solid var(--border); padding-top: .75rem; }
@media print {
  body { background: #fff; padding: 0; }
  .card, .stat { break-inside: avoid; }
}
"""


def build_html_report(decision: CIDecision) -> str:
    """Render the full self-contained HTML developer report as a string."""

    visible = [item for item in decision.findings if item.action != "ignore"]
    visible.sort(key=_sort_key)

    body = [
        '<div class="wrap">',
        "<h1>CredHunter-X Report</h1>",
        f'<p class="engine">{escape(llm_engine_banner(decision))}</p>',
        _summary_block(decision),
    ]

    body.append("<h2>Findings by severity</h2>")
    if visible:
        body.extend(_card(item) for item in visible)
    else:
        body.append('<div class="empty">No reportable findings. &#10003;</div>')

    body.append(_appendix(decision))
    body.append(
        "<footer>CredHunter-X &middot; secret values are masked in this report &mdash; "
        "never the raw secret. Print to PDF via your browser&rsquo;s print dialog.</footer>"
    )
    body.append("</div>")

    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        "<title>CredHunter-X Report</title>"
        f"<style>{_STYLE}</style></head><body>"
        + "".join(body)
        + "</body></html>\n"
    )


def _sort_key(item: FindingDecision) -> tuple[int, int]:
    severity = _SEVERITY_ORDER.get(item.risk_level, 99)
    score = item.risk_score.score if item.risk_score else 0
    return (severity, -score)


def _summary_block(decision: CIDecision) -> str:
    stats = [
        ("Total", decision.finding_count),
        ("Blocking", decision.blocking_count),
        ("Manual review", decision.manual_review_count),
        ("Warnings", decision.warning_count),
        ("Ignored", decision.ignored_count),
    ]
    cells = "".join(
        f'<div class="stat"><span class="n">{value}</span>'
        f'<span class="l">{escape(label)}</span></div>'
        for label, value in stats
    )
    return (
        f"<p><b>Final action:</b> <code>{escape(decision.action)}</code></p>"
        f'<div class="summary">{cells}</div>'
    )


def _card(item: FindingDecision) -> str:
    finding = item.finding
    level = item.risk_level if item.risk_level in _SEVERITY_ORDER else "low"
    title = _SECRET_TITLES.get(finding.secret_type, "Potential Secret")
    location = f"{finding.file_path}:{finding.line_number or 1}"
    classification, confidence = _classification_label(item)
    score = item.risk_score.score if item.risk_score else "—"
    masked = (finding.redacted_secret or "—").strip() or "—"
    safe_pattern = _SAFE_PATTERNS.get(finding.secret_type, _DEFAULT_SAFE_PATTERN)

    parts = [
        f'<div class="card {escape(level)}">',
        f'<h3><span class="badge {escape(level)}">{escape(item.risk_level)}</span>{escape(title)}</h3>',
        "<ul class=\"meta\">",
        f"<li><b>File:</b> <code>{escape(location)}</code></li>",
        f"<li><b>Type:</b> <code>{escape(finding.secret_type)}</code></li>",
        f"<li><b>Action:</b> <code>{escape(item.action)}</code></li>",
        f"<li><b>Risk score:</b> {escape(str(score))}</li>",
        f"<li><b>Classification:</b> {escape(classification)}</li>",
        f"<li><b>Confidence:</b> {escape(confidence)}</li>",
        f"<li><b>Secret (masked):</b> <code>{escape(masked)}</code></li>",
        "</ul>",
    ]

    snippet = _context_snippet(finding)
    if snippet:
        parts.append(snippet)

    parts.append('<div class="label">Why this matters</div>')
    parts.append(f"<p>{escape(item.explanation())}</p>")

    parts.append('<div class="label">Recommended fix</div>')
    parts.append("<ol class=\"steps\">")
    parts.extend(f"<li>{escape(step)}</li>" for step in item.remediation())
    parts.append("</ol>")

    parts.append('<div class="label">Safe code pattern</div>')
    parts.append(f"<pre><code>import os\n{escape(safe_pattern)}</code></pre>")
    parts.append("</div>")
    return "".join(parts)


def _context_snippet(finding) -> str | None:
    """Render the already-masked source context around the finding, if present."""

    target = finding.metadata.get("target_line")
    before = finding.context_before
    after = finding.context_after
    if not (target or before or after):
        return None

    rows = []
    if before:
        rows.append(escape(before))
    if target:
        rows.append(f'<span class="target">{escape(target)}</span>')
    if after:
        rows.append(escape(after))
    return '<pre class="context">' + "\n".join(rows) + "</pre>"


def _appendix(decision: CIDecision) -> str:
    status = decision.llm_status or {}
    model = status.get("model") or "n/a"
    mode = status.get("mode", "deterministic")
    return (
        "<h2>Appendix</h2>"
        '<div class="appendix"><ul>'
        "<li>Machine-readable findings: <code>credhunter-report.json</code></li>"
        "<li>Code-scanning upload: <code>credhunter-report.sarif</code></li>"
        f"<li>LLM engine: <code>{escape(str(mode))}</code>, model <code>{escape(str(model))}</code></li>"
        "<li>Limitations: classifications are advisory; always confirm a flagged "
        "secret is live before treating it as exploited, and rotate it regardless.</li>"
        "<li>Safety: every value shown above is masked; the raw secret is never "
        "written to this report, the logs, or the PR comment.</li>"
        "</ul></div>"
    )
