"""
PentestAI v8 — Agent 5: Reporting & Risk
PTES/OWASP standard reports: HTML (inline), Markdown, LaTeX, PDF (reportlab).
"""
import json
import uuid
import hashlib
from memory.report_artifacts import register_report, worker_evidence_manifest
import re
from datetime import datetime
from typing import Optional
from pathlib import Path

from agents.base_agent import BaseAgent
from memory.knowledge_cache import knowledge_cache
from memory.vector_store import vector_store


# ── Colour palette (shared between HTML and PDF) ─────────────────────────
SEV_HEX = {
    "critical": "#ef4444",
    "high":     "#f97316",
    "medium":   "#f59e0b",
    "low":      "#22c55e",
    "info":     "#6b7280",
}


def _safe(value) -> str:
    """Return a printable, latin-1-safe string for any value."""
    if value is None:
        return ""
    text = str(value)
    # Remove non-printable control characters (keep newlines/tabs)
    text = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f]', '', text)
    return _esc_html(text.replace("—","-").replace("–","-"))


def _esc_html(text: str) -> str:
    """Minimal HTML-escape for untrusted strings embedded in HTML."""
    return (str(text)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


class ReportAgent(BaseAgent):
    agent_name = "report"
    agent_role = "Reporting & Risk — Professional Reports"

    def get_system_prompt(self, skill_level: str = "intermediate") -> str:
        return (
            "You are the REPORTING agent. Generate professional penetration test reports "
            "following PTES/OWASP standards. Include: executive summary, scope, methodology, "
            "findings with evidence and remediation, risk assessment, and recommendations. "
            + self.get_skill_instruction(skill_level)
        )

    async def process(self, session_id: str, user_id: str, input_data: dict,
                      skill_level: str = "intermediate") -> dict:
        report_format = input_data.get("format", "html")
        return await self.generate_report(session_id, user_id, report_format, skill_level)

    # ── Public entry-point ────────────────────────────────────────────────

    async def generate_report(self, session_id: str, user_id: str,
                               fmt: str = "html", skill_level: str = "intermediate") -> dict:
        """Generate a pentest report in the specified format and save it to disk."""
        from memory.session_manager import session_manager
        from config.settings import settings

        # ── Gather data ──
        from api.auth import current_identity
        from api.session_access import get_accessible_session
        session = await get_accessible_session(session_id, await current_identity(user_id))
        findings_data = await session_manager.get_findings_summary(session_id)
        findings = [dict(f) for f in findings_data.get("findings", [])]
        for finding in findings:
            if not finding.get("human_verified"):
                finding["description"] = finding.get("description", "") + "\nEvidence source: " + finding.get("evidence_source", "legacy_unverified") + ". Not human-verified."
        counts   = findings_data.get("counts",   {})
        total    = findings_data.get("total",    0)

        all_intel    = vector_store.get_all(session_id)
        correlations = vector_store.get_correlations(session_id)
        cached       = knowledge_cache.get_all_for_session(session_id)
        tools_run    = list(set(e.get("tool", "") for e in cached if e.get("tool")))

        target = (session or {}).get("target", "Unknown")
        scope  = (session or {}).get("scope",  {})

        saved_logs = await session_manager.get_chat_logs(session_id, limit=200, msg_types=['burp_evidence','burp_replay','burp_comparison'])
        evidence_manifest = [f"{entry['id']} | Burp Community selected capture | "
            f"{entry.get('data',{}).get('summary',{}).get('method','')} "
            f"{entry.get('data',{}).get('summary',{}).get('url','')}"
            for entry in saved_logs if entry.get('type') in {'burp_evidence','burp_replay','burp_comparison'}]
        evidence_manifest.extend(await worker_evidence_manifest(session_id))
        # Sort findings by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f.get("severity", "info"), 5))

        # ── Build content ──
        content = None
        if fmt == "html":
            content = self._generate_html_report(
                target, scope, findings, counts, total, tools_run, correlations, cached)
        elif fmt == "markdown":
            content = self._generate_markdown_report(
                target, scope, findings, counts, total, tools_run)
        elif fmt == "latex":
            content = self._generate_latex_report(
                target, scope, findings, counts, total, tools_run)
        elif fmt == "pdf":
            content = None   # binary — handled separately below
        else:
            content = self._generate_markdown_report(
                target, scope, findings, counts, total, tools_run)

        if evidence_manifest and content is not None:
            limitations = "Execution receipts and selected captures are observations, not verified vulnerabilities. Manifest covers up to 200 recent HTTP captures and 200 worker ledger records."
            if fmt == "html":
                appendix = "<h2>Evidence provenance</h2><p>"+_esc_html(limitations)+"</p><pre>"+_esc_html("\n".join(evidence_manifest))+"</pre>"
                content = content.replace("</body>", appendix+"</body>")
            elif fmt != "latex":
                content += "\n\n## Evidence provenance\n\n"+limitations+"\n\n"+"\n".join(evidence_manifest)
            else:
                # Evidence IDs are UUIDs; source payloads never enter TeX.
                refs = [entry.split(" | ",1)[0] for entry in evidence_manifest]
                content = content.replace("\\end{document}", "\\section{Evidence provenance}\nReceipts and captures do not verify vulnerabilities. Evidence IDs: "+", ".join(refs)+"\n\\end{document}")
        # ── Ensure output dir exists ──
        report_dir = Path(settings.REPORT_OUTPUT_DIR)
        report_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        report_dir.chmod(0o700)

        ext = {"html": "html", "markdown": "md", "latex": "tex", "pdf": "pdf"}.get(fmt, "md")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = re.sub(r'[^\w]', '_', target)[:40]
        filename = f"pentest_report_{uuid.uuid4().hex}.{ext}"
        filepath = report_dir / filename
        filepath.touch(mode=0o600, exist_ok=False)

        # ── Write file ──
        if fmt == "pdf":
            self._generate_pdf_report(
                target, scope, findings, counts, total, tools_run, str(filepath), evidence_manifest)
        else:
            filepath.write_text(content, encoding="utf-8")

        try:
            filepath.chmod(0o600)
            await register_report(session_id, session["user_id"], filename, hashlib.sha256(filepath.read_bytes()).hexdigest())
        except Exception:
            filepath.unlink(missing_ok=True)
            raise RuntimeError("Report registration failed") from None

        return {
            "type":           "report",
            "format":         fmt,
            "filename":       filename,
            "filepath":       str(filepath),
            "content":        content if fmt != "pdf" else None,
            "evidence_manifest": evidence_manifest,
            "findings_count": total,
            "counts":         counts,
        }

    # ── HTML ─────────────────────────────────────────────────────────────

    def _generate_html_report(self, target, scope, findings, counts, total,
                               tools_run, correlations, cached) -> str:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        # Overall risk
        if counts.get("critical", 0):
            risk_label, risk_hex = "CRITICAL", "#ef4444"
        elif counts.get("high", 0):
            risk_label, risk_hex = "HIGH", "#f97316"
        elif counts.get("medium", 0):
            risk_label, risk_hex = "MEDIUM", "#f59e0b"
        elif total > 0:
            risk_label, risk_hex = "LOW", "#22c55e"
        else:
            risk_label, risk_hex = "INFO", "#6b7280"

        # Findings HTML
        findings_html = ""
        for i, f in enumerate(findings):
            sev = f.get("severity", "info")
            sev_hex = SEV_HEX.get(sev, "#6b7280")
            cves = ", ".join(f.get("cve_ids") or []) or "N/A"
            cvss = f.get("cvss_score", "N/A")
            conf = f"{int(f.get('confidence', 0.5) * 100)}%" if f.get("confidence") else "N/A"
            findings_html += (
                f'<div class="finding" onclick="this.classList.toggle(\'expanded\')">'
                f'<div class="finding-header">'
                f'<span class="sev-badge" style="background:{sev_hex}">{_esc_html(sev.upper())}</span>'
                f'<span class="finding-title">{_esc_html(f.get("title","Untitled"))}</span>'
                f'<span class="finding-meta">CVSS: {_esc_html(str(cvss))} | Conf: {conf}</span>'
                f'</div>'
                f'<div class="finding-body">'
                f'<p><strong>Description:</strong> {_esc_html(f.get("description",""))}</p>'
                f'<p><strong>Evidence:</strong> <code>{_esc_html(f.get("evidence",""))}</code></p>'
                f'<p><strong>CVEs:</strong> {_esc_html(cves)}</p>'
                f'<p><strong>Type:</strong> {_esc_html(f.get("vulnerability_type","N/A"))}</p>'
                f'<p><strong>Recommendation:</strong> {_esc_html(f.get("recommendation",""))}</p>'
                f'</div></div>'
            )

        tools_html = "".join(
            f'<span class="tool-tag">{_esc_html(t)}</span>' for t in tools_run
        )

        remediations_html = "".join(
            f'<li><strong>[{_esc_html(f.get("severity","").upper())}]</strong> '
            f'{_esc_html(f.get("title",""))}: {_esc_html(f.get("recommendation","N/A"))}</li>'
            for f in findings[:5]
        )

        # NOTE: CSS braces are doubled ({{ }}) to survive .format() — we use concatenation
        # instead to avoid any f-string vs CSS brace conflicts.
        css = """
*{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0f0f0f;--card:#1a1a1a;--border:#2a2a2a;--text:#e5e5e5;--t2:#999;
      --acc:#10a37f}
body{font-family:'Inter',system-ui,sans-serif;background:var(--bg);color:var(--text);
     padding:24px;max-width:960px;margin:0 auto;line-height:1.6}
h1{font-size:1.8rem;margin-bottom:4px}
h2{font-size:1.2rem;margin:24px 0 12px;color:var(--acc);border-bottom:1px solid var(--border);padding-bottom:6px}
.meta{color:var(--t2);font-size:.85rem;margin-bottom:20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin:12px 0}
.stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px;text-align:center}
.stat-val{font-size:1.6rem;font-weight:700}
.stat-label{font-size:.75rem;color:var(--t2);margin-top:4px}
.finding{background:var(--card);border:1px solid var(--border);border-radius:8px;margin:8px 0;cursor:pointer}
.finding-header{display:flex;align-items:center;gap:10px;padding:12px 16px}
.finding-body{display:none;padding:0 16px 16px;font-size:.9rem}
.finding.expanded .finding-body{display:block}
.finding-body p{margin-bottom:6px}
.sev-badge{padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600;color:#fff;flex-shrink:0}
.finding-title{flex:1;font-weight:500}
.finding-meta{font-size:.8rem;color:var(--t2)}
code{background:#111;padding:2px 6px;border-radius:3px;font-size:.85rem;word-break:break-all}
.tool-tag{display:inline-block;background:var(--card);border:1px solid var(--border);
          padding:3px 10px;border-radius:12px;font-size:.8rem;margin:3px}
table{width:100%;border-collapse:collapse;margin:10px 0}
th,td{border:1px solid var(--border);padding:8px 12px;text-align:left;font-size:.9rem}
th{background:var(--card);color:var(--t2)}
ol{padding-left:18px}
ol li{margin-bottom:4px;font-size:.9rem}
"""

        html = (
            "<!DOCTYPE html>\n"
            '<html lang="en">\n<head>\n'
            '<meta charset="UTF-8">\n'
            '<meta name="viewport" content="width=device-width,initial-scale=1">\n'
            f"<title>Pentest Report \u2014 {_esc_html(target)}</title>\n"
            f"<style>{css}</style>\n"
            "</head>\n<body>\n"
            f'<h1>&#x1F512; Penetration Test Report</h1>\n'
            f'<p class="meta">Target: <strong>{_esc_html(target)}</strong>'
            f' &nbsp;|&nbsp; Generated: {now}'
            f' &nbsp;|&nbsp; PentestAI v8</p>\n'
            "<h2>Executive Summary</h2>\n"
            '<div class="grid">\n'
            f'<div class="stat"><div class="stat-val" style="color:#ef4444">{counts.get("critical",0)}</div><div class="stat-label">Critical</div></div>\n'
            f'<div class="stat"><div class="stat-val" style="color:#f97316">{counts.get("high",0)}</div><div class="stat-label">High</div></div>\n'
            f'<div class="stat"><div class="stat-val" style="color:#f59e0b">{counts.get("medium",0)}</div><div class="stat-label">Medium</div></div>\n'
            f'<div class="stat"><div class="stat-val" style="color:#22c55e">{counts.get("low",0)}</div><div class="stat-label">Low</div></div>\n'
            f'<div class="stat"><div class="stat-val">{total}</div><div class="stat-label">Total</div></div>\n'
            f'<div class="stat"><div class="stat-val" style="color:{risk_hex};font-size:1rem;padding-top:6px">{risk_label}</div><div class="stat-label">Risk Level</div></div>\n'
            "</div>\n"
            "<h2>Scope &amp; Methodology</h2>\n"
            f'<p><strong>Target:</strong> {_esc_html(target)}</p>\n'
            "<p><strong>Methodology:</strong> PTES / OWASP Testing Guide v4</p>\n"
            f"<p><strong>Tools Used:</strong> {tools_html or '<em>None recorded</em>'}</p>\n"
            f"<h2>Findings ({total})</h2>\n"
            "<p style='font-size:.85rem;color:var(--t2);margin-bottom:8px'>Click any finding to expand details.</p>\n"
            + (findings_html or '<p style="color:var(--t2)">No findings recorded for this session.</p>')
            + "\n<h2>Risk Assessment</h2>\n"
            "<table>\n"
            "<tr><th>Severity</th><th>Count</th><th>Impact</th></tr>\n"
            f'<tr><td style="color:#ef4444">Critical</td><td>{counts.get("critical",0)}</td><td>Immediate exploitation possible</td></tr>\n'
            f'<tr><td style="color:#f97316">High</td><td>{counts.get("high",0)}</td><td>Significant risk — exploit within 24h</td></tr>\n'
            f'<tr><td style="color:#f59e0b">Medium</td><td>{counts.get("medium",0)}</td><td>Moderate risk — schedule remediation</td></tr>\n'
            f'<tr><td style="color:#22c55e">Low</td><td>{counts.get("low",0)}</td><td>Minor risk — best effort</td></tr>\n'
            "</table>\n"
            "<h2>Remediation Priorities</h2>\n"
            f"<ol>{remediations_html or '<li>No findings to remediate.</li>'}</ol>\n"
            f'<div style="margin-top:40px;padding-top:16px;border-top:1px solid #2a2a2a;'
            f'text-align:center;color:#555;font-size:.8rem">'
            f'PentestAI v8 &mdash; AI-Assisted Penetration Testing Report &mdash; {now}'
            "</div>\n</body>\n</html>"
        )
        return html

    # ── Markdown ──────────────────────────────────────────────────────────

    def _generate_markdown_report(self, target, scope, findings, counts, total, tools_run) -> str:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        lines = [
            f"# Penetration Test Report — {target}",
            f"**Date:** {now}  ",
            "**Tool:** PentestAI v8  ",
            "**Methodology:** PTES / OWASP Testing Guide v4\n",
            "## Executive Summary",
            f"Total findings: **{total}** | Critical: {counts.get('critical',0)} | "
            f"High: {counts.get('high',0)} | Medium: {counts.get('medium',0)} | "
            f"Low: {counts.get('low',0)}\n",
            "## Scope",
            f"- **Target:** {target}",
            f"- **Tools Used:** {', '.join(tools_run) or 'None'}\n",
            "## Findings\n",
        ]
        if not findings:
            lines.append("_No findings recorded for this session._\n")
        for f in findings:
            lines.append(f"### [{f.get('severity','info').upper()}] {f.get('title','Untitled')}")
            lines.append(f"- **Description:** {f.get('description','')}")
            lines.append(f"- **Evidence:** `{f.get('evidence','')}`")
            lines.append(f"- **CVEs:** {', '.join(f.get('cve_ids') or []) or 'N/A'}")
            lines.append(f"- **CVSS:** {f.get('cvss_score','N/A')}")
            lines.append(f"- **Recommendation:** {f.get('recommendation','')}\n")

        lines.append("## Remediation Priorities\n")
        for i, f in enumerate(findings[:5], 1):
            lines.append(f"{i}. **[{f.get('severity','').upper()}]** {f.get('title','')}: "
                         f"{f.get('recommendation','')}")
        lines.append(f"\n---\n*Generated by PentestAI v8 — {now}*")
        return "\n".join(lines)

    # ── LaTeX ─────────────────────────────────────────────────────────────

    def _generate_latex_report(self, target, scope, findings, counts, total, tools_run) -> str:
        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        def tex(s):
            return (str(s or "")
                    .replace("\\", "\\textbackslash{}")
                    .replace("&", "\\&")
                    .replace("%", "\\%")
                    .replace("$", "\\$")
                    .replace("#", "\\#")
                    .replace("_", "\\_")
                    .replace("{", "\\{")
                    .replace("}", "\\}")
                    .replace("~", "\\textasciitilde{}")
                    .replace("^", "\\textasciicircum{}"))

        findings_tex = ""
        for f in findings:
            title = tex(f.get("title", ""))
            desc  = tex(f.get("description", ""))[:400]
            rec   = tex(f.get("recommendation", ""))
            sev   = f.get("severity", "info").upper()
            cves  = ", ".join(f.get("cve_ids") or []) or "N/A"
            cvss  = f.get("cvss_score", "N/A")
            findings_tex += (
                f"\\subsection{{{title}}}\n"
                f"\\textbf{{Severity:}} {sev} \\\\\n"
                f"\\textbf{{Description:}} {desc} \\\\\n"
                f"\\textbf{{CVEs:}} {tex(cves)} \\\\\n"
                f"\\textbf{{CVSS:}} {tex(str(cvss))} \\\\\n"
                f"\\textbf{{Recommendation:}} {rec}\n\n"
            )

        return (
            "\\documentclass[12pt,a4paper]{article}\n"
            "\\usepackage[utf8]{inputenc}\n"
            "\\usepackage{geometry,fancyhdr,hyperref}\n"
            "\\geometry{margin=2.5cm}\n"
            "\\pagestyle{fancy}\n"
            "\\fancyhead[L]{Penetration Test Report}\n"
            "\\fancyhead[R]{PentestAI v8}\n"
            "\\fancyfoot[C]{\\thepage}\n\n"
            f"\\title{{Penetration Test Report \\\\ \\large {tex(target)}}}\n"
            "\\author{PentestAI v8 --- AI-Assisted Assessment}\n"
            f"\\date{{{tex(now)}}}\n\n"
            "\\begin{document}\n"
            "\\maketitle\n"
            "\\tableofcontents\n"
            "\\newpage\n\n"
            "\\section{Executive Summary}\n"
            f"Total findings: \\textbf{{{total}}} — "
            f"{counts.get('critical',0)} Critical, "
            f"{counts.get('high',0)} High, "
            f"{counts.get('medium',0)} Medium, "
            f"{counts.get('low',0)} Low.\n\n"
            "\\section{Scope \\& Methodology}\n"
            f"\\textbf{{Target:}} \\texttt{{{tex(target)}}} \\\\\n"
            "\\textbf{Methodology:} PTES / OWASP Testing Guide v4 \\\\\n"
            f"\\textbf{{Tools:}} {tex(', '.join(tools_run) or 'None')}\n\n"
            "\\section{Findings}\n"
            + (findings_tex or "No findings recorded.\n")
            + "\n\\section{Risk Assessment}\n"
            "\\begin{tabular}{|l|c|l|}\n\\hline\n"
            "\\textbf{Severity} & \\textbf{Count} & \\textbf{Impact} \\\\\n\\hline\n"
            f"Critical & {counts.get('critical',0)} & Immediate exploitation \\\\\n"
            f"High & {counts.get('high',0)} & Significant risk \\\\\n"
            f"Medium & {counts.get('medium',0)} & Moderate risk \\\\\n"
            f"Low & {counts.get('low',0)} & Minor risk \\\\\n"
            "\\hline\n\\end{tabular}\n\n"
            "\\section{Remediation}\n"
            "Prioritize critical and high severity findings for immediate remediation.\n\n"
            "\\end{document}\n"
        )

    # ── PDF (reportlab) ───────────────────────────────────────────────────

    def _generate_pdf_report(self, target, scope, findings, counts, total, tools_run, filepath, evidence_manifest=()):
        """
        Generate a professional PTES-compliant PDF using reportlab.
        reportlab is pre-installed on the Ubuntu server; fpdf2 is NOT.
        """
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether,
        )

        now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

        # Severity colours
        SEV_RL = {
            "critical": colors.HexColor("#ef4444"),
            "high":     colors.HexColor("#f97316"),
            "medium":   colors.HexColor("#f59e0b"),
            "low":      colors.HexColor("#22c55e"),
            "info":     colors.HexColor("#6b7280"),
        }
        ACC    = colors.HexColor("#10a37f")
        DARK   = colors.HexColor("#111111")
        LGREY  = colors.HexColor("#f5f5f5")
        DGREY  = colors.HexColor("#444444")
        WHITE  = colors.white
        BLACK  = colors.black

        # Overall risk
        if counts.get("critical", 0):
            risk_label, risk_color = "CRITICAL", SEV_RL["critical"]
        elif counts.get("high", 0):
            risk_label, risk_color = "HIGH", SEV_RL["high"]
        elif counts.get("medium", 0):
            risk_label, risk_color = "MEDIUM", SEV_RL["medium"]
        elif total > 0:
            risk_label, risk_color = "LOW", SEV_RL["low"]
        else:
            risk_label, risk_color = "CLEAN", ACC

        # Document
        doc = SimpleDocTemplate(
            filepath, pagesize=A4,
            leftMargin=2.5*cm, rightMargin=2.5*cm,
            topMargin=2.5*cm, bottomMargin=2.5*cm,
            title=f"Pentest Report — {target}",
            author="PentestAI v8",
        )

        base = getSampleStyleSheet()

        def sty(name, **kw):
            return ParagraphStyle(name, **kw)

        s_cover_title = sty("ct", fontSize=26, fontName="Helvetica-Bold",
                            alignment=TA_CENTER, textColor=DARK, spaceAfter=8)
        s_cover_sub   = sty("cs", fontSize=13, alignment=TA_CENTER,
                            textColor=DGREY, spaceAfter=4)
        s_conf        = sty("cf", fontSize=10, alignment=TA_CENTER,
                            textColor=colors.red, spaceAfter=4)
        s_h1          = sty("h1", fontSize=16, fontName="Helvetica-Bold",
                            textColor=ACC, spaceBefore=16, spaceAfter=6,
                            borderPadding=(0, 0, 4, 0))
        s_h2          = sty("h2", fontSize=13, fontName="Helvetica-Bold",
                            textColor=DARK, spaceBefore=10, spaceAfter=4)
        s_body        = sty("bd", fontSize=10, textColor=DARK,
                            leading=15, spaceAfter=4)
        s_code        = sty("co", fontSize=8, fontName="Courier",
                            textColor=DARK, backColor=LGREY,
                            borderPadding=4, leading=11, spaceAfter=4)
        s_toc         = sty("tc", fontSize=11, textColor=DARK,
                            leading=18, leftIndent=12)
        s_center      = sty("ce", fontSize=9, alignment=TA_CENTER,
                            textColor=DGREY, spaceAfter=2)

        story = []

        # ── Cover page ──────────────────────────────────────────────────
        story.append(Spacer(1, 3.5*cm))
        story.append(Paragraph("Penetration Test Report", s_cover_title))
        story.append(Spacer(1, 14))
        story.append(HRFlowable(width="80%", thickness=2, color=ACC, spaceAfter=12))
        story.append(Paragraph(_safe(f"Target: {target}"), s_cover_sub))
        story.append(Paragraph(_safe(f"Date: {now}"), s_cover_sub))
        story.append(Paragraph("PentestAI v8 — AI-Assisted Assessment", s_cover_sub))
        story.append(Spacer(1, 0.6*cm))
        story.append(Paragraph("CONFIDENTIAL", s_conf))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("Methodology: PTES / OWASP Testing Guide v4", s_center))
        story.append(Spacer(1, 2*cm))

        # Risk pill
        risk_data = [[Paragraph(f"<b>Overall Risk: {risk_label}</b>",
                                sty("rp", fontSize=14, textColor=WHITE, alignment=TA_CENTER))]]
        risk_table = Table(risk_data, colWidths=[8*cm])
        risk_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), risk_color),
            ("ROUNDEDCORNERS", [6]),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(risk_table)
        story.append(Spacer(1, 1*cm))
        story.append(Paragraph(
            "This document contains sensitive security information. "
            "Distribution is restricted to authorized personnel only.",
            sty("disc", fontSize=8, textColor=DGREY, alignment=TA_CENTER)
        ))
        story.append(PageBreak())

        # ── Table of Contents ────────────────────────────────────────────
        story.append(Paragraph("Table of Contents", s_h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACC, spaceAfter=8))
        toc_items = [
            "1. Executive Summary",
            "2. Scope & Methodology",
            "3. Risk Assessment",
            f"4. Detailed Findings ({total})",
            "5. Remediation Priorities",
            "6. Appendix - Tools Used",
        ]
        for item in toc_items:
            story.append(Paragraph(_safe(item), s_toc))
        story.append(PageBreak())

        # ── 1. Executive Summary ─────────────────────────────────────────
        story.append(Paragraph("1. Executive Summary", s_h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACC, spaceAfter=8))
        story.append(Paragraph(_safe(
            f"A scoped assessment was recorded for {target}. "
            "Coverage is limited to retained evidence; candidate findings require validation. "
            f"A total of {total} findings were recorded; unverified candidates are not confirmed vulnerabilities. "
            f"The overall risk rating is {risk_label}."
        ), s_body))
        story.append(Spacer(1, 0.4*cm))

        # Summary table
        summary_data = [
            [Paragraph("<b>Severity</b>", s_body), Paragraph("<b>Count</b>", s_body),
             Paragraph("<b>Impact</b>", s_body)],
            [Paragraph("Critical", sty("sc", fontSize=10, textColor=SEV_RL["critical"])),
             str(counts.get("critical", 0)), "Immediate exploitation possible"],
            [Paragraph("High",     sty("sh", fontSize=10, textColor=SEV_RL["high"])),
             str(counts.get("high",     0)), "Significant risk"],
            [Paragraph("Medium",   sty("sm", fontSize=10, textColor=SEV_RL["medium"])),
             str(counts.get("medium",   0)), "Moderate risk"],
            [Paragraph("Low",      sty("sl", fontSize=10, textColor=SEV_RL["low"])),
             str(counts.get("low",      0)), "Minor risk"],
            [Paragraph("Total",    s_body),
             Paragraph(f"<b>{total}</b>", s_body), ""],
        ]
        summary_table = Table(summary_data, colWidths=[5*cm, 3*cm, 8*cm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0),  ACC),
            ("TEXTCOLOR",    (0,0), (-1,0),  WHITE),
            ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [WHITE, LGREY]),
            ("GRID",         (0,0), (-1,-1), 0.5, colors.HexColor("#cccccc")),
            ("TOPPADDING",   (0,0), (-1,-1), 6),
            ("BOTTOMPADDING",(0,0), (-1,-1), 6),
            ("LEFTPADDING",  (0,0), (-1,-1), 8),
        ]))
        story.append(summary_table)
        story.append(PageBreak())

        # ── 2. Scope & Methodology ───────────────────────────────────────
        story.append(Paragraph("2. Scope &amp; Methodology", s_h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACC, spaceAfter=8))
        story.append(Paragraph(f"<b>Target:</b> {_safe(target)}", s_body))
        from security.redaction import redact
        story.append(Paragraph("<b>Configured scope:</b> "+_safe(json.dumps(redact(scope),sort_keys=True)),s_body))
        story.append(Paragraph("<b>Methodology:</b> PTES / OWASP Testing Guide v4", s_body))
        story.append(Paragraph("<b>Assessment:</b> Scoped, evidence-based observations", s_body))
        story.append(Paragraph(
            f"<b>Tools Used:</b> {_safe(', '.join(tools_run) or 'None recorded')}", s_body))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph("<b>Reference phases (coverage varies; consult evidence):</b>", s_body))
        for phase in [
            "Pre-engagement / Scope Definition",
            "Intelligence Gathering / Reconnaissance",
            "Scanning & Enumeration",
            "Vulnerability Analysis",
            "Exploitation (with human approval)",
            "Post-Exploitation & Lateral Movement Assessment",
            "Reporting",
        ]:
            story.append(Paragraph(f"&nbsp;&nbsp;&bull; {phase}", s_body))
        story.append(PageBreak())

        # ── 3. Risk Assessment ───────────────────────────────────────────
        story.append(Paragraph("3. Risk Assessment", s_h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACC, spaceAfter=8))
        story.append(Paragraph(_safe(
            f"Based on the findings, the overall risk level is {risk_label}. "
            "Immediate action is recommended for all Critical and High severity findings."
        ), s_body))
        story.append(PageBreak())

        # ── 4. Detailed Findings ─────────────────────────────────────────
        story.append(Paragraph(f"4. Detailed Findings ({total})", s_h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACC, spaceAfter=8))

        if not findings:
            story.append(Paragraph("No findings recorded for this session.", s_body))
        else:
            for i, f in enumerate(findings, 1):
                sev   = f.get("severity", "info")
                c     = SEV_RL.get(sev, colors.grey)
                title = _safe(f.get("title", "Untitled"))
                cves  = ", ".join(f.get("cve_ids") or []) or "N/A"
                cvss  = f.get("cvss_score", "N/A")
                desc  = _safe(str(f.get("description", ""))[:600])
                evid  = _safe(str(f.get("evidence", ""))[:400])
                rec   = _safe(f.get("recommendation", ""))

                block = []
                block.append(Paragraph(
                    f"<b>4.{i} [{sev.upper()}] {title}</b>",
                    sty(f"fh{i}", fontSize=11, fontName="Helvetica-Bold",
                        textColor=c, spaceBefore=10, spaceAfter=4)
                ))
                block.append(HRFlowable(width="100%", thickness=0.5,
                                        color=colors.HexColor("#cccccc"), spaceAfter=4))
                if desc:
                    block.append(Paragraph(f"<b>Description:</b> {desc}", s_body))
                if evid:
                    block.append(Paragraph("<b>Evidence:</b>", s_body))
                    block.append(Paragraph(evid, s_code))
                block.append(Paragraph(
                    f"<b>CVEs:</b> {_safe(cves)} &nbsp;&nbsp; <b>CVSS:</b> {_safe(str(cvss))}",
                    s_body))
                if rec:
                    block.append(Paragraph(f"<b>Remediation:</b> {rec}", s_body))

                story.append(KeepTogether(block))

        story.append(PageBreak())

        # ── 5. Remediation Priorities ────────────────────────────────────
        story.append(Paragraph("5. Remediation Priorities", s_h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACC, spaceAfter=8))
        if not findings:
            story.append(Paragraph("No findings to remediate.", s_body))
        else:
            for i, f in enumerate(findings[:10], 1):
                sev   = f.get("severity", "").upper()
                title = _safe(f.get("title", ""))
                rec   = _safe(f.get("recommendation", "Investigate further"))
                story.append(Paragraph(
                    f"{i}. <b>[{sev}]</b> {title}: {rec}", s_body))
        story.append(PageBreak())

        # ── 6. Appendix ──────────────────────────────────────────────────
        story.append(Paragraph("6. Appendix - Tools Used", s_h1))
        story.append(HRFlowable(width="100%", thickness=1, color=ACC, spaceAfter=8))
        if tools_run:
            for t in tools_run:
                story.append(Paragraph(f"&bull; {_safe(t)}", s_body))
        else:
            story.append(Paragraph("No tools recorded.", s_body))

        # Footer note
        story.append(Spacer(1, 1.5*cm))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#cccccc"), spaceAfter=6))
        story.append(Paragraph(
            f"Generated by PentestAI v8 — {now}",
            sty("ft", fontSize=8, textColor=DGREY, alignment=TA_CENTER)
        ))

        if evidence_manifest:
            story.append(Paragraph("Evidence provenance (observations, not verified vulnerabilities)", s_h1))
            for reference in evidence_manifest:
                story.append(Paragraph(_esc_html(reference), s_body))
        doc.build(story)


report_agent = ReportAgent()
