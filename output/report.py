"""HTML Report Generator for ShadowStrike."""
import os
from datetime import datetime


class ReportGenerator:
    """Generates HTML pentest reports."""
    
    def generate(self, target: str, findings: list, module_results: list, output_dir: str, notes: str = "") -> tuple:
        """Generate a full HTML report with Enterprise CSS."""
        
        timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        filename = f"report_{target.replace('.', '_')}_{timestamp}.html"
        filepath = os.path.join(output_dir, filename)
        
        # Count severities
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
        
        # Calculate Security Score (1-100)
        risk_weight = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}
        total_risk = sum(risk_weight.get(f.severity.value, 0) for f in findings)
        security_score = max(0, 100 - total_risk)
        
        score_color = "#10b981" if security_score >= 80 else "#f59e0b" if security_score >= 50 else "#ef4444"
        
        # Build findings rows
        findings_html = ""
        severity_colors = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#3b82f6", "INFO": "#6b7280"}
        
        for i, f in enumerate(findings, 1):
            color = severity_colors.get(f.severity.value, "#6b7280")
            
            # Format evidence block if it exists
            evidence_html = ""
            if hasattr(f, 'evidence') and f.evidence:
                evidence_html = f"""
                <div class="evidence">
                    <div class="evidence-title">TARGET EVIDENCE / TECHNICAL LOGS</div>
                    <pre><code>{f.evidence}</code></pre>
                </div>"""

            # Business Impact block
            impact_html = ""
            if hasattr(f, 'business_impact') and f.business_impact:
                impact_html = f"""
                <div class="impact-block">
                    <div class="impact-title">💸 BUSINESS RISK / IMPACT</div>
                    <p>{f.business_impact}</p>
                </div>"""
                
            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <div class="finding-title">
                        <span class="finding-num">#{i:02d}</span>
                        <h3>{f.title}</h3>
                    </div>
                    <span class="badge" style="background-color: {color}15; color: {color}; border: 1px solid {color}40;">
                        {f.severity.value}
                    </span>
                </div>
                
                <div class="finding-meta">
                    <span class="module-badge">Detection Module: {f.module.upper()}</span>
                </div>
                
                <div class="finding-desc">
                    <strong>VULNERABILITY DETAILS:</strong><br>
                    <p>{f.description}</p>
                </div>
                
                {impact_html}
                {evidence_html}
                
                <div class="finding-rem">
                    <div class="rem-title">🛠️ STEP-BY-STEP REMEDIATION</div>
                    <p>{f.recommendation}</p>
                </div>
            </div>"""
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowStrike Penetration Test Report — {target}</title>
    <link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@600;700&family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-dark: #f8fafc;
            --bg-card: #ffffff;
            --bg-lighter: #f1f5f9;
            --text-main: #1e293b;
            --text-muted: #64748b;
            --primary: #dc2626;
            --border: #e2e8f0;
            
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #3b82f6;
            --info: #64748b;
        }}

        @media screen and (prefers-color-scheme: dark) {{
            :root {{
                --bg-dark: #09090b;
                --bg-card: #121214;
                --bg-lighter: #18181b;
                --text-main: #e4e4e7;
                --text-muted: #a1a1aa;
                --primary: #ef4444;
                --border: #27272a;
            }}
        }}
        
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: var(--bg-dark); color: var(--text-main); line-height: 1.6; }}
        
        h1, h2, h3 {{ font-family: 'Cinzel', serif; font-weight: 700; color: var(--text-main); }}
        code, pre {{ font-family: 'JetBrains Mono', monospace; font-size: 0.85em; }}
        
        header {{
            background: linear-gradient(135deg, #0f172a 0%, #020617 100%);
            border-bottom: 4px solid var(--primary);
            padding: 80px 0 60px;
            color: #fff;
            position: relative;
        }}
        
        .container {{ max-width: 1100px; margin: 0 auto; padding: 0 40px; position: relative; z-index: 2; }}
        
        .logo-wrap {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 40px; }}
        .logo {{ font-family: 'Cinzel', serif; font-size: 2.5rem; font-weight: 700; letter-spacing: 2px; }}
        .logo span {{ color: var(--primary); }}
        .classification {{ font-size: 0.8rem; letter-spacing: 2px; font-weight: 600; color: var(--primary); border: 1px solid var(--primary); padding: 4px 12px; border-radius: 4px; text-transform: uppercase; }}
        
        .report-title {{ font-size: 3rem; margin-bottom: 10px; line-height: 1.2; font-family: 'Inter', sans-serif; font-weight: 700; letter-spacing: -1px; }}
        .report-subtitle {{ font-size: 1.2rem; color: #94a3b8; font-weight: 300; letter-spacing: 1px; }}
        
        .exec-grid {{ display: grid; grid-template-columns: 2fr 1fr; gap: 40px; margin-top: -30px; position: relative; z-index: 10; }}
        
        .card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 35px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); margin-bottom: 30px; }}
        .card-header {{ font-size: 1.4rem; margin-bottom: 25px; padding-bottom: 15px; border-bottom: 2px solid var(--border); letter-spacing: 0.5px; text-transform: uppercase; }}
        
        .info-table {{ width: 100%; border-collapse: collapse; font-size: 0.95rem; }}
        .info-table td {{ padding: 12px 0; border-bottom: 1px solid var(--border); }}
        .info-table td:first-child {{ color: var(--text-muted); font-weight: 500; width: 40%; }}
        .info-table td:last-child {{ text-align: right; font-weight: 600; font-family: 'JetBrains Mono', monospace; }}
        
        .score-circle {{ width: 140px; height: 140px; border-radius: 50%; display: flex; align-items: center; justify-content: center; flex-direction: column; margin: 0 auto 25px; border: 8px solid {score_color}; box-shadow: 0 0 20px {score_color}40; }}
        .score-val {{ font-size: 3rem; font-family: 'Inter', sans-serif; font-weight: 800; color: {score_color}; line-height: 1; }}
        .score-label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; font-weight: 700; letter-spacing: 1px; margin-top: 5px; }}
        
        .stat-row {{ display: flex; justify-content: space-between; padding: 10px 0; border-bottom: 1px dashed var(--border); font-size: 0.95rem; }}
        .stat-row:last-child {{ border: none; padding-bottom: 0; }}
        .stat-num {{ font-weight: 700; font-family: 'JetBrains Mono', monospace; }}
        
        .findings-title {{ margin-top: 60px; margin-bottom: 30px; font-size: 2rem; border-bottom: 3px solid var(--border); padding-bottom: 10px; text-transform: uppercase; letter-spacing: 1px; }}
        
        .finding-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 35px; margin-bottom: 30px; box-shadow: 0 4px 15px rgba(0,0,0,0.02); page-break-inside: avoid; }}
        
        .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }}
        .finding-title {{ display: flex; align-items: flex-start; gap: 15px; }}
        .finding-num {{ color: var(--text-muted); font-family: 'JetBrains Mono', monospace; font-size: 1.2rem; font-weight: 700; }}
        .finding-title h3 {{ font-size: 1.3rem; line-height: 1.3; font-family: 'Inter', sans-serif; font-weight: 700; }}
        
        .badge {{ padding: 6px 14px; border-radius: 6px; font-size: 0.8rem; font-weight: 700; letter-spacing: 1px; text-transform: uppercase; }}
        .module-badge {{ background: var(--bg-lighter); color: var(--text-muted); padding: 4px 10px; border-radius: 4px; font-size: 0.75rem; font-family: 'JetBrains Mono', monospace; border: 1px solid var(--border); font-weight: 600; }}
        
        .finding-meta {{ margin-bottom: 25px; }}
        
        .finding-desc strong {{ display: inline-block; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 8px; }}
        .finding-desc p {{ font-size: 1rem; color: var(--text-main); line-height: 1.6; margin-bottom: 20px; }}
        
        .impact-block {{ background: rgba(220, 38, 38, 0.05); border-left: 4px solid var(--primary); padding: 20px; border-radius: 0 8px 8px 0; margin-bottom: 25px; }}
        .impact-title {{ color: var(--primary); font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
        .impact-block p {{ color: var(--text-main); font-weight: 500; margin: 0; font-size: 0.95rem; line-height: 1.5; }}
        
        .evidence {{ background: #0f172a; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 25px; overflow-x: auto; box-shadow: inset 0 2px 10px rgba(0,0,0,0.2); }}
        .evidence-title {{ color: #64748b; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; }}
        .evidence pre {{ color: #10b981; margin: 0; line-height: 1.5; }}
        
        .finding-rem {{ background: var(--bg-lighter); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
        .rem-title {{ color: #0284c7; font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }}
        .finding-rem p {{ margin: 0; font-size: 0.95rem; line-height: 1.5; }}
        
        footer {{ margin-top: 80px; padding: 40px 0; text-align: center; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.85rem; font-weight: 500; }}
        
        @media print {{
            body {{ background: #fff !important; color: #000 !important; }}
            .container {{ width: 100% !important; max-width: none !important; padding: 0 20px !important; }}
            .card, .finding-card {{ box-shadow: none !important; border: 1px solid #ccc !important; break-inside: avoid; }}
            header {{ background: #0f172a !important; color: #fff !important; padding: 40px 0 !important; -webkit-print-color-adjust: exact; }}
            .impact-block {{ background: #fff5f5 !important; -webkit-print-color-adjust: exact; border-left: 4px solid #dc2626 !important; }}
            .evidence {{ background: #111 !important; color: #0f0 !important; -webkit-print-color-adjust: exact; }}
            .score-circle {{ border: 8px solid {score_color} !important; -webkit-print-color-adjust: exact; }}
            .logo span {{ color: #dc2626 !important; }}
            .classification {{ color: #dc2626 !important; border-color: #dc2626 !important; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <div class="logo-wrap">
                <div class="logo">SHADOW<span>STRIKE</span></div>
                <div class="classification">CONFIDENTIAL</div>
            </div>
            <div class="report-title">Security End-of-Test Report</div>
            <div class="report-subtitle">Automated Penetration Test & Reconnaissance</div>
        </div>
    </header>
    
    <div class="container">
        <div class="exec-grid">
            <div class="card">
                <h2 class="card-header">Target Overview</h2>
                <p style="color: var(--text-muted); margin-bottom: 25px; font-size: 0.95rem;">
                    This highly restricted document outlines the external attack surface, exposed vulnerabilities, and security posture of the target system. 
                    The methodology followed includes passive Open-Source Intelligence (OSINT), active service enumeration, and automated vulnerability scanning.
                </p>
                
                <table class="info-table">
                    <tr>
                        <td>Primary Target</td>
                        <td>{target}</td>
                    </tr>
                    <tr>
                        <td>Audit Date</td>
                        <td>{datetime.now().strftime("%B %d, %Y - %H:%M UTC")}</td>
                    </tr>
                    <tr>
                        <td>Security Engine</td>
                        <td>ShadowStrike v1.0.0</td>
                    </tr>
                    <tr>
                        <td>Total Findings</td>
                        <td>{len(findings)}</td>
                    </tr>
                </table>
            </div>
            
            <div class="card">
                <h2 class="card-header" style="text-align: center;">Security Score</h2>
                <div class="score-circle">
                    <div class="score-val">{security_score}</div>
                    <div class="score-label">Out of 100</div>
                </div>
                
                <div class="stat-row">
                    <span style="color: var(--text-muted);">Critical Risk</span>
                    <span class="stat-num" style="color: var(--critical);">{counts['CRITICAL']}</span>
                </div>
                <div class="stat-row">
                    <span style="color: var(--text-muted);">High Risk</span>
                    <span class="stat-num" style="color: var(--high);">{counts['HIGH']}</span>
                </div>
                <div class="stat-row">
                    <span style="color: var(--text-muted);">Medium Risk</span>
                    <span class="stat-num" style="color: var(--medium);">{counts['MEDIUM']}</span>
                </div>
                <div class="stat-row">
                    <span style="color: var(--text-muted);">Low Risk</span>
                    <span class="stat-num" style="color: var(--low);">{counts['LOW']}</span>
                </div>
                <div class="stat-row">
                    <span style="color: var(--text-muted);">Info</span>
                    <span class="stat-num" style="color: var(--info);">{counts['INFO']}</span>
                </div>
            </div>
        </div>
        
        <h2 class="findings-title">Detailed Impact & Findings</h2>
        
        {findings_html if findings else '<div class="card" style="text-align: center; color: #10b981; font-size: 1.2rem; padding: 50px;">✅ Exceptional Posture. No vulnerabilities detected across the external perimeter.</div>'}
        
        <footer>
            <div style="font-family: 'Cinzel', serif; font-size: 1.2rem; font-weight: 700; margin-bottom: 5px; color: var(--text-main);">SHADOWSTRIKE SECURITY</div>
            <p>UNAUTHORIZED REPRODUCTION OR DISTRIBUTION OF THIS DOCUMENT IS STRICTLY PROHIBITED.</p>
        </footer>
    </div>
</body>
</html>"""
        
        with open(filepath, "w") as f:
            f.write(html)
            
        # --- PDF GENERATION ---
        import subprocess
        
        pdf_filename = f"ShadowStrike_Report_{target.replace('.', '_')}_{timestamp}.pdf"
        desktop_dir = os.path.expanduser("~/Desktop")
        pdf_filepath = os.path.join(desktop_dir, pdf_filename)
        
        chrome_path = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        abs_html_filepath = os.path.abspath(filepath)
        
        try:
            subprocess.run([
                chrome_path, 
                "--headless", 
                "--disable-gpu", 
                "--no-pdf-header-footer",
                f"--print-to-pdf={pdf_filepath}", 
                f"file://{abs_html_filepath}"
            ], check=True, capture_output=True)
        except Exception:
            pdf_filepath = "" # Fail silently if Chrome isn't installed
            
        return filepath, pdf_filepath
