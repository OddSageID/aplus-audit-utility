from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime
from jinja2 import Template
from dataclasses import dataclass

@dataclass
class ReporterConfig:
    output_dir: Path = Path("reports")

class HTMLReportGenerator:
    """Generates professional HTML audit reports"""

    def __init__(self, config: Optional[ReporterConfig] = None):
        self.config = config or ReporterConfig()
        self.config.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, audit_results: Dict[str, Any], output_path: str) -> Path:
        """
        Backwards-compatible wrapper expected by tests.
        Writes report to the provided output path.
        """
        # Ensure all_findings exists for template rendering
        if 'all_findings' not in audit_results:
            findings = []
            for collector in audit_results.get('collectors', {}).values():
                findings.extend(collector.get('findings', []))
            audit_results = {
                **audit_results,
                'all_findings': findings,
                'collector_results': audit_results.get('collectors', {})
            }

        # Override output directory to the requested path
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.output_dir = output_file.parent
        return self.generate_report(audit_results)

    def generate_report(self, audit_results: Dict[str, Any]) -> Path:
        template = self._get_template()
        context = self._prepare_context(audit_results)
        html_content = template.render(**context)

        output_file = self.config.output_dir / f"audit_{audit_results['audit_id']}.html"
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_file

    
    def _prepare_context(self, results: Dict[str, Any]) -> Dict:
        severity_counts = {}
        for finding in results['all_findings']:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        risk_score = results.get('ai_analysis', {}).get('risk_score', 0)
        risk_level = 'LOW'
        risk_color = '#28a745'
        
        if risk_score >= 75:
            risk_level, risk_color = 'CRITICAL', '#dc3545'
        elif risk_score >= 50:
            risk_level, risk_color = 'HIGH', '#fd7e14'
        elif risk_score >= 25:
            risk_level, risk_color = 'MEDIUM', '#ffc107'
        
        return {
            'audit_id': results['audit_id'],
            'timestamp': results['timestamp'],
            'platform': results['platform'],
            'hostname': results['hostname'],
            'risk_score': risk_score,
            'risk_level': risk_level,
            'risk_color': risk_color,
            'total_findings': len(results['all_findings']),
            'severity_counts': severity_counts,
            'findings': results['all_findings'],
            'ai_analysis': results.get('ai_analysis', {}),
            'collector_results': results['collector_results'],
            'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def _get_template(self) -> Template:
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>System Audit Report - {{ audit_id }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
               line-height: 1.6; color: #333; background: #f5f7fa; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; background: white; 
                     border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                  color: white; padding: 40px; border-radius: 8px 8px 0 0; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .meta-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                     gap: 20px; padding: 30px 40px; background: #f8f9fa; border-bottom: 1px solid #e9ecef; }
        .dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                     gap: 20px; padding: 40px; }
        .card { background: white; border: 1px solid #e9ecef; border-radius: 8px; padding: 24px; }
        .risk-score-card { grid-column: span 2; 
                           background: linear-gradient(135deg, {{ risk_color }} 0%, {{ risk_color }}dd 100%);
                           color: white; border: none; }
        .card-value { font-size: 2.5em; font-weight: 700; margin: 10px 0; }
        .section { padding: 40px; border-top: 1px solid #e9ecef; }
        .section-title { font-size: 1.8em; margin-bottom: 20px; color: #2c3e50; }
        .findings-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .findings-table th { background: #f8f9fa; padding: 12px; text-align: left; 
                             border-bottom: 2px solid #dee2e6; }
        .findings-table td { padding: 12px; border-bottom: 1px solid #dee2e6; }
        .severity-badge { display: inline-block; padding: 4px 12px; border-radius: 12px;
                          font-size: 0.85em; font-weight: 600; text-transform: uppercase; }
        .badge-critical { background: #dc3545; color: white; }
        .badge-high { background: #fd7e14; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #007bff; color: white; }
        .summary-box { background: #f8f9fa; border-left: 4px solid #667eea; 
                       padding: 20px; margin: 20px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 System Security Audit Report</h1>
        </div>
        
        <div class="meta-info">
            <div><strong>Audit ID:</strong> {{ audit_id }}</div>
            <div><strong>Hostname:</strong> {{ hostname }}</div>
            <div><strong>Platform:</strong> {{ platform }}</div>
            <div><strong>Timestamp:</strong> {{ timestamp[:19] }}</div>
        </div>
        
        <div class="dashboard">
            <div class="card risk-score-card">
                <div>Risk Score</div>
                <div class="card-value">{{ risk_score }}/100</div>
                <div>{{ risk_level }}</div>
            </div>
            <div class="card">
                <div>Total Findings</div>
                <div class="card-value">{{ total_findings }}</div>
            </div>
        </div>
        
        <div class="section">
            <h2 class="section-title">Executive Summary</h2>
            <div class="summary-box">{{ ai_analysis.get('executive_summary', 'No AI analysis available') }}</div>
            
            {% if ai_analysis.get('recommendations') %}
            <h3>Top Recommendations</h3>
            <ol>
                {% for rec in ai_analysis.recommendations %}
                <li style="padding: 10px;">{{ rec }}</li>
                {% endfor %}
            </ol>
            {% endif %}
        </div>
        
        <div class="section">
            <h2 class="section-title">Detailed Findings</h2>
            {% if total_findings > 0 %}
            <table class="findings-table">
                <thead>
                    <tr><th>Severity</th><th>Check ID</th><th>Description</th>
                        <th>Current</th><th>Expected</th><th>Remediation</th></tr>
                </thead>
                <tbody>
                    {% for finding in findings %}
                    <tr>
                        <td><span class="severity-badge badge-{{ finding.severity.lower() }}">{{ finding.severity }}</span></td>
                        <td><code>{{ finding.check_id }}</code></td>
                        <td>{{ finding.description }}</td>
                        <td><code>{{ finding.current_value }}</code></td>
                        <td><code>{{ finding.expected_value }}</code></td>
                        <td>{{ finding.remediation_hint or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
            {% else %}
            <div class="summary-box">✓ No issues detected - system healthy</div>
            {% endif %}
        </div>
        
        <div style="padding: 30px; text-align: center; background: #f8f9fa; border-top: 1px solid #e9ecef;">
            <p><strong>A+ System Audit Utility v1.0</strong></p>
            <p>Generated {{ generated_at }} | CIS Benchmarks + A+ Best Practices</p>
        </div>
    </div>
</body>
</html>
        """
        return Template(template_str)
HTMLReporter = HTMLReportGenerator
