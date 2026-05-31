"""
Report Generator
Educational module to generate security reports in JSON and HTML formats
"""

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any
from jinja2 import Template
from models.schemas import SecurityReport, EndpointResult, ChecklistItem, SecurityIssue

# Optional PDF generation
try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


class ReportGenerator:
    """Generates security reports in JSON and HTML formats (educational)"""
    
    def __init__(self, results_dir: str = "results", reports_dir: str = "reports"):
        self.results_dir = Path(results_dir)
        self.reports_dir = Path(reports_dir)
        self.results_dir.mkdir(exist_ok=True)
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_report_id(self) -> str:
        """Generate a unique report ID"""
        return str(uuid.uuid4())
    
    def generate_json_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate a JSON report
        """
        report_id = report_data.get("report_id", self.generate_report_id())
        filename = f"{report_id}.json"
        filepath = self.results_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return str(filepath)
    
    def generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate an HTML report using Jinja2 template
        """
        report_id = report_data.get("report_id", self.generate_report_id())
        filename = f"{report_id}.html"
        filepath = self.reports_dir / filename
        
        # Load template
        template_path = Path(__file__).parent / "templates" / "report_template.html"
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        template = Template(template_content)
        html_content = template.render(**report_data)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def generate_pdf_report(self, report_data: Dict[str, Any]) -> str:
        """
        Generate a PDF report using reportlab
        Returns None if reportlab is not installed
        """
        if not PDF_AVAILABLE:
            print("Warning: reportlab not installed. Skipping PDF generation.")
            print("To enable PDF generation, install reportlab: pip install reportlab")
            return None
        
        report_id = report_data.get("report_id", self.generate_report_id())
        filename = f"{report_id}.pdf"
        filepath = self.reports_dir / filename
        
        # Create PDF document
        doc = SimpleDocTemplate(str(filepath), pagesize=letter)
        story = []
        styles = getSampleStyleSheet()
        
        # Add custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor='#2c3e50',
            alignment=TA_CENTER,
            spaceAfter=30
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor='#2c3e50',
            spaceAfter=12
        )
        
        # Title
        story.append(Paragraph("🔒 Security Audit Report", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # Report Information
        story.append(Paragraph("Report Information", heading_style))
        info_data = [
            ["Report ID:", report_data.get("report_id", "N/A")],
            ["Date:", report_data.get("date", "N/A")],
            ["Environment:", report_data.get("environment", "N/A")],
            ["Target URL:", report_data.get("target_url", "N/A")],
            ["Risk Level:", report_data.get("risk_level", "N/A")],
            ["Security Score:", f"{report_data.get('security_score', 0)}/100"],
            ["Risk Classification:", report_data.get("risk_classification", "N/A")]
        ]
        if report_data.get("scan_duration"):
            info_data.append(["Scan Duration:", f"{report_data['scan_duration']} sec"])
        
        info_table = Table(info_data, colWidths=[2*inch, 4*inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), '#f8f9fa'),
            ('TEXTCOLOR', (0, 0), (0, -1), '#2c3e50'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, '#dee2e6')
        ]))
        story.append(info_table)
        story.append(Spacer(1, 0.3*inch))
        
        # Endpoint Statistics
        if report_data.get("endpoint_stats"):
            story.append(Paragraph("Endpoint Statistics", heading_style))
            endpoint_stats = report_data["endpoint_stats"]
            stats_data = [
                ["Endpoints Tested:", str(endpoint_stats.get("tested", 0))],
                ["Endpoints Failed:", str(endpoint_stats.get("failed", 0))],
                ["Endpoints Not Found:", str(endpoint_stats.get("not_found", 0))]
            ]
            stats_table = Table(stats_data, colWidths=[2*inch, 4*inch])
            stats_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), '#f8f9fa'),
                ('TEXTCOLOR', (0, 0), (0, -1), '#2c3e50'),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, '#dee2e6')
            ]))
            story.append(stats_table)
            story.append(Spacer(1, 0.3*inch))
        
        # Severity Summary
        story.append(Paragraph("Severity Summary", heading_style))
        severity_counts = report_data.get("severity_counts", {})
        severity_data = [
            ["Critical:", str(severity_counts.get("Critical", 0))],
            ["High:", str(severity_counts.get("High", 0))],
            ["Medium:", str(severity_counts.get("Medium", 0))],
            ["Low:", str(severity_counts.get("Low", 0))]
        ]
        severity_table = Table(severity_data, colWidths=[2*inch, 4*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), '#f8f9fa'),
            ('TEXTCOLOR', (0, 0), (0, -1), '#2c3e50'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, '#dee2e6')
        ]))
        story.append(severity_table)
        story.append(Spacer(1, 0.3*inch))
        
        # OWASP API Risks
        if report_data.get("owasp_risks"):
            story.append(Paragraph("OWASP API Risks Identified", heading_style))
            for risk in report_data["owasp_risks"]:
                story.append(Paragraph(f"✓ {risk}", styles['Normal']))
            story.append(Spacer(1, 0.3*inch))
        
        # Conclusion
        story.append(Paragraph("Conclusion", heading_style))
        story.append(Paragraph(report_data.get("conclusion", "No conclusion available."), styles['Normal']))
        story.append(Spacer(1, 0.3*inch))
        
        # Footer
        story.append(Paragraph("<strong>Academic Use Only</strong> - This report is generated for educational purposes only.", styles['Normal']))
        
        # Build PDF
        doc.build(story)
        
        return str(filepath)
    
    def create_report_data(
        self,
        target_url: str,
        endpoints_analyzed: List[str],
        endpoint_results: List[Dict[str, Any]],
        checklist: List[Dict[str, Any]],
        security_headers: Dict[str, bool],
        endpoints_404: List[str] = None,
        scan_duration: float = None
    ) -> Dict[str, Any]:
        """
        Create complete report data structure
        """
        report_id = self.generate_report_id()
        
        # Handle None inputs
        if endpoint_results is None:
            endpoint_results = []
        if checklist is None:
            checklist = []
        if security_headers is None:
            security_headers = {}
        if endpoints_analyzed is None:
            endpoints_analyzed = []
        if endpoints_404 is None:
            endpoints_404 = []
        
        # Determine environment based on target URL
        if "localhost" in target_url or "127.0.0.1" in target_url:
            environment = "localhost"
        else:
            environment = "remote"
        
        # Calculate risk level
        risk_level = self._calculate_risk_level(endpoint_results, checklist)
        
        # Generate issues
        issues = self._generate_issues(endpoint_results, checklist, security_headers)
        
        # Calculate severity counts
        severity_counts = self._calculate_severity_counts(issues)
        
        # Calculate security score
        security_score = self._calculate_security_score(checklist, severity_counts, endpoints_404)
        
        # Get risk classification
        risk_classification = self._get_risk_classification(security_score)
        
        # Calculate endpoint statistics
        endpoint_stats = self._calculate_endpoint_statistics(endpoint_results)
        
        # Calculate global scan statistics
        scan_statistics = self._calculate_scan_statistics(endpoint_results, issues, security_headers)
        
        # Map to OWASP API Top 10
        owasp_risks = self._map_to_owasp_api_top_10(issues)
        
        # Generate conclusion
        conclusion = self._generate_dynamic_conclusion(security_score, len(issues))
        
        report_data = {
            "report_id": report_id,
            "date": datetime.now().isoformat(),
            "project_name": "API Security Academic Auditor",
            "context": "Academic and educational security analysis for mobile APIs",
            "environment": environment,
            "target_url": target_url,
            "endpoints_analyzed": endpoints_analyzed,
            "checklist": checklist,
            "endpoint_results": endpoint_results,
            "security_headers": security_headers,
            "issues": issues,
            "risk_level": risk_level,
            "conclusion": conclusion,
            "severity_counts": severity_counts,
            "security_score": security_score,
            "risk_classification": risk_classification,
            "endpoints_404": endpoints_404,
            "endpoint_stats": endpoint_stats,
            "scan_statistics": scan_statistics,
            "owasp_risks": owasp_risks,
            "scan_duration": scan_duration
        }
        
        return report_data
    
    def _calculate_risk_level(self, endpoint_results: List[Dict], checklist: List[Dict]) -> str:
        """
        Calculate overall risk level (educational)
        """
        # Handle None inputs
        if endpoint_results is None:
            endpoint_results = []
        if checklist is None:
            checklist = []
        
        # Count issues
        total_sensitive_data = sum(len(r.get("sensitive_data_found", []) or []) for r in endpoint_results)
        total_error_messages = sum(len(r.get("error_messages_found", []) or []) for r in endpoint_results)
        non_compliant_checklist = sum(1 for c in checklist if c.get("status") == "non-compliant")
        
        # Calculate risk
        if total_sensitive_data > 3 or total_error_messages > 3 or non_compliant_checklist >= 4:
            return "High"
        elif total_sensitive_data > 0 or total_error_messages > 0 or non_compliant_checklist >= 2:
            return "Medium"
        else:
            return "Low"
    
    def _generate_issues(
        self,
        endpoint_results: List[Dict],
        checklist: List[Dict],
        security_headers: Dict[str, bool]
    ) -> List[Dict[str, str]]:
        """
        Generate security issues list (educational)
        Groups issues of the same type for the same endpoint
        """
        issues = []
        
        # Handle None inputs
        if endpoint_results is None:
            endpoint_results = []
        if checklist is None:
            checklist = []
        if security_headers is None:
            security_headers = {}
        
        # Group sensitive data findings by endpoint
        sensitive_data_by_endpoint = {}
        for result in endpoint_results:
            if result.get("test_status") == "not_tested":
                continue
            sensitive_data_findings = result.get("sensitive_data_findings", []) or []
            if sensitive_data_findings:
                endpoint = result.get("endpoint", "unknown")
                if endpoint not in sensitive_data_by_endpoint:
                    sensitive_data_by_endpoint[endpoint] = []
                sensitive_data_by_endpoint[endpoint].extend(sensitive_data_findings)
        
        # Create grouped sensitive data issues
        for endpoint, findings in sensitive_data_by_endpoint.items():
            # Determine highest severity
            severities = [f.get("severity", "High") for f in findings]
            severity = "Critical" if "Critical" in severities else "High" if "High" in severities else "Medium" if "Medium" in severities else "Low"
            
            issues.append({
                "severity": severity,
                "category": "Sensitive Data Exposure",
                "description": f"Endpoint {endpoint} exposes sensitive data",
                "recommendation": "Remove sensitive data from responses or implement proper encryption",
                "endpoint": endpoint,
                "grouped_findings": findings
            })
        
        # Group error message findings by endpoint
        error_messages_by_endpoint = {}
        for result in endpoint_results:
            if result.get("test_status") == "not_tested":
                continue
            error_message_findings = result.get("error_message_findings", []) or []
            if error_message_findings:
                endpoint = result.get("endpoint", "unknown")
                if endpoint not in error_messages_by_endpoint:
                    error_messages_by_endpoint[endpoint] = []
                error_messages_by_endpoint[endpoint].extend(error_message_findings)
        
        # Create grouped error message issues
        for endpoint, findings in error_messages_by_endpoint.items():
            # Determine highest severity
            severities = [f.get("severity", "Medium") for f in findings]
            severity = "High" if "High" in severities else "Medium" if "Medium" in severities else "Low"
            
            issues.append({
                "severity": severity,
                "category": "Information Disclosure",
                "description": f"Endpoint {endpoint} reveals technical error details",
                "recommendation": "Implement generic error messages without exposing technical details",
                "endpoint": endpoint,
                "grouped_findings": findings
            })
        
        # Check for server errors (500, 502, 503, 504)
        server_error_codes = [500, 502, 503, 504]
        for result in endpoint_results:
            if result.get("status_code") in server_error_codes:
                issues.append({
                    "severity": "Medium",
                    "category": "Server Error Detected",
                    "description": f"Endpoint {result.get('endpoint', 'unknown')} returned {result.get('status_code')} server error",
                    "recommendation": "Investigate server-side exceptions and ensure production error handling is enabled."
                })
        
        # Check security headers
        missing_headers = [h for h, present in security_headers.items() if not present]
        if missing_headers:
            issues.append({
                "severity": "Medium",
                "category": "Missing Security Headers",
                "description": f"Missing security headers: {', '.join(missing_headers)}",
                "recommendation": "Implement all required security headers"
            })
        
        # Check authentication
        auth_checklist = [c for c in checklist if c.get("item") == "Authentication Present"]
        if auth_checklist and auth_checklist[0].get("status") == "non-compliant":
            issues.append({
                "severity": "Critical",
                "category": "Authentication",
                "description": "API endpoints lack proper authentication",
                "recommendation": "Implement authentication for all sensitive endpoints"
            })
        
        return issues
    
    def _calculate_severity_counts(self, issues: List[Dict[str, str]]) -> Dict[str, int]:
        """
        Calculate counts by severity level
        """
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }
        
        for issue in issues:
            severity = issue.get("severity", "Low")
            if severity in counts:
                counts[severity] += 1
        
        return counts
    
    def _calculate_security_score(self, checklist: List[Dict], severity_counts: Dict[str, int], endpoints_404: List[str]) -> int:
        """
        Calculate security score out of 100
        Only penalize tested endpoints, not not-applicable or not-tested ones
        """
        score = 100
        
        # Deduct points for non-compliant checklist items (exclude not-applicable)
        non_compliant = sum(1 for c in checklist if c.get("status") == "non-compliant")
        score -= non_compliant * 10
        
        # Deduct points for severity issues
        score -= severity_counts.get("Critical", 0) * 25
        score -= severity_counts.get("High", 0) * 15
        score -= severity_counts.get("Medium", 0) * 8
        score -= severity_counts.get("Low", 0) * 3
        
        # Deduct minimal points for 404 endpoints (not tested)
        score -= len(endpoints_404) * 2
        
        # Ensure score is between 0 and 100
        score = max(0, score)
        score = min(100, score)
        
        return score
    
    def _get_risk_classification(self, score: int) -> str:
        """
        Get risk classification based on security score
        """
        if score <= 20:
            return "Critical Risk"
        elif score <= 40:
            return "High Risk"
        elif score <= 60:
            return "Medium Risk"
        elif score <= 80:
            return "Low Risk"
        else:
            return "Secure"
    
    def _calculate_endpoint_statistics(self, endpoint_results: List[Dict]) -> Dict[str, int]:
        """
        Calculate endpoint statistics
        """
        stats = {
            "tested": 0,
            "failed": 0,
            "not_found": 0
        }
        
        for result in endpoint_results:
            test_status = result.get("test_status", "")
            if test_status == "tested":
                stats["tested"] += 1
            elif test_status == "error":
                stats["failed"] += 1
            elif test_status == "not_tested":
                stats["not_found"] += 1
        
        return stats
    
    def _calculate_scan_statistics(self, endpoint_results: List[Dict], issues: List[Dict], security_headers: Dict[str, bool]) -> Dict[str, int]:
        """
        Calculate global scan statistics
        """
        # Count sensitive data findings
        sensitive_data_count = 0
        for result in endpoint_results:
            sensitive_data_findings = result.get("sensitive_data_findings", []) or []
            sensitive_data_count += len(sensitive_data_findings)
        
        # Count information disclosure findings
        info_disclosure_count = 0
        for result in endpoint_results:
            error_message_findings = result.get("error_message_findings", []) or []
            info_disclosure_count += len(error_message_findings)
        
        # Count authentication issues
        auth_issues = sum(1 for issue in issues if issue.get("category") == "Authentication")
        
        # Count missing headers
        missing_headers = sum(1 for h, present in security_headers.items() if not present)
        
        return {
            "total_endpoints": len(endpoint_results),
            "successful_requests": sum(1 for r in endpoint_results if r.get("test_status") == "tested"),
            "failed_requests": sum(1 for r in endpoint_results if r.get("test_status") == "error"),
            "sensitive_data_findings": sensitive_data_count,
            "information_disclosure_findings": info_disclosure_count,
            "authentication_issues": auth_issues,
            "missing_headers": missing_headers,
            "total_vulnerabilities": len(issues)
        }
    
    def _map_to_owasp_api_top_10(self, issues: List[Dict]) -> List[str]:
        """
        Map detected vulnerabilities to OWASP API Security Top 10 2023
        """
        owasp_risks = set()
        
        for issue in issues:
            category = issue.get("category", "")
            
            if category == "Authentication":
                owasp_risks.add("API2:2023 Broken Authentication")
            elif category == "Sensitive Data Exposure":
                owasp_risks.add("API3:2023 Broken Object Property Level Authorization")
            elif category in ["Information Disclosure", "Server Error Detected", "Missing Security Headers"]:
                owasp_risks.add("API8:2023 Security Misconfiguration")
            elif category == "Missing Security Headers":
                owasp_risks.add("API8:2023 Security Misconfiguration")
        
        return sorted(list(owasp_risks))
    
    def _generate_dynamic_conclusion(self, security_score: int, issue_count: int) -> str:
        """
        Generate dynamic conclusion based on security score
        """
        if security_score > 80:
            return f"The API demonstrates strong security practices with only minor issues identified. Security Score: {security_score}/100."
        elif security_score > 50:
            return f"The API contains several security weaknesses that should be addressed. Security Score: {security_score}/100."
        elif security_score > 20:
            return f"The API contains significant security vulnerabilities requiring immediate remediation. Security Score: {security_score}/100."
        else:
            return f"The API is critically vulnerable and exposes multiple high-risk security issues. Security Score: {security_score}/100."
    
    def _generate_conclusion(self, risk_level: str, issue_count: int, security_score: int) -> str:
        """
        Generate conclusion based on analysis (educational)
        """
        if risk_level == "High":
            return f"The API has {issue_count} security issues requiring immediate attention. Multiple critical vulnerabilities were identified that could lead to data exposure or unauthorized access. Security Score: {security_score}/100."
        elif risk_level == "Medium":
            return f"The API has {issue_count} security issues that should be addressed. While no critical vulnerabilities were found, several areas need improvement to meet security best practices. Security Score: {security_score}/100."
        else:
            return f"The API demonstrates good security practices with minimal issues identified. Continue monitoring and following security best practices to maintain this level of security. Security Score: {security_score}/100."
    
    def load_json_report(self, report_id: str) -> Dict[str, Any]:
        """
        Load a JSON report by ID
        """
        filepath = self.results_dir / f"{report_id}.json"
        if not filepath.exists():
            raise FileNotFoundError(f"Report {report_id} not found")
        
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def list_reports(self) -> List[Dict[str, str]]:
        """
        List all available reports
        """
        reports = []
        
        for filepath in self.results_dir.glob("*.json"):
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
                reports.append({
                    "report_id": data.get("report_id"),
                    "date": data.get("date"),
                    "target_url": data.get("target_url"),
                    "risk_level": data.get("risk_level")
                })
        
        return sorted(reports, key=lambda x: x["date"], reverse=True)
