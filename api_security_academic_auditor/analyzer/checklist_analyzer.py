"""
OWASP Checklist Analyzer
Educational module to check OWASP API Security and Mobile best practices
This is a passive, educational analysis tool
"""

from typing import List, Dict, Any
from models.schemas import ChecklistItem


class ChecklistAnalyzer:
    """Analyzes API compliance against OWASP best practices (educational)"""
    
    def __init__(self):
        self.owasp_checklist = [
            {
                "item": "Authentication Present",
                "description": "API should implement proper authentication mechanisms"
            },
            {
                "item": "Authorization Server-Side",
                "description": "Authorization checks should be performed on the server side"
            },
            {
                "item": "Sensitive Data Protected",
                "description": "Sensitive data should be protected in transit and at rest"
            },
            {
                "item": "Technical Errors Masked",
                "description": "Error messages should not reveal technical details"
            },
            {
                "item": "Security Headers Present",
                "description": "Security headers should be implemented"
            },
            {
                "item": "Logging Recommended",
                "description": "Security events should be logged for monitoring"
            },
            {
                "item": "Rate Limiting Recommended",
                "description": "API should implement rate limiting to prevent abuse"
            }
        ]
    
    def analyze_checklist(self, endpoint_results: List[Dict], security_headers: Dict[str, bool]) -> List[ChecklistItem]:
        """
        Analyze compliance against OWASP checklist
        This is an educational analysis based on observed data
        """
        checklist = []
        
        # Handle None inputs
        if endpoint_results is None:
            endpoint_results = []
        if security_headers is None:
            security_headers = {}
        
        # Filter out not_tested endpoints for authentication check
        tested_endpoints = [r for r in endpoint_results if r.get("test_status") != "not_tested"]
        
        # Check authentication (educational - based on actual response codes)
        # If any endpoint returns 401 or 403, authentication is present
        # If sensitive endpoints (profile, admin, user) are accessible without auth, authentication is missing
        auth_protected_endpoints = [r for r in tested_endpoints if r.get("status_code") in [401, 403]]
        sensitive_endpoints = [r for r in tested_endpoints if any(keyword in r.get("endpoint", "") for keyword in ["profile", "admin", "user", "account"])]
        sensitive_accessible_without_auth = [r for r in sensitive_endpoints if r.get("status_code") == 200]
        
        # Authentication is present if:
        # 1. Some endpoints return 401/403, OR
        # 2. Sensitive endpoints are NOT accessible without auth
        auth_present = len(auth_protected_endpoints) > 0 or len(sensitive_accessible_without_auth) == 0
        
        # If there are no sensitive endpoints at all, mark as not-applicable
        if len(sensitive_endpoints) == 0:
            auth_status = "not-applicable"
        else:
            auth_status = "compliant" if auth_present else "non-compliant"
        
        checklist.append(ChecklistItem(
            item="Authentication Present",
            status=auth_status,
            description="API should implement proper authentication mechanisms"
        ))
        
        # Check authorization (educational - based on endpoint analysis)
        # Authorization is present if sensitive endpoints are protected
        auth_server_side = len(sensitive_accessible_without_auth) == 0
        if len(sensitive_endpoints) == 0:
            auth_server_status = "not-applicable"
        else:
            auth_server_status = "compliant" if auth_server_side else "non-compliant"
        
        checklist.append(ChecklistItem(
            item="Authorization Server-Side",
            status=auth_server_status,
            description="Authorization checks should be performed on the server side"
        ))
        
        # Check sensitive data protection (educational - based on data analysis)
        sensitive_data_found = any(
            len(result.get("sensitive_data_found", []) or []) > 0 
            for result in endpoint_results
        )
        checklist.append(ChecklistItem(
            item="Sensitive Data Protected",
            status="non-compliant" if sensitive_data_found else "compliant",
            description="Sensitive data should be protected in transit and at rest"
        ))
        
        # Check error message masking (educational - based on error analysis)
        error_messages_found = any(
            len(result.get("error_messages_found", []) or []) > 0 
            for result in endpoint_results
        )
        checklist.append(ChecklistItem(
            item="Technical Errors Masked",
            status="non-compliant" if error_messages_found else "compliant",
            description="Error messages should not reveal technical details"
        ))
        
        # Check security headers (educational - based on header analysis)
        headers_present = all(security_headers.values()) if security_headers else False
        checklist.append(ChecklistItem(
            item="Security Headers Present",
            status="compliant" if headers_present else "non-compliant",
            description="Security headers should be implemented"
        ))
        
        # Logging and rate limiting are recommendations (cannot be verified passively)
        checklist.append(ChecklistItem(
            item="Logging Recommended",
            status="not-applicable",
            description="Security events should be logged for monitoring (cannot be verified passively)"
        ))
        
        checklist.append(ChecklistItem(
            item="Rate Limiting Recommended",
            status="not-applicable",
            description="API should implement rate limiting to prevent abuse (cannot be verified passively)"
        ))
        
        return checklist
    
    def get_compliance_score(self, checklist: List[ChecklistItem]) -> Dict[str, int]:
        """
        Calculate compliance score (educational metric)
        """
        compliant = sum(1 for item in checklist if item.status == "compliant")
        non_compliant = sum(1 for item in checklist if item.status == "non-compliant")
        not_applicable = sum(1 for item in checklist if item.status == "not-applicable")
        
        total_checkable = compliant + non_compliant
        compliance_percentage = (compliant / total_checkable * 100) if total_checkable > 0 else 0
        
        return {
            "compliant": compliant,
            "non_compliant": non_compliant,
            "not_applicable": not_applicable,
            "compliance_percentage": round(compliance_percentage, 2)
        }
