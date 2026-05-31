"""
Header Checker
Educational module to verify security headers
This is a passive analysis tool that checks for security headers
"""

from typing import Dict, List, Any


class HeaderChecker:
    """Checks for security headers in API responses (educational)"""
    
    def __init__(self):
        self.required_security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy"
        ]
        
        self.recommended_security_headers = [
            "Strict-Transport-Security",
            "X-XSS-Protection",
            "Referrer-Policy",
            "Permissions-Policy"
        ]
    
    def check_headers(self, headers: Dict[str, str]) -> Dict[str, bool]:
        """
        Check if required security headers are present
        This is a passive, educational check
        """
        header_status = {}
        
        if headers is None:
            headers = {}
        
        for header in self.required_security_headers:
            header_status[header] = False
            for key in headers.keys():
                if key.lower() == header.lower():
                    header_status[header] = True
                    break
        
        return header_status
    
    def check_recommended_headers(self, headers: Dict[str, str]) -> Dict[str, bool]:
        """
        Check if recommended security headers are present
        This is a passive, educational check
        """
        header_status = {}
        
        if headers is None:
            headers = {}
        
        for header in self.recommended_security_headers:
            header_status[header] = False
            for key in headers.keys():
                if key.lower() == header.lower():
                    header_status[header] = True
                    break
        
        return header_status
    
    def get_header_compliance_score(self, header_status: Dict[str, bool]) -> Dict[str, Any]:
        """
        Calculate header compliance score (educational metric)
        """
        present = sum(1 for status in header_status.values() if status)
        total = len(header_status)
        compliance_percentage = (present / total * 100) if total > 0 else 0
        
        return {
            "present": present,
            "total": total,
            "compliance_percentage": round(compliance_percentage, 2)
        }
    
    def get_missing_headers(self, header_status: Dict[str, bool]) -> List[str]:
        """
        Get list of missing security headers
        """
        return [header for header, status in header_status.items() if not status]
