"""
Sensitive Data Checker
Educational module to detect sensitive data in API responses
This is a passive analysis tool that checks for sensitive keywords in JSON keys
"""

from typing import List, Dict, Any
import re


class SensitiveDataChecker:
    """Checks for sensitive data in API responses (educational)"""
    
    def __init__(self):
        # Sensitive JSON keys to check
        self.sensitive_keys = [
            "password",
            "passwd",
            "pwd",
            "secret",
            "token",
            "apikey",
            "api_key",
            "private_key",
            "jwt",
            "auth_token",
            "access_token",
            "refresh_token",
            "api_secret",
            "client_secret",
            "session_token",
            "bearer_token",
            "authorization",
            "credit_card",
            "cc_number",
            "cvv",
            "ssn",
            "social_security",
            "pin"
        ]
    
    def check_json_response(self, response_json: dict) -> List[Dict[str, Any]]:
        """
        Check JSON response for sensitive data in keys and values
        This analyzes JSON keys instead of string matching to reduce false positives
        Returns detailed information about each finding
        """
        findings = []
        
        if response_json is None:
            return findings
        
        # Recursively analyze JSON structure
        self._analyze_json_structure(response_json, "", findings)
        
        return findings
    
    def _analyze_json_structure(self, data: Any, path: str, findings: List[Dict[str, Any]]):
        """
        Recursively analyze JSON structure for sensitive data
        """
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Check if the key itself is sensitive
                if self._is_sensitive_key(key):
                    findings.append({
                        "key": key,
                        "path": current_path,
                        "value": self._sanitize_value(value),
                        "reason": f"Sensitive key name: {key}",
                        "severity": self._get_key_severity(key)
                    })
                
                # Special handling for PIN: only sensitive if value looks like a PIN code
                elif key.lower() == "pin":
                    if self._is_pin_code(value):
                        findings.append({
                            "key": key,
                            "path": current_path,
                            "value": str(value),
                            "reason": "PIN code detected (4-6 digits)",
                            "severity": "Medium"
                        })
                
                # Recursively analyze nested structures
                self._analyze_json_structure(value, current_path, findings)
        
        elif isinstance(data, list):
            for index, item in enumerate(data):
                current_path = f"{path}[{index}]" if path else f"[{index}]"
                self._analyze_json_structure(item, current_path, findings)
    
    def _is_sensitive_key(self, key: str) -> bool:
        """
        Check if a JSON key is in the sensitive keys list
        """
        key_lower = key.lower()
        return any(sensitive_key in key_lower for sensitive_key in self.sensitive_keys)
    
    def _get_key_severity(self, key: str) -> str:
        """
        Determine severity based on the sensitive key
        """
        key_lower = key.lower()
        high_risk_keys = ["password", "secret", "token", "private_key", "api_key", "jwt"]
        medium_risk_keys = ["credit_card", "cvv", "ssn", "social_security", "pin"]
        
        if any(risk_key in key_lower for risk_key in high_risk_keys):
            return "High"
        elif any(risk_key in key_lower for risk_key in medium_risk_keys):
            return "Medium"
        else:
            return "Low"
    
    def _is_pin_code(self, value: Any) -> bool:
        """
        Check if a value looks like a PIN code (4-6 digits)
        """
        if isinstance(value, (int, str)):
            value_str = str(value).strip()
            # Check if it's a 4-6 digit number
            if value_str.isdigit() and 4 <= len(value_str) <= 6:
                return True
        return False
    
    def _sanitize_value(self, value: Any) -> str:
        """
        Sanitize value for display (truncate if too long)
        """
        value_str = str(value)
        if len(value_str) > 50:
            return value_str[:50] + "..."
        return value_str
    
    def check_response(self, response_text: str) -> List[str]:
        """
        Check response text for sensitive keywords (legacy method)
        This is less accurate than JSON analysis
        """
        found_keywords = []
        
        if response_text is None:
            return found_keywords
        
        # This method is deprecated in favor of JSON analysis
        # Kept for backward compatibility with non-JSON responses
        response_lower = response_text.lower()
        
        for keyword in self.sensitive_keys:
            if keyword.lower() in response_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def get_sensitive_data_risk_level(self, findings: List[Dict[str, Any]]) -> str:
        """
        Determine risk level based on found sensitive data (educational)
        """
        if not findings:
            return "Low"
        
        has_high_risk = any(finding.get("severity") == "High" for finding in findings)
        has_medium_risk = any(finding.get("severity") == "Medium" for finding in findings)
        
        if has_high_risk:
            return "High"
        elif has_medium_risk:
            return "Medium"
        else:
            return "Low"

