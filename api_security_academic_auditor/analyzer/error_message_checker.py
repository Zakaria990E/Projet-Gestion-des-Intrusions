"""
Error Message Checker
Educational module to detect technical error messages
This is a passive analysis tool that checks for verbose error messages in JSON keys and values
"""

from typing import List, Dict, Any


class ErrorMessageChecker:
    """Checks for technical error messages in API responses (educational)"""
    
    def __init__(self):
        # Whitelist of common HTML and non-error words to avoid false positives
        self.html_whitelist = {
            "text", "html", "body", "div", "span", "script", "link", "meta", "head",
            "title", "style", "class", "id", "href", "src", "alt", "width", "height",
            "button", "input", "form", "label", "select", "option", "textarea",
            "ul", "ol", "li", "table", "tr", "td", "th", "thead", "tbody",
            "nav", "header", "footer", "section", "article", "aside", "main",
            "p", "h1", "h2", "h3", "h4", "h5", "h6", "strong", "em", "a",
            "img", "br", "hr", "code", "pre", "blockquote", "iframe", "canvas",
            "svg", "path", "rect", "circle", "polygon", "line", "polyline",
            "doctype", "html5", "xml", "json", "javascript", "css", "stylesheet",
            "charset", "encoding", "utf-8", "viewport", "content-type", "content",
            "description", "keywords", "author", "robots", "canonical", "og:",
            "twitter:", "schema", "ld+json", "application", "www", "http", "https",
            "com", "org", "net", "io", "co", "app", "dev", "local", "localhost",
            "127.0.0.1", "0.0.0.0", "port", "host", "domain", "subdomain",
            "path", "query", "fragment", "url", "uri", "urn", "hreflang", "lang",
            "dir", "ltr", "rtl", "charset", "encoding", "utf-8", "iso-8859-1",
            "windows-1252", "gbk", "gb2312", "big5", "shift_jis", "euc-kr",
            "koi8-r", "koi8-u", "iso-8859-2", "iso-8859-5", "iso-8859-7",
            "iso-8859-9", "iso-8859-15", "tis-620", "tscii", "viscii"
        }
        
        # Specific error patterns to look for (only for HTML/text responses)
        self.html_error_patterns = [
            "traceback",
            "stack trace",
            "exception",
            "sql syntax",
            "mysql",
            "postgresql",
            "sqlite",
            "internal server error",
            "uncaught exception",
            "debug mode",
            "file path",
            "warning:",
            "fatal error",
            "syntax error",
            "type error",
            "value error",
            "attribute error",
            "key error",
            "index error",
            "import error",
            "runtime error",
            "null pointer",
            "segmentation fault",
            "memory error",
            "permission denied",
            "access denied",
            "unauthorized",
            "forbidden"
        ]
        
        # Technical error patterns to look for in JSON keys and values
        self.json_error_patterns = [
            "traceback",
            "exception",
            "debug",
            "error",
            "stack",
            "file",
            "line",
            "sql",
            "query",
            "database",
            "connection",
            "failed",
            "warning",
            "notice"
        ]
    
    def check_json_response(self, response_json: dict, content_type: str = None) -> List[Dict[str, Any]]:
        """
        Check JSON response for technical error messages
        This analyzes JSON keys and values instead of string matching
        Returns detailed information about each finding
        
        Args:
            response_json: JSON response to analyze
            content_type: Content-Type header to check if response is JSON
        """
        findings = []
        
        if response_json is None:
            return findings
        
        # Check if content-type indicates JSON
        if content_type:
            content_type_lower = content_type.lower()
            # Skip analysis for non-JSON content types
            if any(ct in content_type_lower for ct in ["text/html", "text/plain", "text/css", "application/javascript"]):
                return findings
            # Only analyze if content-type contains application/json
            if "application/json" not in content_type_lower:
                return findings
        
        # Recursively analyze JSON structure
        self._analyze_json_structure(response_json, "", findings)
        
        return findings
    
    def check_html_response(self, response_text: str, content_type: str = None) -> List[Dict[str, Any]]:
        """
        Check HTML/text response for specific error patterns
        Only flags real error patterns, not common HTML words
        
        Args:
            response_text: Response text to analyze
            content_type: Content-Type header
        """
        findings = []
        
        if response_text is None:
            return findings
        
        # Check if content-type indicates HTML/text
        if content_type:
            content_type_lower = content_type.lower()
            # Only analyze if it's HTML or plain text
            if not any(ct in content_type_lower for ct in ["text/html", "text/plain"]):
                return findings
        
        response_lower = response_text.lower()
        
        # Check for specific error patterns
        for pattern in self.html_error_patterns:
            if pattern.lower() in response_lower:
                # Check if the pattern is in the whitelist
                if pattern.lower() not in self.html_whitelist:
                    findings.append({
                        "key": pattern,
                        "path": "response_body",
                        "value": self._sanitize_value(pattern),
                        "reason": f"Technical error pattern detected in HTML response",
                        "severity": self._get_html_error_severity(pattern)
                    })
        
        return findings
    
    def _analyze_json_structure(self, data: Any, path: str, findings: List[Dict[str, Any]]):
        """
        Recursively analyze JSON structure for technical error messages
        """
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}" if path else key
                
                # Skip if key is in whitelist
                if key.lower() in self.html_whitelist:
                    continue
                
                # Check if the key itself indicates an error
                if self._is_error_key(key):
                    findings.append({
                        "key": key,
                        "path": current_path,
                        "value": self._sanitize_value(value),
                        "reason": f"Error-related key name: {key}",
                        "severity": self._get_error_severity(key)
                    })
                
                # Check if the value contains technical error patterns
                elif isinstance(value, str) and self._contains_error_pattern(value):
                    # Skip if value is in whitelist
                    if value.lower() not in self.html_whitelist:
                        findings.append({
                            "key": key,
                            "path": current_path,
                            "value": self._sanitize_value(value),
                            "reason": f"Contains technical error pattern",
                            "severity": self._get_value_severity(value)
                        })
                
                # Recursively analyze nested structures
                self._analyze_json_structure(value, current_path, findings)
        
        elif isinstance(data, list):
            for index, item in enumerate(data):
                current_path = f"{path}[{index}]" if path else f"[{index}]"
                self._analyze_json_structure(item, current_path, findings)
    
    def _is_error_key(self, key: str) -> bool:
        """
        Check if a JSON key indicates an error
        """
        key_lower = key.lower()
        error_indicators = ["error", "exception", "traceback", "debug", "stack", "warning", "fail"]
        return any(indicator in key_lower for indicator in error_indicators)
    
    def _contains_error_pattern(self, value: str) -> bool:
        """
        Check if a value contains technical error patterns
        """
        value_lower = value.lower()
        high_risk_patterns = ["traceback", "stack trace", "file path", "sql", "database error"]
        medium_risk_patterns = ["error", "exception", "debug", "warning", "failed"]
        
        return any(pattern in value_lower for pattern in high_risk_patterns + medium_risk_patterns)
    
    def _get_error_severity(self, key: str) -> str:
        """
        Determine severity based on the error key
        """
        key_lower = key.lower()
        high_risk_keys = ["traceback", "stack", "exception", "debug"]
        medium_risk_keys = ["error", "warning", "fail"]
        
        if any(risk_key in key_lower for risk_key in high_risk_keys):
            return "High"
        elif any(risk_key in key_lower for risk_key in medium_risk_keys):
            return "Medium"
        else:
            return "Low"
    
    def _get_value_severity(self, value: str) -> str:
        """
        Determine severity based on the error value
        """
        value_lower = value.lower()
        high_risk_patterns = ["traceback", "stack trace", "file path", "sql", "database error"]
        medium_risk_patterns = ["error", "exception", "debug", "warning", "failed"]
        
        if any(pattern in value_lower for pattern in high_risk_patterns):
            return "High"
        elif any(pattern in value_lower for pattern in medium_risk_patterns):
            return "Medium"
        else:
            return "Low"
    
    def _get_html_error_severity(self, pattern: str) -> str:
        """
        Determine severity based on HTML error pattern
        """
        pattern_lower = pattern.lower()
        high_risk_patterns = ["traceback", "stack trace", "file path", "sql", "database error", "uncaught exception"]
        medium_risk_patterns = ["error", "exception", "debug", "warning", "fatal error", "internal server error"]
        
        if any(risk_pattern in pattern_lower for risk_pattern in high_risk_patterns):
            return "High"
        elif any(risk_pattern in pattern_lower for risk_pattern in medium_risk_patterns):
            return "Medium"
        else:
            return "Low"
    
    def _sanitize_value(self, value: Any) -> str:
        """
        Sanitize value for display (truncate if too long)
        """
        value_str = str(value)
        if len(value_str) > 100:
            return value_str[:100] + "..."
        return value_str
    
    def check_response(self, response_text: str) -> List[str]:
        """
        Check response text for technical error messages (legacy method)
        This is less accurate than JSON analysis
        """
        found_patterns = []
        
        if response_text is None:
            return found_patterns
        
        # This method is deprecated in favor of JSON analysis
        # Kept for backward compatibility with non-JSON responses
        response_lower = response_text.lower()
        
        for pattern in self.json_error_patterns:
            if pattern.lower() in response_lower:
                found_patterns.append(pattern)
        
        return found_patterns
    
    def get_error_risk_level(self, findings: List[Dict[str, Any]]) -> str:
        """
        Determine risk level based on found error messages (educational)
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
