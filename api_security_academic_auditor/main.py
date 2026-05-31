"""
Main Application - API Security Academic Auditor
Educational security analysis tool for mobile APIs
This is a defensive, academic project for learning security best practices
"""

import sys
import os
import traceback
import time
from pathlib import Path
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import requests
from datetime import datetime

from models.schemas import AnalysisRequest, AnalysisResponse, HealthResponse
from analyzer.checklist_analyzer import ChecklistAnalyzer
from analyzer.sensitive_data_checker import SensitiveDataChecker
from analyzer.error_message_checker import ErrorMessageChecker
from analyzer.header_checker import HeaderChecker
from reports.report_generator import ReportGenerator

app = FastAPI(
    title="API Security Academic Auditor",
    description="Educational security analysis tool for mobile APIs - Academic Use Only",
    version="1.0.0"
)

# Mount static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Initialize analyzers
checklist_analyzer = ChecklistAnalyzer()
sensitive_data_checker = SensitiveDataChecker()
error_message_checker = ErrorMessageChecker()
header_checker = HeaderChecker()
report_generator = ReportGenerator()


def build_url(base_url: str, endpoint: str) -> str:
    """
    Build full URL from base URL and endpoint
    Ensures correct handling of slashes
    
    Args:
        base_url: Base URL (e.g., https://demo.owasp-juice.shop)
        endpoint: Endpoint path (e.g., /rest/products)
    
    Returns:
        Full URL (e.g., https://demo.owasp-juice.shop/rest/products)
    """
    return f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"

# Default endpoints to analyze (used only if user doesn't specify)
DEFAULT_ENDPOINTS = [
    "/api/public",
    "/api/profile",
    "/api/admin",
    "/api/debug",
    "/api/headers-check"
]


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Main web interface"""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(),
        version="1.0.0"
    )


@app.post("/analyze")
async def analyze_api(request: AnalysisRequest):
    """
    Launch educational security analysis on API
    This is a passive, educational analysis tool
    """
    start_time = time.time()
    
    try:
        # Validate URL scheme (HTTP/HTTPS only)
        parsed = urlparse(request.target_url)
        if parsed.scheme not in ["http", "https"]:
            raise HTTPException(
                status_code=400,
                detail="Only HTTP/HTTPS URLs are allowed"
            )
        
        # Determine endpoints to analyze
        if not request.endpoints:
            raise HTTPException(
                status_code=400,
                detail="Endpoints must be specified. Please provide a list of endpoints to analyze."
            )
        
        # Ensure endpoints is a list
        if isinstance(request.endpoints, str):
            # If endpoints is a string, split by comma
            endpoints = [e.strip() for e in request.endpoints.split(',') if e.strip()]
        else:
            endpoints = request.endpoints
        
        print(f"DEBUG: Endpoints to analyze: {endpoints}")  # Debug logging
        
        # Analyze each endpoint
        endpoint_results = []
        all_security_headers = {}
        endpoints_404 = []
        
        for endpoint in endpoints:
            try:
                # Build full URL using helper
                full_url = build_url(request.target_url, endpoint)
                print(f"DEBUG FULL URL: {full_url}")  # Debug logging
                
                # Measure response time
                start_time_endpoint = time.time()
                response = requests.get(full_url, timeout=10)
                response_time = round(time.time() - start_time_endpoint, 3)
                
                # Check for 404
                if response.status_code == 404:
                    endpoints_404.append(endpoint)
                    endpoint_result = {
                        "endpoint": endpoint,
                        "status_code": 404,
                        "has_auth": False,
                        "sensitive_data_found": [],
                        "sensitive_data_findings": [],
                        "error_messages_found": ["Endpoint not found (404)"],
                        "error_message_findings": [],
                        "security_headers": {},
                        "test_status": "not_tested",
                        "content_type": response.headers.get("Content-Type", "unknown"),
                        "response_size": len(response.content),
                        "response_preview": response.text[:200] if response.text else "",
                        "response_time": response_time
                    }
                    endpoint_results.append(endpoint_result)
                    continue
                
                # Try to parse JSON response
                content_type = response.headers.get("Content-Type", "unknown")
                try:
                    response_json = response.json()
                except ValueError:
                    # If response is not JSON, use text
                    response_json = {"text": response.text}
                
                # Check sensitive data (now returns detailed findings)
                sensitive_data_findings = sensitive_data_checker.check_json_response(response_json)
                
                # Extract just the key names for backward compatibility
                sensitive_data = [finding["key"] for finding in sensitive_data_findings]
                
                # Check error messages (now returns detailed findings with Content-Type check)
                error_message_findings = error_message_checker.check_json_response(response_json, content_type)
                
                # If not JSON, check HTML/text response for error patterns
                if not error_message_findings and "application/json" not in content_type.lower():
                    error_message_findings = error_message_checker.check_html_response(response.text, content_type)
                
                # Extract just the patterns for backward compatibility
                error_messages = [finding["key"] for finding in error_message_findings]
                
                # Check security headers
                headers_status = header_checker.check_headers(dict(response.headers))
                
                # Determine if endpoint requires auth (educational - based on endpoint name)
                has_auth = endpoint in ["/api/profile", "/api/admin"]
                
                endpoint_result = {
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "has_auth": has_auth,
                    "sensitive_data_found": sensitive_data,
                    "sensitive_data_findings": sensitive_data_findings,
                    "error_messages_found": error_messages,
                    "error_message_findings": error_message_findings,
                    "security_headers": headers_status,
                    "test_status": "tested",
                    "content_type": response.headers.get("Content-Type", "unknown"),
                    "response_size": len(response.content),
                    "response_preview": response.text[:200] if response.text else "",
                    "response_time": response_time
                }
                
                endpoint_results.append(endpoint_result)
                
                # Collect all security headers
                for header, status in headers_status.items():
                    if header not in all_security_headers:
                        all_security_headers[header] = status
                    all_security_headers[header] = all_security_headers[header] and status
                
            except Exception as e:
                # Handle endpoint analysis errors
                endpoint_result = {
                    "endpoint": endpoint,
                    "status_code": 0,
                    "has_auth": False,
                    "sensitive_data_found": [],
                    "sensitive_data_findings": [],
                    "error_messages_found": [str(e)],
                    "security_headers": {},
                    "test_status": "error",
                    "content_type": "unknown",
                    "response_size": 0,
                    "response_preview": "",
                    "response_time": 0
                }
                endpoint_results.append(endpoint_result)
        
        # Analyze checklist
        checklist = checklist_analyzer.analyze_checklist(endpoint_results, all_security_headers)
        
        # Convert checklist to dict for report
        checklist_dicts = [
            {
                "item": item.item,
                "status": item.status,
                "description": item.description
            }
            for item in checklist
        ]
        
        # Generate report
        scan_duration = round(time.time() - start_time, 2)
        report_data = report_generator.create_report_data(
            target_url=request.target_url,
            endpoints_analyzed=endpoints,
            endpoint_results=endpoint_results,
            checklist=checklist_dicts,
            security_headers=all_security_headers,
            endpoints_404=endpoints_404,
            scan_duration=scan_duration
        )
        
        print(f"DEBUG: Report endpoints_analyzed: {report_data.get('endpoints_analyzed')}")  # Debug logging
        
        # Save reports
        json_path = report_generator.generate_json_report(report_data)
        html_path = report_generator.generate_html_report(report_data)
        pdf_path = report_generator.generate_pdf_report(report_data)
        
        return AnalysisResponse(
            message="Analysis completed successfully",
            report_id=report_data["report_id"],
            status="completed"
        )
        
    except Exception as e:
        # Print full traceback for debugging
        traceback.print_exc()
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Analysis failed",
                "message": str(e),
                "type": type(e).__name__
            }
        )


@app.get("/reports")
async def list_reports():
    """List all generated reports"""
    try:
        reports = report_generator.list_reports()
        return {"reports": reports}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list reports: {str(e)}")


@app.get("/reports/{report_id}")
async def get_report_json(report_id: str):
    """Get a report in JSON format"""
    try:
        report = report_generator.load_json_report(report_id)
        return report
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load report: {str(e)}")


@app.get("/reports/{report_id}/html")
async def get_report_html(report_id: str):
    """Get a report in HTML format"""
    try:
        # Check if report exists
        report_generator.load_json_report(report_id)
        
        # Return HTML file
        html_path = report_generator.reports_dir / f"{report_id}.html"
        if not html_path.exists():
            raise HTTPException(status_code=404, detail="HTML report not found")
        
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load HTML report: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
