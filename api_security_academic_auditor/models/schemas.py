"""
Pydantic schemas for the API Security Academic Auditor
Defines data models for requests, responses, and reports
"""

from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional, Dict, Any


class AnalysisRequest(BaseModel):
    """Request model for API analysis"""
    target_url: str = Field(..., description="URL of the local API to analyze")
    endpoints: Optional[List[str]] = Field(default=None, description="List of endpoints to analyze")


class EndpointResult(BaseModel):
    """Result for a single endpoint analysis"""
    endpoint: str
    status_code: int
    has_auth: bool
    sensitive_data_found: List[str]
    error_messages_found: List[str]
    security_headers: Dict[str, bool]


class ChecklistItem(BaseModel):
    """Single checklist item for OWASP compliance"""
    item: str
    status: str  # "compliant", "non-compliant", "not-applicable"
    description: str


class SecurityIssue(BaseModel):
    """Security issue found during analysis"""
    severity: str  # "Low", "Medium", "High"
    category: str
    description: str
    recommendation: str


class SecurityReport(BaseModel):
    """Complete security report model"""
    report_id: str
    date: datetime
    project_name: str
    context: str
    environment: str
    target_url: str
    endpoints_analyzed: List[str]
    checklist: List[ChecklistItem]
    endpoint_results: List[EndpointResult]
    issues: List[SecurityIssue]
    risk_level: str
    conclusion: str
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: datetime
    version: str = "1.0.0"


class AnalysisResponse(BaseModel):
    """Response after launching analysis"""
    message: str
    report_id: str
    status: str
