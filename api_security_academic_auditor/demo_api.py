"""
Demo API for Educational Security Analysis
This is a local demonstration API with intentional security issues for educational purposes.
This API should ONLY be used on localhost for academic learning.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Demo API for Educational Security Analysis")


class UserProfile(BaseModel):
    user_id: int
    username: str
    email: str
    role: str


# Simulated database
users_db = {
    1: {"id": 1, "username": "admin", "email": "admin@example.com", "role": "isAdmin"},
    2: {"id": 2, "username": "user1", "email": "user1@example.com", "role": "user"}
}


@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "Demo API for Educational Security Analysis"}


@app.get("/api/public")
async def public_endpoint():
    """
    Public endpoint - no authentication required
    This is a normal public endpoint
    """
    return {
        "message": "This is a public endpoint",
        "data": "Public information accessible to everyone"
    }


@app.get("/api/profile")
async def profile_endpoint(user_id: int = 1):
    """
    Profile endpoint - returns user information
    EDUCATIONAL NOTE: This endpoint exposes sensitive data (role, email)
    and lacks proper authentication in this demo
    """
    if user_id not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    
    user = users_db[user_id]
    return {
        "user_id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "api_token": "demo_token_12345",  # EDUCATIONAL: Exposed token
        "secret_key": "demo_secret_key_abc"  # EDUCATIONAL: Exposed secret
    }


@app.get("/api/admin")
async def admin_endpoint():
    """
    Admin endpoint - should require authentication
    EDUCATIONAL NOTE: This endpoint lacks authentication and authorization
    """
    return {
        "message": "Admin dashboard",
        "admin_data": {
            "total_users": 100,
            "system_status": "active",
            "database_password": "admin_password_123"  # EDUCATIONAL: Exposed password
        }
    }


@app.get("/api/debug")
async def debug_endpoint():
    """
    Debug endpoint - returns technical information
    EDUCATIONAL NOTE: This endpoint exposes technical details and error information
    """
    try:
        # Simulate an error for educational purposes
        result = 1 / 0
    except Exception as e:
        # EDUCATIONAL: Exposing full traceback and error details
        import traceback
        error_details = {
            "error_type": type(e).__name__,
            "error_message": str(e),
            "traceback": traceback.format_exc(),
            "debug_info": "This is debug information that should not be exposed",
            "internal_server_error": "Database connection failed at line 42",
            "file_path": "/app/api/debug.py"
        }
        return JSONResponse(
            status_code=500,
            content=error_details
        )


@app.get("/api/headers-check")
async def headers_check():
    """
    Endpoint to check response headers
    EDUCATIONAL NOTE: This endpoint intentionally lacks security headers
    """
    return {
        "message": "This endpoint checks security headers",
        "note": "Security headers should be implemented in production"
    }


@app.get("/api/login")
async def login_endpoint(username: str, password: str):
    """
    Login endpoint - EDUCATIONAL: Insecure implementation
    NOTE: This is a demo with intentional security issues for learning
    """
    # EDUCATIONAL: Password transmitted in query parameters (insecure)
    # EDUCATIONAL: No proper authentication mechanism
    # EDUCATIONAL: Returns sensitive token in response
    
    if username == "admin" and password == "admin123":
        return {
            "status": "success",
            "message": "Login successful",
            "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.demo",
            "user_id": 1,
            "role": "isAdmin",
            "session_id": "session_12345"
        }
    else:
        return {
            "status": "error",
            "message": "Invalid credentials",
            "debug": "User not found in database at users_table"  # EDUCATIONAL: Debug info
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=9000)
