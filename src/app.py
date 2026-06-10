"""
FastAPI Backend for AntiV-AI
Provides REST API endpoints for the antivirus system
"""

import os
import sys
import json          # used by the MFA endpoints (backup codes) — was missing, causing 500s
import tempfile
import shutil
import sqlite3
import logging
import time
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path

import yaml          # used by the ML retraining scheduler to read config.yaml — was missing

# `status` provides HTTP status constants used across the auth endpoints; it was
# previously not imported, so any code path touching status.HTTP_* raised NameError.
from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer
from pydantic import BaseModel
import uvicorn

# Add src directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

# Repository root, used to build absolute paths (e.g. for the ML evaluation report).
# Previously referenced as PROJECT_ROOT without being defined, causing a NameError.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Directories that the path-based /scan and /scan/multiple endpoints may read from.
# This stops an authenticated user from turning the scanner into an arbitrary-file
# oracle over the host filesystem (e.g. /etc/passwd, ~/.ssh/id_rsa). Override with
# the SCAN_ALLOWED_DIRS env var (os.pathsep-separated absolute paths).
_DEFAULT_SCAN_DIRS = [
    str(PROJECT_ROOT / "uploads"),
    str(PROJECT_ROOT / "quarantine"),
    str(PROJECT_ROOT / "test_files"),
    str(Path(tempfile.gettempdir())),
]
SCAN_ALLOWED_DIRS = [
    os.path.realpath(p) for p in (
        os.environ["SCAN_ALLOWED_DIRS"].split(os.pathsep)
        if os.environ.get("SCAN_ALLOWED_DIRS") else _DEFAULT_SCAN_DIRS
    )
]


def _ensure_path_allowed(file_path: str) -> str:
    """Resolve `file_path` and require it to live inside an allowlisted directory.

    os.path.realpath canonicalises the path (collapsing ``..`` and following
    symlinks), defeating traversal tricks like ``uploads/../../etc/passwd``.
    Returns the safe real path, or raises HTTP 400 if it escapes the allowlist.
    """
    real = os.path.realpath(file_path)
    for base in SCAN_ALLOWED_DIRS:
        # Exact match or a true subpath (the os.sep guard prevents '/data-evil'
        # from matching an allowed '/data' prefix).
        if real == base or real.startswith(base + os.sep):
            return real
    raise HTTPException(status_code=400, detail="file_path is outside the allowed scan directories")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

from antiv_engine import AntiVEngine
from auth import auth_manager, TokenData
from upload_security import upload_manager
from network_security import rate_limiter, SecurityMiddleware, configure_cors
from ddos_protector import ddos_protector
from monitoring.siem_integration import siem_integration
from blockchain_audit import blockchain_audit
from integrations.slack_notifier import slack_notifier
from database import ScanDatabase
from process_monitor import ProcessMonitor
from quarantine import QuarantineManager

# ML Training imports
import subprocess
import asyncio
from pathlib import Path
from ml_model_manager import ml_model_manager
from ml_evaluation import ml_evaluator

# Scheduler imports
try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    SCHEDULER_AVAILABLE = True
except ImportError:
    SCHEDULER_AVAILABLE = False

# Initialize FastAPI app.
# Interactive docs (/docs, /openapi.json) expose the entire endpoint surface and
# request/response schemas, which is useful in development but is reconnaissance
# fuel in production. They are enabled only outside production; set
# ANTIV_ENV=production (or ENVIRONMENT=production) to turn them off.
_DOCS_ENABLED = os.getenv("ANTIV_ENV", os.getenv("ENVIRONMENT", "development")).strip().lower() not in ("production", "prod")
app = FastAPI(
    title="AntiV-AI API",
    description="Secure AI-Powered Antivirus System REST API",
    version="1.0.0",
    docs_url="/docs" if _DOCS_ENABLED else None,        # disabled in production
    redoc_url=None,                                       # redoc always off
    openapi_url="/openapi.json" if _DOCS_ENABLED else None,
)

# Global variables for ML training
ml_training_jobs = {}  # Track training job status
scheduler = None

# Initialize database instance
database = ScanDatabase()

# ML Training job status tracking
class TrainingJobStatus:
    def __init__(self, job_id: str):
        self.job_id = job_id
        self.status = "running"
        self.start_time = datetime.now()
        self.end_time = None
        self.metrics = {}
        self.error = None
        self.log_file = None

# Add security middleware
app.add_middleware(SecurityMiddleware)

# Configure secure CORS
configure_cors(app)

# Mount static files from React build
frontend_build_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "build")
if os.path.exists(frontend_build_path):
    app.mount("/static", StaticFiles(directory=os.path.join(frontend_build_path, "static")), name="static")

# SIEM Integration Middleware
@app.middleware("http")
async def siem_logging_middleware(request: Request, call_next):
    """SIEM integration middleware for security event logging"""
    start_time = time.time()
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    # Extract user info if authenticated
    user_id = None
    username = None
    try:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            token_data = auth_manager.verify_token(token)
            if token_data:
                user_id = str(token_data.user_id)
                username = token_data.username
    except:
        pass  # Not authenticated or invalid token

    # Process request
    response = await call_next(request)

    # Calculate response time
    response_time = time.time() - start_time

    # Determine event severity based on status code and endpoint
    if response.status_code >= 500:
        severity = "HIGH"
    elif response.status_code >= 400:
        severity = "MEDIUM"
    elif request.url.path.startswith("/auth/") or request.url.path.startswith("/security/"):
        severity = "MEDIUM"
    else:
        severity = "LOW"

    # Determine outcome
    if response.status_code < 400:
        outcome = "SUCCESS"
    elif response.status_code == 429:
        outcome = "BLOCKED"
    else:
        outcome = "FAILURE"

    # Calculate risk score
    risk_score = 0.0
    threat_indicators = []

    if response.status_code == 429:
        risk_score = 0.6
        threat_indicators.append("rate_limit_exceeded")
    elif response.status_code >= 500:
        risk_score = 0.4
        threat_indicators.append("server_error")
    elif response.status_code == 401:
        risk_score = 0.3
        threat_indicators.append("authentication_failure")

    # Create security event
    security_event = siem_integration.create_security_event(
        event_type="api_request",
        severity=severity,
        action=f"{request.method} {request.url.path}",
        resource=request.url.path,
        outcome=outcome,
        details={
            "method": request.method,
            "status_code": response.status_code,
            "response_time": response_time,
            "content_length": response.headers.get("content-length", "0"),
            "referer": request.headers.get("referer", ""),
            "query_params": str(request.query_params) if request.query_params else ""
        },
        source_ip=client_ip,
        user_id=user_id,
        username=username,
        risk_score=risk_score,
        threat_indicators=threat_indicators
    )

    # Add to SIEM queue
    siem_integration.add_security_event(security_event)

    return response

# Advanced DDoS Protection Middleware
@app.middleware("http")
async def ddos_protection_middleware(request: Request, call_next):
    """Advanced DDoS protection with adaptive rate limiting"""
    # Check DDoS protection
    allowed, rate_info = await ddos_protector.check_rate_limit(request)

    if not allowed:
        error_detail = rate_info.get('error', 'Request blocked')
        retry_after = rate_info.get('retry_after')

        headers = {}
        if retry_after:
            headers["Retry-After"] = str(retry_after)

        # Log security event
        client_ip = ddos_protector._get_client_ip(request)
        logging.getLogger("security").warning(
            f"DDoS protection blocked request from {client_ip}: {error_detail}"
        )

        return JSONResponse(
            status_code=429,
            content={
                "detail": error_detail,
                "retry_after": retry_after,
                "blocked_by": "DDoS Protection"
            },
            headers=headers
        )

    # Process request
    response = await call_next(request)

    # Add DDoS protection headers
    if rate_info:
        if 'limit' in rate_info:
            response.headers["X-RateLimit-Limit"] = str(rate_info['limit'])
        if 'remaining' in rate_info:
            response.headers["X-RateLimit-Remaining"] = str(rate_info['remaining'])
        if 'reset_time' in rate_info:
            response.headers["X-RateLimit-Reset"] = str(rate_info['reset_time'])
        if 'reputation_score' in rate_info:
            response.headers["X-IP-Reputation"] = f"{rate_info['reputation_score']:.2f}"

    return response

# Enhanced rate limiting middleware with geolocation
@app.middleware("http")
async def enhanced_rate_limit_middleware(request: Request, call_next):
    """Enhanced rate limiting middleware with geolocation and reputation"""
    try:
        # Use advanced rate limiting if available
        if hasattr(rate_limiter, 'check_rate_limit_advanced'):
            allowed, rate_info = rate_limiter.check_rate_limit_advanced(request)

            if not allowed:
                # Create detailed error response
                error_detail = rate_info.get('error', 'Rate limit exceeded')
                reason = rate_info.get('reason', 'unknown')

                headers = {
                    "Retry-After": "60",
                    "X-RateLimit-Limit": str(rate_info.get('limit', 0)),
                    "X-RateLimit-Remaining": "0"
                }

                # Add geolocation headers for debugging
                if rate_info.get('country'):
                    headers["X-Country-Code"] = rate_info['country']
                if rate_info.get('region'):
                    headers["X-Region"] = rate_info['region']
                if rate_info.get('limit_reason'):
                    headers["X-Limit-Reason"] = rate_info['limit_reason']

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": f"{error_detail} (reason: {reason})",
                        "country": rate_info.get('country'),
                        "limit": rate_info.get('limit'),
                        "retry_after": 60
                    },
                    headers=headers
                )

            # Process request
            response = await call_next(request)

            # Add rate limit info to response headers
            if rate_info.get('limit'):
                response.headers["X-RateLimit-Limit"] = str(rate_info['limit'])
            if rate_info.get('remaining') is not None:
                response.headers["X-RateLimit-Remaining"] = str(rate_info['remaining'])
            if rate_info.get('country'):
                response.headers["X-Country-Code"] = rate_info['country']
            if rate_info.get('region'):
                response.headers["X-Region"] = rate_info['region']
            if rate_info.get('limit_reason'):
                response.headers["X-Limit-Reason"] = rate_info['limit_reason']

            return response
        else:
            # Fallback to basic rate limiting
            if not rate_limiter.check_rate_limit(request):
                rate_info = rate_limiter.get_rate_limit_info(request)
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded", "retry_after": rate_info['window']},
                    headers={
                        "X-RateLimit-Limit": str(rate_info['limit']),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(rate_info['reset_time']),
                        "Retry-After": str(rate_info['window'])
                    }
                )

            response = await call_next(request)

            # Add rate limit headers to successful responses
            rate_info = rate_limiter.get_rate_limit_info(request)
            response.headers["X-RateLimit-Limit"] = str(rate_info['limit'])
            response.headers["X-RateLimit-Remaining"] = str(rate_info['remaining'])
            response.headers["X-RateLimit-Reset"] = str(rate_info['reset_time'])

            return response

    except Exception as e:
        # Log error but don't block request
        logging.error(f"Rate limiting error: {str(e)}")
        response = await call_next(request)
        return response

# Initialize the antivirus engine
antiv_engine = AntiVEngine()

# Pydantic models for API responses
class ScanResult(BaseModel):
    success: bool
    file_path: str
    file_name: str
    risk_score: float
    threat_level: str
    flagged: bool
    scan_timestamp: str
    analysis_details: Dict
    error: Optional[str] = None

class ScanHistory(BaseModel):
    id: int
    file_path: str
    file_name: str
    file_size: int
    risk_score: float
    threat_level: str
    scan_timestamp: str
    flagged: bool

class SystemStats(BaseModel):
    total_scans: int
    total_flagged: int
    flagged_percentage: float
    average_risk_score: float
    threat_level_distribution: Dict[str, int]
    recent_flagged_files: List[str]

class MonitoringEvent(BaseModel):
    timestamp: str
    event_type: str
    data: Dict

class QuarantineEntry(BaseModel):
    id: str
    original_path: str
    file_hash: str
    file_size: int
    risk_score: float
    threat_level: str
    quarantine_timestamp: str
    reason: str
    restored: bool

class SandboxExecution(BaseModel):
    execution_id: str
    file_path: str
    file_hash: str
    status: str
    start_time: str
    end_time: Optional[str]
    execution_time: float
    risk_assessment: Dict

class ScanRequest(BaseModel):
    file_path: str

# Authentication models
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    user: Dict

class RefreshRequest(BaseModel):
    refresh_token: str

class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = 'user'

class MFASetupResponse(BaseModel):
    secret: str
    qr_code_url: str
    backup_codes: List[str]

class MFAVerifyRequest(BaseModel):
    username: str
    password: str
    totp_code: str

# API Endpoints

@app.get("/")
async def root():
    """Root endpoint - serve React app or API information"""
    frontend_index = os.path.join(os.path.dirname(__file__), "..", "frontend", "build", "index.html")
    if os.path.exists(frontend_index):
        return FileResponse(frontend_index)

    # Fallback to API information
    return {
        "message": "AntiV-AI API Server",
        "version": "1.0.0",
        "status": "running",
        "security": "JWT Authentication Required",
        "endpoints": {
            "auth": "POST /auth/*",
            "scan_file": "POST /scan",
            "upload_scan": "POST /upload-scan",
            "history": "GET /history",
            "flagged": "GET /flagged",
            "stats": "GET /stats",
            "monitoring": "GET /monitoring/*",
            "quarantine": "GET /quarantine/*",
            "sandbox": "GET /sandbox/*"
        }
    }

# Authentication Endpoints

@app.post("/auth/login", response_model=LoginResponse)
async def login(request: Request, login_data: LoginRequest):
    """Authenticate user and return JWT tokens"""
    try:
        # Get client info for audit logging
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent", "")

        # Authenticate user
        user = auth_manager.authenticate_user(
            login_data.username,
            login_data.password,
            ip_address,
            user_agent
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )

        # Create tokens
        access_token = auth_manager.create_access_token(user)
        refresh_token = auth_manager.create_refresh_token(user)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=1800,  # 30 minutes
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Authentication failed")

@app.post("/auth/refresh")
async def refresh_token(refresh_data: RefreshRequest):
    """Refresh access token using refresh token"""
    try:
        # Enforce that this is genuinely a REFRESH token (not an access token being
        # replayed here), via the type claim now checked inside verify_token.
        token_data = auth_manager.verify_token(refresh_data.refresh_token, expected_type='refresh')
        if not token_data or token_data.exp < datetime.utcnow().timestamp():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired refresh token"
            )

        # Get user data
        with sqlite3.connect(auth_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, username, email, role, is_active
                FROM users WHERE id = ? AND is_active = 1
            ''', (token_data.user_id,))

            row = cursor.fetchone()
            if not row:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not found or inactive"
                )

        from auth import User
        user = User(
            id=row[0],
            username=row[1],
            email=row[2],
            role=row[3],
            is_active=bool(row[4]),
            created_at=""
        )

        # Create new access token
        new_access_token = auth_manager.create_access_token(user)

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": 1800
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Token refresh failed")

@app.post("/auth/logout")
async def logout(current_user: TokenData = Depends(auth_manager.get_current_user)):
    """Logout user and revoke token"""
    try:
        auth_manager.revoke_token(current_user.jti)
        return {"message": "Successfully logged out"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Logout failed")

@app.post("/auth/create-user")
async def create_user(
    user_data: CreateUserRequest,
    current_user: TokenData = Depends(auth_manager.require_role('admin'))
):
    """Create new user (admin only)"""
    try:
        user = auth_manager.create_user(
            user_data.username,
            user_data.email,
            user_data.password,
            user_data.role
        )

        return {
            "message": "User created successfully",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role
            }
        }

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="User creation failed")

@app.post("/auth/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Setup MFA for admin user (admin only)"""
    try:
        import pyotp
        import qrcode
        import io
        import base64
        import secrets

        # Generate TOTP secret
        secret = pyotp.random_base32()

        # Create TOTP URI
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.username,
            issuer_name="AntiV-AI Security System"
        )

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = io.BytesIO()
        img.save(img_buffer, format='PNG')
        img_buffer.seek(0)

        qr_code_b64 = base64.b64encode(img_buffer.getvalue()).decode()
        qr_code_url = f"data:image/png;base64,{qr_code_b64}"

        # Generate backup codes
        backup_codes = [secrets.token_hex(4).upper() for _ in range(10)]

        # Store MFA secret in user record (in production, encrypt this)
        with sqlite3.connect(auth_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET mfa_secret = ?, mfa_backup_codes = ?, mfa_enabled = 1
                WHERE id = ?
            ''', (secret, json.dumps(backup_codes), current_user.user_id))
            conn.commit()

        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'mfa_setup',
            None, None, True, 'MFA setup completed'
        )

        return MFASetupResponse(
            secret=secret,
            qr_code_url=qr_code_url,
            backup_codes=backup_codes
        )

    except Exception as e:
        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'mfa_setup',
            None, None, False, f'MFA setup failed: {str(e)}'
        )
        raise HTTPException(status_code=500, detail="MFA setup failed")

@app.post("/auth/mfa/verify")
async def verify_mfa_login(request: Request, mfa_data: MFAVerifyRequest):
    """Verify MFA and complete login"""
    try:
        import pyotp

        # Get client info
        ip_address = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent", "")

        # First verify username/password
        user = auth_manager.authenticate_user(
            mfa_data.username, mfa_data.password, ip_address, user_agent
        )

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )

        # Check if user has MFA enabled
        with sqlite3.connect(auth_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT mfa_secret, mfa_backup_codes, mfa_enabled
                FROM users WHERE id = ?
            ''', (user.id,))

            row = cursor.fetchone()
            if not row or not row[2]:  # MFA not enabled
                # For admin users, require MFA
                if user.role == 'admin':
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="MFA required for admin accounts"
                    )

                # Regular users can login without MFA (for now)
                access_token = auth_manager.create_access_token(user)
                refresh_token = auth_manager.create_refresh_token(user)

                return LoginResponse(
                    access_token=access_token,
                    refresh_token=refresh_token,
                    token_type="bearer",
                    expires_in=1800,
                    user={
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "role": user.role
                    }
                )

            mfa_secret, backup_codes_json, mfa_enabled = row

        # Verify TOTP code
        totp = pyotp.TOTP(mfa_secret)

        # Check TOTP code
        if totp.verify(mfa_data.totp_code, valid_window=1):
            # TOTP verified
            auth_manager._log_auth_event(
                user.id, user.username, 'mfa_success', ip_address, user_agent,
                True, 'MFA verification successful'
            )
        else:
            # Check backup codes
            backup_codes = json.loads(backup_codes_json) if backup_codes_json else []
            if mfa_data.totp_code.upper() in backup_codes:
                # Remove used backup code
                backup_codes.remove(mfa_data.totp_code.upper())

                with sqlite3.connect(auth_manager.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE users SET mfa_backup_codes = ? WHERE id = ?
                    ''', (json.dumps(backup_codes), user.id))
                    conn.commit()

                auth_manager._log_auth_event(
                    user.id, user.username, 'mfa_backup_used', ip_address, user_agent,
                    True, 'Backup code used for MFA'
                )
            else:
                # MFA verification failed
                auth_manager._log_auth_event(
                    user.id, user.username, 'mfa_failed', ip_address, user_agent,
                    False, 'Invalid MFA code'
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid MFA code"
                )

        # Create tokens after successful MFA
        access_token = auth_manager.create_access_token(user)
        refresh_token = auth_manager.create_refresh_token(user)

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=1800,
            user={
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "mfa_enabled": True
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="MFA verification failed")

@app.post("/auth/mfa/disable")
async def disable_mfa(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Disable MFA for current user (admin only)"""
    try:
        with sqlite3.connect(auth_manager.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET mfa_secret = NULL, mfa_backup_codes = NULL, mfa_enabled = 0
                WHERE id = ?
            ''', (current_user.user_id,))
            conn.commit()

        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'mfa_disabled',
            None, None, True, 'MFA disabled'
        )

        return {"message": "MFA disabled successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to disable MFA")

# DDoS Protection Management Endpoints

@app.get("/security/ddos/stats")
async def get_ddos_stats(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get DDoS protection statistics (admin only)"""
    try:
        stats = ddos_protector.get_statistics()
        return {
            "ddos_protection": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get DDoS statistics")

@app.post("/security/ddos/block-ip")
async def block_ip(
    ip_address: str,
    permanent: bool = False,
    current_user: TokenData = Depends(auth_manager.require_role('admin'))
):
    """Block an IP address (admin only)"""
    try:
        ddos_protector.block_ip(ip_address, permanent)

        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'ip_blocked',
            None, None, True, f'IP {ip_address} blocked (permanent: {permanent})'
        )

        return {
            "message": f"IP {ip_address} {'permanently' if permanent else 'temporarily'} blocked",
            "ip_address": ip_address,
            "permanent": permanent
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to block IP")

@app.post("/security/ddos/unblock-ip")
async def unblock_ip(
    ip_address: str,
    current_user: TokenData = Depends(auth_manager.require_role('admin'))
):
    """Unblock an IP address (admin only)"""
    try:
        ddos_protector.unblock_ip(ip_address)

        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'ip_unblocked',
            None, None, True, f'IP {ip_address} unblocked'
        )

        return {
            "message": f"IP {ip_address} unblocked",
            "ip_address": ip_address
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to unblock IP")

# SIEM Integration Management Endpoints

@app.get("/security/siem/metrics")
async def get_siem_metrics(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get SIEM integration metrics (admin only)"""
    try:
        metrics = siem_integration.get_siem_metrics()
        return {
            "siem_integration": metrics,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get SIEM metrics")

@app.get("/security/siem/unsent-events")
async def get_unsent_events(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get events that haven't been sent to SIEM (admin only)"""
    try:
        unsent_events = siem_integration.get_unsent_events()
        return {
            "unsent_events": unsent_events,
            "count": len(unsent_events),
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get unsent events")

@app.post("/security/siem/retry-failed")
async def retry_failed_siem_events(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Retry sending failed SIEM events (admin only)"""
    try:
        await siem_integration.retry_failed_events()

        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'siem_retry',
            None, None, True, 'SIEM failed events retry initiated'
        )

        return {
            "message": "SIEM failed events retry initiated",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to retry SIEM events")

# Blockchain Audit Management Endpoints

@app.get("/security/blockchain/stats")
async def get_blockchain_stats(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get blockchain audit statistics (admin only)"""
    try:
        stats = blockchain_audit.get_blockchain_statistics()
        return {
            "blockchain_audit": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get blockchain statistics")

@app.post("/security/blockchain/verify")
async def verify_blockchain_integrity(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Verify blockchain integrity (admin only)"""
    try:
        verification_result = blockchain_audit.verify_integrity()

        # Log verification attempt
        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'blockchain_verification',
            None, None, verification_result.is_valid,
            f'Blockchain verification: {"PASSED" if verification_result.is_valid else "FAILED"}'
        )

        return {
            "verification_result": {
                "is_valid": verification_result.is_valid,
                "total_blocks": verification_result.total_blocks,
                "total_entries": verification_result.total_entries,
                "broken_chains": verification_result.broken_chains,
                "tampered_blocks": verification_result.tampered_blocks,
                "verification_timestamp": verification_result.verification_timestamp,
                "details": verification_result.details
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to verify blockchain integrity")

@app.post("/security/blockchain/finalize-block")
async def finalize_current_block(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Force finalization of current blockchain block (admin only)"""
    try:
        blockchain_audit.force_finalize_block()

        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'blockchain_finalize',
            None, None, True, 'Blockchain block manually finalized'
        )

        return {
            "message": "Current blockchain block finalized",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to finalize blockchain block")

# Slack Notification Management Endpoints

@app.get("/security/notifications/stats")
async def get_notification_stats(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get notification system statistics (admin only)"""
    try:
        stats = slack_notifier.get_notification_stats()
        return {
            "notification_system": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get notification statistics")

@app.post("/security/notifications/test")
async def send_test_notification(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Send test notification to verify configuration (admin only)"""
    try:
        success = await slack_notifier.send_test_alert()

        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'test_notification',
            None, None, success, f'Test notification {"sent" if success else "failed"}'
        )

        return {
            "message": "Test notification sent" if success else "Test notification failed",
            "success": success,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to send test notification")

# Rate Limiting Management Endpoints

@app.get("/security/rate-limiting/stats")
async def get_rate_limiting_stats(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get rate limiting statistics including geolocation data (admin only)"""
    try:
        stats = rate_limiter.get_rate_limit_stats()
        return {
            "rate_limiting": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get rate limiting statistics")

@app.post("/security/rate-limiting/unblock-ip")
async def unblock_ip_address(
    ip_address: str,
    current_user: TokenData = Depends(auth_manager.require_role('admin'))
):
    """Unblock a specific IP address (admin only)"""
    try:
        if ip_address in rate_limiter.blocked_ips:
            del rate_limiter.blocked_ips[ip_address]

            auth_manager._log_auth_event(
                current_user.user_id, current_user.username, 'ip_unblock',
                None, None, True, f'IP address unblocked: {ip_address}'
            )

            return {
                "message": f"IP address {ip_address} has been unblocked",
                "timestamp": datetime.now().isoformat()
            }
        else:
            return {
                "message": f"IP address {ip_address} was not blocked",
                "timestamp": datetime.now().isoformat()
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to unblock IP address")

# Performance Optimization Endpoints

@app.get("/performance/stats")
async def get_performance_stats(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get performance statistics for caching and parallel processing (admin only)"""
    try:
        stats = antiv_engine.get_performance_stats()
        return {
            "performance": stats,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get performance statistics")

@app.post("/scan/multiple")
async def scan_multiple_files(
    file_paths: List[str],
    current_user: TokenData = Depends(auth_manager.require_role('analyst'))
):
    """Scan multiple files in parallel (analyst+ role required)"""
    try:
        if not file_paths:
            raise HTTPException(status_code=400, detail="No file paths provided")

        if len(file_paths) > 50:  # Limit batch size
            raise HTTPException(status_code=400, detail="Too many files (max 50)")

        # Validate file paths: each must resolve INSIDE the allowlist AND exist.
        # Paths outside the allowlist are skipped silently (not echoed back) so we
        # do not leak host filesystem structure to the caller.
        valid_paths = []
        for file_path in file_paths:
            try:
                safe_path = _ensure_path_allowed(file_path)
            except HTTPException:
                logging.warning("Rejected batch-scan path outside the allowlist")
                continue
            if os.path.exists(safe_path):
                valid_paths.append(safe_path)
            else:
                logging.warning("Batch-scan path not found in allowed directories")

        if not valid_paths:
            raise HTTPException(status_code=400, detail="No valid file paths found")

        # Perform parallel scanning
        results = await antiv_engine.scan_multiple_files(valid_paths)

        # Log the batch scan
        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'batch_scan',
            None, None, True, f'Batch scan of {len(valid_paths)} files completed'
        )

        return {
            "results": results,
            "total_files": len(file_paths),
            "valid_files": len(valid_paths),
            "successful_scans": len(results),
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch scan failed: {str(e)}")

@app.post("/performance/cache/clear")
async def clear_performance_cache(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Clear performance cache (admin only)"""
    try:
        from performance import redis_cache

        success = redis_cache.clear()

        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'cache_clear',
            None, None, success, 'Performance cache cleared'
        )

        return {
            "message": "Performance cache cleared" if success else "Cache clear failed",
            "success": success,
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to clear cache")

# ML Training and Retraining Endpoints

@app.post("/retrain")
async def trigger_retraining(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Trigger ML model retraining (admin only)"""
    try:
        logger.info(f"ML retraining triggered by admin user: {current_user.username}")

        # Start training job asynchronously
        job_status = await run_training_script()

        # Log the retraining event
        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'ml_retrain',
            None, None, job_status.status == "completed",
            f'ML retraining job {job_status.job_id} {job_status.status}'
        )

        return {
            "message": "ML retraining completed" if job_status.status == "completed" else "ML retraining failed",
            "job_id": job_status.job_id,
            "status": job_status.status,
            "start_time": job_status.start_time.isoformat(),
            "end_time": job_status.end_time.isoformat() if job_status.end_time else None,
            "metrics": job_status.metrics,
            "error": job_status.error,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        logger.error(f"ML retraining failed: {e}")
        raise HTTPException(status_code=500, detail=f"ML retraining failed: {str(e)}")

@app.get("/retrain/status/{job_id}")
async def get_training_status(
    job_id: str,
    current_user: TokenData = Depends(auth_manager.require_role('analyst'))
):
    """Get ML training job status (analyst+ role required)"""
    try:
        if job_id not in ml_training_jobs:
            raise HTTPException(status_code=404, detail="Training job not found")

        job_status = ml_training_jobs[job_id]

        return {
            "job_id": job_status.job_id,
            "status": job_status.status,
            "start_time": job_status.start_time.isoformat(),
            "end_time": job_status.end_time.isoformat() if job_status.end_time else None,
            "metrics": job_status.metrics,
            "error": job_status.error,
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get training status")

@app.get("/retrain/jobs")
async def list_training_jobs(current_user: TokenData = Depends(auth_manager.require_role('analyst'))):
    """List all ML training jobs (analyst+ role required)"""
    try:
        jobs = []
        for job_id, job_status in ml_training_jobs.items():
            jobs.append({
                "job_id": job_status.job_id,
                "status": job_status.status,
                "start_time": job_status.start_time.isoformat(),
                "end_time": job_status.end_time.isoformat() if job_status.end_time else None,
                "has_metrics": bool(job_status.metrics),
                "has_error": bool(job_status.error)
            })

        return {
            "jobs": jobs,
            "total_jobs": len(jobs),
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to list training jobs")

# ML Model Management Endpoints

@app.get("/models")
async def list_model_versions(
    model_type: str = None,
    current_user: TokenData = Depends(auth_manager.require_role('analyst'))
):
    """List all model versions, optionally filtered by type (analyst+ role required)"""
    try:
        versions = ml_model_manager.list_versions(model_type)

        version_data = []
        for version in versions:
            version_data.append({
                "version": version.version,
                "timestamp": version.timestamp,
                "model_type": version.model_type,
                "metrics": version.metrics,
                "training_samples": version.training_samples,
                "feature_count": version.feature_count,
                "algorithm": version.algorithm,
                "is_active": version.is_active,
                "created_by": version.created_by,
                "notes": version.notes
            })

        return {
            "versions": version_data,
            "total_versions": len(version_data),
            "filter": model_type,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to list model versions")

@app.get("/models/{model_type}/latest")
async def get_latest_model_info(
    model_type: str,
    current_user: TokenData = Depends(auth_manager.require_role('analyst'))
):
    """Get information about the latest model version (analyst+ role required)"""
    try:
        latest_model = ml_model_manager.get_latest_model(model_type)

        if not latest_model:
            raise HTTPException(status_code=404, detail=f"No models found for type: {model_type}")

        return {
            "version": latest_model.version,
            "timestamp": latest_model.timestamp,
            "model_type": latest_model.model_type,
            "file_path": latest_model.file_path,
            "metrics": latest_model.metrics,
            "training_samples": latest_model.training_samples,
            "feature_count": latest_model.feature_count,
            "algorithm": latest_model.algorithm,
            "parameters": latest_model.parameters,
            "is_active": latest_model.is_active,
            "created_by": latest_model.created_by,
            "notes": latest_model.notes
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get latest model info")

@app.get("/models/{model_type}/active")
async def get_active_model_info(
    model_type: str,
    current_user: TokenData = Depends(auth_manager.require_role('analyst'))
):
    """Get information about the currently active model (analyst+ role required)"""
    try:
        active_model = ml_model_manager.get_active_model(model_type)

        if not active_model:
            raise HTTPException(status_code=404, detail=f"No active model found for type: {model_type}")

        return {
            "version": active_model.version,
            "timestamp": active_model.timestamp,
            "model_type": active_model.model_type,
            "file_path": active_model.file_path,
            "metrics": active_model.metrics,
            "training_samples": active_model.training_samples,
            "feature_count": active_model.feature_count,
            "algorithm": active_model.algorithm,
            "parameters": active_model.parameters,
            "is_active": active_model.is_active,
            "created_by": active_model.created_by,
            "notes": active_model.notes
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get active model info")

@app.post("/models/{model_type}/rollback/{version}")
async def rollback_model(
    model_type: str,
    version: str,
    current_user: TokenData = Depends(auth_manager.require_role('admin'))
):
    """Rollback to a specific model version (admin only)"""
    try:
        success = ml_model_manager.rollback_to(model_type, version)

        if not success:
            raise HTTPException(status_code=400, detail="Failed to rollback model")

        # Log the rollback event
        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'model_rollback',
            None, None, True, f'Rolled back {model_type} to version {version}'
        )

        return {
            "message": f"Successfully rolled back {model_type} to version {version}",
            "model_type": model_type,
            "version": version,
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to rollback model")

@app.get("/models/stats")
async def get_model_stats(current_user: TokenData = Depends(auth_manager.require_role('analyst'))):
    """Get model management statistics (analyst+ role required)"""
    try:
        stats = ml_model_manager.get_model_stats()

        return {
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get model statistics")

# ML Evaluation Endpoints

@app.post("/models/evaluate")
async def evaluate_models(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Run comprehensive model evaluation (admin only)"""
    try:
        logger.info(f"Model evaluation triggered by admin user: {current_user.username}")

        # Load test data (simplified - in production, use dedicated test set)
        from scripts.train_models import MLTrainingPipeline

        pipeline = MLTrainingPipeline()
        X, y = pipeline.load_training_data()

        if len(X) == 0:
            raise HTTPException(status_code=400, detail="No evaluation data available")

        # Run evaluation
        evaluation_results = ml_evaluator.evaluate_all_models(X, y)

        # Generate report
        report_file = ml_evaluator.generate_markdown_report()

        # Log the evaluation event
        auth_manager._log_auth_event(
            current_user.user_id, current_user.username, 'model_evaluation',
            None, None, True, f'Model evaluation completed'
        )

        return {
            "message": "Model evaluation completed successfully",
            "evaluation_results": evaluation_results,
            "report_file": report_file,
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Model evaluation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Model evaluation failed: {str(e)}")

@app.get("/models/evaluation/report")
async def get_evaluation_report(current_user: TokenData = Depends(auth_manager.require_role('analyst'))):
    """Get the latest evaluation report (analyst+ role required)"""
    try:
        report_file = PROJECT_ROOT / "reports" / "ml_evaluation.md"

        if not report_file.exists():
            raise HTTPException(status_code=404, detail="No evaluation report found")

        with open(report_file, 'r') as f:
            report_content = f.read()

        return {
            "report_content": report_content,
            "report_file": str(report_file),
            "last_modified": datetime.fromtimestamp(report_file.stat().st_mtime).isoformat(),
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to get evaluation report")

@app.get("/models/{model_type}/evaluate")
async def evaluate_single_model(
    model_type: str,
    current_user: TokenData = Depends(auth_manager.require_role('analyst'))
):
    """Evaluate a specific model type (analyst+ role required)"""
    try:
        # Load test data
        from scripts.train_models import MLTrainingPipeline

        pipeline = MLTrainingPipeline()
        X, y = pipeline.load_training_data()

        if len(X) == 0:
            raise HTTPException(status_code=400, detail="No evaluation data available")

        # Evaluate specific model
        evaluation_results = ml_evaluator.evaluate_model(model_type, X, y)

        if 'error' in evaluation_results:
            raise HTTPException(status_code=400, detail=evaluation_results['error'])

        return {
            "model_type": model_type,
            "evaluation_results": evaluation_results,
            "timestamp": datetime.now().isoformat()
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to evaluate {model_type} model")

@app.post("/scan", response_model=ScanResult)
async def scan_file(
    scan_request: ScanRequest,
    current_user: TokenData = Depends(auth_manager.get_current_user)
):
    """
    Scan a file by file path
    """
    try:
        # Constrain to the allowlisted scan directories. This prevents an
        # authenticated user from probing arbitrary host files (existence + hash +
        # entropy oracle). Raises HTTP 400 on traversal / escape.
        file_path = _ensure_path_allowed(scan_request.file_path)

        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="File not found")
        
        # Perform scan
        result = await antiv_engine.scan_file(file_path)
        
        if not result.get('success', False):
            raise HTTPException(status_code=500, detail=result.get('error', 'Scan failed'))
        
        return ScanResult(
            success=True,
            file_path=result['file_path'],
            file_name=os.path.basename(result['file_path']),
            risk_score=result['risk_score'],
            threat_level=result['threat_level'],
            flagged=result['flagged'],
            scan_timestamp=result['scan_timestamp'],
            analysis_details=result['analysis_details']
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/upload-scan", response_model=ScanResult)
async def upload_and_scan(
    file: UploadFile = File(...),
    current_user: TokenData = Depends(auth_manager.get_current_user)
):
    """
    Upload a file and scan it with comprehensive security validation
    """
    try:
        # Validate and securely store upload
        validation_result = await upload_manager.validate_and_store_upload(file, current_user.user_id)

        if not validation_result.valid:
            raise HTTPException(
                status_code=400,
                detail={
                    "message": "File upload validation failed",
                    "errors": validation_result.errors,
                    "warnings": validation_result.warnings
                }
            )

        # Log security warnings
        if validation_result.warnings:
            antiv_engine.logger.warning(f"Upload security warnings for {file.filename}: {validation_result.warnings}")

        try:
            # Perform scan on validated file
            result = await antiv_engine.scan_file(validation_result.file_path)

            if not result.get('success', False):
                raise HTTPException(status_code=500, detail=result.get('error', 'Scan failed'))

            # Add upload security information to result
            result['upload_security'] = {
                'security_score': validation_result.security_score,
                'mime_type': validation_result.mime_type,
                'detected_type': validation_result.detected_type,
                'warnings': validation_result.warnings
            }

            return ScanResult(
                success=True,
                file_path=file.filename,  # Use original filename for response
                file_name=file.filename,
                risk_score=result['risk_score'],
                threat_level=result['threat_level'],
                flagged=result['flagged'],
                scan_timestamp=result['scan_timestamp'],
                analysis_details=result['analysis_details']
            )

        finally:
            # Always clean up temporary file
            if validation_result.file_path:
                upload_manager.cleanup_temp_file(validation_result.file_path)

    except HTTPException:
        raise
    except Exception as e:
        antiv_engine.logger.error(f"Upload scan failed: {str(e)}")
        raise HTTPException(status_code=500, detail="Upload processing failed")

@app.get("/history", response_model=List[ScanHistory])
async def get_scan_history(
    limit: int = 50,
    current_user: TokenData = Depends(auth_manager.get_current_user)
):
    """
    Get recent scan history
    """
    try:
        history = antiv_engine.get_recent_scans(limit)
        
        return [
            ScanHistory(
                id=scan.get('id', 0),
                file_path=scan['file_path'],
                file_name=os.path.basename(scan['file_path']),
                file_size=scan.get('file_size', 0),
                risk_score=scan.get('risk_score', 0.0),
                threat_level=scan.get('threat_level', 'UNKNOWN'),
                scan_timestamp=scan.get('scan_timestamp', ''),
                flagged=scan.get('flagged', False)
            )
            for scan in history
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/flagged", response_model=List[ScanHistory])
async def get_flagged_files(current_user: TokenData = Depends(auth_manager.get_current_user)):
    """
    Get all flagged files
    """
    try:
        flagged = antiv_engine.get_flagged_files()
        
        return [
            ScanHistory(
                id=scan.get('id', 0),
                file_path=scan['file_path'],
                file_name=os.path.basename(scan['file_path']),
                file_size=scan.get('file_size', 0),
                risk_score=scan.get('risk_score', 0.0),
                threat_level=scan.get('threat_level', 'UNKNOWN'),
                scan_timestamp=scan.get('scan_timestamp', ''),
                flagged=True
            )
            for scan in flagged
        ]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/stats", response_model=SystemStats)
async def get_system_stats(current_user: TokenData = Depends(auth_manager.get_current_user)):
    """
    Get system statistics
    """
    try:
        stats = antiv_engine.get_scan_statistics()

        if 'error' in stats:
            raise HTTPException(status_code=500, detail=stats['error'])

        return SystemStats(
            total_scans=stats.get('total_scans', 0),
            total_flagged=stats.get('total_flagged', 0),
            flagged_percentage=stats.get('flagged_percentage', 0.0),
            average_risk_score=stats.get('average_risk_score', 0.0),
            threat_level_distribution=stats.get('threat_level_distribution', {}),
            recent_flagged_files=stats.get('recent_flagged_files', [])
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Real-Time Monitoring Endpoints

@app.post("/monitoring/start")
async def start_monitoring(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Start real-time monitoring"""
    try:
        success = antiv_engine.start_real_time_monitoring()
        return {"success": success, "message": "Monitoring started" if success else "Failed to start monitoring"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/monitoring/stop")
async def stop_monitoring(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Stop real-time monitoring"""
    try:
        success = antiv_engine.stop_real_time_monitoring()
        return {"success": success, "message": "Monitoring stopped" if success else "Failed to stop monitoring"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitoring/events")
async def get_monitoring_events(event_type: str = "all", limit: int = 100,
                                current_user: TokenData = Depends(auth_manager.get_current_user)):
    """Get recent monitoring events (authentication required)"""
    try:
        events = antiv_engine.get_monitoring_events(event_type, limit)
        return {"events": events, "count": len(events)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitoring/process-tree")
async def get_process_tree(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get the current host process tree (admin only — exposes host internals)"""
    try:
        tree = antiv_engine.get_process_tree()
        return {"process_tree": tree}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/monitoring/status")
async def get_monitoring_status(current_user: TokenData = Depends(auth_manager.get_current_user)):
    """Get monitoring system status (authentication required)"""
    try:
        stats = antiv_engine.get_comprehensive_statistics()
        return stats.get('monitoring', {})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Quarantine Management Endpoints

@app.get("/quarantine/list")
async def list_quarantined_files(current_user: TokenData = Depends(auth_manager.get_current_user)):
    """List all quarantined files (authentication required)"""
    try:
        files = antiv_engine.get_quarantined_files()
        return {"quarantined_files": files, "count": len(files)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/quarantine/restore/{quarantine_id}")
async def restore_quarantined_file(quarantine_id: str, restore_path: Optional[str] = None,
                                   current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Restore a quarantined file (admin only). The restore path is additionally
    constrained to a safe directory inside the quarantine layer to prevent
    arbitrary file writes."""
    try:
        success = antiv_engine.restore_quarantined_file(quarantine_id, restore_path)
        return {"success": success, "message": "File restored" if success else "Failed to restore file"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/quarantine/delete/{quarantine_id}")
async def delete_quarantined_file(quarantine_id: str,
                                  current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Permanently delete a quarantined file (admin only)"""
    try:
        success = antiv_engine.delete_quarantined_file(quarantine_id)
        return {"success": success, "message": "File deleted" if success else "Failed to delete file"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/quarantine/stats")
async def get_quarantine_stats(current_user: TokenData = Depends(auth_manager.get_current_user)):
    """Get quarantine statistics (authentication required)"""
    try:
        stats = antiv_engine.get_comprehensive_statistics()
        return stats.get('quarantine', {})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Sandbox Execution Endpoints

@app.post("/sandbox/execute")
async def execute_in_sandbox(file_path: str, file_hash: str,
                             current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Execute a file in the isolated sandbox (admin only)."""
    try:
        # Only sandbox files inside the allowlisted directories — never an arbitrary
        # host path supplied by the caller.
        file_path = _ensure_path_allowed(file_path)
        execution = antiv_engine.execute_in_sandbox(file_path, file_hash)
        if execution is None:
            # Fail closed and loud when the sandbox backend (Docker) is unavailable,
            # instead of returning HTTP 200 with {"execution": null}.
            raise HTTPException(status_code=503, detail="Sandbox unavailable (Docker not running)")
        return {"execution": execution}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sandbox/executions")
async def list_sandbox_executions(limit: int = 50,
                                  current_user: TokenData = Depends(auth_manager.get_current_user)):
    """List recent sandbox executions (authentication required)"""
    try:
        executions = antiv_engine.get_sandbox_executions(limit)
        return {"executions": executions, "count": len(executions)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sandbox/execution/{execution_id}")
async def get_sandbox_execution_status(execution_id: str,
                                       current_user: TokenData = Depends(auth_manager.get_current_user)):
    """Get status of a sandbox execution (authentication required)"""
    try:
        execution = antiv_engine.get_sandbox_execution_status(execution_id)
        if not execution:
            raise HTTPException(status_code=404, detail="Execution not found")
        return {"execution": execution}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sandbox/stats")
async def get_sandbox_stats(current_user: TokenData = Depends(auth_manager.get_current_user)):
    """Get sandbox statistics (authentication required)"""
    try:
        stats = antiv_engine.get_comprehensive_statistics()
        return stats.get('sandbox', {})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Comprehensive System Status

@app.get("/system/status")
async def get_system_status(current_user: TokenData = Depends(auth_manager.require_role('admin'))):
    """Get comprehensive system status (admin only — aggregates host internals)"""
    try:
        stats = antiv_engine.get_comprehensive_statistics()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "engine_status": "operational"
    }

# Serve static files (for production deployment)
if os.path.exists("frontend/build"):
    app.mount("/static", StaticFiles(directory="frontend/build/static"), name="static")
    
    @app.get("/{full_path:path}")
    async def serve_react_app(full_path: str):
        """Serve React app for any unmatched routes"""
        if full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API endpoint not found")
        
        index_file = "frontend/build/index.html"
        if os.path.exists(index_file):
            return FileResponse(index_file)
        else:
            raise HTTPException(status_code=404, detail="Frontend not built")

# ML Training Functions
async def run_training_script() -> TrainingJobStatus:
    """Run the ML training script asynchronously"""
    import uuid

    job_id = str(uuid.uuid4())
    job_status = TrainingJobStatus(job_id)
    ml_training_jobs[job_id] = job_status

    try:
        # Path to training script
        script_path = Path(__file__).parent.parent / "scripts" / "train_models.py"

        # Run training script
        process = await asyncio.create_subprocess_exec(
            "python3", str(script_path), "--verbose",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(Path(__file__).parent.parent)
        )

        stdout, stderr = await process.communicate()

        job_status.end_time = datetime.now()

        if process.returncode == 0:
            job_status.status = "completed"

            # Parse metrics from output (simplified)
            output_text = stdout.decode()
            if "TRAINING SUMMARY" in output_text:
                # Extract metrics from output
                job_status.metrics = {"training_completed": True}

            logger.info(f"ML training job {job_id} completed successfully")

        else:
            job_status.status = "failed"
            job_status.error = stderr.decode()
            logger.error(f"ML training job {job_id} failed: {job_status.error}")

    except Exception as e:
        job_status.status = "failed"
        job_status.error = str(e)
        job_status.end_time = datetime.now()
        logger.error(f"ML training job {job_id} failed with exception: {e}")

    return job_status

def init_ml_scheduler():
    """Initialize the ML retraining scheduler"""
    global scheduler

    if not SCHEDULER_AVAILABLE:
        logger.warning("APScheduler not available, ML scheduling disabled")
        return

    try:
        # Load ML configuration
        with open("config.yaml", 'r') as f:
            config = yaml.safe_load(f)

        ml_config = config.get('machine_learning', {})
        schedule_config = ml_config.get('training', {}).get('schedule', {})

        if not schedule_config.get('enabled', False):
            logger.info("ML retraining scheduler disabled in configuration")
            return

        scheduler = AsyncIOScheduler()

        # Parse schedule configuration
        frequency = schedule_config.get('frequency', 'daily')
        time_str = schedule_config.get('time', '02:00')

        if frequency == 'daily':
            hour, minute = map(int, time_str.split(':'))
            scheduler.add_job(
                scheduled_retraining,
                CronTrigger(hour=hour, minute=minute),
                id='ml_retraining',
                name='ML Model Retraining',
                replace_existing=True
            )
            logger.info(f"ML retraining scheduled daily at {time_str} UTC")

        scheduler.start()
        logger.info("ML retraining scheduler initialized successfully")

    except Exception as e:
        logger.error(f"Failed to initialize ML scheduler: {e}")

async def scheduled_retraining():
    """Scheduled ML retraining job"""
    logger.info("Starting scheduled ML retraining...")

    try:
        job_status = await run_training_script()

        if job_status.status == "completed":
            logger.info("Scheduled ML retraining completed successfully")

            # Send notification if configured
            try:
                alert = slack_notifier.create_system_alert(
                    title="ML Model Retraining Completed",
                    description="Scheduled ML model retraining completed successfully",
                    details={"job_id": job_status.job_id, "metrics": job_status.metrics}
                )
                await slack_notifier.send_alert(alert)
            except Exception as e:
                logger.warning(f"Failed to send retraining notification: {e}")
        else:
            logger.error(f"Scheduled ML retraining failed: {job_status.error}")

    except Exception as e:
        logger.error(f"Scheduled ML retraining failed with exception: {e}")

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    logger.info("Starting AntiV-AI API server...")

    try:
        # Initialize ML scheduler
        init_ml_scheduler()
    except Exception as e:
        logger.warning(f"ML scheduler initialization warning: {e}")

    logger.info("AntiV-AI API server started successfully")

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global scheduler

    if scheduler:
        scheduler.shutdown()
        logger.info("ML scheduler shut down")

    logger.info("AntiV-AI API server shut down")

if __name__ == "__main__":
    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        log_level="info"
    )
