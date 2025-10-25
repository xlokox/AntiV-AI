"""
Secure File Upload System for AntiV-AI
Implements comprehensive upload security with validation, rate limiting, and safe storage
"""

import os
import magic
import hashlib
import secrets
import tempfile
import time
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
from fastapi import HTTPException, UploadFile
import logging

# Security configuration
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB
UPLOAD_RATE_LIMIT = 5  # uploads per minute per user
RATE_LIMIT_WINDOW = 60  # seconds

# Allowed file types and their magic bytes
ALLOWED_FILE_TYPES = {
    # Executables
    'application/x-executable': [b'MZ', b'\x7fELF'],
    'application/x-msdos-program': [b'MZ'],
    'application/x-msdownload': [b'MZ'],
    
    # Archives
    'application/zip': [b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08'],
    'application/x-rar-compressed': [b'Rar!\x1a\x07\x00', b'Rar!\x1a\x07\x01\x00'],
    'application/x-7z-compressed': [b'7z\xbc\xaf\x27\x1c'],
    'application/gzip': [b'\x1f\x8b'],
    
    # Documents
    'application/pdf': [b'%PDF'],
    'application/msword': [b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'],
    'application/vnd.openxmlformats-officedocument': [b'PK\x03\x04'],
    
    # Scripts
    'text/x-python': [b'#!/usr/bin/python', b'#!/usr/bin/env python', b'# -*- coding:'],
    'text/x-shellscript': [b'#!/bin/sh', b'#!/bin/bash'],
    'application/x-powershell': [b'#!', b'param('],
    
    # General text
    'text/plain': [],
    'text/html': [b'<!DOCTYPE', b'<html', b'<HTML'],
    'application/json': [b'{', b'['],
    'application/xml': [b'<?xml', b'<xml'],
}

# Dangerous file extensions (blocked)
BLOCKED_EXTENSIONS = {
    '.scr', '.pif', '.com', '.cpl', '.msc', '.hta', '.jar', '.jse', '.vbe', '.vbs',
    '.wsf', '.wsh', '.ps1', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2',
    '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml'
}

@dataclass
class UploadValidationResult:
    """Result of upload validation"""
    valid: bool
    file_path: Optional[str]
    file_hash: str
    file_size: int
    mime_type: str
    detected_type: str
    security_score: float
    warnings: List[str]
    errors: List[str]

class UploadRateLimiter:
    """Rate limiter for file uploads"""
    
    def __init__(self):
        self.upload_history = {}  # user_id -> list of timestamps
    
    def check_rate_limit(self, user_id: int) -> bool:
        """Check if user is within rate limit"""
        current_time = time.time()
        
        # Clean old entries
        if user_id in self.upload_history:
            self.upload_history[user_id] = [
                timestamp for timestamp in self.upload_history[user_id]
                if current_time - timestamp < RATE_LIMIT_WINDOW
            ]
        else:
            self.upload_history[user_id] = []
        
        # Check rate limit
        if len(self.upload_history[user_id]) >= UPLOAD_RATE_LIMIT:
            return False
        
        # Record this upload
        self.upload_history[user_id].append(current_time)
        return True

class SecureUploadManager:
    """Manages secure file uploads with comprehensive validation"""
    
    def __init__(self, upload_dir: str = "uploads"):
        """Initialize secure upload manager"""
        self.logger = logging.getLogger(__name__)
        self.upload_dir = Path(upload_dir)
        self.rate_limiter = UploadRateLimiter()
        
        # Create secure upload directory
        self.upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions
        if os.name != 'nt':  # Unix-like systems
            os.chmod(self.upload_dir, 0o700)
        
        self.logger.info(f"Secure upload manager initialized: {self.upload_dir}")
    
    def validate_file_content(self, file_data: bytes, filename: str) -> Tuple[str, str, float, List[str]]:
        """
        Validate file content using magic bytes and MIME type detection
        
        Returns:
            (mime_type, detected_type, security_score, warnings)
        """
        warnings = []
        security_score = 0.0
        
        try:
            # Detect MIME type using python-magic
            mime_type = magic.from_buffer(file_data, mime=True)
            detected_type = magic.from_buffer(file_data)
            
        except Exception as e:
            self.logger.warning(f"Magic detection failed: {str(e)}")
            mime_type = "application/octet-stream"
            detected_type = "unknown"
            warnings.append("Could not detect file type")
            security_score += 0.2
        
        # Check if MIME type is allowed
        if mime_type not in ALLOWED_FILE_TYPES and not mime_type.startswith('text/'):
            warnings.append(f"Unusual MIME type: {mime_type}")
            security_score += 0.3
        
        # Validate magic bytes for known types
        if mime_type in ALLOWED_FILE_TYPES:
            expected_signatures = ALLOWED_FILE_TYPES[mime_type]
            if expected_signatures:  # Some types don't have specific signatures
                signature_match = any(
                    file_data.startswith(sig) for sig in expected_signatures
                )
                if not signature_match:
                    warnings.append("File signature doesn't match MIME type")
                    security_score += 0.4
        
        # Check file extension vs content
        file_ext = Path(filename).suffix.lower()
        
        # Block dangerous extensions
        if file_ext in BLOCKED_EXTENSIONS:
            warnings.append(f"Blocked file extension: {file_ext}")
            security_score += 0.8
        
        # Check for executable content
        if b'MZ' in file_data[:1024] or b'\x7fELF' in file_data[:1024]:
            warnings.append("Executable content detected")
            security_score += 0.3
        
        # Check for script content
        script_indicators = [b'#!/', b'<script', b'eval(', b'exec(', b'system(']
        if any(indicator in file_data[:2048] for indicator in script_indicators):
            warnings.append("Script content detected")
            security_score += 0.2
        
        # Check for suspicious patterns
        suspicious_patterns = [
            b'cmd.exe', b'powershell', b'rundll32', b'regsvr32',
            b'CreateProcess', b'ShellExecute', b'WinExec'
        ]
        if any(pattern in file_data for pattern in suspicious_patterns):
            warnings.append("Suspicious API calls detected")
            security_score += 0.4
        
        return mime_type, detected_type, min(security_score, 1.0), warnings
    
    def create_secure_temp_path(self, original_filename: str, file_hash: str) -> Path:
        """Create secure, non-predictable temporary file path"""
        # Generate random directory name
        random_dir = secrets.token_urlsafe(16)
        
        # Create subdirectory structure based on hash (for organization)
        hash_prefix = file_hash[:2]
        
        # Secure filename with hash and random component
        secure_filename = f"{file_hash}_{secrets.token_urlsafe(8)}.upload"
        
        # Full path
        secure_path = self.upload_dir / hash_prefix / random_dir / secure_filename
        
        # Create directory structure
        secure_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions on directory
        if os.name != 'nt':
            os.chmod(secure_path.parent, 0o700)
        
        return secure_path
    
    def calculate_file_hash(self, file_data: bytes) -> str:
        """Calculate SHA-256 hash of file data"""
        return hashlib.sha256(file_data).hexdigest()
    
    async def validate_and_store_upload(self, file: UploadFile, user_id: int) -> UploadValidationResult:
        """
        Validate and securely store uploaded file
        
        Args:
            file: FastAPI UploadFile object
            user_id: ID of uploading user
            
        Returns:
            UploadValidationResult with validation details
        """
        errors = []
        warnings = []
        
        try:
            # Check rate limit
            if not self.rate_limiter.check_rate_limit(user_id):
                errors.append(f"Rate limit exceeded: max {UPLOAD_RATE_LIMIT} uploads per minute")
                return UploadValidationResult(
                    valid=False,
                    file_path=None,
                    file_hash="",
                    file_size=0,
                    mime_type="",
                    detected_type="",
                    security_score=1.0,
                    warnings=warnings,
                    errors=errors
                )
            
            # Read file data
            file_data = await file.read()
            file_size = len(file_data)
            
            # Check file size
            if file_size == 0:
                errors.append("Empty file not allowed")
            elif file_size > MAX_UPLOAD_SIZE:
                errors.append(f"File too large: {file_size} bytes (max: {MAX_UPLOAD_SIZE})")
            
            if errors:
                return UploadValidationResult(
                    valid=False,
                    file_path=None,
                    file_hash="",
                    file_size=file_size,
                    mime_type="",
                    detected_type="",
                    security_score=1.0,
                    warnings=warnings,
                    errors=errors
                )
            
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_data)
            
            # Validate file content
            mime_type, detected_type, security_score, content_warnings = self.validate_file_content(
                file_data, file.filename or "unknown"
            )
            warnings.extend(content_warnings)
            
            # Check if file is too risky
            if security_score >= 0.8:
                errors.append("File rejected due to high security risk")
                return UploadValidationResult(
                    valid=False,
                    file_path=None,
                    file_hash=file_hash,
                    file_size=file_size,
                    mime_type=mime_type,
                    detected_type=detected_type,
                    security_score=security_score,
                    warnings=warnings,
                    errors=errors
                )
            
            # Create secure storage path
            secure_path = self.create_secure_temp_path(file.filename or "unknown", file_hash)
            
            # Store file securely
            with open(secure_path, 'wb') as f:
                f.write(file_data)
            
            # Set restrictive permissions
            if os.name != 'nt':
                os.chmod(secure_path, 0o600)
            
            self.logger.info(f"File uploaded securely: {file.filename} -> {secure_path}")
            
            return UploadValidationResult(
                valid=True,
                file_path=str(secure_path),
                file_hash=file_hash,
                file_size=file_size,
                mime_type=mime_type,
                detected_type=detected_type,
                security_score=security_score,
                warnings=warnings,
                errors=errors
            )
            
        except Exception as e:
            self.logger.error(f"Upload validation failed: {str(e)}")
            errors.append("Upload processing failed")
            
            return UploadValidationResult(
                valid=False,
                file_path=None,
                file_hash="",
                file_size=0,
                mime_type="",
                detected_type="",
                security_score=1.0,
                warnings=warnings,
                errors=errors
            )
    
    def cleanup_temp_file(self, file_path: str):
        """Securely clean up temporary file"""
        try:
            if os.path.exists(file_path):
                # Overwrite file with random data before deletion (basic secure delete)
                file_size = os.path.getsize(file_path)
                with open(file_path, 'wb') as f:
                    f.write(secrets.token_bytes(file_size))
                
                # Delete file
                os.remove(file_path)
                
                # Try to remove empty parent directories
                try:
                    parent_dir = Path(file_path).parent
                    if parent_dir != self.upload_dir:
                        parent_dir.rmdir()  # Only removes if empty
                        parent_dir.parent.rmdir()  # Remove hash prefix dir if empty
                except OSError:
                    pass  # Directory not empty, which is fine
                
                self.logger.debug(f"Temporary file cleaned up: {file_path}")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up temp file {file_path}: {str(e)}")
    
    def get_upload_statistics(self) -> Dict:
        """Get upload system statistics"""
        try:
            total_uploads = 0
            total_size = 0
            
            # Count files in upload directory
            for root, dirs, files in os.walk(self.upload_dir):
                for file in files:
                    if file.endswith('.upload'):
                        file_path = os.path.join(root, file)
                        try:
                            total_uploads += 1
                            total_size += os.path.getsize(file_path)
                        except OSError:
                            pass
            
            # Rate limiter statistics
            active_users = len(self.rate_limiter.upload_history)
            
            return {
                'total_temp_files': total_uploads,
                'total_temp_size': total_size,
                'active_uploaders': active_users,
                'max_upload_size': MAX_UPLOAD_SIZE,
                'rate_limit': UPLOAD_RATE_LIMIT,
                'allowed_types': list(ALLOWED_FILE_TYPES.keys()),
                'blocked_extensions': list(BLOCKED_EXTENSIONS)
            }
            
        except Exception as e:
            self.logger.error(f"Error getting upload statistics: {str(e)}")
            return {}

# Global upload manager instance
upload_manager = SecureUploadManager()
