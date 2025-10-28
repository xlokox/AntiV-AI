# AntiV-AI API Endpoints - Detailed Reference

## Authentication Endpoints

### POST /auth/login
**Description:** Authenticate user and return JWT tokens  
**Role Required:** None  
**Request:**
```json
{
  "username": "admin",
  "password": "password123"
}
```
**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "username": "admin",
    "role": "admin"
  }
}
```

### POST /auth/logout
**Description:** Logout user and revoke token  
**Role Required:** Any authenticated user  
**Headers:** `Authorization: Bearer {token}`  
**Response (200):** `{"message": "Logged out successfully"}`

### POST /auth/refresh
**Description:** Refresh access token using refresh token  
**Request:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

### POST /auth/create-user
**Description:** Create new user (admin only)  
**Role Required:** admin  
**Request:**
```json
{
  "username": "analyst1",
  "password": "secure_password",
  "role": "analyst"
}
```
**Response (201):**
```json
{
  "id": 2,
  "username": "analyst1",
  "role": "analyst"
}
```

### POST /auth/mfa/setup
**Description:** Setup MFA for admin user  
**Role Required:** admin  
**Response (200):**
```json
{
  "qr_code": "data:image/png;base64,...",
  "secret": "JBSWY3DPEBLW64TMMQ======",
  "backup_codes": ["12345678", "87654321", ...]
}
```

### POST /auth/mfa/verify
**Description:** Verify MFA and complete login  
**Request:**
```json
{
  "username": "admin",
  "password": "password123",
  "totp_code": "123456"
}
```
**Response (200):** Same as /auth/login

### POST /auth/mfa/disable
**Description:** Disable MFA for current user  
**Role Required:** admin  
**Response (200):** `{"message": "MFA disabled"}`

---

## Scanning Endpoints

### POST /scan
**Description:** Scan a file by file path  
**Role Required:** analyst+  
**Request:**
```json
{
  "file_path": "/path/to/file.exe"
}
```
**Response (200):**
```json
{
  "scan_id": "scan_12345",
  "file_path": "/path/to/file.exe",
  "status": "clean",
  "risk_score": 0.15,
  "threat_level": "low",
  "detections": [],
  "scan_time": 2.34,
  "timestamp": "2024-10-26T10:30:00Z"
}
```

### POST /upload-scan
**Description:** Upload a file and scan it  
**Role Required:** analyst+  
**Content-Type:** multipart/form-data  
**Request:** File upload  
**Response (200):** Same as /scan

### POST /scan/multiple
**Description:** Scan multiple files in parallel  
**Role Required:** analyst+  
**Request:**
```json
{
  "file_paths": [
    "/path/to/file1.exe",
    "/path/to/file2.dll",
    "/path/to/file3.bin"
  ]
}
```
**Response (200):**
```json
{
  "scan_id": "batch_12345",
  "total_files": 3,
  "results": [
    {"file": "file1.exe", "status": "clean", "risk_score": 0.1},
    {"file": "file2.dll", "status": "suspicious", "risk_score": 0.65},
    {"file": "file3.bin", "status": "clean", "risk_score": 0.2}
  ],
  "scan_time": 5.67
}
```

---

## Quarantine Endpoints

### GET /quarantine/list
**Description:** List all quarantined files  
**Role Required:** analyst+  
**Response (200):**
```json
{
  "total": 5,
  "quarantined_files": [
    {
      "id": "q_001",
      "filename": "malware.exe",
      "quarantine_date": "2024-10-25T14:30:00Z",
      "risk_score": 0.95,
      "reason": "Detected as trojan"
    }
  ]
}
```

### POST /quarantine/restore/{quarantine_id}
**Description:** Restore a quarantined file  
**Role Required:** admin  
**Response (200):** `{"message": "File restored successfully"}`

### DELETE /quarantine/delete/{quarantine_id}
**Description:** Permanently delete a quarantined file  
**Role Required:** admin  
**Response (200):** `{"message": "File deleted permanently"}`

### GET /quarantine/stats
**Description:** Get quarantine statistics  
**Role Required:** analyst+  
**Response (200):**
```json
{
  "total_quarantined": 42,
  "total_size_mb": 156.8,
  "by_threat_level": {
    "critical": 5,
    "high": 12,
    "medium": 15,
    "low": 10
  }
}
```

---

## System Endpoints

### GET /health
**Description:** Health check endpoint  
**Response (200):**
```json
{
  "status": "healthy",
  "timestamp": "2024-10-26T10:30:00Z",
  "version": "1.0.0"
}
```

### GET /stats
**Description:** Get system statistics  
**Response (200):**
```json
{
  "total_scans": 1250,
  "threats_detected": 87,
  "files_quarantined": 42,
  "uptime_hours": 168,
  "cpu_usage": 12.5,
  "memory_usage": 45.3
}
```

### GET /system/status
**Description:** Get comprehensive system status  
**Response (200):**
```json
{
  "status": "operational",
  "components": {
    "database": "connected",
    "ml_models": "loaded",
    "threat_intel": "updated",
    "blockchain": "synced"
  },
  "last_update": "2024-10-26T10:30:00Z"
}
```

---

## Model Management Endpoints

### GET /models
**Description:** List all model versions  
**Role Required:** analyst+  
**Response (200):**
```json
{
  "models": [
    {
      "type": "behavioral_analysis",
      "version": "1.2.3",
      "active": true,
      "accuracy": 0.94,
      "created": "2024-10-20T10:00:00Z"
    }
  ]
}
```

### POST /models/evaluate
**Description:** Run comprehensive model evaluation  
**Role Required:** admin  
**Response (200):**
```json
{
  "evaluation_id": "eval_12345",
  "status": "completed",
  "results": {
    "accuracy": 0.94,
    "precision": 0.92,
    "recall": 0.96,
    "f1_score": 0.94
  }
}
```

---

## Security Endpoints

### GET /security/blockchain/stats
**Description:** Get blockchain audit statistics  
**Role Required:** admin  
**Response (200):**
```json
{
  "total_blocks": 156,
  "total_entries": 12450,
  "chain_integrity": "verified",
  "last_block_hash": "abc123def456..."
}
```

### GET /security/ddos/stats
**Description:** Get DDoS protection statistics  
**Role Required:** admin  
**Response (200):**
```json
{
  "blocked_ips": 23,
  "attacks_detected": 156,
  "requests_blocked": 45000,
  "last_attack": "2024-10-26T09:15:00Z"
}
```

### GET /security/rate-limiting/stats
**Description:** Get rate limiting statistics  
**Role Required:** admin  
**Response (200):**
```json
{
  "total_requests": 50000,
  "rate_limited": 234,
  "by_country": {
    "US": 25000,
    "UK": 15000,
    "CN": 10000
  }
}
```

---

## Monitoring Endpoints

### GET /monitoring/status
**Description:** Get monitoring system status  
**Response (200):**
```json
{
  "monitoring_active": true,
  "processes_tracked": 156,
  "events_logged": 5432,
  "last_update": "2024-10-26T10:30:00Z"
}
```

### POST /monitoring/start
**Description:** Start real-time monitoring  
**Role Required:** analyst+  
**Response (200):** `{"message": "Monitoring started"}`

### POST /monitoring/stop
**Description:** Stop real-time monitoring  
**Role Required:** analyst+  
**Response (200):** `{"message": "Monitoring stopped"}`

---

## Training Endpoints

### POST /retrain
**Description:** Trigger ML model retraining  
**Role Required:** admin  
**Response (200):**
```json
{
  "job_id": "train_12345",
  "status": "started",
  "estimated_time": "45 minutes"
}
```

### GET /retrain/jobs
**Description:** List all ML training jobs  
**Role Required:** analyst+  
**Response (200):**
```json
{
  "jobs": [
    {
      "job_id": "train_12345",
      "status": "completed",
      "started": "2024-10-26T08:00:00Z",
      "completed": "2024-10-26T08:45:00Z"
    }
  ]
}
```

---

## Sandbox Endpoints

### POST /sandbox/execute
**Description:** Execute file in sandbox environment  
**Role Required:** analyst+  
**Request:**
```json
{
  "file_path": "/path/to/file.exe",
  "timeout": 30
}
```
**Response (200):**
```json
{
  "execution_id": "exec_12345",
  "status": "running",
  "started": "2024-10-26T10:30:00Z"
}
```

### GET /sandbox/executions
**Description:** List recent sandbox executions  
**Response (200):**
```json
{
  "executions": [
    {
      "execution_id": "exec_12345",
      "file": "test.exe",
      "status": "completed",
      "behavior_score": 0.75
    }
  ]
}
```

---

## Interactive Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI JSON:** http://localhost:8000/openapi.json

