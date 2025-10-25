# 🔌 AntiV-AI API Endpoints Reference

## 📍 Base URL
```
http://127.0.0.1:8000
```

## 🔐 Authentication Endpoints

### Login
```
POST /auth/login
```
Authenticate user and receive JWT tokens
- **Request**: `{username, password}`
- **Response**: `{access_token, refresh_token, token_type}`

### Refresh Token
```
POST /auth/refresh
```
Refresh access token using refresh token
- **Request**: `{refresh_token}`
- **Response**: `{access_token, token_type}`

### Logout
```
POST /auth/logout
```
Logout user and revoke token
- **Auth**: Required (Bearer token)

### Create User (Admin)
```
POST /auth/create-user
```
Create new user account
- **Auth**: Admin role required
- **Request**: `{username, password, role}`

### Setup MFA
```
POST /auth/mfa/setup
```
Setup multi-factor authentication
- **Auth**: Admin role required
- **Response**: `{secret, qr_code, backup_codes}`

### Verify MFA
```
POST /auth/mfa/verify
```
Verify MFA code during login
- **Request**: `{username, mfa_code}`

### Disable MFA
```
POST /auth/mfa/disable
```
Disable MFA for current user
- **Auth**: Admin role required

---

## 🛡️ Security Endpoints

### DDoS Protection Stats
```
GET /security/ddos/stats
```
Get DDoS protection statistics
- **Auth**: Admin role required

### Block IP
```
POST /security/ddos/block-ip
```
Block an IP address
- **Auth**: Admin role required
- **Params**: `ip_address, permanent`

### Unblock IP
```
POST /security/ddos/unblock-ip
```
Unblock an IP address
- **Auth**: Admin role required

### SIEM Metrics
```
GET /security/siem/metrics
```
Get SIEM integration metrics
- **Auth**: Admin role required

### Blockchain Stats
```
GET /security/blockchain/stats
```
Get blockchain audit statistics
- **Auth**: Admin role required

### Verify Blockchain Integrity
```
POST /security/blockchain/verify
```
Verify blockchain integrity
- **Auth**: Admin role required

### Rate Limiting Stats
```
GET /security/rate-limiting/stats
```
Get rate limiting statistics with geolocation
- **Auth**: Admin role required

### Unblock IP (Rate Limiting)
```
POST /security/rate-limiting/unblock-ip
```
Unblock IP from rate limiting
- **Auth**: Admin role required

---

## 🤖 Machine Learning Endpoints

### Trigger Retraining
```
POST /retrain
```
Trigger ML model retraining
- **Auth**: Admin role required
- **Response**: `{job_id, status, start_time}`

### Get Training Status
```
GET /retrain/status/{job_id}
```
Get status of training job
- **Auth**: Analyst role required

### List Training Jobs
```
GET /retrain/jobs
```
List all ML training jobs
- **Auth**: Analyst role required

### List Model Versions
```
GET /models
```
List all model versions
- **Auth**: Analyst role required
- **Params**: `model_type` (optional)

### Get Latest Model Info
```
GET /models/{model_type}/latest
```
Get latest model information
- **Auth**: Analyst role required

### Get Active Model Info
```
GET /models/{model_type}/active
```
Get currently active model
- **Auth**: Analyst role required

### Rollback Model
```
POST /models/{model_type}/rollback/{version}
```
Rollback to previous model version
- **Auth**: Admin role required

### Model Statistics
```
GET /models/stats
```
Get model management statistics
- **Auth**: Analyst role required

### Evaluate Models
```
POST /models/evaluate
```
Run comprehensive model evaluation
- **Auth**: Admin role required

### Get Evaluation Report
```
GET /models/evaluation/report
```
Get latest evaluation report
- **Auth**: Analyst role required

### Evaluate Single Model
```
GET /models/{model_type}/evaluate
```
Evaluate specific model
- **Auth**: Analyst role required

---

## 🔍 File Scanning Endpoints

### Scan File
```
POST /scan
```
Scan a file by path
- **Auth**: Required
- **Request**: `{file_path}`
- **Response**: `{file_hash, risk_score, threat_level, analysis}`

### Upload & Scan
```
POST /upload-scan
```
Upload and scan file
- **Auth**: Required
- **Request**: Multipart file upload
- **Response**: `{file_hash, risk_score, threat_level, analysis}`

### Scan Multiple Files
```
POST /scan/multiple
```
Scan multiple files
- **Auth**: Analyst role required
- **Request**: `{file_paths: [...]}`

---

## 📊 History & Statistics Endpoints

### Get Scan History
```
GET /history
```
Get scan history
- **Auth**: Required
- **Params**: `limit` (default: 50)

### Get Flagged Files
```
GET /flagged
```
Get all flagged high-risk files
- **Auth**: Required

### Get System Statistics
```
GET /stats
```
Get system statistics
- **Auth**: Required
- **Response**: `{total_scans, flagged_count, avg_risk_score}`

### Get Performance Stats
```
GET /performance/stats
```
Get performance statistics
- **Auth**: Admin role required

### Clear Performance Cache
```
POST /performance/cache/clear
```
Clear performance cache
- **Auth**: Admin role required

---

## 📡 Monitoring Endpoints

### Start Monitoring
```
POST /monitoring/start
```
Start real-time monitoring
- **Auth**: Admin role required

### Stop Monitoring
```
POST /monitoring/stop
```
Stop real-time monitoring
- **Auth**: Admin role required

### Get Monitoring Events
```
GET /monitoring/events
```
Get recent monitoring events
- **Params**: `event_type, limit`

### Get Process Tree
```
GET /monitoring/process-tree
```
Get current process tree

### Get Monitoring Status
```
GET /monitoring/status
```
Get monitoring system status

---

## 🔒 Quarantine Endpoints

### List Quarantined Files
```
GET /quarantine/list
```
List all quarantined files

### Restore Quarantined File
```
POST /quarantine/restore/{quarantine_id}
```
Restore a quarantined file
- **Params**: `restore_path` (optional)

### Delete Quarantined File
```
DELETE /quarantine/delete/{quarantine_id}
```
Permanently delete quarantined file

### Get Quarantine Stats
```
GET /quarantine/stats
```
Get quarantine statistics

---

## 🏝️ Sandbox Endpoints

### Execute in Sandbox
```
POST /sandbox/execute
```
Execute file in sandbox
- **Params**: `file_path, file_hash`

### List Sandbox Executions
```
GET /sandbox/executions
```
List recent sandbox executions
- **Params**: `limit` (default: 50)

### Get Execution Status
```
GET /sandbox/execution/{execution_id}
```
Get sandbox execution status

### Get Sandbox Stats
```
GET /sandbox/stats
```
Get sandbox statistics

---

## 🏥 System Endpoints

### System Status
```
GET /system/status
```
Get comprehensive system status

### Health Check
```
GET /health
```
Health check endpoint

### Root
```
GET /
```
API information and documentation

---

## 🔑 Authentication

All endpoints (except `/health` and `/`) require authentication via JWT Bearer token:

```
Authorization: Bearer <access_token>
```

## 👥 Role-Based Access Control

- **Admin**: Full access to all endpoints
- **Analyst**: Access to scanning, history, models, monitoring
- **User**: Access to scanning and history only

---

## 📚 Interactive API Documentation

Visit: **http://127.0.0.1:8000/docs**

This provides an interactive Swagger UI where you can:
- View all endpoints
- See request/response schemas
- Test endpoints directly
- View authentication requirements

