# AntiV-AI API Reference - Complete Guide

**Server:** http://localhost:8000  
**API Version:** 1.0.0  
**Total Endpoints:** 56  
**Authentication:** JWT Bearer Token  

---

## Quick Start

### 1. Login to Get Access Token
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "your_password"
  }'
```

**Response:**
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

### 2. Use Token in Requests
```bash
curl -X GET http://localhost:8000/stats \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

---

## API Endpoint Categories

### Authentication (7 endpoints)
- `POST /auth/login` - Authenticate user
- `POST /auth/logout` - Logout and revoke token
- `POST /auth/refresh` - Refresh access token
- `POST /auth/create-user` - Create new user (admin only)
- `POST /auth/mfa/setup` - Setup MFA (admin only)
- `POST /auth/mfa/verify` - Verify MFA login
- `POST /auth/mfa/disable` - Disable MFA (admin only)

### Scanning (3 endpoints)
- `POST /scan` - Scan file by path
- `POST /upload-scan` - Upload and scan file
- `POST /scan/multiple` - Scan multiple files (analyst+)

### Quarantine (4 endpoints)
- `GET /quarantine/list` - List quarantined files
- `POST /quarantine/restore/{id}` - Restore file
- `DELETE /quarantine/delete/{id}` - Delete file
- `GET /quarantine/stats` - Get statistics

### Models (8 endpoints)
- `GET /models` - List all models
- `GET /models/stats` - Get model statistics
- `POST /models/evaluate` - Evaluate all models (admin)
- `GET /models/{type}/active` - Get active model
- `GET /models/{type}/latest` - Get latest model
- `GET /models/{type}/evaluate` - Evaluate specific model
- `POST /models/{type}/rollback/{version}` - Rollback model
- `GET /models/evaluation/report` - Get evaluation report

### Security (13 endpoints)
- `GET /security/blockchain/stats` - Blockchain statistics
- `POST /security/blockchain/verify` - Verify blockchain
- `POST /security/blockchain/finalize-block` - Finalize block
- `GET /security/ddos/stats` - DDoS statistics
- `POST /security/ddos/block-ip` - Block IP
- `POST /security/ddos/unblock-ip` - Unblock IP
- `GET /security/rate-limiting/stats` - Rate limit stats
- `POST /security/rate-limiting/unblock-ip` - Unblock IP
- `GET /security/siem/metrics` - SIEM metrics
- `GET /security/siem/unsent-events` - Unsent events
- `POST /security/siem/retry-failed` - Retry failed events
- `GET /security/notifications/stats` - Notification stats
- `POST /security/notifications/test` - Send test notification

### Monitoring (5 endpoints)
- `GET /monitoring/status` - Get monitoring status
- `POST /monitoring/start` - Start monitoring
- `POST /monitoring/stop` - Stop monitoring
- `GET /monitoring/events` - Get events
- `GET /monitoring/process-tree` - Get process tree

### System (16 endpoints)
- `GET /` - Root endpoint
- `GET /health` - Health check
- `GET /stats` - System statistics
- `GET /system/status` - Comprehensive status
- `GET /history` - Scan history
- `GET /flagged` - Flagged files
- `POST /retrain` - Trigger retraining (admin)
- `GET /retrain/jobs` - List training jobs
- `GET /retrain/status/{job_id}` - Get job status
- `POST /sandbox/execute` - Execute in sandbox
- `GET /sandbox/executions` - List executions
- `GET /sandbox/execution/{id}` - Get execution status
- `GET /sandbox/stats` - Sandbox statistics
- `GET /performance/stats` - Performance stats (admin)
- `POST /performance/cache/clear` - Clear cache (admin)
- `GET /{full_path}` - Serve React app

---

## Common Response Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request |
| 401 | Unauthorized |
| 403 | Forbidden |
| 404 | Not Found |
| 422 | Validation Error |
| 500 | Server Error |

---

## Interactive API Documentation

Visit **http://localhost:8000/docs** for interactive Swagger UI  
Visit **http://localhost:8000/redoc** for ReDoc documentation

---

## Rate Limiting

- **Default:** 100 requests per minute per IP
- **Adaptive:** Limits adjust based on geolocation and reputation
- **DDoS Protection:** Automatic IP blocking for suspicious patterns

---

## Authentication Roles

- **admin** - Full system access
- **analyst** - Can scan, view reports, manage quarantine
- **user** - Basic scanning and history viewing

---

## Error Handling

All errors return JSON with this format:
```json
{
  "detail": "Error message here"
}
```

---

## WebSocket Endpoints (Real-time)

- `/ws/monitoring` - Real-time monitoring events
- `/ws/scan-progress` - Real-time scan progress

---

## File Upload Limits

- **Max file size:** 500 MB
- **Allowed types:** All (validated server-side)
- **Timeout:** 30 minutes

---

## Next Steps

1. Read the full endpoint documentation in `API_ENDPOINTS.md`
2. Try the interactive API at http://localhost:8000/docs
3. Check authentication examples in `AUTH_EXAMPLES.md`
4. Review security best practices in `SECURITY.md`

