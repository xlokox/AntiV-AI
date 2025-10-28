# AntiV-AI API - cURL Examples

**Base URL:** http://localhost:8000

---

## Authentication Examples

### 1. Login
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin"
  }'
```

**Save token for later use:**
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

echo $TOKEN
```

### 2. Logout
```bash
curl -X POST http://localhost:8000/auth/logout \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Refresh Token
```bash
curl -X POST http://localhost:8000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refresh_token": "YOUR_REFRESH_TOKEN"
  }'
```

### 4. Create User (Admin Only)
```bash
curl -X POST http://localhost:8000/auth/create-user \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "analyst1",
    "password": "secure_password",
    "role": "analyst"
  }'
```

### 5. Setup MFA
```bash
curl -X POST http://localhost:8000/auth/mfa/setup \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Verify MFA Login
```bash
curl -X POST http://localhost:8000/auth/mfa/verify \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "admin",
    "totp_code": "123456"
  }'
```

---

## Scanning Examples

### 1. Scan File by Path
```bash
curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/path/to/file.exe"
  }'
```

### 2. Upload and Scan File
```bash
curl -X POST http://localhost:8000/upload-scan \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/file.exe"
```

### 3. Scan Multiple Files
```bash
curl -X POST http://localhost:8000/scan/multiple \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_paths": [
      "/path/to/file1.exe",
      "/path/to/file2.dll",
      "/path/to/file3.bin"
    ]
  }'
```

---

## Quarantine Examples

### 1. List Quarantined Files
```bash
curl -X GET http://localhost:8000/quarantine/list \
  -H "Authorization: Bearer $TOKEN"
```

### 2. Get Quarantine Stats
```bash
curl -X GET http://localhost:8000/quarantine/stats \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Restore Quarantined File
```bash
curl -X POST http://localhost:8000/quarantine/restore/q_001 \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Delete Quarantined File
```bash
curl -X DELETE http://localhost:8000/quarantine/delete/q_001 \
  -H "Authorization: Bearer $TOKEN"
```

---

## System Information Examples

### 1. Health Check
```bash
curl -X GET http://localhost:8000/health
```

### 2. Get System Stats
```bash
curl -X GET http://localhost:8000/stats \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Get System Status
```bash
curl -X GET http://localhost:8000/system/status \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Get Scan History
```bash
curl -X GET http://localhost:8000/history \
  -H "Authorization: Bearer $TOKEN"
```

### 5. Get Flagged Files
```bash
curl -X GET http://localhost:8000/flagged \
  -H "Authorization: Bearer $TOKEN"
```

---

## Model Management Examples

### 1. List All Models
```bash
curl -X GET http://localhost:8000/models \
  -H "Authorization: Bearer $TOKEN"
```

### 2. Get Model Stats
```bash
curl -X GET http://localhost:8000/models/stats \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Get Active Model Info
```bash
curl -X GET http://localhost:8000/models/behavioral_analysis/active \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Get Latest Model Info
```bash
curl -X GET http://localhost:8000/models/behavioral_analysis/latest \
  -H "Authorization: Bearer $TOKEN"
```

### 5. Evaluate Models (Admin Only)
```bash
curl -X POST http://localhost:8000/models/evaluate \
  -H "Authorization: Bearer $TOKEN"
```

### 6. Get Evaluation Report
```bash
curl -X GET http://localhost:8000/models/evaluation/report \
  -H "Authorization: Bearer $TOKEN"
```

### 7. Rollback Model (Admin Only)
```bash
curl -X POST http://localhost:8000/models/behavioral_analysis/rollback/1.0.0 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Security Examples

### 1. Get Blockchain Stats (Admin Only)
```bash
curl -X GET http://localhost:8000/security/blockchain/stats \
  -H "Authorization: Bearer $TOKEN"
```

### 2. Verify Blockchain Integrity (Admin Only)
```bash
curl -X POST http://localhost:8000/security/blockchain/verify \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Get DDoS Stats (Admin Only)
```bash
curl -X GET http://localhost:8000/security/ddos/stats \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Block IP (Admin Only)
```bash
curl -X POST http://localhost:8000/security/ddos/block-ip \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100"
  }'
```

### 5. Unblock IP (Admin Only)
```bash
curl -X POST http://localhost:8000/security/ddos/unblock-ip \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100"
  }'
```

### 6. Get Rate Limiting Stats (Admin Only)
```bash
curl -X GET http://localhost:8000/security/rate-limiting/stats \
  -H "Authorization: Bearer $TOKEN"
```

### 7. Get SIEM Metrics (Admin Only)
```bash
curl -X GET http://localhost:8000/security/siem/metrics \
  -H "Authorization: Bearer $TOKEN"
```

---

## Monitoring Examples

### 1. Get Monitoring Status
```bash
curl -X GET http://localhost:8000/monitoring/status \
  -H "Authorization: Bearer $TOKEN"
```

### 2. Start Monitoring
```bash
curl -X POST http://localhost:8000/monitoring/start \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Stop Monitoring
```bash
curl -X POST http://localhost:8000/monitoring/stop \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Get Monitoring Events
```bash
curl -X GET http://localhost:8000/monitoring/events \
  -H "Authorization: Bearer $TOKEN"
```

### 5. Get Process Tree
```bash
curl -X GET http://localhost:8000/monitoring/process-tree \
  -H "Authorization: Bearer $TOKEN"
```

---

## Training Examples

### 1. Trigger Retraining (Admin Only)
```bash
curl -X POST http://localhost:8000/retrain \
  -H "Authorization: Bearer $TOKEN"
```

### 2. List Training Jobs
```bash
curl -X GET http://localhost:8000/retrain/jobs \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Get Training Job Status
```bash
curl -X GET http://localhost:8000/retrain/status/train_12345 \
  -H "Authorization: Bearer $TOKEN"
```

---

## Sandbox Examples

### 1. Execute File in Sandbox
```bash
curl -X POST http://localhost:8000/sandbox/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "file_path": "/path/to/file.exe",
    "timeout": 30
  }'
```

### 2. List Sandbox Executions
```bash
curl -X GET http://localhost:8000/sandbox/executions \
  -H "Authorization: Bearer $TOKEN"
```

### 3. Get Execution Status
```bash
curl -X GET http://localhost:8000/sandbox/execution/exec_12345 \
  -H "Authorization: Bearer $TOKEN"
```

### 4. Get Sandbox Stats
```bash
curl -X GET http://localhost:8000/sandbox/stats \
  -H "Authorization: Bearer $TOKEN"
```

---

## Performance Examples

### 1. Get Performance Stats (Admin Only)
```bash
curl -X GET http://localhost:8000/performance/stats \
  -H "Authorization: Bearer $TOKEN"
```

### 2. Clear Performance Cache (Admin Only)
```bash
curl -X POST http://localhost:8000/performance/cache/clear \
  -H "Authorization: Bearer $TOKEN"
```

---

## Useful Tips

### Pretty Print JSON Response
```bash
curl -s http://localhost:8000/health | jq .
```

### Save Response to File
```bash
curl -X GET http://localhost:8000/stats \
  -H "Authorization: Bearer $TOKEN" \
  -o response.json
```

### Show Response Headers
```bash
curl -i http://localhost:8000/health
```

### Verbose Output (Debug)
```bash
curl -v http://localhost:8000/health
```

### Set Custom Headers
```bash
curl -X GET http://localhost:8000/stats \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-Custom-Header: value"
```

---

## Interactive API Documentation

- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI JSON:** http://localhost:8000/openapi.json

Try all endpoints interactively in the Swagger UI!

