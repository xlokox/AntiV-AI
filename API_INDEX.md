# 🎯 AntiV-AI API - Complete Index & Navigation

**Backend Status:** ✅ Running on http://localhost:8000  
**Total Endpoints:** 56  
**Documentation Files:** 5  

---

## 🚀 Start Here

### 1. **Interactive API Documentation** (Best for Testing)
- **Swagger UI:** http://localhost:8000/docs
- **ReDoc:** http://localhost:8000/redoc
- **OpenAPI JSON:** http://localhost:8000/openapi.json

### 2. **Quick Start (5 minutes)**
```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

# 2. Check health
curl http://localhost:8000/health | jq .

# 3. Get stats
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/stats | jq .
```

---

## 📚 Documentation Files

### **API_SUMMARY.md** ⭐ START HERE
- Overview of all 56 endpoints
- System components
- Quick start guide
- Troubleshooting tips
- **Best for:** Getting oriented

### **API_REFERENCE_COMPLETE.md** 📖 QUICK REFERENCE
- All endpoints categorized
- Common response codes
- Authentication info
- Rate limiting details
- File upload limits
- **Best for:** Quick lookups

### **API_ENDPOINTS_DETAILED.md** 🔍 DETAILED SPECS
- Endpoint descriptions
- Request/response examples
- JSON payloads
- Role requirements
- Status codes
- **Best for:** Understanding each endpoint

### **API_CURL_EXAMPLES.md** 💻 COPY-PASTE READY
- 50+ cURL command examples
- Organized by category
- Debugging tips
- Useful tricks
- **Best for:** Testing endpoints

### **API_ENDPOINTS.md** 📋 COMPLETE LIST
- All 56 endpoints listed
- Organized by category
- Brief descriptions
- **Best for:** Finding endpoints

---

## 🔐 Authentication

### Default Credentials
```
Username: admin
Password: admin
```

### Get Access Token
```bash
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

### Use Token in Requests
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://localhost:8000/stats
```

---

## 📊 Endpoint Categories (56 Total)

| Category | Count | Key Endpoints |
|----------|-------|---------------|
| **Authentication** | 7 | Login, Logout, MFA, Create User |
| **Scanning** | 3 | Scan File, Upload & Scan, Batch Scan |
| **Quarantine** | 4 | List, Restore, Delete, Stats |
| **Models** | 8 | List, Evaluate, Rollback, Stats |
| **Security** | 13 | Blockchain, DDoS, Rate Limiting, SIEM |
| **Monitoring** | 5 | Status, Start, Stop, Events, Process Tree |
| **System** | 16 | Health, Stats, History, Sandbox, Training |

---

## 🎯 Common Tasks

### Task 1: Scan a File
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.access_token')

curl -X POST http://localhost:8000/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"file_path":"/path/to/file.exe"}'
```

### Task 2: Upload and Scan File
```bash
curl -X POST http://localhost:8000/upload-scan \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/file.exe"
```

### Task 3: List Quarantined Files
```bash
curl -X GET http://localhost:8000/quarantine/list \
  -H "Authorization: Bearer $TOKEN"
```

### Task 4: Get System Stats
```bash
curl -X GET http://localhost:8000/stats \
  -H "Authorization: Bearer $TOKEN"
```

### Task 5: Check Blockchain Integrity
```bash
curl -X POST http://localhost:8000/security/blockchain/verify \
  -H "Authorization: Bearer $TOKEN"
```

### Task 6: Get Model Information
```bash
curl -X GET http://localhost:8000/models \
  -H "Authorization: Bearer $TOKEN"
```

### Task 7: Start Real-time Monitoring
```bash
curl -X POST http://localhost:8000/monitoring/start \
  -H "Authorization: Bearer $TOKEN"
```

### Task 8: Execute File in Sandbox
```bash
curl -X POST http://localhost:8000/sandbox/execute \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"file_path":"/path/to/file.exe","timeout":30}'
```

---

## 🔗 API Endpoints by Category

### Authentication (7)
- `POST /auth/login` - Login
- `POST /auth/logout` - Logout
- `POST /auth/refresh` - Refresh token
- `POST /auth/create-user` - Create user (admin)
- `POST /auth/mfa/setup` - Setup MFA (admin)
- `POST /auth/mfa/verify` - Verify MFA
- `POST /auth/mfa/disable` - Disable MFA (admin)

### Scanning (3)
- `POST /scan` - Scan file by path
- `POST /upload-scan` - Upload and scan
- `POST /scan/multiple` - Scan multiple files

### Quarantine (4)
- `GET /quarantine/list` - List files
- `POST /quarantine/restore/{id}` - Restore file
- `DELETE /quarantine/delete/{id}` - Delete file
- `GET /quarantine/stats` - Get stats

### Models (8)
- `GET /models` - List models
- `GET /models/stats` - Get stats
- `POST /models/evaluate` - Evaluate (admin)
- `GET /models/{type}/active` - Get active
- `GET /models/{type}/latest` - Get latest
- `GET /models/{type}/evaluate` - Evaluate type
- `POST /models/{type}/rollback/{version}` - Rollback
- `GET /models/evaluation/report` - Get report

### Security (13)
- `GET /security/blockchain/stats` - Blockchain stats
- `POST /security/blockchain/verify` - Verify blockchain
- `POST /security/blockchain/finalize-block` - Finalize block
- `GET /security/ddos/stats` - DDoS stats
- `POST /security/ddos/block-ip` - Block IP
- `POST /security/ddos/unblock-ip` - Unblock IP
- `GET /security/rate-limiting/stats` - Rate limit stats
- `POST /security/rate-limiting/unblock-ip` - Unblock IP
- `GET /security/siem/metrics` - SIEM metrics
- `GET /security/siem/unsent-events` - Unsent events
- `POST /security/siem/retry-failed` - Retry failed
- `GET /security/notifications/stats` - Notification stats
- `POST /security/notifications/test` - Test notification

### Monitoring (5)
- `GET /monitoring/status` - Get status
- `POST /monitoring/start` - Start monitoring
- `POST /monitoring/stop` - Stop monitoring
- `GET /monitoring/events` - Get events
- `GET /monitoring/process-tree` - Get process tree

### System (16)
- `GET /` - Root
- `GET /health` - Health check
- `GET /stats` - System stats
- `GET /system/status` - System status
- `GET /history` - Scan history
- `GET /flagged` - Flagged files
- `POST /retrain` - Trigger retraining (admin)
- `GET /retrain/jobs` - List jobs
- `GET /retrain/status/{job_id}` - Get job status
- `POST /sandbox/execute` - Execute in sandbox
- `GET /sandbox/executions` - List executions
- `GET /sandbox/execution/{id}` - Get execution status
- `GET /sandbox/stats` - Sandbox stats
- `GET /performance/stats` - Performance stats (admin)
- `POST /performance/cache/clear` - Clear cache (admin)
- `GET /{full_path}` - Serve React app

---

## 🛠️ Tools & Resources

### Command Line Tools
- **curl** - Make HTTP requests
- **jq** - Parse JSON responses
- **httpie** - Alternative to curl

### Browser Tools
- **Swagger UI** - Interactive API testing
- **Postman** - API client
- **Insomnia** - REST client

### Documentation
- **OpenAPI/Swagger** - API specification
- **ReDoc** - Beautiful API docs
- **Markdown** - Local documentation

---

## 📞 Support & Troubleshooting

### Server Not Running?
```bash
python -m uvicorn src.app:app --host 0.0.0.0 --port 8000
```

### Authentication Failed?
- Check credentials (admin/admin)
- Verify token hasn't expired
- Refresh token if needed

### Rate Limited?
- Wait 1 minute or
- Use admin endpoint to unblock IP

### Need Help?
1. Check `API_SUMMARY.md` for overview
2. Check `API_ENDPOINTS_DETAILED.md` for specs
3. Try interactive API at http://localhost:8000/docs
4. Review logs in `./logs/`

---

## 📝 File Organization

```
AntiV-AI/
├── API_INDEX.md ← You are here
├── API_SUMMARY.md ← Overview
├── API_REFERENCE_COMPLETE.md ← Quick reference
├── API_ENDPOINTS_DETAILED.md ← Detailed specs
├── API_CURL_EXAMPLES.md ← cURL examples
├── API_ENDPOINTS.md ← Full list
├── src/
│   ├── app.py ← FastAPI application
│   ├── auth.py ← Authentication
│   ├── file_analysis.py ← File scanning
│   └── ... (other modules)
└── ... (other files)
```

---

## ✅ What's Ready

- ✅ Backend server running
- ✅ All 56 endpoints documented
- ✅ Interactive API docs available
- ✅ cURL examples provided
- ✅ Quick start guide ready
- ✅ Troubleshooting guide included

---

## 🎓 Learning Path

1. **Start:** Read `API_SUMMARY.md`
2. **Explore:** Visit http://localhost:8000/docs
3. **Test:** Try cURL examples from `API_CURL_EXAMPLES.md`
4. **Deep Dive:** Read `API_ENDPOINTS_DETAILED.md`
5. **Reference:** Use `API_REFERENCE_COMPLETE.md` for lookups

---

**Last Updated:** 2024-10-26  
**Backend Version:** 1.0.0  
**Status:** ✅ All systems operational

