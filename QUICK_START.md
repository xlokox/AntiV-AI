# 🚀 AntiV-AI Quick Start Guide

## ✅ Application Status

Your AntiV-AI application is **RUNNING** and fully operational!

```
✅ Backend Server: http://127.0.0.1:8000
✅ API Documentation: http://127.0.0.1:8000/docs
✅ All Components: Initialized and Ready
```

---

## 🌐 Access Points

### 1. **Main Web Interface**
```
http://127.0.0.1:8000
```
- Real-time threat dashboard
- File upload and scanning
- Scan history and statistics
- Flagged files management

### 2. **Interactive API Documentation**
```
http://127.0.0.1:8000/docs
```
- Complete API reference
- Test endpoints directly
- View request/response schemas
- Authentication testing

### 3. **Alternative API Docs (ReDoc)**
```
http://127.0.0.1:8000/redoc
```
- Alternative documentation format
- Better for reading

---

## 🔑 Default Credentials

### Test User
```
Username: testuser
Password: TestPassword123!
```

### Admin User
```
Username: admin
Password: AdminPassword123!
```

**Note**: Change these credentials in production!

---

## 🎯 Quick Actions

### 1. Upload & Scan a File
```
1. Go to http://127.0.0.1:8000
2. Click "Upload File" or drag & drop
3. View real-time analysis results
4. Check risk score and threat level
```

### 2. View Scan History
```
1. Click "Scan History" tab
2. View all previous scans
3. Filter by risk level
4. Export results
```

### 3. Check Flagged Files
```
1. Click "Flagged Files" tab
2. View high-risk files
3. Manage quarantine
4. Restore or delete files
```

### 4. Access API Documentation
```
1. Go to http://127.0.0.1:8000/docs
2. Expand any endpoint
3. Click "Try it out"
4. Enter parameters and execute
```

---

## 🔐 Authentication

### Login via API
```bash
curl -X POST "http://127.0.0.1:8000/auth/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPassword123!"
  }'
```

### Response
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "bearer"
}
```

### Use Token in Requests
```bash
curl -X GET "http://127.0.0.1:8000/stats" \
  -H "Authorization: Bearer <access_token>"
```

---

## 📁 Key Files & Directories

### Source Code
```
src/
├── app.py                 # FastAPI main application
├── antiv_engine.py        # Core detection engine
├── ml_detector.py         # ML-based detection
├── auth.py                # Authentication & MFA
├── network_security.py    # Rate limiting & geo-blocking
├── blockchain_audit.py    # Immutable audit trail
├── quarantine.py          # Threat isolation
└── sandbox.py             # Docker sandbox
```

### Configuration
```
config.yaml               # All settings
requirements.txt          # Python dependencies
```

### Data
```
data/
├── antiv_ai.db           # Main database
├── blockchain_audit.db   # Audit ledger
├── training/             # ML training data
└── siem/                 # SIEM events
```

### Models
```
models/
├── behavioral_analysis.pkl
├── isolation_forest.pkl
├── ensemble_model.pkl
├── feature_scaler.pkl
└── metadata.json         # Version info
```

---

## 🧪 Testing

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test
```bash
pytest tests/test_advanced_security.py -v
```

### Run with Coverage
```bash
pytest tests/ --cov=src --cov-report=html
```

---

## 📊 Key Features

### 🤖 Machine Learning
- 3 ensemble models (RandomForest, IsolationForest, Ensemble)
- 15-feature behavioral analysis
- Automated retraining pipeline
- Model versioning and rollback

### 🔐 Security
- JWT + TOTP MFA authentication
- Geo-based rate limiting
- DDoS protection
- Field-level database encryption
- Blockchain audit trail
- SIEM integration

### 📈 Analysis
- Static file analysis (hash, entropy, PE)
- Behavioral analysis (15 features)
- Threat intelligence integration
- Risk scoring (0.0-1.0 scale)

### 🔒 Advanced
- Quarantine system
- Docker sandbox
- Process monitoring
- Real-time alerts

---

## 🛠️ Common Tasks

### Scan a File
```bash
curl -X POST "http://127.0.0.1:8000/scan" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"file_path": "/path/to/file.exe"}'
```

### Get Scan History
```bash
curl -X GET "http://127.0.0.1:8000/history?limit=10" \
  -H "Authorization: Bearer <token>"
```

### Trigger ML Retraining
```bash
curl -X POST "http://127.0.0.1:8000/retrain" \
  -H "Authorization: Bearer <admin_token>"
```

### Get System Statistics
```bash
curl -X GET "http://127.0.0.1:8000/stats" \
  -H "Authorization: Bearer <token>"
```

### Check System Status
```bash
curl -X GET "http://127.0.0.1:8000/system/status"
```

---

## 📚 Documentation Files

- **PROJECT_OVERVIEW.md** - Complete project architecture
- **API_ENDPOINTS.md** - All 56 API endpoints reference
- **FEATURES_SUMMARY.md** - Detailed feature descriptions
- **README.md** - Original project documentation

---

## ⚠️ Important Notes

### Optional Components
- **Redis**: Using fallback (in-memory caching)
- **GeoIP Database**: Using fallback (basic geo-blocking)
- **Slack**: Notifications disabled (webhook not configured)

### Configuration
- Edit `config.yaml` to customize settings
- All security settings are configurable
- ML model parameters can be adjusted
- Rate limiting rules are customizable

### Database
- SQLite database with encryption
- Automatic backups enabled
- Field-level encryption active
- 30-day backup retention

---

## 🆘 Troubleshooting

### Application Won't Start
```bash
# Check if port 8000 is in use
lsof -i :8000

# Kill existing process if needed
kill -9 <PID>

# Restart application
python src/app.py
```

### Database Errors
```bash
# Check database permissions
ls -la data/

# Verify database integrity
sqlite3 data/antiv_ai.db ".tables"
```

### Import Errors
```bash
# Reinstall dependencies
pip install -r requirements.txt

# Verify Python path
python -c "import sys; print(sys.path)"
```

---

## 📞 Support

- **API Docs**: http://127.0.0.1:8000/docs
- **Health Check**: http://127.0.0.1:8000/health
- **System Status**: http://127.0.0.1:8000/system/status

---

## 🎉 You're All Set!

Your AntiV-AI application is ready to use. Start by:

1. ✅ Opening http://127.0.0.1:8000 in your browser
2. ✅ Logging in with test credentials
3. ✅ Uploading a file to scan
4. ✅ Exploring the API at http://127.0.0.1:8000/docs

**Enjoy your military-grade AI-powered antivirus! 🛡️🤖**

