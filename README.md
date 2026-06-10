# AntiV-AI 🛡️

**AI-assisted static malware detection for Windows PE files**

AntiV-AI scores how likely a Windows executable (PE file) is to be malicious by combining a **real, trained machine-learning model** with static heuristics and optional threat-intelligence lookups. The ML detector is a gradient-boosted model trained on the public **EMBER-2018** dataset (600,000 labeled samples) and evaluated on 200,000 held-out samples — the measured results and honest limitations are in [AI Detection](#-ai-detection-real-and-measured) below.

> **Project status (2026-06).** This is an actively-developed portfolio project, documented honestly. The machine-learning detection has been rebuilt to be genuinely real (see [models/ember/MODEL_CARD.md](models/ember/MODEL_CARD.md)); the previous version scored files with a random-number placeholder. Security hardening of the API layer is in progress and tracked separately — **do not rely on this as the only protection on a production endpoint.**

## 🚀 Features

### File Analysis Engine
- **Hash Calculation**: SHA-256 and MD5 hashing for file identification
- **Entropy Analysis**: Detects obfuscated/encrypted content using Shannon entropy
- **PE Header Inspection**: Analyzes Windows executable files for suspicious indicators
- **Risk Scoring**: Deterministic heuristic score (0.0-1.0) fused with the ML probability
- **ML Integration**: A real gradient-boosted model trained on EMBER-2018 — see [AI Detection](#-ai-detection-real-and-measured)

### Web Dashboard
- **Beautiful UI**: Modern React-based dashboard with Material-UI components
- **Real-time Scanning**: Drag & drop file upload with instant analysis
- **Interactive Charts**: Visual threat statistics and system metrics
- **Responsive Design**: Works perfectly on desktop and mobile devices
- **Live Updates**: Real-time notifications and data refresh

### REST API
- **FastAPI Backend**: High-performance Python API server
- **File Upload**: Secure file upload and scanning endpoints
- **History API**: Complete scan history and flagged files access
- **Statistics**: System performance and threat metrics
- **CORS Enabled**: Frontend-backend communication optimized

### 🔐 Military-Grade Security Features (10/10 Rating)
- **Container Security**: Non-root execution, capability dropping, read-only filesystem
- **Threat Intelligence**: VirusTotal, AlienVault OTX, MalwareBazaar integration
- **Advanced Cryptography**: HSM-compatible key management with Perfect Forward Secrecy
- **Multi-Factor Authentication**: TOTP-based MFA for admin accounts with backup codes
- **JWT Authentication**: Role-based access control with session management
- **Secure File Uploads**: Content validation, magic byte checking, rate limiting
- **Database Encryption**: Field-level encryption with automated key rotation
- **HTTPS/TLS**: SSL certificate management and secure communications
- **Rate Limiting**: Global and endpoint-specific request throttling
- **Security Headers**: Comprehensive HTTP security headers
- **Audit Logging**: Complete security event tracking and monitoring

### Database & Logging
- **Encrypted SQLite Database**: Stores scan results with field-level encryption
- **Automated Backups**: Encrypted, compressed database backups with rotation
- **JSON Fallback**: Backup logging system with secure permissions
- **Alert System**: Automatic flagging of high-risk files (>0.6 risk score)
- **Scan History**: Complete audit trail of all scans with encryption

### Real-Time Monitoring
- **Process Monitoring**: Real-time process creation, termination, and behavior tracking
- **Network Activity**: Monitor network connections, DNS queries, and suspicious traffic
- **Filesystem Watching**: Track file system changes and suspicious file operations
- **Behavioral Analysis**: Detect suspicious patterns and anomalies in real-time

### Quarantine System
- **Automatic Quarantine**: High-risk files automatically isolated and secured
- **Secure Storage**: Files encrypted and stored in isolated quarantine directory
- **Restore Capability**: Safe restoration of quarantined files when needed
- **Permanent Deletion**: Secure deletion of confirmed threats

### Sandbox Environment
- **Docker Integration**: Lightweight containerized execution environment
- **Behavior Logging**: Comprehensive monitoring of sandboxed file execution
- **Risk Assessment**: Automated analysis of sandbox execution results
- **Isolated Execution**: Safe analysis of suspicious files without system risk

### CLI Tools
- **Interactive Dashboard**: Command-line interface with tables and colors
- **Batch Scanning**: Directory and recursive scanning
- **Real-time Statistics**: System performance metrics
- **Color-coded Results**: Visual threat level indicators

## 🤖 AI Detection (real and measured)

The malware classifier is a **gradient-boosted decision-tree model (LightGBM)** trained on the
public **EMBER-2018** dataset. Every number below was *measured* on EMBER's 200,000-sample
held-out test set — none of it is assumed or hand-set.

| Metric | Value | Plain-English meaning |
|---|---|---|
| ROC-AUC (overall) | **0.9969** | How well it ranks malware above benign overall |
| **Detection @ 0.1% FPR** | **88.5%** | Catches 88.5% of malware while false-flagging only **1 in 1,000** clean files |
| Detection @ 1% FPR | 96.6% | Catches 96.6% if you tolerate 1% false alarms |
| PR-AUC | 0.9973 | Precision/recall quality (robust to class balance) |
| Brier score | 0.0172 | Probability calibration (lower is better) |

Trained on 600,000 labeled EMBER samples (300k malicious / 300k benign); tested on 200,000
held-out samples (100k / 100k). Full details: **[models/ember/MODEL_CARD.md](models/ember/MODEL_CARD.md)**.

**How it works (and why it's trustworthy):**
- **One feature pipeline for training *and* inference.** `src/ml/features.py` turns a PE file into
  the same 2,381-dimensional [EMBER](https://github.com/elastic/ember) feature vector whether it is
  vectorising the training set or scoring a live upload. This *structurally* prevents "train-serve
  skew" — the bug that made the previous model non-functional.
- **No fabricated metrics.** The model is *not* claimed to be perfect; an honest ~0.997 AUC with a
  measured 88.5% catch rate at 0.1% false positives is far more credible than a suspicious "1.0".
- **Honest degradation.** If the model file is absent, the detector reports *unavailable* and
  contributes no score — it never invents a number (`src/ml/detector.py`).

**Reproduce it yourself:**
```bash
# 1) Download + extract EMBER-2018 into data/ember/ (~1.6GB download, ~10GB extracted)
curl -L -o data/ember/ember.tar.bz2 https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar -xjf data/ember/ember.tar.bz2 -C data/ember/
# 2) Train (LightGBM if installed, else scikit-learn HistGradientBoosting)
python scripts/train_ember.py --train-limit 0 --algo lgbm
```

**Limitations (read these).** Static analysis of **PE files only**; it does not inspect scripts,
documents, ELF/Mach-O, archives, or runtime behaviour. Static models are evadable by packing and
adversarial perturbation, and accuracy on genuinely new malware families will be lower than these
2018-test numbers — retrain periodically. Use it as one layer in a defense-in-depth stack.

## 📋 Requirements

```bash
pip install -r requirements.txt
# On macOS, LightGBM also needs the OpenMP runtime:  brew install libomp
```

**Backend Dependencies:**
- `fastapi`: Modern Python web framework
- `uvicorn`: ASGI server for FastAPI
- `pefile`: PE file analysis (Windows executables)
- `python-multipart`: File upload support
- `aiofiles`: Async file operations

**Frontend Dependencies:**
- `react`: Modern JavaScript UI library
- `@mui/material`: Beautiful Material-UI components
- `axios`: HTTP client for API calls
- `recharts`: Interactive charts and graphs
- `react-dropzone`: Drag & drop file uploads

## 🛠️ Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd AntiV-AI
```

2. Install backend dependencies:
```bash
pip install -r requirements.txt
```

3. Install frontend dependencies:
```bash
cd frontend
npm install
cd ..
```

4. Run tests to verify installation:
```bash
python test_antiv.py
```

## 🎯 Usage

### 🌐 Web Dashboard (Recommended)

**1. Start the backend server:**
```bash
./start_backend.sh
# Or manually: uvicorn src.app:app --host 127.0.0.1 --port 8000 --reload
```

**2. Start the frontend dashboard:**
```bash
./start_frontend.sh
# Or manually: cd frontend && npm start
```

**3. Open your browser:**
- **Dashboard**: http://localhost:3000
- **API Documentation**: http://localhost:8000/docs

### ✨ Web Dashboard Features

- **🎯 File Scanner**: Drag & drop files for instant analysis
- **📊 Dashboard**: Real-time statistics and threat visualization
- **📋 Scan History**: Complete audit trail with filtering
- **⚠️ Flagged Files**: High-risk file management
- **🔄 Live Updates**: Real-time notifications and data refresh

### 💻 Command Line Interface

**Scan a single file:**
```bash
python main.py --file /path/to/suspicious/file.exe
```

**Scan a directory:**
```bash
python main.py --directory /path/to/scan --recursive
```

**View system statistics:**
```bash
python main.py --stats
```

**Run test suite:**
```bash
python main.py --test
```

### 📱 CLI Dashboard

**Launch interactive CLI:**
```bash
python cli_dashboard.py
```

**CLI options:**
```bash
python cli_dashboard.py --stats          # Show statistics
python cli_dashboard.py --recent 50      # Show 50 recent scans
python cli_dashboard.py --flagged        # Show flagged files
python cli_dashboard.py --scan file.exe  # Scan specific file
python cli_dashboard.py --all            # Show everything
```

## 📊 Risk Scoring System

The system uses a multi-factor heuristic approach:

### Entropy Analysis (0.0-1.0)
- **High entropy (>0.8)**: +0.3 risk (potential encryption/obfuscation)
- **Medium entropy (0.6-0.8)**: +0.2 risk
- **Low entropy (0.4-0.6)**: +0.1 risk

### PE Analysis
- **Suspicious DLL imports**: +0.15 per indicator
- **Possible packing**: +0.15
- **Unusual section characteristics**: Variable risk

### File Characteristics
- **Suspicious extensions** (.exe, .scr, .bat): +0.1
- **Very small files** (<1KB): +0.1
- **Very large files** (>50MB): +0.05

### ML Component (real)
- **EMBER-trained model**: contributes its malware probability (0.0–1.0) to the fused score
- **Fusion**: when available, the final risk = 40% static heuristics + 30% threat-intel + 30% ML
- **Details & measured accuracy**: see [AI Detection](#-ai-detection-real-and-measured)

### Threat Levels
- **HIGH** (≥0.8): Immediate attention required
- **MEDIUM** (0.6-0.8): Potentially suspicious, investigate
- **LOW** (0.3-0.6): Minor concerns, monitor
- **CLEAN** (<0.3): Appears safe

## 🗂️ Project Structure

```
AntiV-AI/
├── src/
│   ├── __init__.py
│   ├── app.py               # FastAPI backend server
│   ├── file_analysis.py     # Core file analysis engine
│   ├── database.py          # SQLite database management
│   └── antiv_engine.py      # Main engine coordinator
├── frontend/
│   ├── public/              # Static assets
│   ├── src/
│   │   ├── components/      # React components
│   │   │   ├── Dashboard.js
│   │   │   ├── FileScanner.js
│   │   │   ├── ScanHistory.js
│   │   │   └── FlaggedFiles.js
│   │   ├── App.js           # Main React app
│   │   └── index.js         # React entry point
│   ├── package.json         # Frontend dependencies
│   └── build/               # Production build (after npm run build)
├── data/                    # Database and scan results
├── logs/                    # System logs
├── test_files/             # Generated test files
├── main.py                 # CLI entry point
├── cli_dashboard.py        # Interactive CLI dashboard
├── test_antiv.py          # Test suite
├── start_backend.sh       # Backend startup script
├── start_frontend.sh      # Frontend startup script
├── requirements.txt       # Backend dependencies
└── README.md             # This file
```

## 🧪 Testing

The system includes comprehensive testing:

```bash
# Run full test suite
python test_antiv.py

# Test specific components
python -c "from src.file_analysis import FileAnalyzer; fa = FileAnalyzer(); print('✓ File analyzer loaded')"
```

**Test files created:**
- `clean_document.txt`: Low entropy, clean file
- `suspicious_encrypted.bin`: High entropy, random data
- `fake_malware.exe`: Simulated PE with suspicious characteristics
- `suspicious_script.bat`: Script with suspicious extension
- `normal_program.exe`: Normal-looking executable

## 📈 Performance Metrics

**Target Performance:**
- **Scan Speed**: <100ms per file
- **Memory Usage**: <50MB baseline
- **CPU Impact**: <5% during normal operation
- **Database**: Handles 10,000+ scan records efficiently

## 🔮 Future Enhancements

### Phase 2: Real-Time Process Monitor
- System call interception
- Behavioral analysis
- Process tree monitoring
- Network activity tracking

### Phase 3: Machine Learning Integration
- Neural network training pipeline
- Feature engineering automation
- Continuous learning from new threats
- Cloud-based model updates

### Phase 4: Advanced Features
- Sandbox execution environment
- Reputation-based scoring
- Integration with threat intelligence feeds
- Web-based dashboard

## 🛡️ Security Considerations

- **Isolation**: File analysis runs in controlled environment
- **Permissions**: Minimal system access required
- **Privacy**: All analysis performed locally
- **Logging**: Comprehensive audit trail maintained

## 🤝 Contributing

This is a personal AI-powered antivirus project. Future contributions welcome for:
- ML model improvements
- Additional file format support
- Performance optimizations
- Cross-platform compatibility

## 📄 License

Personal project - Educational and research purposes.

## 🔧 Troubleshooting

**Common Issues:**

1. **PE analysis unavailable**: Install `pefile` package
2. **Colors not working**: Install `colorama` package
3. **Database errors**: Check write permissions in `data/` directory
4. **Import errors**: Ensure `src/` directory is in Python path

**Debug Mode:**
```bash
python -c "import logging; logging.basicConfig(level=logging.DEBUG); from src.antiv_engine import AntiVEngine; engine = AntiVEngine(logging.DEBUG)"
```

---

**AntiV-AI** - Intelligent threat detection for the modern era 🛡️🤖
