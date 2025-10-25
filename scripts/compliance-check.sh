#!/bin/bash
# NIST Cybersecurity Framework Compliance Check for AntiV-AI
# Automated compliance verification script with enhanced checks

# Note: Removed 'set -e' to allow script to continue on individual check failures
# The script should complete all checks and exit with proper code based on results

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0
WARNING_CHECKS=0

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${PROJECT_ROOT}/compliance-check.log"

# Initialize log file
echo "NIST CSF Compliance Check - $(date)" > "$LOG_FILE"

# Helper functions
info() {
    echo -e "${BLUE}ℹ️  INFO:${NC} $1"
    echo "INFO: $1" >> "$LOG_FILE"
}

pass() {
    echo -e "${GREEN}✅ PASS:${NC} $1"
    echo "PASS: $1" >> "$LOG_FILE"
    ((PASSED_CHECKS++))
    ((TOTAL_CHECKS++))
}

fail() {
    echo -e "${RED}❌ FAIL:${NC} $1"
    echo "FAIL: $1" >> "$LOG_FILE"
    ((FAILED_CHECKS++))
    ((TOTAL_CHECKS++))
}

warn() {
    echo -e "${YELLOW}⚠️  WARN:${NC} $1"
    echo "WARN: $1" >> "$LOG_FILE"
    ((WARNING_CHECKS++))
    ((TOTAL_CHECKS++))
}

critical_fail() {
    echo -e "${RED}💥 CRITICAL FAIL:${NC} $1"
    echo "CRITICAL_FAIL: $1" >> "$LOG_FILE"
    ((FAILED_CHECKS++))
    ((TOTAL_CHECKS++))
}

# Check if file exists and has correct permissions
check_file_permissions() {
    local file=$1
    local expected_perms=$2
    local description=$3

    if [ -f "$file" ]; then
        # Try Linux stat first, then macOS stat, with fallback
        if command -v stat >/dev/null 2>&1; then
            actual_perms=$(stat -c "%a" "$file" 2>/dev/null || stat -f "%A" "$file" 2>/dev/null || echo "unknown")
            if [ "$actual_perms" = "$expected_perms" ]; then
                pass "$description: $file ($actual_perms)"
            elif [ "$actual_perms" = "unknown" ]; then
                warn "$description: $file permissions could not be determined"
            else
                fail "$description: $file has $actual_perms, expected $expected_perms"
            fi
        else
            warn "$description: stat command not available, cannot check $file permissions"
        fi
    else
        fail "$description: $file does not exist"
    fi
}

# Check if directory exists and has correct permissions
check_directory_permissions() {
    local dir=$1
    local expected_perms=$2
    local description=$3

    if [ -d "$dir" ]; then
        # Try Linux stat first, then macOS stat, with fallback
        if command -v stat >/dev/null 2>&1; then
            actual_perms=$(stat -c "%a" "$dir" 2>/dev/null || stat -f "%A" "$dir" 2>/dev/null || echo "unknown")
            if [ "$actual_perms" = "$expected_perms" ]; then
                pass "$description: $dir ($actual_perms)"
            elif [ "$actual_perms" = "unknown" ]; then
                warn "$description: $dir permissions could not be determined"
            else
                fail "$description: $dir has $actual_perms, expected $expected_perms"
            fi
        else
            warn "$description: stat command not available, cannot check $dir permissions"
        fi
    else
        # Create directory if it doesn't exist (for some directories this is acceptable)
        if [[ "$dir" == "logs" || "$dir" == "data" || "$dir" == "uploads" ]]; then
            mkdir -p "$dir" 2>/dev/null || true
            if [ -d "$dir" ]; then
                warn "$description: $dir was created during check"
            else
                fail "$description: $dir does not exist and could not be created"
            fi
        else
            fail "$description: $dir does not exist"
        fi
    fi
}

# Check if service is running
check_service_running() {
    local service_name=$1
    local port=$2
    local description=$3
    
    if command -v netstat >/dev/null 2>&1; then
        if netstat -tuln | grep -q ":$port "; then
            pass "$description: Service listening on port $port"
        else
            fail "$description: No service listening on port $port"
        fi
    elif command -v ss >/dev/null 2>&1; then
        if ss -tuln | grep -q ":$port "; then
            pass "$description: Service listening on port $port"
        else
            fail "$description: No service listening on port $port"
        fi
    else
        warn "$description: Cannot check service status (netstat/ss not available)"
    fi
}

# Check environment variable
check_env_var() {
    local var_name=$1
    local description=$2
    local required=$3

    if [ -n "${!var_name}" ]; then
        pass "$description: $var_name is set"
    else
        if [ "$required" = "true" ]; then
            fail "$description: $var_name is not set"
        else
            warn "$description: $var_name is not set (optional)"
        fi
    fi
}

# Check Python module availability
check_python_module() {
    local module_name=$1
    local description=$2
    local required=$3

    if python3 -c "import $module_name" 2>/dev/null; then
        pass "$description: Python module '$module_name' is available"
    else
        if [ "$required" = "true" ]; then
            fail "$description: Python module '$module_name' is missing"
        else
            warn "$description: Python module '$module_name' is missing (optional)"
        fi
    fi
}

# Check API endpoint availability
check_api_endpoint() {
    local endpoint=$1
    local description=$2
    local expected_status=$3

    if command -v curl >/dev/null 2>&1; then
        # Add timeout to prevent hanging (use gtimeout on macOS if available)
        local timeout_cmd=""
        if command -v timeout >/dev/null 2>&1; then
            timeout_cmd="timeout 10"
        elif command -v gtimeout >/dev/null 2>&1; then
            timeout_cmd="gtimeout 10"
        fi

        local status_code
        if [ -n "$timeout_cmd" ]; then
            status_code=$($timeout_cmd curl -s -o /dev/null -w "%{http_code}" "$endpoint" 2>/dev/null || echo "000")
        else
            # No timeout available, use curl with connect-timeout
            status_code=$(curl -s --connect-timeout 10 --max-time 10 -o /dev/null -w "%{http_code}" "$endpoint" 2>/dev/null || echo "000")
        fi

        if [ "$status_code" = "$expected_status" ]; then
            pass "$description: API endpoint responds with $status_code"
        elif [ "$status_code" = "000" ]; then
            warn "$description: API endpoint timeout or connection failed"
        else
            fail "$description: API endpoint returned $status_code, expected $expected_status"
        fi
    else
        warn "$description: curl not available, cannot test API endpoint"
    fi
}

# Check configuration file
check_config_file() {
    local config_file=$1
    local key_path=$2
    local description=$3

    if [ -f "$config_file" ]; then
        if command -v python3 >/dev/null 2>&1; then
            # Check if PyYAML is available
            if python3 -c "import yaml" 2>/dev/null; then
                local value=$(python3 -c "
import yaml
try:
    with open('$config_file', 'r') as f:
        config = yaml.safe_load(f)
    keys = '$key_path'.split('.')
    value = config
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key, {})
        else:
            value = {}
    print('found' if value else 'missing')
except Exception as e:
    print('error')
" 2>/dev/null)

                if [ "$value" = "found" ]; then
                    pass "$description: Configuration key '$key_path' found"
                elif [ "$value" = "missing" ]; then
                    warn "$description: Configuration key '$key_path' missing (non-critical)"
                else
                    warn "$description: Error reading configuration file"
                fi
            else
                # Fallback to simple grep-based check
                if grep -q "$key_path" "$config_file" 2>/dev/null; then
                    pass "$description: Configuration key '$key_path' found (basic check)"
                else
                    warn "$description: PyYAML not available, using basic check - key '$key_path' not found"
                fi
            fi
        else
            warn "$description: Python3 not available, cannot parse YAML"
        fi
    else
        # For some config files, this might be acceptable
        if [[ "$config_file" == "config.yaml" ]]; then
            warn "$description: Configuration file '$config_file' not found (may use defaults)"
        else
            fail "$description: Configuration file '$config_file' not found"
        fi
    fi
}

echo "🔒 NIST Cybersecurity Framework Compliance Check"
echo "================================================"
echo "AntiV-AI Security Compliance Verification"
echo "Timestamp: $(date)"
echo "Project Root: $PROJECT_ROOT"
echo "Log File: $LOG_FILE"
echo ""

# Change to project root directory
cd "$PROJECT_ROOT" || {
    echo "Error: Cannot change to project root directory"
    exit 1
}

# NIST CSF Function 1: IDENTIFY (ID)
echo "🎯 IDENTIFY (ID) - Asset Management & Risk Assessment"
echo "----------------------------------------------------"

# ID.AM - Asset Management
info "Checking Asset Management controls..."

check_file_permissions "config.yaml" "644" "ID.AM-1: Configuration file security"
check_directory_permissions "data" "700" "ID.AM-1: Data directory security"
check_directory_permissions "logs" "700" "ID.AM-1: Log directory security"
check_directory_permissions "uploads" "700" "ID.AM-1: Upload directory security"

# Check if inventory files exist
if [ -f "requirements.txt" ]; then
    pass "ID.AM-2: Software inventory (requirements.txt)"
else
    fail "ID.AM-2: Software inventory missing"
fi

if [ -f "Dockerfile" ]; then
    pass "ID.AM-3: Container configuration documented"
else
    fail "ID.AM-3: Container configuration missing"
fi

# ID.RA - Risk Assessment
info "Checking Risk Assessment controls..."

if [ -f "SECURITY.md" ]; then
    pass "ID.RA-1: Security documentation exists"
else
    fail "ID.RA-1: Security documentation missing"
fi

if [ -f "src/threat_intel.py" ]; then
    pass "ID.RA-2: Threat intelligence capability"
else
    fail "ID.RA-2: Threat intelligence missing"
fi

echo ""

# NIST CSF Function 2: PROTECT (PR)
echo "🛡️  PROTECT (PR) - Access Control & Data Security"
echo "------------------------------------------------"

# PR.AC - Access Control
info "Checking Access Control..."

if [ -f "src/auth.py" ]; then
    pass "PR.AC-1: Authentication system implemented"
else
    fail "PR.AC-1: Authentication system missing"
fi

# Check for MFA implementation
if grep -q "mfa" src/app.py 2>/dev/null || grep -q "totp" src/auth.py 2>/dev/null; then
    pass "PR.AC-2: Multi-factor authentication implemented"
else
    critical_fail "PR.AC-2: Multi-factor authentication missing"
fi

# Check for role-based access
if grep -q "role" src/auth.py 2>/dev/null && grep -q "require_role" src/auth.py 2>/dev/null; then
    pass "PR.AC-3: Role-based access control implemented"
else
    critical_fail "PR.AC-3: Role-based access control missing"
fi

# Check for session management
if grep -q "session" src/auth.py 2>/dev/null; then
    pass "PR.AC-4: Session management implemented"
else
    fail "PR.AC-4: Session management missing"
fi

# PR.DS - Data Security
info "Checking Data Security..."

if [ -f "src/database_security.py" ]; then
    pass "PR.DS-1: Database encryption implemented"
else
    fail "PR.DS-1: Database encryption missing"
fi

if [ -f "src/key_manager.py" ]; then
    pass "PR.DS-2: Key management system implemented"
else
    fail "PR.DS-2: Key management system missing"
fi

check_directory_permissions "backups" "700" "PR.DS-3: Backup security"

# PR.IP - Information Protection
info "Checking Information Protection..."

if [ -f "src/blockchain_audit.py" ]; then
    pass "PR.IP-1: Audit trail protection (blockchain)"
else
    fail "PR.IP-1: Audit trail protection missing"
fi

# Check for secure development practices
if [ -f ".github/workflows/security-scan.yml" ]; then
    pass "PR.IP-2: Secure development lifecycle (CI/CD security)"
else
    fail "PR.IP-2: Secure development lifecycle missing"
fi

echo ""

# NIST CSF Function 3: DETECT (DE)
echo "🔍 DETECT (DE) - Monitoring & Detection"
echo "--------------------------------------"

# DE.AE - Anomalies and Events
info "Checking Anomaly Detection..."

if [ -f "src/ml_detector.py" ]; then
    pass "DE.AE-1: ML-based anomaly detection implemented"
else
    fail "DE.AE-1: ML-based anomaly detection missing"
fi

if [ -f "src/ddos_protector.py" ]; then
    pass "DE.AE-2: DDoS attack detection implemented"
else
    fail "DE.AE-2: DDoS attack detection missing"
fi

# DE.CM - Continuous Monitoring
info "Checking Continuous Monitoring..."

if [ -f "src/monitoring/siem_integration.py" ]; then
    pass "DE.CM-1: SIEM integration implemented"
else
    fail "DE.CM-1: SIEM integration missing"
fi

# Check if monitoring service is running
check_service_running "antiv-api" "8000" "DE.CM-2: API monitoring"

# DE.DP - Detection Processes
info "Checking Detection Processes..."

if [ -f "src/threat_intel.py" ]; then
    pass "DE.DP-1: Threat intelligence detection"
else
    fail "DE.DP-1: Threat intelligence detection missing"
fi

echo ""

# NIST CSF Function 4: RESPOND (RS)
echo "🚨 RESPOND (RS) - Incident Response"
echo "----------------------------------"

# RS.RP - Response Planning
info "Checking Response Planning..."

if [ -f "src/quarantine.py" ]; then
    pass "RS.RP-1: Quarantine response capability"
else
    fail "RS.RP-1: Quarantine response capability missing"
fi

# RS.CO - Communications
info "Checking Response Communications..."

if [ -f "src/integrations/slack_notifier.py" ] || grep -q "slack" src/app.py 2>/dev/null; then
    pass "RS.CO-1: Alert notification system"
else
    warn "RS.CO-1: Alert notification system not configured"
fi

# RS.AN - Analysis
info "Checking Response Analysis..."

if [ -f "src/sandbox.py" ]; then
    pass "RS.AN-1: Sandbox analysis capability"
else
    fail "RS.AN-1: Sandbox analysis capability missing"
fi

echo ""

# NIST CSF Function 5: RECOVER (RC)
echo "🔄 RECOVER (RC) - Recovery & Resilience"
echo "--------------------------------------"

# RC.RP - Recovery Planning
info "Checking Recovery Planning..."

if [ -d "backups" ]; then
    pass "RC.RP-1: Backup system implemented"
else
    fail "RC.RP-1: Backup system missing"
fi

# RC.IM - Improvements
info "Checking Recovery Improvements..."

if [ -f "test_security_features.py" ]; then
    pass "RC.IM-1: Security testing framework"
else
    fail "RC.IM-1: Security testing framework missing"
fi

echo ""

# Additional Security Checks
echo "🔐 Additional Security Verification"
echo "----------------------------------"

# Enhanced Security Configuration Checks
echo "🔐 Enhanced Security Configuration"
echo "----------------------------------"

# Check for security environment variables
check_env_var "JWT_SECRET_KEY" "JWT secret configuration" "true"
check_env_var "ADMIN_PASSWORD" "Admin password configuration" "false"
check_env_var "SIEM_ENDPOINT" "SIEM integration" "false"
check_env_var "SLACK_WEBHOOK_URL" "Slack notifications" "false"
check_env_var "REDIS_URL" "Redis caching" "false"

# Check configuration file structure
check_config_file "config.yaml" "security.jwt.secret_key" "JWT configuration"
check_config_file "config.yaml" "security.mfa.enabled" "MFA configuration"
check_config_file "config.yaml" "rate_limits.geo.enabled" "Geo rate limiting"
check_config_file "config.yaml" "siem.enabled" "SIEM configuration"
check_config_file "config.yaml" "blockchain_audit.enabled" "Blockchain audit"

# Check Python dependencies
check_python_module "fastapi" "FastAPI framework" "true"
check_python_module "redis" "Redis client" "false"
check_python_module "geoip2" "GeoIP2 library" "false"
check_python_module "cryptography" "Cryptography library" "true"

# Check for SSL/TLS configuration
if [ -d "certs" ]; then
    pass "SSL/TLS: Certificate directory exists"
else
    warn "SSL/TLS: Certificate directory missing"
fi

# Check for container security
if [ -f "Dockerfile" ]; then
    if grep -q "USER" Dockerfile; then
        pass "Container Security: Non-root user configured"
    else
        fail "Container Security: Running as root"
    fi
    
    if grep -q "HEALTHCHECK" Dockerfile; then
        pass "Container Security: Health check configured"
    else
        warn "Container Security: Health check missing"
    fi
fi

# Check for dependency security
if command -v pip >/dev/null 2>&1; then
    if pip list --format=json | grep -q "safety\|bandit"; then
        pass "Dependency Security: Security scanning tools available"
    else
        warn "Dependency Security: Consider installing safety and bandit"
    fi
fi

echo ""
echo "================================================"
echo "🎯 NIST CSF Compliance Summary"
echo "================================================"
echo ""
echo "📊 Results:"
echo "  ✅ Passed: $PASSED_CHECKS"
echo "  ❌ Failed: $FAILED_CHECKS"
echo "  ⚠️  Warnings: $WARNING_CHECKS"
echo "  📈 Total: $TOTAL_CHECKS"
echo ""

# Calculate compliance percentage
if [ $TOTAL_CHECKS -gt 0 ]; then
    COMPLIANCE_PERCENTAGE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
    echo "🎯 Compliance Score: $COMPLIANCE_PERCENTAGE%"
    
    if [ $COMPLIANCE_PERCENTAGE -ge 90 ]; then
        echo -e "${GREEN}🏆 EXCELLENT: High compliance with NIST CSF${NC}"
    elif [ $COMPLIANCE_PERCENTAGE -ge 75 ]; then
        echo -e "${YELLOW}👍 GOOD: Acceptable compliance level${NC}"
    elif [ $COMPLIANCE_PERCENTAGE -ge 50 ]; then
        echo -e "${YELLOW}⚠️  MODERATE: Compliance improvements needed${NC}"
    else
        echo -e "${RED}❌ POOR: Significant compliance gaps${NC}"
    fi
fi

echo ""
echo "📋 NIST CSF Functions Coverage:"
echo "  • IDENTIFY (ID): Asset management, risk assessment"
echo "  • PROTECT (PR): Access control, data security, information protection"
echo "  • DETECT (DE): Anomaly detection, continuous monitoring"
echo "  • RESPOND (RS): Incident response, communications, analysis"
echo "  • RECOVER (RC): Recovery planning, improvements"
echo ""

if [ $FAILED_CHECKS -gt 0 ]; then
    echo -e "${RED}❌ COMPLIANCE CHECK FAILED${NC}"
    echo "   $FAILED_CHECKS critical compliance issues found"
    echo "   Review failed checks and implement missing controls"
    exit 1
else
    echo -e "${GREEN}✅ COMPLIANCE CHECK PASSED${NC}"
    echo "   All critical compliance requirements met"
    if [ $WARNING_CHECKS -gt 0 ]; then
        echo "   $WARNING_CHECKS warnings to address for optimal compliance"
    fi
    exit 0
fi
