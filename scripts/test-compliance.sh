#!/bin/bash
# Test version of compliance script to debug issues

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

echo "🔒 NIST Cybersecurity Framework Compliance Check (Test Version)"
echo "=============================================================="
echo "AntiV-AI Security Compliance Verification"
echo "Timestamp: $(date)"
echo "Project Root: $PROJECT_ROOT"
echo "Log File: $LOG_FILE"
echo ""

# Change to project root directory
if ! cd "$PROJECT_ROOT"; then
    echo "Error: Cannot change to project root directory: $PROJECT_ROOT"
    exit 1
fi

echo "✅ Successfully changed to project directory: $(pwd)"

# Simple test checks
echo "🔍 IDENTIFY (ID) - Asset Management & Risk Assessment"
echo "---------------------------------------------------"

# Check if basic files exist
if [ -f "src/app.py" ]; then
    pass "ID.AM-1: Main application file exists"
else
    fail "ID.AM-1: Main application file missing"
fi

if [ -f "config.yaml" ]; then
    pass "ID.AM-2: Configuration file exists"
else
    fail "ID.AM-2: Configuration file missing"
fi

if [ -f "requirements.txt" ]; then
    pass "ID.AM-3: Dependencies file exists"
else
    fail "ID.AM-3: Dependencies file missing"
fi

echo ""
echo "🛡️ PROTECT (PR) - Access Control & Data Security"
echo "-----------------------------------------------"

# Check for authentication
if grep -q "auth" src/app.py 2>/dev/null; then
    pass "PR.AC-1: Authentication system implemented"
else
    fail "PR.AC-1: Authentication system missing"
fi

# Check for MFA implementation
if grep -q "mfa" src/app.py 2>/dev/null || grep -q "totp" src/auth.py 2>/dev/null; then
    pass "PR.AC-2: Multi-factor authentication implemented"
else
    warn "PR.AC-2: Multi-factor authentication missing"
fi

echo ""
echo "📊 Test Results Summary"
echo "======================"
echo "Total Checks: $TOTAL_CHECKS"
echo "Passed: $PASSED_CHECKS"
echo "Failed: $FAILED_CHECKS"
echo "Warnings: $WARNING_CHECKS"

# Calculate compliance percentage
if [ $TOTAL_CHECKS -gt 0 ]; then
    COMPLIANCE_PERCENTAGE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
    echo "Compliance Score: $COMPLIANCE_PERCENTAGE%"
fi

echo ""

if [ $FAILED_CHECKS -gt 0 ]; then
    echo -e "${RED}❌ TEST FAILED${NC}"
    echo "   $FAILED_CHECKS critical issues found"
    exit 1
else
    echo -e "${GREEN}✅ TEST PASSED${NC}"
    echo "   All critical requirements met"
    if [ $WARNING_CHECKS -gt 0 ]; then
        echo "   $WARNING_CHECKS warnings to address"
    fi
    exit 0
fi
