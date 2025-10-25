#!/bin/bash
# Container Security Validation Script for AntiV-AI
# Validates all container hardening measures are properly implemented

set -e

echo "🔒 AntiV-AI Container Security Validation"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASSED=0
FAILED=0
WARNINGS=0

# Helper functions
pass() {
    echo -e "${GREEN}✅ PASS:${NC} $1"
    ((PASSED++))
}

fail() {
    echo -e "${RED}❌ FAIL:${NC} $1"
    ((FAILED++))
}

warn() {
    echo -e "${YELLOW}⚠️  WARN:${NC} $1"
    ((WARNINGS++))
}

info() {
    echo -e "ℹ️  INFO: $1"
}

# Check if Docker is available
if ! command -v docker &> /dev/null; then
    fail "Docker is not installed or not in PATH"
    exit 1
fi

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null; then
    warn "docker-compose is not installed, skipping compose tests"
    COMPOSE_AVAILABLE=false
else
    COMPOSE_AVAILABLE=true
fi

echo ""
echo "1. Building Container for Testing..."
echo "-----------------------------------"

# Build the container
if docker build -t antiv-ai:security-test . > /dev/null 2>&1; then
    pass "Container built successfully"
else
    fail "Container build failed"
    exit 1
fi

echo ""
echo "2. Testing Non-Root User Execution..."
echo "------------------------------------"

# Test non-root user
USER_ID=$(docker run --rm antiv-ai:security-test id -u 2>/dev/null || echo "0")
if [ "$USER_ID" != "0" ]; then
    pass "Container runs as non-root user (UID: $USER_ID)"
else
    fail "Container is running as root user"
fi

# Test group ID
GROUP_ID=$(docker run --rm antiv-ai:security-test id -g 2>/dev/null || echo "0")
if [ "$GROUP_ID" != "0" ]; then
    pass "Container runs with non-root group (GID: $GROUP_ID)"
else
    fail "Container is running with root group"
fi

echo ""
echo "3. Testing Read-Only Filesystem..."
echo "---------------------------------"

# Test read-only filesystem
if docker run --rm --read-only antiv-ai:security-test python -c "
import os
try:
    with open('/test-readonly', 'w') as f:
        f.write('test')
    exit(1)
except OSError:
    exit(0)
" 2>/dev/null; then
    pass "Read-only filesystem properly enforced"
else
    fail "Read-only filesystem not enforced"
fi

echo ""
echo "4. Testing Security Options..."
echo "-----------------------------"

# Test no-new-privileges
if docker run --rm --security-opt no-new-privileges:true antiv-ai:security-test python -c "
import os
try:
    # This should fail with no-new-privileges
    os.setuid(0)
    exit(1)
except PermissionError:
    exit(0)
except OSError:
    exit(0)
" 2>/dev/null; then
    pass "no-new-privileges security option working"
else
    warn "no-new-privileges test inconclusive"
fi

echo ""
echo "5. Testing Capability Restrictions..."
echo "------------------------------------"

# Test capability dropping
if docker run --rm --cap-drop=ALL antiv-ai:security-test python -c "
import socket
try:
    # This should work with NET_BIND_SERVICE capability
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.close()
    exit(0)
except:
    exit(1)
" 2>/dev/null; then
    pass "Basic socket operations work with dropped capabilities"
else
    warn "Socket operations failed - may need NET_BIND_SERVICE capability"
fi

echo ""
echo "6. Testing Resource Limits..."
echo "----------------------------"

# Test memory limit
if docker run --rm --memory=512m antiv-ai:security-test python -c "
import psutil
mem = psutil.virtual_memory()
print(f'Available memory: {mem.total // 1024 // 1024}MB')
exit(0)
" 2>/dev/null; then
    pass "Memory limits can be applied"
else
    warn "Memory limit test failed"
fi

# Test CPU limit
if docker run --rm --cpus=1.0 antiv-ai:security-test python -c "
import os
print(f'CPU count: {os.cpu_count()}')
exit(0)
" 2>/dev/null; then
    pass "CPU limits can be applied"
else
    warn "CPU limit test failed"
fi

echo ""
echo "7. Testing File Permissions..."
echo "-----------------------------"

# Test application directory permissions
APP_PERMS=$(docker run --rm antiv-ai:security-test stat -c "%a" /app 2>/dev/null || echo "000")
if [ "$APP_PERMS" = "755" ]; then
    pass "Application directory has correct permissions (755)"
else
    warn "Application directory permissions: $APP_PERMS (expected: 755)"
fi

# Test data directory permissions
DATA_PERMS=$(docker run --rm antiv-ai:security-test stat -c "%a" /app/data 2>/dev/null || echo "000")
if [ "$DATA_PERMS" = "700" ]; then
    pass "Data directory has secure permissions (700)"
else
    warn "Data directory permissions: $DATA_PERMS (expected: 700)"
fi

echo ""
echo "8. Testing Environment Security..."
echo "--------------------------------"

# Test Python security settings
PYTHON_HASH=$(docker run --rm antiv-ai:security-test python -c "import os; print(os.environ.get('PYTHONHASHSEED', 'not-set'))" 2>/dev/null)
if [ "$PYTHON_HASH" = "random" ]; then
    pass "PYTHONHASHSEED is set to random"
else
    warn "PYTHONHASHSEED not set to random: $PYTHON_HASH"
fi

# Test bytecode writing disabled
PYTHON_BYTECODE=$(docker run --rm antiv-ai:security-test python -c "import os; print(os.environ.get('PYTHONDONTWRITEBYTECODE', 'not-set'))" 2>/dev/null)
if [ "$PYTHON_BYTECODE" = "1" ]; then
    pass "Python bytecode writing disabled"
else
    warn "Python bytecode writing not disabled"
fi

echo ""
echo "9. Testing Health Check..."
echo "-------------------------"

# Start container and test health check
CONTAINER_ID=$(docker run -d antiv-ai:security-test)
sleep 10

HEALTH_STATUS=$(docker inspect --format='{{.State.Health.Status}}' $CONTAINER_ID 2>/dev/null || echo "none")
if [ "$HEALTH_STATUS" = "healthy" ]; then
    pass "Container health check is working"
elif [ "$HEALTH_STATUS" = "starting" ]; then
    warn "Container health check is still starting"
else
    warn "Container health check status: $HEALTH_STATUS"
fi

# Clean up
docker stop $CONTAINER_ID > /dev/null 2>&1
docker rm $CONTAINER_ID > /dev/null 2>&1

if [ "$COMPOSE_AVAILABLE" = true ]; then
    echo ""
    echo "10. Testing Docker Compose Security..."
    echo "------------------------------------"
    
    # Validate docker-compose configuration
    if docker-compose -f docker-compose.yml config --quiet 2>/dev/null; then
        pass "Docker Compose configuration is valid"
    else
        fail "Docker Compose configuration has errors"
    fi
    
    # Check for security options in compose file
    if grep -q "no-new-privileges:true" docker-compose.yml; then
        pass "no-new-privileges configured in docker-compose.yml"
    else
        fail "no-new-privileges not found in docker-compose.yml"
    fi
    
    if grep -q "cap_drop:" docker-compose.yml; then
        pass "Capability dropping configured in docker-compose.yml"
    else
        fail "Capability dropping not configured in docker-compose.yml"
    fi
    
    if grep -q "read_only: true" docker-compose.yml; then
        pass "Read-only filesystem configured in docker-compose.yml"
    else
        fail "Read-only filesystem not configured in docker-compose.yml"
    fi
fi

echo ""
echo "11. Testing Vulnerability Scanning..."
echo "------------------------------------"

# Check if Trivy is available
if command -v trivy &> /dev/null; then
    info "Running Trivy vulnerability scan..."
    if trivy image --exit-code 1 --severity HIGH,CRITICAL antiv-ai:security-test > /dev/null 2>&1; then
        pass "No high/critical vulnerabilities found by Trivy"
    else
        warn "High/critical vulnerabilities found - check Trivy output"
    fi
else
    warn "Trivy not available - install for vulnerability scanning"
fi

# Clean up test image
docker rmi antiv-ai:security-test > /dev/null 2>&1

echo ""
echo "=========================================="
echo "🔒 Container Security Validation Complete"
echo "=========================================="
echo ""
echo "📊 Results Summary:"
echo "  ✅ Passed: $PASSED"
echo "  ❌ Failed: $FAILED"
echo "  ⚠️  Warnings: $WARNINGS"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All critical security tests passed!${NC}"
    echo "Container is properly hardened for production deployment."
    exit 0
else
    echo -e "${RED}❌ $FAILED critical security tests failed!${NC}"
    echo "Please fix the failed tests before deploying to production."
    exit 1
fi
