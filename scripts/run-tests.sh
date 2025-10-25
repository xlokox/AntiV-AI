#!/bin/bash
# Test runner script for AntiV-AI
# Runs comprehensive test suite with different configurations

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEST_RESULTS_DIR="${PROJECT_ROOT}/test-results"

# Helper functions
info() {
    echo -e "${BLUE}ℹ️  INFO:${NC} $1"
}

success() {
    echo -e "${GREEN}✅ SUCCESS:${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠️  WARNING:${NC} $1"
}

error() {
    echo -e "${RED}❌ ERROR:${NC} $1"
}

# Create test results directory
mkdir -p "$TEST_RESULTS_DIR"

# Change to project root
cd "$PROJECT_ROOT"

echo "🧪 AntiV-AI Test Suite Runner"
echo "============================="
echo "Project Root: $PROJECT_ROOT"
echo "Test Results: $TEST_RESULTS_DIR"
echo ""

# Check if pytest is available
if ! command -v pytest >/dev/null 2>&1; then
    error "pytest is not installed. Please install it with: pip install pytest"
    exit 1
fi

# Install test dependencies if needed
info "Installing test dependencies..."
pip install pytest pytest-asyncio pytest-cov pytest-timeout pytest-xdist 2>/dev/null || {
    warning "Could not install some test dependencies. Some features may not work."
}

# Function to run test suite
run_test_suite() {
    local test_name=$1
    local test_args=$2
    local output_file="${TEST_RESULTS_DIR}/${test_name}.xml"
    
    info "Running $test_name tests..."
    
    if pytest $test_args --junitxml="$output_file" 2>&1 | tee "${TEST_RESULTS_DIR}/${test_name}.log"; then
        success "$test_name tests passed"
        return 0
    else
        error "$test_name tests failed"
        return 1
    fi
}

# Test execution based on arguments
case "${1:-all}" in
    "unit")
        info "Running unit tests only..."
        run_test_suite "unit" "tests/ -m 'not slow and not integration'"
        ;;
    
    "integration")
        info "Running integration tests only..."
        run_test_suite "integration" "tests/ -m integration"
        ;;
    
    "security")
        info "Running security tests only..."
        run_test_suite "security" "tests/test_advanced_security.py -m 'not slow'"
        ;;
    
    "performance")
        info "Running performance tests only..."
        run_test_suite "performance" "tests/test_performance.py"
        ;;

    "ml"|"training")
        info "Running ML training pipeline tests only..."
        run_test_suite "ml_training" "tests/test_training_pipeline.py"
        ;;
    
    "compliance")
        info "Running compliance tests only..."
        run_test_suite "compliance" "tests/ -k compliance"
        ;;
    
    "fast")
        info "Running fast tests only (excluding slow tests)..."
        run_test_suite "fast" "tests/ -m 'not slow'"
        ;;
    
    "coverage")
        info "Running tests with coverage analysis..."
        if command -v pytest-cov >/dev/null 2>&1; then
            run_test_suite "coverage" "tests/ --cov=src --cov-report=html:${TEST_RESULTS_DIR}/htmlcov --cov-report=term-missing --cov-fail-under=70"
            info "Coverage report generated in ${TEST_RESULTS_DIR}/htmlcov/"
        else
            warning "pytest-cov not available, running tests without coverage"
            run_test_suite "coverage" "tests/"
        fi
        ;;
    
    "parallel")
        info "Running tests in parallel..."
        if command -v pytest-xdist >/dev/null 2>&1; then
            run_test_suite "parallel" "tests/ -n auto"
        else
            warning "pytest-xdist not available, running tests sequentially"
            run_test_suite "parallel" "tests/"
        fi
        ;;
    
    "all")
        info "Running complete test suite..."
        
        # Track overall results
        TOTAL_SUITES=0
        PASSED_SUITES=0
        
        # Unit tests
        ((TOTAL_SUITES++))
        if run_test_suite "unit" "tests/ -m 'not slow and not integration'"; then
            ((PASSED_SUITES++))
        fi
        
        # Security tests
        ((TOTAL_SUITES++))
        if run_test_suite "security" "tests/test_advanced_security.py -m 'not slow'"; then
            ((PASSED_SUITES++))
        fi
        
        # Performance tests
        ((TOTAL_SUITES++))
        if run_test_suite "performance" "tests/test_performance.py -m 'not slow'"; then
            ((PASSED_SUITES++))
        fi

        # ML training pipeline tests
        ((TOTAL_SUITES++))
        if run_test_suite "ml_training" "tests/test_training_pipeline.py"; then
            ((PASSED_SUITES++))
        fi
        
        # Integration tests
        ((TOTAL_SUITES++))
        if run_test_suite "integration" "tests/ -m integration"; then
            ((PASSED_SUITES++))
        fi
        
        # Compliance script test
        ((TOTAL_SUITES++))
        if run_test_suite "compliance" "tests/ -k compliance"; then
            ((PASSED_SUITES++))
        fi
        
        echo ""
        echo "📊 Test Suite Summary"
        echo "===================="
        echo "Total test suites: $TOTAL_SUITES"
        echo "Passed: $PASSED_SUITES"
        echo "Failed: $((TOTAL_SUITES - PASSED_SUITES))"
        
        if [ $PASSED_SUITES -eq $TOTAL_SUITES ]; then
            success "All test suites passed! 🎉"
            exit 0
        else
            error "Some test suites failed. Check logs in $TEST_RESULTS_DIR"
            exit 1
        fi
        ;;
    
    "help"|"-h"|"--help")
        echo "Usage: $0 [test_type]"
        echo ""
        echo "Test types:"
        echo "  unit        - Run unit tests only"
        echo "  integration - Run integration tests only"
        echo "  security    - Run security tests only"
        echo "  performance - Run performance tests only"
        echo "  ml          - Run ML training pipeline tests only"
        echo "  compliance  - Run compliance tests only"
        echo "  fast        - Run fast tests (exclude slow tests)"
        echo "  coverage    - Run tests with coverage analysis"
        echo "  parallel    - Run tests in parallel"
        echo "  all         - Run complete test suite (default)"
        echo "  help        - Show this help message"
        echo ""
        echo "Examples:"
        echo "  $0                    # Run all tests"
        echo "  $0 unit              # Run only unit tests"
        echo "  $0 fast              # Run fast tests only"
        echo "  $0 coverage          # Run with coverage"
        echo ""
        exit 0
        ;;
    
    *)
        error "Unknown test type: $1"
        echo "Use '$0 help' to see available options"
        exit 1
        ;;
esac

# Generate test summary
if [ -d "$TEST_RESULTS_DIR" ]; then
    info "Test results saved in: $TEST_RESULTS_DIR"
    
    # Count XML files (test results)
    xml_count=$(find "$TEST_RESULTS_DIR" -name "*.xml" | wc -l)
    log_count=$(find "$TEST_RESULTS_DIR" -name "*.log" | wc -l)
    
    echo "Generated files:"
    echo "  - Test results (XML): $xml_count"
    echo "  - Test logs: $log_count"
    
    if [ -d "${TEST_RESULTS_DIR}/htmlcov" ]; then
        echo "  - Coverage report: ${TEST_RESULTS_DIR}/htmlcov/index.html"
    fi
fi

success "Test execution completed!"
