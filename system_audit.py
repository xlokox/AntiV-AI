#!/usr/bin/env python3
"""
Comprehensive System Audit for AntiV-AI
Performs end-to-end functional and operational checks
"""

import os
import sys
import subprocess
import time
import asyncio
import requests
import json
from pathlib import Path

class SystemAuditor:
    def __init__(self):
        self.results = {}
        self.project_root = Path.cwd()
        
    def run_command(self, command, timeout=30, capture_output=True):
        """Run a shell command and capture results"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=capture_output,
                text=True, 
                timeout=timeout,
                cwd=self.project_root
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': 'Command timed out',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }
    
    def test_backend_import(self):
        """Test if backend can be imported"""
        print("1. Testing Backend Service Import...")
        
        cmd = '''python -c "
import sys
sys.path.append('src')
try:
    from app import app
    print('SUCCESS: FastAPI app imports successfully')
except Exception as e:
    print(f'ERROR: {str(e)}')
    sys.exit(1)
"'''
        
        result = self.run_command(cmd)
        
        self.results['backend_import'] = {
            'status': '✅ Pass' if result['success'] else '❌ Fail',
            'command': 'python -c "import src.app"',
            'output': result['stdout'][:200] if result['stdout'] else result['stderr'][:200],
            'details': 'Backend service imports without errors' if result['success'] else 'Import failed'
        }
        
        return result['success']
    
    def test_cli_tools(self):
        """Test CLI tools functionality"""
        print("2. Testing CLI Tools...")
        
        # Test main.py help
        result1 = self.run_command("python main.py --help")
        
        # Test cli_dashboard.py help  
        result2 = self.run_command("python cli_dashboard.py --help")
        
        # Test file scan
        result3 = self.run_command("python main.py --file test_files/clean_document.txt")
        
        success = all([result1['success'], result2['success'], result3['success']])
        
        self.results['cli_tools'] = {
            'status': '✅ Pass' if success else '❌ Fail',
            'command': 'python main.py --help && python cli_dashboard.py --help && python main.py --file test_files/clean_document.txt',
            'output': f"main.py help: {result1['success']}, cli_dashboard.py help: {result2['success']}, file scan: {result3['success']}",
            'details': 'All CLI tools work correctly' if success else 'Some CLI tools failed'
        }
        
        return success
    
    def test_ml_training_pipeline(self):
        """Test ML training pipeline"""
        print("3. Testing ML Training Pipeline...")
        
        result = self.run_command("python scripts/train_models.py --verbose", timeout=120)
        
        # Check if model files were created
        model_files = [
            'models/behavioral_analysis.pkl',
            'models/isolation_forest.pkl', 
            'models/ensemble_model.pkl',
            'models/feature_scaler.pkl'
        ]
        
        models_exist = all(Path(f).exists() for f in model_files)
        success = result['success'] and models_exist
        
        self.results['ml_training'] = {
            'status': '✅ Pass' if success else '❌ Fail',
            'command': 'python scripts/train_models.py --verbose',
            'output': result['stdout'][-300:] if result['stdout'] else result['stderr'][-300:],
            'details': f'Training completed: {result["success"]}, Models created: {models_exist}'
        }
        
        return success
    
    def test_automated_tests(self):
        """Test automated test suite"""
        print("4. Testing Automated Tests...")
        
        result = self.run_command("pytest --maxfail=3 --disable-warnings -q", timeout=180)
        
        self.results['automated_tests'] = {
            'status': '✅ Pass' if result['success'] else '❌ Fail',
            'command': 'pytest --maxfail=3 --disable-warnings -q',
            'output': result['stdout'][-300:] if result['stdout'] else result['stderr'][-300:],
            'details': 'All tests passed' if result['success'] else 'Some tests failed'
        }
        
        return result['success']
    
    def test_compliance_script(self):
        """Test compliance automation script"""
        print("5. Testing Compliance Script...")
        
        result = self.run_command("bash scripts/compliance-check.sh", timeout=60)
        
        # Check if compliance log was created
        log_exists = Path('compliance-check.log').exists()
        
        self.results['compliance_script'] = {
            'status': '✅ Pass' if result['success'] else '❌ Fail',
            'command': 'bash scripts/compliance-check.sh',
            'output': result['stdout'][-300:] if result['stdout'] else result['stderr'][-300:],
            'details': f'Script exit code: {result["returncode"]}, Log created: {log_exists}'
        }
        
        return result['returncode'] == 0
    
    def test_docker_environment(self):
        """Test Docker environment"""
        print("6. Testing Docker Environment...")
        
        # Check if docker-compose.yml exists
        compose_exists = Path('docker-compose.yml').exists()
        
        # Test docker-compose config validation
        result = self.run_command("docker-compose config", timeout=30)
        
        self.results['docker_environment'] = {
            'status': '✅ Pass' if (result['success'] and compose_exists) else '❌ Fail',
            'command': 'docker-compose config',
            'output': result['stdout'][:200] if result['stdout'] else result['stderr'][:200],
            'details': f'Compose file exists: {compose_exists}, Config valid: {result["success"]}'
        }
        
        return result['success'] and compose_exists
    
    def test_ci_cd_pipeline(self):
        """Test CI/CD pipeline configuration"""
        print("7. Testing CI/CD Pipeline...")
        
        # Check for workflow files
        workflows = [
            '.github/workflows/ml-pipeline.yml',
            '.github/workflows/security-scan.yml'
        ]
        
        workflows_exist = all(Path(f).exists() for f in workflows)
        
        # Basic YAML syntax validation
        yaml_valid = True
        try:
            import yaml
            for workflow_file in workflows:
                if Path(workflow_file).exists():
                    with open(workflow_file, 'r') as f:
                        yaml.safe_load(f)
        except Exception:
            yaml_valid = False
        
        success = workflows_exist and yaml_valid
        
        self.results['ci_cd_pipeline'] = {
            'status': '✅ Pass' if success else '❌ Fail',
            'command': 'Check .github/workflows/*.yml files',
            'output': f'Workflows found: {workflows_exist}, YAML valid: {yaml_valid}',
            'details': 'CI/CD pipeline properly configured' if success else 'CI/CD configuration issues'
        }
        
        return success
    
    def test_frontend_setup(self):
        """Test frontend application setup"""
        print("8. Testing Frontend Setup...")
        
        # Check if frontend directory and package.json exist
        frontend_dir = Path('frontend')
        package_json = frontend_dir / 'package.json'
        
        setup_ok = frontend_dir.exists() and package_json.exists()
        
        # Check if node_modules exists (dependencies installed)
        node_modules = frontend_dir / 'node_modules'
        deps_installed = node_modules.exists()
        
        self.results['frontend_setup'] = {
            'status': '✅ Pass' if (setup_ok and deps_installed) else '❌ Fail',
            'command': 'Check frontend/ structure',
            'output': f'Frontend dir: {frontend_dir.exists()}, package.json: {package_json.exists()}, Dependencies: {deps_installed}',
            'details': 'Frontend properly set up' if (setup_ok and deps_installed) else 'Frontend setup incomplete'
        }
        
        return setup_ok and deps_installed
    
    def generate_report(self):
        """Generate comprehensive audit report"""
        print("\n" + "="*80)
        print("COMPREHENSIVE SYSTEM AUDIT REPORT")
        print("="*80)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results.values() if r['status'] == '✅ Pass')
        
        print(f"\nOVERALL SUMMARY")
        print(f"Tests Passed: {passed_tests}/{total_tests}")
        print(f"Success Rate: {(passed_tests/total_tests*100):.1f}%")
        
        print(f"\nDETAILED RESULTS")
        print("-" * 80)
        
        for component, result in self.results.items():
            print(f"\n{component.upper().replace('_', ' ')}")
            print(f"Status: {result['status']}")
            print(f"Command: {result['command']}")
            print(f"Output: {result['output']}")
            print(f"Details: {result['details']}")
            
        return passed_tests, total_tests

async def main():
    """Main audit function"""
    auditor = SystemAuditor()
    
    print("🔍 Starting Comprehensive System Audit...")
    print("="*80)
    
    # Run all tests
    tests = [
        auditor.test_backend_import,
        auditor.test_cli_tools, 
        auditor.test_ml_training_pipeline,
        auditor.test_automated_tests,
        auditor.test_compliance_script,
        auditor.test_docker_environment,
        auditor.test_ci_cd_pipeline,
        auditor.test_frontend_setup
    ]
    
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
    
    # Generate final report
    passed, total = auditor.generate_report()
    
    print(f"\n🏁 Audit Complete: {passed}/{total} tests passed")
    
    return passed == total

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)