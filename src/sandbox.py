"""
Lightweight Sandbox Environment for AntiV-AI
Executes flagged files in isolated Docker containers for behavior analysis
"""

import os
import json
import time
import tempfile
import logging
import threading
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from pathlib import Path

# Optional Docker import
try:
    import docker
    DOCKER_AVAILABLE = True
except ImportError:
    DOCKER_AVAILABLE = False
    docker = None

@dataclass
class SandboxExecution:
    """Sandbox execution record"""
    execution_id: str
    file_path: str
    file_hash: str
    container_id: str
    start_time: str
    end_time: Optional[str]
    status: str  # running, completed, failed, timeout
    exit_code: Optional[int]
    execution_time: float
    behavior_log: List[Dict]
    network_activity: List[Dict]
    filesystem_changes: List[Dict]
    risk_assessment: Dict

class SandboxManager:
    """Manages sandbox execution of suspicious files"""
    
    def __init__(self, docker_image: str = "ubuntu:20.04", timeout: int = 300):
        """
        Initialize sandbox manager
        
        Args:
            docker_image: Docker image to use for sandbox
            timeout: Maximum execution time in seconds
        """
        self.logger = logging.getLogger(__name__)
        self.docker_image = docker_image
        self.timeout = timeout
        
        # Initialize Docker client
        if DOCKER_AVAILABLE:
            try:
                self.docker_client = docker.from_env()
                self.docker_available = True
                self.logger.info("Docker client initialized successfully")
            except Exception as e:
                self.docker_available = False
                self.logger.error(f"Docker not available: {str(e)}")
        else:
            self.docker_available = False
            self.docker_client = None
            self.logger.warning("Docker module not installed. Sandbox functionality will be limited.")
        
        # Sandbox configuration
        self.sandbox_config = {
            'memory_limit': '512m',
            'cpu_limit': '0.5',
            'network_mode': 'none',  # Isolated network
            'read_only': False,
            'security_opt': ['no-new-privileges:true'],
            'cap_drop': ['ALL'],
            'cap_add': ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETGID', 'SETUID'],
        }
        
        # Execution tracking
        self.active_executions = {}
        self.execution_history = []
        
        # Ensure sandbox image is available
        if self.docker_available:
            self._prepare_sandbox_image()
    
    def _prepare_sandbox_image(self):
        """Prepare or build sandbox Docker image"""
        try:
            # Try to pull the base image
            self.docker_client.images.pull(self.docker_image)
            self.logger.info(f"Docker image {self.docker_image} ready")
            
            # Create custom sandbox image with monitoring tools
            dockerfile_content = f"""
FROM {self.docker_image}

# Install monitoring and analysis tools
RUN apt-get update && apt-get install -y \\
    strace \\
    tcpdump \\
    netstat-nat \\
    lsof \\
    procfs \\
    python3 \\
    python3-pip \\
    curl \\
    wget \\
    file \\
    && rm -rf /var/lib/apt/lists/*

# Create sandbox user
RUN useradd -m -s /bin/bash sandbox

# Create monitoring script
COPY monitor.py /usr/local/bin/monitor.py
RUN chmod +x /usr/local/bin/monitor.py

# Set working directory
WORKDIR /sandbox

# Switch to sandbox user
USER sandbox

# Default command
CMD ["/bin/bash"]
"""
            
            # Create monitoring script
            monitor_script = '''#!/usr/bin/env python3
import os
import sys
import json
import time
import subprocess
import threading
from datetime import datetime

class SandboxMonitor:
    def __init__(self):
        self.start_time = time.time()
        self.behavior_log = []
        self.network_activity = []
        self.filesystem_changes = []
        
    def log_event(self, event_type, data):
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "data": data
        }
        self.behavior_log.append(event)
        
    def monitor_process(self, pid):
        """Monitor process using strace"""
        try:
            cmd = ["strace", "-p", str(pid), "-f", "-e", "trace=file,network,process"]
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            for line in proc.stderr:
                if line.strip():
                    self.log_event("syscall", {"line": line.strip()})
                    
        except Exception as e:
            self.log_event("error", {"message": f"Process monitoring error: {str(e)}"})
    
    def monitor_network(self):
        """Monitor network activity"""
        try:
            # Monitor network connections
            result = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True)
            if result.stdout:
                self.log_event("network", {"netstat": result.stdout})
                
        except Exception as e:
            self.log_event("error", {"message": f"Network monitoring error: {str(e)}"})
    
    def monitor_filesystem(self):
        """Monitor filesystem changes"""
        try:
            # List files in common directories
            for directory in ["/tmp", "/var/tmp", "/home/sandbox"]:
                if os.path.exists(directory):
                    files = os.listdir(directory)
                    self.log_event("filesystem", {"directory": directory, "files": files})
                    
        except Exception as e:
            self.log_event("error", {"message": f"Filesystem monitoring error: {str(e)}"})
    
    def execute_file(self, file_path):
        """Execute file and monitor behavior"""
        try:
            self.log_event("execution_start", {"file": file_path})
            
            # Start monitoring threads
            monitor_thread = threading.Thread(target=self.monitor_network)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            fs_thread = threading.Thread(target=self.monitor_filesystem)
            fs_thread.daemon = True
            fs_thread.start()
            
            # Execute the file
            if os.access(file_path, os.X_OK):
                proc = subprocess.Popen([file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                
                # Monitor the process
                proc_thread = threading.Thread(target=self.monitor_process, args=(proc.pid,))
                proc_thread.daemon = True
                proc_thread.start()
                
                # Wait for completion
                stdout, stderr = proc.communicate(timeout=60)
                
                self.log_event("execution_complete", {
                    "exit_code": proc.returncode,
                    "stdout": stdout.decode('utf-8', errors='ignore'),
                    "stderr": stderr.decode('utf-8', errors='ignore')
                })
                
                return proc.returncode
            else:
                self.log_event("execution_error", {"message": "File not executable"})
                return -1
                
        except subprocess.TimeoutExpired:
            self.log_event("execution_timeout", {"message": "Execution timed out"})
            proc.kill()
            return -2
        except Exception as e:
            self.log_event("execution_error", {"message": str(e)})
            return -3
    
    def save_results(self, output_file):
        """Save monitoring results"""
        results = {
            "execution_time": time.time() - self.start_time,
            "behavior_log": self.behavior_log,
            "network_activity": self.network_activity,
            "filesystem_changes": self.filesystem_changes
        }
        
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: monitor.py <file_to_execute> <output_file>")
        sys.exit(1)
    
    file_to_execute = sys.argv[1]
    output_file = sys.argv[2]
    
    monitor = SandboxMonitor()
    exit_code = monitor.execute_file(file_to_execute)
    monitor.save_results(output_file)
    
    sys.exit(exit_code)
'''
            
            # Build custom sandbox image
            with tempfile.TemporaryDirectory() as build_dir:
                dockerfile_path = os.path.join(build_dir, 'Dockerfile')
                monitor_path = os.path.join(build_dir, 'monitor.py')
                
                with open(dockerfile_path, 'w') as f:
                    f.write(dockerfile_content)
                
                with open(monitor_path, 'w') as f:
                    f.write(monitor_script)
                
                # Build image
                try:
                    self.docker_client.images.build(
                        path=build_dir,
                        tag='antiv-ai-sandbox:latest',
                        rm=True
                    )
                    self.docker_image = 'antiv-ai-sandbox:latest'
                    self.logger.info("Custom sandbox image built successfully")
                except Exception as e:
                    self.logger.warning(f"Failed to build custom image, using base image: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Error preparing sandbox image: {str(e)}")
    
    def execute_in_sandbox(self, file_path: str, file_hash: str) -> Optional[SandboxExecution]:
        """
        Execute file in sandbox environment
        
        Args:
            file_path: Path to file to execute
            file_hash: SHA-256 hash of file
            
        Returns:
            SandboxExecution record if successful, None otherwise
        """
        if not self.docker_available:
            self.logger.error("Docker not available for sandbox execution")
            return None
        
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return None
        
        execution_id = f"exec_{file_hash}_{int(time.time())}"
        start_time = datetime.now()
        
        try:
            # Create temporary directory for sandbox files
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy file to sandbox directory
                sandbox_file = os.path.join(temp_dir, "target_file")
                with open(file_path, 'rb') as src, open(sandbox_file, 'wb') as dst:
                    dst.write(src.read())
                
                # Make file executable
                os.chmod(sandbox_file, 0o755)
                
                # Results file
                results_file = os.path.join(temp_dir, "results.json")
                
                # Create container
                container = self.docker_client.containers.create(
                    image=self.docker_image,
                    command=[
                        "python3", "/usr/local/bin/monitor.py",
                        "/sandbox/target_file",
                        "/sandbox/results.json"
                    ],
                    volumes={
                        temp_dir: {'bind': '/sandbox', 'mode': 'rw'}
                    },
                    mem_limit=self.sandbox_config['memory_limit'],
                    cpu_period=100000,
                    cpu_quota=int(50000 * float(self.sandbox_config['cpu_limit'])),
                    network_mode=self.sandbox_config['network_mode'],
                    security_opt=self.sandbox_config['security_opt'],
                    cap_drop=self.sandbox_config['cap_drop'],
                    cap_add=self.sandbox_config['cap_add'],
                    detach=True,
                    remove=True
                )
                
                # Start container
                container.start()
                container_id = container.id
                
                self.logger.info(f"Sandbox execution started: {execution_id} in container {container_id[:12]}")
                
                # Create execution record
                execution = SandboxExecution(
                    execution_id=execution_id,
                    file_path=file_path,
                    file_hash=file_hash,
                    container_id=container_id,
                    start_time=start_time.isoformat(),
                    end_time=None,
                    status='running',
                    exit_code=None,
                    execution_time=0.0,
                    behavior_log=[],
                    network_activity=[],
                    filesystem_changes=[],
                    risk_assessment={}
                )
                
                self.active_executions[execution_id] = execution
                
                # Wait for completion with timeout
                try:
                    result = container.wait(timeout=self.timeout)
                    exit_code = result['StatusCode']
                    status = 'completed'
                    
                except Exception as e:
                    # Timeout or error
                    try:
                        container.kill()
                    except:
                        pass
                    exit_code = -1
                    status = 'timeout' if 'timeout' in str(e).lower() else 'failed'
                
                end_time = datetime.now()
                execution_time = (end_time - start_time).total_seconds()
                
                # Read results if available
                behavior_log = []
                network_activity = []
                filesystem_changes = []
                
                if os.path.exists(results_file):
                    try:
                        with open(results_file, 'r') as f:
                            results = json.load(f)
                            behavior_log = results.get('behavior_log', [])
                            network_activity = results.get('network_activity', [])
                            filesystem_changes = results.get('filesystem_changes', [])
                    except Exception as e:
                        self.logger.error(f"Error reading sandbox results: {str(e)}")
                
                # Perform risk assessment
                risk_assessment = self._assess_sandbox_behavior(
                    behavior_log, network_activity, filesystem_changes, exit_code
                )
                
                # Update execution record
                execution.end_time = end_time.isoformat()
                execution.status = status
                execution.exit_code = exit_code
                execution.execution_time = execution_time
                execution.behavior_log = behavior_log
                execution.network_activity = network_activity
                execution.filesystem_changes = filesystem_changes
                execution.risk_assessment = risk_assessment
                
                # Move to history
                if execution_id in self.active_executions:
                    del self.active_executions[execution_id]
                
                self.execution_history.append(execution)
                
                # Keep only recent history
                if len(self.execution_history) > 100:
                    self.execution_history = self.execution_history[-100:]
                
                self.logger.info(f"Sandbox execution completed: {execution_id} (Status: {status}, Risk: {risk_assessment.get('total_risk_score', 0):.3f})")
                
                return execution
                
        except Exception as e:
            self.logger.error(f"Error in sandbox execution {execution_id}: {str(e)}")
            
            # Clean up
            if execution_id in self.active_executions:
                execution = self.active_executions[execution_id]
                execution.status = 'failed'
                execution.end_time = datetime.now().isoformat()
                del self.active_executions[execution_id]
                self.execution_history.append(execution)
            
            return None
    
    def _assess_sandbox_behavior(self, behavior_log: List[Dict], network_activity: List[Dict], 
                                filesystem_changes: List[Dict], exit_code: int) -> Dict:
        """Assess risk based on sandbox behavior"""
        risk_score = 0.0
        risk_factors = []
        
        # Analyze behavior log
        for event in behavior_log:
            event_type = event.get('type', '')
            data = event.get('data', {})
            
            if event_type == 'syscall':
                line = data.get('line', '').lower()
                
                # Check for suspicious system calls
                if any(call in line for call in ['execve', 'fork', 'clone']):
                    risk_score += 0.1
                    risk_factors.append('process_creation')
                
                if any(call in line for call in ['socket', 'connect', 'bind']):
                    risk_score += 0.2
                    risk_factors.append('network_activity')
                
                if any(call in line for call in ['unlink', 'rmdir', 'rename']):
                    risk_score += 0.1
                    risk_factors.append('file_deletion')
            
            elif event_type == 'execution_timeout':
                risk_score += 0.3
                risk_factors.append('execution_timeout')
            
            elif event_type == 'execution_error':
                risk_score += 0.2
                risk_factors.append('execution_error')
        
        # Analyze network activity
        if network_activity:
            risk_score += 0.3
            risk_factors.append('network_connections')
        
        # Analyze filesystem changes
        for change in filesystem_changes:
            directory = change.get('directory', '')
            files = change.get('files', [])
            
            if '/tmp' in directory and files:
                risk_score += 0.2
                risk_factors.append('temp_file_creation')
        
        # Exit code analysis
        if exit_code != 0:
            risk_score += 0.1
            risk_factors.append('abnormal_exit')
        
        return {
            'total_risk_score': min(risk_score, 1.0),
            'risk_factors': list(set(risk_factors)),
            'behavior_events': len(behavior_log),
            'network_events': len(network_activity),
            'filesystem_events': len(filesystem_changes),
            'exit_code': exit_code
        }
    
    def get_execution_status(self, execution_id: str) -> Optional[Dict]:
        """Get status of sandbox execution"""
        if execution_id in self.active_executions:
            return asdict(self.active_executions[execution_id])
        
        for execution in self.execution_history:
            if execution.execution_id == execution_id:
                return asdict(execution)
        
        return None
    
    def list_executions(self, limit: int = 50) -> List[Dict]:
        """List recent sandbox executions"""
        all_executions = list(self.active_executions.values()) + self.execution_history
        all_executions.sort(key=lambda x: x.start_time, reverse=True)
        
        return [asdict(execution) for execution in all_executions[:limit]]
    
    def get_sandbox_statistics(self) -> Dict:
        """Get sandbox statistics"""
        total_executions = len(self.execution_history)
        active_executions = len(self.active_executions)
        
        # Calculate success rate
        completed_executions = [e for e in self.execution_history if e.status == 'completed']
        success_rate = len(completed_executions) / total_executions if total_executions > 0 else 0
        
        # Average execution time
        avg_execution_time = sum(e.execution_time for e in completed_executions) / len(completed_executions) if completed_executions else 0
        
        # Risk distribution
        risk_scores = [e.risk_assessment.get('total_risk_score', 0) for e in self.execution_history]
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        
        return {
            'docker_available': self.docker_available,
            'total_executions': total_executions,
            'active_executions': active_executions,
            'success_rate': success_rate,
            'average_execution_time': avg_execution_time,
            'average_risk_score': avg_risk_score,
            'sandbox_config': self.sandbox_config.copy()
        }
    
    def cleanup_old_executions(self, max_age_hours: int = 24) -> int:
        """Clean up old execution records"""
        from datetime import timedelta
        
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        cutoff_str = cutoff_time.isoformat()
        
        original_count = len(self.execution_history)
        self.execution_history = [
            e for e in self.execution_history 
            if e.start_time > cutoff_str
        ]
        
        cleaned_count = original_count - len(self.execution_history)
        
        if cleaned_count > 0:
            self.logger.info(f"Cleaned up {cleaned_count} old sandbox execution records")
        
        return cleaned_count
