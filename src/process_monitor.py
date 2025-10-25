"""
Real-Time Process and Behavioral Monitoring
Monitors system calls, process trees, filesystem changes, and network activity
"""

import os
import sys
import time
import json
import psutil
import threading
import platform
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass, asdict
import logging
from pathlib import Path

# Platform-specific imports
if platform.system() == "Windows":
    try:
        import wmi
        import win32evtlog
        import win32evtlogutil
        import win32con
        WMI_AVAILABLE = True
    except ImportError:
        WMI_AVAILABLE = False
        print("Warning: WMI not available. Install pywin32 for full Windows monitoring.")
else:
    WMI_AVAILABLE = False

# Check for psutil availability
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("Warning: psutil not available. Process monitoring will be limited.")

@dataclass
class ProcessEvent:
    """Process lifecycle event"""
    timestamp: str
    event_type: str  # created, terminated, modified
    pid: int
    ppid: int
    name: str
    cmdline: List[str]
    exe_path: str
    username: str
    risk_score: float = 0.0
    suspicious_indicators: List[str] = None

    def __post_init__(self):
        if self.suspicious_indicators is None:
            self.suspicious_indicators = []

@dataclass
class FileSystemEvent:
    """Filesystem change event"""
    timestamp: str
    event_type: str  # created, modified, deleted, moved
    path: str
    process_pid: int
    process_name: str
    file_size: int = 0
    risk_score: float = 0.0

@dataclass
class NetworkEvent:
    """Network activity event"""
    timestamp: str
    event_type: str  # connection, dns_query, http_request
    process_pid: int
    process_name: str
    local_addr: str
    remote_addr: str
    remote_port: int
    protocol: str
    data: Dict = None
    risk_score: float = 0.0

class ProcessMonitor:
    """Real-time process and behavioral monitoring system"""
    
    def __init__(self, callback: Optional[Callable] = None):
        """
        Initialize process monitor
        
        Args:
            callback: Function to call when events are detected
        """
        self.logger = logging.getLogger(__name__)
        self.callback = callback
        self.monitoring = False
        self.monitor_thread = None
        
        # Event storage
        self.process_events = []
        self.filesystem_events = []
        self.network_events = []
        
        # Process tracking
        self.known_processes = {}
        self.process_tree = {}
        
        # Monitoring configuration
        self.config = {
            'monitor_processes': True,
            'monitor_filesystem': True,
            'monitor_network': True,
            'monitor_registry': platform.system() == "Windows",
            'event_buffer_size': 1000,
            'scan_interval': 1.0,  # seconds
        }
        
        # Suspicious patterns
        self.suspicious_patterns = {
            'processes': [
                'powershell.exe -enc',  # Encoded PowerShell
                'cmd.exe /c echo',      # Command injection
                'rundll32.exe',         # DLL execution
                'regsvr32.exe',         # COM registration
                'mshta.exe',            # HTML Application
                'wscript.exe',          # Windows Script Host
                'cscript.exe',          # Console Script Host
            ],
            'files': [
                '.tmp',     # Temporary files
                '.exe',     # Executables
                '.scr',     # Screen savers
                '.bat',     # Batch files
                '.cmd',     # Command files
                '.ps1',     # PowerShell scripts
                '.vbs',     # VBScript files
                '.js',      # JavaScript files
            ],
            'network': [
                'pastebin.com',         # Common malware C&C
                'discord.com/api',      # Discord webhooks
                'raw.githubusercontent.com',  # Raw GitHub content
                'bit.ly',               # URL shorteners
                'tinyurl.com',
            ]
        }
        
        self.logger.info("Process monitor initialized")
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        if self.monitoring:
            self.logger.warning("Monitoring already active")
            return
        
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.monitor_thread.start()
        
        self.logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
        
        self.logger.info("Real-time monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                if self.config['monitor_processes']:
                    self._scan_processes()
                
                if self.config['monitor_network']:
                    self._scan_network_connections()
                
                if self.config['monitor_filesystem']:
                    self._scan_filesystem_changes()
                
                # Clean up old events
                self._cleanup_events()
                
                time.sleep(self.config['scan_interval'])
                
            except Exception as e:
                self.logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(5)  # Wait before retrying
    
    def _scan_processes(self):
        """Scan for new and modified processes"""
        if not PSUTIL_AVAILABLE:
            self.logger.warning("psutil not available, skipping process scan")
            return

        try:
            current_processes = {}

            for proc in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'exe', 'username', 'create_time']):
                try:
                    info = proc.info
                    pid = info['pid']
                    current_processes[pid] = info
                    
                    # Check for new processes
                    if pid not in self.known_processes:
                        event = self._create_process_event(info, 'created')
                        self._add_process_event(event)
                        
                        # Update process tree
                        ppid = info.get('ppid', 0)
                        if ppid not in self.process_tree:
                            self.process_tree[ppid] = []
                        self.process_tree[ppid].append(pid)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Check for terminated processes
            for pid in list(self.known_processes.keys()):
                if pid not in current_processes:
                    info = self.known_processes[pid]
                    event = self._create_process_event(info, 'terminated')
                    self._add_process_event(event)
                    
                    # Clean up process tree
                    if pid in self.process_tree:
                        del self.process_tree[pid]
            
            self.known_processes = current_processes
            
        except Exception as e:
            self.logger.error(f"Error scanning processes: {str(e)}")
    
    def _create_process_event(self, proc_info: Dict, event_type: str) -> ProcessEvent:
        """Create a process event from process info"""
        cmdline = proc_info.get('cmdline', []) or []
        cmdline_str = ' '.join(cmdline) if cmdline else ''
        
        # Calculate risk score based on suspicious patterns
        risk_score = 0.0
        suspicious_indicators = []
        
        # Check command line for suspicious patterns
        for pattern in self.suspicious_patterns['processes']:
            if pattern.lower() in cmdline_str.lower():
                risk_score += 0.3
                suspicious_indicators.append(f"suspicious_cmdline_{pattern}")
        
        # Check executable path
        exe_path = proc_info.get('exe', '') or ''
        if exe_path:
            # Check for execution from temp directories
            temp_dirs = ['/tmp/', 'C:\\Temp\\', 'C:\\Windows\\Temp\\', '%TEMP%']
            for temp_dir in temp_dirs:
                if temp_dir.lower() in exe_path.lower():
                    risk_score += 0.2
                    suspicious_indicators.append("execution_from_temp")
                    break
        
        # Check process name
        proc_name = proc_info.get('name', '') or ''
        suspicious_names = ['rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'powershell.exe']
        if proc_name.lower() in [name.lower() for name in suspicious_names]:
            risk_score += 0.1
            suspicious_indicators.append(f"suspicious_process_{proc_name}")
        
        return ProcessEvent(
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            pid=proc_info.get('pid', 0),
            ppid=proc_info.get('ppid', 0),
            name=proc_name,
            cmdline=cmdline,
            exe_path=exe_path,
            username=proc_info.get('username', '') or '',
            risk_score=min(risk_score, 1.0),
            suspicious_indicators=suspicious_indicators
        )
    
    def _scan_network_connections(self):
        """Scan for network connections"""
        if not PSUTIL_AVAILABLE:
            return

        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        proc_name = proc.name() if proc else 'unknown'
                        
                        # Check for suspicious remote addresses
                        risk_score = 0.0
                        remote_addr = conn.raddr.ip if conn.raddr else ''
                        
                        for suspicious_domain in self.suspicious_patterns['network']:
                            # This is a simplified check - in practice, you'd resolve IPs to domains
                            if suspicious_domain in remote_addr:
                                risk_score += 0.5
                                break
                        
                        event = NetworkEvent(
                            timestamp=datetime.now().isoformat(),
                            event_type='connection',
                            process_pid=conn.pid or 0,
                            process_name=proc_name,
                            local_addr=f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else '',
                            remote_addr=remote_addr,
                            remote_port=conn.raddr.port if conn.raddr else 0,
                            protocol='TCP' if conn.type == 1 else 'UDP',
                            risk_score=risk_score
                        )
                        
                        self._add_network_event(event)
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error scanning network connections: {str(e)}")
    
    def _scan_filesystem_changes(self):
        """Scan for filesystem changes (simplified implementation)"""
        # This is a basic implementation - for production, use inotify/ReadDirectoryChangesW
        try:
            # Monitor common suspicious directories
            watch_dirs = [
                '/tmp',
                '/var/tmp',
                os.path.expanduser('~/Downloads'),
                os.path.expanduser('~/Desktop'),
            ]
            
            if platform.system() == "Windows":
                watch_dirs.extend([
                    'C:\\Temp',
                    'C:\\Windows\\Temp',
                    os.path.expanduser('~\\Downloads'),
                    os.path.expanduser('~\\Desktop'),
                ])
            
            for watch_dir in watch_dirs:
                if os.path.exists(watch_dir):
                    self._scan_directory_for_changes(watch_dir)
                    
        except Exception as e:
            self.logger.error(f"Error scanning filesystem: {str(e)}")
    
    def _scan_directory_for_changes(self, directory: str):
        """Scan a directory for recent changes"""
        try:
            current_time = time.time()
            recent_threshold = 60  # Files modified in last 60 seconds
            
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        if current_time - stat.st_mtime < recent_threshold:
                            # File was recently modified
                            risk_score = 0.0
                            
                            # Check file extension
                            _, ext = os.path.splitext(file)
                            if ext.lower() in self.suspicious_patterns['files']:
                                risk_score += 0.2
                            
                            event = FileSystemEvent(
                                timestamp=datetime.now().isoformat(),
                                event_type='modified',
                                path=file_path,
                                process_pid=0,  # Would need process tracking to determine
                                process_name='unknown',
                                file_size=stat.st_size,
                                risk_score=risk_score
                            )
                            
                            self._add_filesystem_event(event)
                            
                    except (OSError, IOError):
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error scanning directory {directory}: {str(e)}")
    
    def _add_process_event(self, event: ProcessEvent):
        """Add process event to buffer"""
        self.process_events.append(event)
        if len(self.process_events) > self.config['event_buffer_size']:
            self.process_events.pop(0)
        
        if self.callback:
            self.callback('process', event)
        
        if event.risk_score > 0.5:
            self.logger.warning(f"Suspicious process event: {event.name} (PID: {event.pid}, Risk: {event.risk_score:.3f})")
    
    def _add_network_event(self, event: NetworkEvent):
        """Add network event to buffer"""
        self.network_events.append(event)
        if len(self.network_events) > self.config['event_buffer_size']:
            self.network_events.pop(0)
        
        if self.callback:
            self.callback('network', event)
        
        if event.risk_score > 0.3:
            self.logger.warning(f"Suspicious network event: {event.process_name} -> {event.remote_addr}:{event.remote_port}")
    
    def _add_filesystem_event(self, event: FileSystemEvent):
        """Add filesystem event to buffer"""
        self.filesystem_events.append(event)
        if len(self.filesystem_events) > self.config['event_buffer_size']:
            self.filesystem_events.pop(0)
        
        if self.callback:
            self.callback('filesystem', event)
        
        if event.risk_score > 0.3:
            self.logger.warning(f"Suspicious filesystem event: {event.path}")
    
    def _cleanup_events(self):
        """Clean up old events to prevent memory leaks"""
        max_age = 3600  # 1 hour
        current_time = time.time()
        
        # This is a simplified cleanup - in practice, you'd parse timestamps
        if len(self.process_events) > self.config['event_buffer_size'] * 2:
            self.process_events = self.process_events[-self.config['event_buffer_size']:]
        
        if len(self.network_events) > self.config['event_buffer_size'] * 2:
            self.network_events = self.network_events[-self.config['event_buffer_size']:]
        
        if len(self.filesystem_events) > self.config['event_buffer_size'] * 2:
            self.filesystem_events = self.filesystem_events[-self.config['event_buffer_size']:]
    
    def get_recent_events(self, event_type: str = 'all', limit: int = 100) -> List[Dict]:
        """Get recent events"""
        events = []
        
        if event_type in ['all', 'process']:
            events.extend([asdict(event) for event in self.process_events[-limit:]])
        
        if event_type in ['all', 'network']:
            events.extend([asdict(event) for event in self.network_events[-limit:]])
        
        if event_type in ['all', 'filesystem']:
            events.extend([asdict(event) for event in self.filesystem_events[-limit:]])
        
        # Sort by timestamp
        events.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return events[:limit]
    
    def get_process_tree(self) -> Dict:
        """Get current process tree"""
        return self.process_tree.copy()
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        return {
            'monitoring_active': self.monitoring,
            'total_process_events': len(self.process_events),
            'total_network_events': len(self.network_events),
            'total_filesystem_events': len(self.filesystem_events),
            'known_processes': len(self.known_processes),
            'process_tree_size': len(self.process_tree),
            'config': self.config.copy()
        }
