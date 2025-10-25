"""
AntiV-AI Main Engine
Integrates file analysis, database logging, and alerting system
"""

import os
import logging
import asyncio
import hashlib
from typing import Dict, List, Optional
from dataclasses import asdict
from file_analysis import FileAnalyzer
from database import ScanDatabase
from process_monitor import ProcessMonitor
from quarantine import QuarantineManager
from sandbox import SandboxManager
from threat_intel import threat_intel
from ml_detector import ml_detector
from blockchain_audit import blockchain_audit
from integrations.slack_notifier import slack_notifier
from performance import redis_cache, parallel_scanner

class AntiVEngine:
    """Main antivirus engine that coordinates all components"""
    
    def __init__(self, log_level=logging.INFO):
        """
        Initialize the AntiV-AI engine
        
        Args:
            log_level: Logging level for the engine
        """
        self.setup_logging(log_level)
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.file_analyzer = FileAnalyzer(log_level)
        self.database = ScanDatabase()
        self.process_monitor = ProcessMonitor(callback=self._handle_monitoring_event)
        self.quarantine_manager = QuarantineManager()
        self.sandbox_manager = SandboxManager()

        # Configuration
        self.alert_threshold = 0.6
        self.auto_quarantine = True
        self.auto_sandbox = True

        self.logger.info("AntiV-AI Engine initialized successfully")
    
    def setup_logging(self, level):
        """Configure logging for the main engine"""
        os.makedirs('logs', exist_ok=True)
        
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/antiv_engine.log'),
                logging.StreamHandler()
            ]
        )
    
    async def scan_file(self, file_path: str) -> Dict:
        """
        Perform complete file scan with analysis, logging, and alerting
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary containing scan results and actions taken
        """
        self.logger.info(f"Starting scan for: {file_path}")
        
        # Perform file analysis
        analysis_result = self.file_analyzer.analyze_file(file_path)

        if 'error' in analysis_result:
            self.logger.error(f"Scan failed for {file_path}: {analysis_result['error']}")
            return {
                'success': False,
                'error': analysis_result['error'],
                'file_path': file_path
            }

        # Get file hash for threat intelligence lookup
        file_hash = analysis_result.get('sha256', '')
        threat_intel_result = None

        # Perform threat intelligence lookup
        if file_hash:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                async def get_threat_intel():
                    async with threat_intel as ti:
                        return await ti.check_reputation(file_hash)

                threat_intel_result = loop.run_until_complete(get_threat_intel())
                loop.close()

                self.logger.info(f"Threat intelligence: {threat_intel_result.overall_threat_level} "
                               f"(Score: {threat_intel_result.overall_reputation_score:.3f})")

            except Exception as e:
                self.logger.warning(f"Threat intelligence lookup failed: {str(e)}")

        # Perform ML behavioral analysis
        ml_prediction = None
        ml_score = 0.0

        try:
            ml_prediction = await ml_detector.analyze_behavior(file_path, analysis_result)
            ml_score = ml_prediction.confidence_score

            self.logger.info(f"ML analysis: Confidence {ml_prediction.confidence_score:.3f}, "
                           f"Threat probability {ml_prediction.threat_probability:.3f}")

        except Exception as e:
            self.logger.warning(f"ML behavioral analysis failed: {str(e)}")

        # Integrate all scores: static analysis, threat intelligence, and ML
        base_risk_score = analysis_result.get('risk_score', 0.0)
        threat_intel_score = 0.0

        if threat_intel_result:
            threat_intel_score = threat_intel_result.overall_reputation_score

        # Advanced scoring: 40% static, 30% threat intel, 30% ML
        if threat_intel_result and ml_prediction:
            risk_score = (base_risk_score * 0.4) + (threat_intel_score * 0.3) + (ml_score * 0.3)
        elif threat_intel_result:
            # Fallback: 60% static, 40% threat intel
            risk_score = (base_risk_score * 0.6) + (threat_intel_score * 0.4)
        elif ml_prediction:
            # Fallback: 60% static, 40% ML
            risk_score = (base_risk_score * 0.6) + (ml_score * 0.4)
        else:
            # Static analysis only
            risk_score = base_risk_score

        # Update threat level based on combined analysis
        if risk_score >= 0.8:
            threat_level = "HIGH"
        elif risk_score >= 0.6:
            threat_level = "MEDIUM"
        elif risk_score >= 0.3:
            threat_level = "LOW"
        else:
            threat_level = "CLEAN"

        analysis_result['threat_level'] = threat_level
        analysis_result['risk_score'] = risk_score
        analysis_result['threat_intel_score'] = threat_intel_score
        analysis_result['ml_score'] = ml_score

        # Check if file should be flagged
        flagged = risk_score > self.alert_threshold

        # Store scan result in database
        storage_success = self.database.store_scan_result(analysis_result)

        # Add to blockchain audit trail
        try:
            audit_entry = blockchain_audit.create_audit_entry(
                event_type="file_scan",
                action=f"scan_file",
                resource=file_path,
                outcome="SUCCESS" if analysis_result.get('success', False) else "FAILURE",
                details={
                    'file_hash': analysis_result.get('sha256', ''),
                    'file_size': analysis_result.get('file_size', 0),
                    'risk_score': risk_score,
                    'threat_level': analysis_result.get('threat_level', 'UNKNOWN'),
                    'flagged': flagged,
                    'threat_intel_available': threat_intel_result is not None,
                    'ml_analysis_available': ml_prediction is not None,
                    'quarantined': False,  # Will be updated later
                    'sandbox_executed': False  # Will be updated later
                },
                user_id=None,  # System scan
                username="system",
                risk_score=risk_score,
                source_ip="127.0.0.1",
                session_id=None
            )

            blockchain_audit.add_audit_entry(audit_entry)

        except Exception as e:
            self.logger.error(f"Error adding scan to blockchain audit: {str(e)}")

        # Create alert if necessary
        alert_created = False
        quarantined = False
        sandbox_execution_id = None

        if flagged:
            alert_reason = f"Risk score {risk_score:.3f} exceeds threshold {self.alert_threshold}"
            alert_created = self.database.create_alert(analysis_result, alert_reason)

            # Send Slack notification for high-risk files
            try:
                if risk_score >= 0.7:  # High or critical risk
                    slack_alert = slack_notifier.create_scan_alert(
                        file_path=file_path,
                        risk_score=risk_score,
                        threat_level=analysis_result.get('threat_level', 'UNKNOWN'),
                        file_hash=analysis_result.get('sha256', ''),
                        details={
                            'file_size': analysis_result.get('file_size', 0),
                            'entropy': analysis_result.get('entropy', 0.0),
                            'threat_intel_score': threat_intel_score,
                            'ml_score': ml_score,
                            'scan_timestamp': analysis_result.get('scan_timestamp', ''),
                            'alert_reason': alert_reason
                        }
                    )

                    # Send notification asynchronously
                    asyncio.create_task(slack_notifier.send_alert(slack_alert))

            except Exception as e:
                self.logger.error(f"Error sending Slack notification: {str(e)}")

            # Auto-quarantine high-risk files
            if self.auto_quarantine and self.quarantine_manager.should_quarantine(risk_score, analysis_result.get('threat_level', 'UNKNOWN')):
                quarantine_entry = self.quarantine_manager.quarantine_file(
                    file_path, risk_score, analysis_result.get('threat_level', 'UNKNOWN'), alert_reason
                )
                quarantined = quarantine_entry is not None

            # Auto-sandbox execution for analysis
            if self.auto_sandbox and risk_score >= 0.7:
                try:
                    sandbox_execution = self.sandbox_manager.execute_in_sandbox(
                        file_path, analysis_result.get('sha256', '')
                    )
                    if sandbox_execution:
                        sandbox_execution_id = sandbox_execution.execution_id
                except Exception as e:
                    self.logger.error(f"Sandbox execution failed: {str(e)}")
        
        # Prepare response
        scan_response = {
            'success': True,
            'file_path': file_path,
            'risk_score': risk_score,
            'base_risk_score': base_risk_score,
            'threat_intel_score': threat_intel_score,
            'threat_level': analysis_result.get('threat_level', 'UNKNOWN'),
            'flagged': flagged,
            'alert_created': alert_created,
            'quarantined': quarantined,
            'sandbox_execution_id': sandbox_execution_id,
            'storage_success': storage_success,
            'scan_timestamp': analysis_result.get('scan_timestamp', ''),
            'analysis_details': {
                'sha256': analysis_result.get('sha256', ''),
                'md5': analysis_result.get('md5', ''),
                'entropy': analysis_result.get('entropy', 0.0),
                'file_size': analysis_result.get('file_size', 0),
                'pe_analysis': analysis_result.get('pe_analysis', {})
            },
            'threat_intelligence': {
                'available': threat_intel_result is not None,
                'overall_score': threat_intel_result.overall_reputation_score if threat_intel_result else 0.0,
                'overall_threat_level': threat_intel_result.overall_threat_level if threat_intel_result else 'UNKNOWN',
                'confidence': threat_intel_result.confidence_score if threat_intel_result else 0.0,
                'recommendation': threat_intel_result.recommendation if threat_intel_result else 'No data available',
                'sources': len(threat_intel_result.source_results) if threat_intel_result else 0,
                'source_details': [
                    {
                        'source': r.source,
                        'reputation_score': r.reputation_score,
                        'threat_level': r.threat_level,
                        'detections': r.detections,
                        'total_scans': r.total_scans,
                        'cached': r.cached
                    } for r in threat_intel_result.source_results
                ] if threat_intel_result else []
            }
        }
        
        # Log scan completion
        status = "FLAGGED" if flagged else "CLEAN"
        self.logger.info(f"Scan complete for {file_path}: {status} (Risk: {risk_score:.3f})")
        
        return scan_response

    async def scan_multiple_files(self, file_paths: List[str]) -> List[Dict]:
        """
        Scan multiple files in parallel for improved performance

        Args:
            file_paths: List of file paths to scan

        Returns:
            List of scan results
        """
        if not file_paths:
            return []

        self.logger.info(f"Starting parallel scan of {len(file_paths)} files")

        try:
            # Use parallel scanner for multiple files
            results = await parallel_scanner.scan_files_async(
                self.scan_file, file_paths
            )

            # Filter out None results and add metadata
            valid_results = []
            for i, result in enumerate(results):
                if result:
                    result['batch_scan'] = True
                    result['batch_index'] = i
                    result['batch_size'] = len(file_paths)
                    valid_results.append(result)

            self.logger.info(f"Completed parallel scan: {len(valid_results)}/{len(file_paths)} successful")

            return valid_results

        except Exception as e:
            self.logger.error(f"Parallel file scanning failed: {str(e)}")
            # Fallback to sequential scanning
            results = []
            for file_path in file_paths:
                try:
                    result = await self.scan_file(file_path)
                    if result:
                        result['batch_scan'] = True
                        result['sequential_fallback'] = True
                        results.append(result)
                except Exception as e:
                    self.logger.error(f"Sequential scan failed for {file_path}: {str(e)}")

            return results

    def get_performance_stats(self) -> Dict:
        """Get performance statistics for caching and parallel processing"""
        try:
            cache_stats = redis_cache.get_metrics()
            scanner_stats = parallel_scanner.get_stats()

            return {
                'cache_performance': cache_stats,
                'parallel_scanning': scanner_stats,
                'timestamp': datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Error getting performance stats: {str(e)}")
            return {'error': str(e)}

    async def scan_directory(self, directory_path: str, recursive: bool = True,
                      file_extensions: Optional[List[str]] = None) -> Dict:
        """
        Scan all files in a directory
        
        Args:
            directory_path: Path to directory to scan
            recursive: Whether to scan subdirectories
            file_extensions: List of file extensions to scan (None for all)
            
        Returns:
            Dictionary containing batch scan results
        """
        if not os.path.exists(directory_path):
            self.logger.error(f"Directory not found: {directory_path}")
            return {'success': False, 'error': 'Directory not found'}
        
        self.logger.info(f"Starting directory scan: {directory_path}")
        
        # Default suspicious file extensions if none specified
        if file_extensions is None:
            file_extensions = ['.exe', '.dll', '.scr', '.bat', '.cmd', '.com', '.pif', '.jar']
        
        scan_results = []
        total_files = 0
        flagged_files = 0
        errors = 0
        
        # Walk through directory
        for root, dirs, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                
                # Check file extension filter
                if file_extensions and not any(file.lower().endswith(ext) for ext in file_extensions):
                    continue
                
                total_files += 1
                
                # Scan individual file
                scan_result = await self.scan_file(file_path)
                scan_results.append(scan_result)
                
                if scan_result.get('success', False):
                    if scan_result.get('flagged', False):
                        flagged_files += 1
                else:
                    errors += 1
            
            # Stop recursion if not requested
            if not recursive:
                break
        
        batch_result = {
            'success': True,
            'directory_path': directory_path,
            'total_files_scanned': total_files,
            'flagged_files': flagged_files,
            'errors': errors,
            'scan_results': scan_results
        }
        
        self.logger.info(f"Directory scan complete: {total_files} files, {flagged_files} flagged, {errors} errors")
        
        return batch_result
    
    def get_scan_statistics(self) -> Dict:
        """
        Get overall scan statistics
        
        Returns:
            Dictionary containing scan statistics
        """
        try:
            scan_history = self.database.get_scan_history(limit=1000)
            flagged_files = self.database.get_flagged_files()
            
            # Calculate statistics
            total_scans = len(scan_history)
            total_flagged = len(flagged_files)
            
            threat_levels = {}
            for scan in scan_history:
                level = scan.get('threat_level', 'UNKNOWN')
                threat_levels[level] = threat_levels.get(level, 0) + 1
            
            avg_risk_score = 0.0
            if scan_history:
                avg_risk_score = sum(scan.get('risk_score', 0) for scan in scan_history) / len(scan_history)
            
            return {
                'total_scans': total_scans,
                'total_flagged': total_flagged,
                'flagged_percentage': (total_flagged / total_scans * 100) if total_scans > 0 else 0,
                'average_risk_score': avg_risk_score,
                'threat_level_distribution': threat_levels,
                'recent_flagged_files': [f['file_path'] for f in flagged_files[:10]]
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating statistics: {str(e)}")
            return {'error': str(e)}
    
    def set_alert_threshold(self, threshold: float):
        """
        Set the risk score threshold for alerts
        
        Args:
            threshold: New threshold value (0.0-1.0)
        """
        if 0.0 <= threshold <= 1.0:
            self.alert_threshold = threshold
            self.logger.info(f"Alert threshold set to {threshold}")
        else:
            self.logger.error(f"Invalid threshold value: {threshold}. Must be between 0.0 and 1.0")
    
    def get_flagged_files(self) -> List[Dict]:
        """
        Get all currently flagged files
        
        Returns:
            List of flagged file information
        """
        return self.database.get_flagged_files()
    
    def get_recent_scans(self, limit: int = 50) -> List[Dict]:
        """
        Get recent scan history
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of recent scan results
        """
        return self.database.get_scan_history(limit)

    def _handle_monitoring_event(self, event_type: str, event_data):
        """Handle real-time monitoring events"""
        try:
            # Log high-risk events
            if hasattr(event_data, 'risk_score') and event_data.risk_score > 0.5:
                self.logger.warning(f"High-risk {event_type} event detected: {event_data}")

                # Store event in database for analysis
                # This could be extended to trigger automatic responses

        except Exception as e:
            self.logger.error(f"Error handling monitoring event: {str(e)}")

    def start_real_time_monitoring(self):
        """Start real-time process and behavior monitoring"""
        try:
            self.process_monitor.start_monitoring()
            self.logger.info("Real-time monitoring started")
            return True
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {str(e)}")
            return False

    def stop_real_time_monitoring(self):
        """Stop real-time monitoring"""
        try:
            self.process_monitor.stop_monitoring()
            self.logger.info("Real-time monitoring stopped")
            return True
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring: {str(e)}")
            return False

    def get_monitoring_events(self, event_type: str = 'all', limit: int = 100) -> List[Dict]:
        """Get recent monitoring events"""
        return self.process_monitor.get_recent_events(event_type, limit)

    def get_process_tree(self) -> Dict:
        """Get current process tree"""
        return self.process_monitor.get_process_tree()

    def get_quarantined_files(self) -> List[Dict]:
        """Get list of quarantined files"""
        entries = self.quarantine_manager.list_quarantined_files()
        return [asdict(entry) for entry in entries]

    def restore_quarantined_file(self, quarantine_id: str, restore_path: Optional[str] = None) -> bool:
        """Restore a quarantined file"""
        return self.quarantine_manager.restore_file(quarantine_id, restore_path)

    def delete_quarantined_file(self, quarantine_id: str) -> bool:
        """Permanently delete a quarantined file"""
        return self.quarantine_manager.delete_quarantined_file(quarantine_id)

    def execute_in_sandbox(self, file_path: str, file_hash: str) -> Optional[Dict]:
        """Execute file in sandbox environment"""
        execution = self.sandbox_manager.execute_in_sandbox(file_path, file_hash)
        return asdict(execution) if execution else None

    def get_sandbox_executions(self, limit: int = 50) -> List[Dict]:
        """Get recent sandbox executions"""
        return self.sandbox_manager.list_executions(limit)

    def get_sandbox_execution_status(self, execution_id: str) -> Optional[Dict]:
        """Get status of sandbox execution"""
        return self.sandbox_manager.get_execution_status(execution_id)

    def get_comprehensive_statistics(self) -> Dict:
        """Get comprehensive system statistics including all components"""
        base_stats = self.get_scan_statistics()

        # Add monitoring statistics
        monitoring_stats = self.process_monitor.get_statistics()

        # Add quarantine statistics
        quarantine_stats = self.quarantine_manager.get_quarantine_statistics()

        # Add sandbox statistics
        sandbox_stats = self.sandbox_manager.get_sandbox_statistics()

        return {
            'scan_engine': base_stats,
            'monitoring': monitoring_stats,
            'quarantine': quarantine_stats,
            'sandbox': sandbox_stats,
            'system_status': {
                'monitoring_active': monitoring_stats.get('monitoring_active', False),
                'quarantine_active': True,
                'sandbox_available': sandbox_stats.get('docker_available', False)
            }
        }
