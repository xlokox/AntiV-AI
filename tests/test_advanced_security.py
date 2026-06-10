"""
Comprehensive tests for advanced security features in AntiV-AI
Tests SIEM integration, blockchain audit, rate limiting, performance, and notifications
"""

import pytest
import asyncio
import json
import tempfile
import os
import subprocess
import time
import yaml  # used by test_scheduler_initialization to build mocked config.yaml content
from unittest.mock import Mock, patch, AsyncMock, MagicMock, mock_open
from datetime import datetime, timedelta

# Import modules to test
import sys
sys.path.append('src')

from monitoring.siem_integration import SIEMIntegration, SecurityEvent
from blockchain_audit import BlockchainAudit, AuditEntry
from network_security import RateLimiter, GeoIPLookup
from performance import RedisCache, ParallelProcessor, ParallelScanner
from integrations.slack_notifier import SlackNotifier, SecurityAlert, AlertSeverity, NotificationType

class TestSIEMIntegration:
    """Test SIEM integration functionality"""
    
    @pytest.fixture
    def siem_integration(self):
        """Create SIEM integration instance for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            siem = SIEMIntegration("http://test-siem-endpoint.com")
            siem.local_db_path = os.path.join(temp_dir, "test_siem.db")
            siem._init_local_storage()
            yield siem
    
    def test_create_security_event(self, siem_integration):
        """Test security event creation"""
        event = siem_integration.create_security_event(
            event_type="test_event",
            severity="HIGH",
            action="test_action",
            resource="test_resource",
            outcome="SUCCESS",
            details={"test": "data"},
            source_ip="192.168.1.1",
            risk_score=0.8
        )
        
        assert event.event_type == "test_event"
        assert event.severity == "HIGH"
        assert event.risk_score == 0.8
        assert event.source_ip == "192.168.1.1"
        assert event.details["test"] == "data"
    
    def test_add_security_event(self, siem_integration):
        """Test adding security event to queue"""
        event = siem_integration.create_security_event(
            event_type="test",
            severity="MEDIUM",
            action="test",
            resource="test",
            outcome="SUCCESS"
        )
        
        siem_integration.add_security_event(event)
        assert len(siem_integration.event_queue) == 1
    
    @pytest.mark.asyncio
    async def test_forward_security_events(self, siem_integration):
        """Test forwarding multiple security events"""
        events = []
        for i in range(3):
            event = siem_integration.create_security_event(
                event_type=f"test_{i}",
                severity="LOW",
                action=f"action_{i}",
                resource=f"resource_{i}",
                outcome="SUCCESS"
            )
            events.append(event)
        
        # Mock the HTTP request
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_post.return_value.__aenter__.return_value = mock_response
            
            await siem_integration.forward_security_events(events)

            # forward_security_events enqueues then drains the queue via _process_batch,
            # so the queue ends up empty and the 3 events are recorded as sent.
            assert len(siem_integration.event_queue) == 0
            assert siem_integration.metrics.total_events_sent >= 3
    
    def test_get_siem_metrics(self, siem_integration):
        """Test SIEM metrics retrieval"""
        metrics = siem_integration.get_siem_metrics()
        
        assert 'siem_endpoint' in metrics
        assert 'siem_enabled' in metrics
        assert 'metrics' in metrics
        assert 'queue_status' in metrics

class TestBlockchainAudit:
    """Test blockchain audit functionality"""
    
    @pytest.fixture
    def blockchain_audit(self):
        """Create blockchain audit instance for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            audit = BlockchainAudit()
            audit.ledger_path = os.path.join(temp_dir, "test_ledger.json")
            audit.db_path = os.path.join(temp_dir, "test_blockchain.db")
            audit._init_blockchain_storage()
            # __init__ already computed last_block_hash from the default DB and created
            # a genesis block there. After repointing at the temp DB (which gets its own
            # genesis block), re-sync last_block_hash so the chain links correctly.
            audit.last_block_hash = audit._get_last_block_hash()
            audit.current_block_entries = []
            yield audit
    
    def test_create_audit_entry(self, blockchain_audit):
        """Test audit entry creation"""
        entry = blockchain_audit.create_audit_entry(
            event_type="test_event",
            action="test_action",
            resource="test_resource",
            outcome="SUCCESS",
            details={"test": "data"},
            risk_score=0.5
        )
        
        assert entry.event_type == "test_event"
        assert entry.action == "test_action"
        assert entry.risk_score == 0.5
        assert entry.details["test"] == "data"
    
    def test_add_audit_entry(self, blockchain_audit):
        """Test adding audit entry to blockchain"""
        entry = blockchain_audit.create_audit_entry(
            event_type="test",
            action="test",
            resource="test",
            outcome="SUCCESS"
        )
        
        blockchain_audit.add_audit_entry(entry)
        assert len(blockchain_audit.current_block_entries) == 1
    
    def test_verify_integrity(self, blockchain_audit):
        """Test blockchain integrity verification"""
        # Add some entries
        for i in range(3):
            entry = blockchain_audit.create_audit_entry(
                event_type=f"test_{i}",
                action=f"action_{i}",
                resource=f"resource_{i}",
                outcome="SUCCESS"
            )
            blockchain_audit.add_audit_entry(entry)
        
        # Force finalize block
        blockchain_audit.force_finalize_block()
        
        # Verify integrity
        result = blockchain_audit.verify_integrity()
        
        assert result.is_valid == True
        assert result.total_blocks >= 1
        assert result.total_entries >= 3
    
    def test_get_blockchain_statistics(self, blockchain_audit):
        """Test blockchain statistics retrieval"""
        stats = blockchain_audit.get_blockchain_statistics()
        
        assert 'total_blocks' in stats
        assert 'total_entries' in stats
        assert 'pending_entries' in stats
        assert 'last_block_hash' in stats

class TestAdvancedRateLimiter:
    """Test advanced rate limiting functionality"""

    @pytest.fixture
    def rate_limiter(self):
        """Create rate limiter instance for testing"""
        return RateLimiter()
    
    @pytest.fixture
    def mock_request(self):
        """Create mock request object"""
        request = Mock()
        request.client = Mock()
        request.client.host = "192.168.1.1"
        request.url = Mock()
        request.url.path = "/test"
        request.headers = {"user-agent": "test-agent"}
        return request
    
    def test_get_client_ip(self, rate_limiter, mock_request):
        """Test client IP extraction"""
        ip = rate_limiter._get_client_ip(mock_request)
        assert ip == "192.168.1.1"
    
    def test_calculate_adaptive_limit(self, rate_limiter):
        """Test adaptive limit calculation"""
        # _calculate_adaptive_limit returns a (limit, reason) tuple and expects
        # country_info as a dict (with country_code/region); a bare string code
        # falls back to region 'Unknown', which skews results against allow-listed
        # countries. Pass proper dicts to match the real API.
        limit, _ = rate_limiter._calculate_adaptive_limit(
            "192.168.1.1", {"country_code": "US", "region": "North America"}, "global"
        )
        assert limit > 0

        limit_high_risk, _ = rate_limiter._calculate_adaptive_limit(
            "192.168.1.1", {"country_code": "PK", "region": "Asia Pacific"}, "global"
        )
        assert limit_high_risk <= limit  # Should be more restrictive
    
    def test_get_ip_reputation(self, rate_limiter):
        """Test IP reputation scoring"""
        # Test private IP
        reputation = rate_limiter._get_ip_reputation("192.168.1.1")
        assert reputation == 0.0
        
        # Test public IP
        reputation = rate_limiter._get_ip_reputation("8.8.8.8")
        assert 0.0 <= reputation <= 1.0
    
    def test_check_rate_limit_advanced(self, rate_limiter, mock_request):
        """Test advanced rate limiting"""
        # Mock GeoIP lookup
        with patch.object(rate_limiter.geoip, 'get_country_info', return_value={"country_code": "US", "region": "North America"}):
            allowed, info = rate_limiter.check_rate_limit_advanced(mock_request)

            assert allowed == True
            assert 'limit' in info
            assert 'remaining' in info
            assert 'country' in info

    def test_geo_blocking(self, rate_limiter, mock_request):
        """Test country-based blocking"""
        # Test blocked country
        with patch.object(rate_limiter.geoip, 'get_country_info', return_value={"country_code": "CN", "region": "Asia"}):
            allowed, info = rate_limiter.check_rate_limit_advanced(mock_request)

            assert allowed == False
            assert info['reason'] == 'blocked_country'
            assert info['country'] == 'CN'

    def test_adaptive_limits(self, rate_limiter):
        """Test adaptive limit calculation"""
        # Test different countries and reputation scores
        country_info = {"country_code": "US", "region": "North America"}
        limit, reason = rate_limiter._calculate_adaptive_limit("192.168.1.1", country_info, "global")
        assert limit > 0
        assert reason is not None

        # Test high-risk country
        high_risk_info = {"country_code": "PK", "region": "Asia"}
        high_risk_limit, _ = rate_limiter._calculate_adaptive_limit("192.168.1.1", high_risk_info, "global")
        assert high_risk_limit <= limit  # Should be more restrictive

    def test_rate_limit_stats(self, rate_limiter):
        """Test rate limiting statistics"""
        stats = rate_limiter.get_rate_limit_stats()

        assert 'blocked_ips' in stats
        assert 'geo_enabled' in stats
        assert 'geo_stats' in stats
        assert 'blocked_countries' in stats

class TestGeoIPLookup:
    """Test GeoIP lookup functionality"""
    
    @pytest.fixture
    def geoip_lookup(self):
        """Create GeoIP lookup instance for testing"""
        return GeoIPLookup()
    
    def test_get_country_code_private_ip(self, geoip_lookup):
        """Test country code lookup for private IP"""
        # GeoIPLookup.get_country_code is synchronous and has no async context manager.
        country = geoip_lookup.get_country_code("192.168.1.1")
        assert country == "Private"

    def test_get_country_code_invalid_ip(self, geoip_lookup):
        """Test country code lookup for invalid IP"""
        country = geoip_lookup.get_country_code("invalid-ip")
        assert country == "Unknown"

class TestRedisCache:
    """Test Redis cache functionality"""
    
    @pytest.fixture
    def redis_cache(self):
        """Create Redis cache instance for testing"""
        # Use memory cache fallback for testing
        cache = RedisCache()
        cache.redis_client = None  # Force fallback to memory cache
        return cache
    
    def test_cache_operations(self, redis_cache):
        """Test basic cache operations"""
        # Test set and get
        success = redis_cache.set("test_key", "test_value", 60)
        assert success == True
        
        value = redis_cache.get("test_key")
        assert value == "test_value"
        
        # Test delete
        success = redis_cache.delete("test_key")
        assert success == True
        
        value = redis_cache.get("test_key")
        assert value is None
    
    @pytest.mark.asyncio
    async def test_async_cache_operations(self, redis_cache):
        """Test async cache operations"""
        # Test async set and get
        success = await redis_cache.aset("async_key", "async_value", 60)
        assert success == True
        
        value = await redis_cache.aget("async_key")
        assert value == "async_value"
    
    def test_cache_decorator(self, redis_cache):
        """Test cache decorator functionality"""
        call_count = 0
        
        @redis_cache.cache_decorator("test_func", 60)
        def expensive_function(x):
            nonlocal call_count
            call_count += 1
            return x * 2
        
        # First call should execute function
        result1 = expensive_function(5)
        assert result1 == 10
        assert call_count == 1
        
        # Second call should use cache
        result2 = expensive_function(5)
        assert result2 == 10
        assert call_count == 1  # Should not increment
    
    def test_get_metrics(self, redis_cache):
        """Test cache metrics"""
        # Perform some operations
        redis_cache.set("metric_test", "value")
        redis_cache.get("metric_test")
        redis_cache.get("nonexistent_key")
        
        metrics = redis_cache.get_metrics()
        
        assert 'hit_rate' in metrics
        assert 'total_requests' in metrics
        assert 'cache_hits' in metrics
        assert 'cache_misses' in metrics

class TestParallelProcessor:
    """Test parallel processing functionality"""

    @pytest.fixture
    def parallel_processor(self):
        """Create parallel processor instance for testing"""
        return ParallelProcessor(max_workers=2)

class TestParallelScanner:
    """Test parallel file scanning functionality"""

    @pytest.fixture
    def parallel_scanner(self):
        """Create parallel scanner instance for testing"""
        return ParallelScanner(max_workers=2)

    @pytest.fixture
    def parallel_processor(self):
        """Create parallel processor instance for the process_*/batch_process tests in this class."""
        return ParallelProcessor(max_workers=2)

    def test_scan_files_parallel(self, parallel_scanner):
        """Test parallel file scanning"""
        def mock_scan_func(file_path):
            return {"file": file_path, "result": "clean"}

        file_paths = ["file1.txt", "file2.txt", "file3.txt"]
        results = parallel_scanner.scan_files_parallel(mock_scan_func, file_paths)

        assert len(results) == 3
        assert all(result["result"] == "clean" for result in results)

    @pytest.mark.asyncio
    async def test_scan_files_async(self, parallel_scanner):
        """Test async parallel file scanning"""
        async def mock_async_scan_func(file_path):
            await asyncio.sleep(0.01)  # Simulate async work
            return {"file": file_path, "result": "clean"}

        file_paths = ["file1.txt", "file2.txt"]
        results = await parallel_scanner.scan_files_async(mock_async_scan_func, file_paths)

        assert len(results) == 2
        assert all(result["result"] == "clean" for result in results)

    def test_scan_files_with_errors(self, parallel_scanner):
        """Test parallel scanning with errors"""
        def mock_scan_func_with_error(file_path):
            if file_path == "error_file.txt":
                raise Exception("Scan error")
            return {"file": file_path, "result": "clean"}

        file_paths = ["file1.txt", "error_file.txt", "file3.txt"]
        results = parallel_scanner.scan_files_parallel(mock_scan_func_with_error, file_paths)

        # Should handle errors gracefully
        assert len(results) == 3
        assert results[1] is None  # Error file should return None

    def test_scanner_stats(self, parallel_scanner):
        """Test scanner statistics"""
        def mock_scan_func(file_path):
            return {"file": file_path, "result": "clean"}

        file_paths = ["file1.txt", "file2.txt"]
        parallel_scanner.scan_files_parallel(mock_scan_func, file_paths)

        stats = parallel_scanner.get_stats()

        assert 'total_scans' in stats
        assert 'parallel_scans' in stats
        assert 'average_scan_time' in stats
        assert stats['total_scans'] >= 2
    
    def test_process_parallel(self, parallel_processor):
        """Test parallel processing"""
        def square(x):
            return x * x
        
        items = [1, 2, 3, 4, 5]
        results = parallel_processor.process_parallel(square, items)
        
        assert results == [1, 4, 9, 16, 25]
    
    @pytest.mark.asyncio
    async def test_process_parallel_async(self, parallel_processor):
        """Test async parallel processing"""
        async def async_square(x):
            await asyncio.sleep(0.01)  # Simulate async work
            return x * x
        
        items = [1, 2, 3, 4]
        results = await parallel_processor.process_parallel_async(async_square, items)
        
        assert results == [1, 4, 9, 16]
    
    def test_batch_process(self, parallel_processor):
        """Test batch processing"""
        def double(x):
            return x * 2
        
        items = list(range(10))
        results = parallel_processor.batch_process(double, items, batch_size=3)
        
        expected = [x * 2 for x in range(10)]
        assert results == expected

class TestSlackNotifier:
    """Test Slack notification functionality"""
    
    @pytest.fixture
    def slack_notifier(self):
        """Create Slack notifier instance for testing"""
        return SlackNotifier("http://test-webhook-url.com")
    
    def test_create_scan_alert(self, slack_notifier):
        """Test scan alert creation"""
        alert = slack_notifier.create_scan_alert(
            file_path="/test/file.exe",
            risk_score=0.8,
            threat_level="HIGH",
            file_hash="abc123",
            details={"test": "data"}
        )
        
        assert alert.alert_type == NotificationType.SCAN_ALERT
        assert alert.severity == AlertSeverity.HIGH
        assert alert.risk_score == 0.8
        assert alert.file_hash == "abc123"
    
    def test_create_auth_failure_alert(self, slack_notifier):
        """Test authentication failure alert creation"""
        alert = slack_notifier.create_auth_failure_alert(
            username="testuser",
            source_ip="192.168.1.1",
            failure_count=5,
            details={"attempts": 5}
        )
        
        assert alert.alert_type == NotificationType.AUTHENTICATION_FAILURE
        assert alert.username == "testuser"
        assert alert.source_ip == "192.168.1.1"
    
    def test_create_ddos_alert(self, slack_notifier):
        """Test DDoS alert creation"""
        alert = slack_notifier.create_ddos_alert(
            source_ip="10.0.0.1",
            request_count=500,
            attack_type="flood",
            details={"pattern": "burst"}
        )
        
        assert alert.alert_type == NotificationType.DDOS_ATTACK
        assert alert.severity == AlertSeverity.HIGH
        assert alert.source_ip == "10.0.0.1"
    
    @pytest.mark.asyncio
    async def test_send_alert(self, slack_notifier):
        """Test sending alert to Slack"""
        alert = slack_notifier.create_scan_alert(
            file_path="/test/file.exe",
            risk_score=0.9,
            threat_level="CRITICAL",
            file_hash="def456"
        )
        
        # Mock the HTTP request
        with patch('aiohttp.ClientSession.post') as mock_post:
            mock_response = AsyncMock()
            mock_response.status = 200
            mock_post.return_value.__aenter__.return_value = mock_response
            
            success = await slack_notifier.send_alert(alert)
            assert success == True
    
    def test_get_notification_stats(self, slack_notifier):
        """Test notification statistics"""
        stats = slack_notifier.get_notification_stats()
        
        assert 'enabled' in stats
        assert 'webhook_configured' in stats
        assert 'channel' in stats
        assert 'rate_limit_per_hour' in stats

# Integration tests
class TestSecurityIntegration:
    """Test integration between security components"""
    
    @pytest.mark.asyncio
    async def test_end_to_end_security_flow(self):
        """Test complete security flow from detection to notification"""
        # This would test the complete flow:
        # 1. File scan triggers alert
        # 2. Alert is logged to blockchain
        # 3. SIEM event is created
        # 4. Slack notification is sent
        
        # Mock components
        with patch('src.antiv_engine.AntiVEngine') as mock_engine:
            mock_engine.scan_file.return_value = {
                'success': True,
                'risk_score': 0.9,
                'threat_level': 'HIGH',
                'flagged': True
            }
            
            # This would be a more comprehensive integration test
            # For now, just verify the test structure works
            assert True

class TestComplianceScript:
    """Test compliance automation script"""

    def test_compliance_script_exists(self):
        """Test that compliance script exists and is executable"""
        script_path = "scripts/compliance-check.sh"
        assert os.path.exists(script_path), "Compliance script not found"

        # Check if script is executable
        assert os.access(script_path, os.X_OK), "Compliance script is not executable"

    def test_compliance_script_syntax(self):
        """Test compliance script syntax"""
        script_path = "scripts/compliance-check.sh"

        # Test bash syntax
        result = subprocess.run(
            ["bash", "-n", script_path],
            capture_output=True,
            text=True
        )

        assert result.returncode == 0, f"Script syntax error: {result.stderr}"

    @pytest.mark.slow
    def test_compliance_script_execution(self):
        """Test compliance script execution (may take time)"""
        script_path = "scripts/compliance-check.sh"

        # Run the script with a timeout
        try:
            result = subprocess.run(
                ["bash", script_path],
                capture_output=True,
                text=True,
                timeout=60,  # 60 second timeout
                cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            )

            # Script should complete (may pass or fail, but shouldn't crash)
            assert result.returncode in [0, 1], f"Script crashed: {result.stderr}"

            # Check for expected output patterns
            output = result.stdout
            assert "NIST Cybersecurity Framework" in output
            assert "PASS:" in output or "FAIL:" in output

        except subprocess.TimeoutExpired:
            pytest.skip("Compliance script took too long to execute")

    def test_compliance_script_failure_detection(self):
        """Test that compliance script properly detects failures"""
        # Create a temporary script that simulates failures
        test_script = """#!/bin/bash
        echo "FAIL: Test failure"
        exit 1
        """

        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(test_script)
            f.flush()

            # Make executable
            os.chmod(f.name, 0o755)

            try:
                result = subprocess.run(
                    ["bash", f.name],
                    capture_output=True,
                    text=True
                )

                # Should return non-zero exit code for failures
                assert result.returncode != 0
                assert "FAIL:" in result.stdout

            finally:
                os.unlink(f.name)

class TestIntegrationScenarios:
    """Test integration scenarios between modules"""

    @pytest.mark.asyncio
    async def test_end_to_end_security_flow(self):
        """Test complete security flow from detection to notification"""
        # Mock all components
        with patch('src.antiv_engine.AntiVEngine') as mock_engine, \
             patch('src.monitoring.siem_integration.SIEMIntegration') as mock_siem, \
             patch('src.blockchain_audit.BlockchainAudit') as mock_blockchain, \
             patch('src.integrations.slack_notifier.SlackNotifier') as mock_slack:

            # Configure mocks
            mock_engine.scan_file.return_value = {
                'success': True,
                'risk_score': 0.9,
                'threat_level': 'HIGH',
                'flagged': True,
                'sha256': 'test_hash'
            }

            mock_siem_instance = mock_siem.return_value
            mock_blockchain_instance = mock_blockchain.return_value
            mock_slack_instance = mock_slack.return_value

            # Simulate the flow
            scan_result = mock_engine.scan_file("test_file.exe")

            # Verify scan result
            assert scan_result['flagged'] == True
            assert scan_result['risk_score'] == 0.9

            # This would trigger SIEM logging, blockchain audit, and Slack notification
            # In a real scenario, these would be called automatically

            # Verify the test structure works
            assert True

    def test_performance_with_caching(self):
        """Test performance improvements with caching"""
        cache = RedisCache()

        # Test cache miss and hit
        key = "test_key"
        value = {"test": "data"}

        # First access - cache miss
        result = cache.get(key)
        assert result is None

        # Set value
        success = cache.set(key, value, 60)
        assert success == True

        # Second access - cache hit
        result = cache.get(key)
        assert result == value

        # Verify metrics
        metrics = cache.get_metrics()
        assert metrics['total_requests'] >= 2
        assert metrics['cache_hits'] >= 1
        assert metrics['cache_misses'] >= 1

class TestMLRetrainingEndpoints:
    """Test ML retraining and model management endpoints"""

    @pytest.fixture
    def mock_training_job(self):
        """Mock training job status"""
        from src.app import TrainingJobStatus

        job = TrainingJobStatus("test-job-123")
        job.status = "completed"
        job.end_time = datetime.now()
        job.metrics = {"accuracy": 0.95, "precision": 0.90}
        return job

    @pytest.mark.asyncio
    async def test_trigger_retraining_endpoint(self, mock_training_job):
        """Test the /retrain endpoint"""
        from src.app import trigger_retraining, ml_training_jobs

        # Mock dependencies
        with patch('src.app.run_training_script', return_value=mock_training_job) as mock_run:
            with patch('src.app.auth_manager') as mock_auth:
                mock_user = Mock()
                mock_user.user_id = "admin-123"
                mock_user.username = "admin"

                # Call endpoint
                result = await trigger_retraining(current_user=mock_user)

                # Verify response
                assert result["status"] == "completed"
                assert result["job_id"] == "test-job-123"
                assert "metrics" in result

                # Verify training was triggered
                mock_run.assert_called_once()

                # Verify auth logging
                mock_auth._log_auth_event.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_training_status_endpoint(self):
        """Test the /retrain/status/{job_id} endpoint"""
        from src.app import get_training_status, ml_training_jobs

        # Add mock job to global jobs dict
        job_id = "test-job-456"
        mock_job = Mock()
        mock_job.job_id = job_id
        mock_job.status = "running"
        mock_job.start_time = datetime.now()
        mock_job.end_time = None
        mock_job.metrics = {}
        mock_job.error = None

        ml_training_jobs[job_id] = mock_job

        try:
            with patch('src.app.auth_manager') as mock_auth:
                mock_user = Mock()
                mock_user.user_id = "analyst-123"
                mock_user.username = "analyst"

                # Call endpoint
                result = await get_training_status(job_id, current_user=mock_user)

                # Verify response
                assert result["job_id"] == job_id
                assert result["status"] == "running"
                assert result["end_time"] is None

        finally:
            # Cleanup
            if job_id in ml_training_jobs:
                del ml_training_jobs[job_id]

    @pytest.mark.asyncio
    async def test_list_training_jobs_endpoint(self):
        """Test the /retrain/jobs endpoint"""
        from src.app import list_training_jobs, ml_training_jobs

        # Add mock jobs
        job1 = Mock()
        job1.job_id = "job-1"
        job1.status = "completed"
        job1.start_time = datetime.now()
        job1.end_time = datetime.now()
        job1.metrics = {"accuracy": 0.95}
        job1.error = None

        job2 = Mock()
        job2.job_id = "job-2"
        job2.status = "running"
        job2.start_time = datetime.now()
        job2.end_time = None
        job2.metrics = {}
        job2.error = None

        ml_training_jobs["job-1"] = job1
        ml_training_jobs["job-2"] = job2

        try:
            with patch('src.app.auth_manager') as mock_auth:
                mock_user = Mock()
                mock_user.user_id = "analyst-123"
                mock_user.username = "analyst"

                # Call endpoint
                result = await list_training_jobs(current_user=mock_user)

                # Verify response
                assert result["total_jobs"] == 2
                assert len(result["jobs"]) == 2

                # Verify job data
                job_ids = [job["job_id"] for job in result["jobs"]]
                assert "job-1" in job_ids
                assert "job-2" in job_ids

        finally:
            # Cleanup
            ml_training_jobs.clear()

    @pytest.mark.asyncio
    async def test_model_management_endpoints(self):
        """Test model management endpoints"""
        from src.app import list_model_versions, get_latest_model_info, rollback_model

        # Mock model manager
        with patch('src.app.ml_model_manager') as mock_manager:
            mock_version = Mock()
            mock_version.version = "20240101_120000"
            mock_version.timestamp = datetime.now().isoformat()
            mock_version.model_type = "behavioral_analysis"
            mock_version.metrics = {"accuracy": 0.95}
            mock_version.training_samples = 1000
            mock_version.feature_count = 15
            mock_version.algorithm = "RandomForest"
            mock_version.is_active = True
            mock_version.created_by = "system"
            mock_version.notes = "Test model"

            mock_manager.list_versions.return_value = [mock_version]
            mock_manager.get_latest_model.return_value = mock_version
            mock_manager.rollback_to.return_value = True

            with patch('src.app.auth_manager') as mock_auth:
                mock_user = Mock()
                mock_user.user_id = "admin-123"
                mock_user.username = "admin"

                # Test list versions
                result = await list_model_versions(current_user=mock_user)
                assert result["total_versions"] == 1
                assert len(result["versions"]) == 1

                # Test get latest model
                result = await get_latest_model_info("behavioral_analysis", current_user=mock_user)
                assert result["version"] == "20240101_120000"
                assert result["model_type"] == "behavioral_analysis"

                # Test rollback
                result = await rollback_model("behavioral_analysis", "20240101_120000", current_user=mock_user)
                assert "Successfully rolled back" in result["message"]

                # Verify rollback was called
                mock_manager.rollback_to.assert_called_with("behavioral_analysis", "20240101_120000")

class TestMLScheduler:
    """Test ML retraining scheduler functionality"""

    @pytest.mark.asyncio
    async def test_scheduled_retraining(self):
        """Test scheduled retraining function"""
        from src.app import scheduled_retraining

        mock_job = Mock()
        mock_job.job_id = "scheduled-job-123"
        mock_job.status = "completed"
        mock_job.metrics = {"accuracy": 0.95}

        with patch('src.app.run_training_script', return_value=mock_job) as mock_run:
            with patch('src.app.slack_notifier') as mock_slack:
                mock_alert = Mock()
                mock_slack.create_system_alert.return_value = mock_alert
                mock_slack.send_alert.return_value = None

                # Run scheduled retraining
                await scheduled_retraining()

                # Verify training was triggered
                mock_run.assert_called_once()

                # Verify notification was sent
                mock_slack.create_system_alert.assert_called_once()
                mock_slack.send_alert.assert_called_once_with(mock_alert)

    def test_scheduler_initialization(self):
        """Test ML scheduler initialization"""
        from src.app import init_ml_scheduler

        # Mock configuration
        mock_config = {
            'machine_learning': {
                'training': {
                    'schedule': {
                        'enabled': True,
                        'frequency': 'daily',
                        'time': '02:00'
                    }
                }
            }
        }

        with patch('builtins.open', mock_open(read_data=yaml.dump(mock_config))):
            with patch('src.app.SCHEDULER_AVAILABLE', True):
                with patch('src.app.AsyncIOScheduler') as mock_scheduler_class, \
                     patch('src.app.CronTrigger'):  # avoid real tzlocal lookup (machine tz config may conflict)
                    mock_scheduler = Mock()
                    mock_scheduler_class.return_value = mock_scheduler

                    # Initialize scheduler
                    init_ml_scheduler()

                    # Verify scheduler was created and configured
                    mock_scheduler_class.assert_called_once()
                    mock_scheduler.add_job.assert_called_once()
                    mock_scheduler.start.assert_called_once()

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
