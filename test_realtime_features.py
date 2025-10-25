#!/usr/bin/env python3
"""
Test script for Real-Time Monitoring, Quarantine, and Sandbox features
"""

import os
import sys
import time
import requests
import json
import asyncio

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from antiv_engine import AntiVEngine

import pytest

@pytest.mark.asyncio
async def test_realtime_features():
    """Test the new real-time features"""
    print("🧪 Testing AntiV-AI Real-Time Features...")
    print("="*60)
    
    # Initialize engine
    engine = AntiVEngine()
    
    print("\n1. Testing Process Monitoring...")
    print("-" * 40)
    
    # Test process monitoring
    success = engine.start_real_time_monitoring()
    print(f"   ✓ Start monitoring: {'Success' if success else 'Failed'}")
    
    # Wait a bit for events
    time.sleep(3)
    
    # Get monitoring events
    events = engine.get_monitoring_events(limit=10)
    print(f"   ✓ Monitoring events captured: {len(events)}")
    
    # Get process tree
    process_tree = engine.get_process_tree()
    print(f"   ✓ Process tree size: {len(process_tree)}")
    
    # Stop monitoring
    success = engine.stop_real_time_monitoring()
    print(f"   ✓ Stop monitoring: {'Success' if success else 'Failed'}")
    
    print("\n2. Testing Quarantine System...")
    print("-" * 40)
    
    # Create a test file for quarantine
    test_file = "test_files/quarantine_test.exe"
    if not os.path.exists("test_files"):
        os.makedirs("test_files")
    
    with open(test_file, 'wb') as f:
        # Create a high-entropy file that should trigger quarantine
        import random
        random_data = bytes([random.randint(0, 255) for _ in range(1000)])
        f.write(random_data)
    
    print(f"   ✓ Created test file: {test_file}")
    
    # Scan the file (should trigger quarantine)
    scan_result = await engine.scan_file(test_file)
    print(f"   ✓ File scan completed")
    print(f"     - Risk Score: {scan_result.get('risk_score', 0):.3f}")
    print(f"     - Threat Level: {scan_result.get('threat_level', 'UNKNOWN')}")
    print(f"     - Quarantined: {scan_result.get('quarantined', False)}")
    
    # List quarantined files
    quarantined = engine.get_quarantined_files()
    print(f"   ✓ Quarantined files: {len(quarantined)}")
    
    if quarantined:
        # Test restore (optional - be careful)
        # restore_success = engine.restore_quarantined_file(quarantined[0]['id'])
        # print(f"   ✓ Restore test: {'Success' if restore_success else 'Failed'}")
        print(f"   ✓ First quarantined file ID: {quarantined[0]['id']}")
    
    print("\n3. Testing Sandbox System...")
    print("-" * 40)
    
    # Test sandbox (if Docker is available)
    sandbox_stats = engine.sandbox_manager.get_sandbox_statistics()
    docker_available = sandbox_stats.get('docker_available', False)
    print(f"   ✓ Docker available: {docker_available}")
    
    if docker_available:
        print("   ⚠️  Docker sandbox testing skipped (requires manual Docker setup)")
        print("   ℹ️  To test sandbox: ensure Docker is running and try:")
        print("      engine.execute_in_sandbox('path/to/file', 'file_hash')")
    else:
        print("   ℹ️  Docker not available - sandbox features will be limited")
    
    # Get sandbox executions
    executions = engine.get_sandbox_executions()
    print(f"   ✓ Sandbox execution history: {len(executions)}")
    
    print("\n4. Testing Comprehensive Statistics...")
    print("-" * 40)
    
    # Get comprehensive stats
    stats = engine.get_comprehensive_statistics()
    
    print("   ✓ System Statistics:")
    print(f"     - Scan Engine: {stats.get('scan_engine', {}).get('total_scans', 0)} total scans")
    print(f"     - Monitoring: {stats.get('monitoring', {}).get('total_process_events', 0)} process events")
    print(f"     - Quarantine: {stats.get('quarantine', {}).get('active_quarantined', 0)} active quarantined")
    print(f"     - Sandbox: {stats.get('sandbox', {}).get('total_executions', 0)} total executions")
    
    system_status = stats.get('system_status', {})
    print(f"   ✓ System Status:")
    print(f"     - Monitoring Active: {system_status.get('monitoring_active', False)}")
    print(f"     - Quarantine Active: {system_status.get('quarantine_active', False)}")
    print(f"     - Sandbox Available: {system_status.get('sandbox_available', False)}")
    
    print("\n" + "="*60)
    print("✅ Real-Time Features Test Completed!")
    print("\n🌐 API Endpoints to test:")
    print("   • GET  /system/status - Comprehensive system status")
    print("   • POST /monitoring/start - Start real-time monitoring")
    print("   • GET  /monitoring/events - Get monitoring events")
    print("   • GET  /quarantine/list - List quarantined files")
    print("   • GET  /sandbox/stats - Sandbox statistics")
    print("\n📱 Frontend Features:")
    print("   • Real-Time Monitoring tab - Live process/network/filesystem monitoring")
    print("   • Quarantine Manager tab - Manage quarantined files")
    print("   • Enhanced file scanner with auto-quarantine")

def test_api_endpoints():
    """Test the new API endpoints"""
    print("\n🔌 Testing API Endpoints...")
    print("-" * 40)
    
    base_url = "http://localhost:8000"
    
    endpoints_to_test = [
        "/system/status",
        "/monitoring/status", 
        "/quarantine/stats",
        "/sandbox/stats",
        "/monitoring/events",
        "/quarantine/list",
        "/sandbox/executions"
    ]
    
    for endpoint in endpoints_to_test:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            status = "✅ OK" if response.status_code == 200 else f"❌ {response.status_code}"
            print(f"   {endpoint:<25} {status}")
        except requests.exceptions.RequestException as e:
            print(f"   {endpoint:<25} ❌ Connection Error")
    
    print("\n   ℹ️  Start the backend with: uvicorn src.app:app --reload")

if __name__ == "__main__":
    try:
        asyncio.run(test_realtime_features())
        test_api_endpoints()
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
