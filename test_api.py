#!/usr/bin/env python3
"""
Test script for AntiV-AI API endpoints
"""

import requests
import json
import os

def test_api():
    """Test the API endpoints"""
    base_url = "http://localhost:8000"
    
    print("🧪 Testing AntiV-AI API...")
    print(f"📍 Base URL: {base_url}")
    print()
    
    try:
        # Test root endpoint
        print("1. Testing root endpoint...")
        response = requests.get(f"{base_url}/")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {json.dumps(response.json(), indent=2)}")
        print()
        
        # Test health endpoint
        print("2. Testing health endpoint...")
        response = requests.get(f"{base_url}/health")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {json.dumps(response.json(), indent=2)}")
        print()
        
        # Test stats endpoint
        print("3. Testing stats endpoint...")
        response = requests.get(f"{base_url}/stats")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {json.dumps(response.json(), indent=2)}")
        print()
        
        # Test history endpoint
        print("4. Testing history endpoint...")
        response = requests.get(f"{base_url}/history")
        print(f"   Status: {response.status_code}")
        print(f"   Found {len(response.json())} scan records")
        print()
        
        # Test flagged files endpoint
        print("5. Testing flagged files endpoint...")
        response = requests.get(f"{base_url}/flagged")
        print(f"   Status: {response.status_code}")
        print(f"   Found {len(response.json())} flagged files")
        print()
        
        # Test file upload (if test file exists)
        test_file = "test_files/malicious.exe"
        if os.path.exists(test_file):
            print("6. Testing file upload and scan...")
            with open(test_file, 'rb') as f:
                files = {'file': (os.path.basename(test_file), f, 'application/octet-stream')}
                response = requests.post(f"{base_url}/upload-scan", files=files)
            print(f"   Status: {response.status_code}")
            if response.status_code == 200:
                result = response.json()
                print(f"   File: {result['file_name']}")
                print(f"   Risk Score: {result['risk_score']}")
                print(f"   Threat Level: {result['threat_level']}")
                print(f"   Flagged: {result['flagged']}")
            else:
                print(f"   Error: {response.text}")
            print()
        
        print("✅ API testing completed successfully!")
        print()
        print("🌐 You can now:")
        print("   • Open http://localhost:8000/docs for API documentation")
        print("   • Start the frontend with: cd frontend && npm start")
        print("   • Access the dashboard at: http://localhost:3000")
        
    except requests.exceptions.ConnectionError:
        print("❌ Error: Could not connect to the API server")
        print("   Make sure the backend is running with: uvicorn src.app:app --reload")
    except Exception as e:
        print(f"❌ Error: {str(e)}")

if __name__ == "__main__":
    test_api()
