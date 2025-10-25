#!/usr/bin/env python3
"""
Test script for AntiV-AI File Analysis Engine
Creates sample files and demonstrates the scanning functionality
"""

import os
import sys
import random
import struct

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from antiv_engine import AntiVEngine

def create_test_files():
    """Create various test files to demonstrate the scanner"""
    os.makedirs('test_files', exist_ok=True)
    
    # 1. Clean text file (low entropy, low risk)
    with open('test_files/clean_document.txt', 'w') as f:
        f.write("This is a clean text document with normal content.\n" * 50)
    
    # 2. High entropy file (simulates encrypted/obfuscated content)
    with open('test_files/suspicious_encrypted.bin', 'wb') as f:
        # Generate random bytes (high entropy)
        random_data = bytes([random.randint(0, 255) for _ in range(10000)])
        f.write(random_data)
    
    # 3. Fake executable with suspicious characteristics
    with open('test_files/fake_malware.exe', 'wb') as f:
        # Create a minimal PE header structure (simplified)
        # DOS header
        dos_header = b'MZ' + b'\x00' * 58 + struct.pack('<L', 0x80)  # e_lfanew
        f.write(dos_header)
        
        # PE signature and headers (simplified)
        pe_signature = b'PE\x00\x00'
        file_header = struct.pack('<HHLLHH', 0x014c, 3, 0, 0, 0, 0)  # Machine, sections, etc.
        optional_header = struct.pack('<HBB', 0x010b, 1, 0) + b'\x00' * 220  # Magic + version
        
        f.write(pe_signature + file_header + optional_header)
        
        # Add some high-entropy data to simulate packed/encrypted payload
        random_payload = bytes([random.randint(0, 255) for _ in range(5000)])
        f.write(random_payload)
    
    # 4. Script file with suspicious extension
    with open('test_files/suspicious_script.bat', 'w') as f:
        f.write('@echo off\n')
        f.write('echo This is a batch script\n')
        f.write('pause\n')
    
    # 5. Normal executable-like file (lower risk)
    with open('test_files/normal_program.exe', 'wb') as f:
        # Create a more normal-looking file with lower entropy
        normal_data = b'Normal program data with some structure.\n' * 200
        f.write(normal_data)
    
    print("Created test files in 'test_files' directory:")
    for file in os.listdir('test_files'):
        print(f"  - {file}")

def run_test_scans():
    """Run scans on test files and display results"""
    print("\n" + "="*60)
    print("ANTIV-AI FILE ANALYSIS ENGINE TEST")
    print("="*60)
    
    # Initialize engine
    engine = AntiVEngine()
    
    # Create test files
    create_test_files()
    
    # Scan each test file
    test_files = [
        'test_files/clean_document.txt',
        'test_files/suspicious_encrypted.bin',
        'test_files/fake_malware.exe',
        'test_files/suspicious_script.bat',
        'test_files/normal_program.exe'
    ]
    
    results = []
    
    for file_path in test_files:
        if os.path.exists(file_path):
            print(f"\n--- Scanning: {file_path} ---")
            result = engine.scan_file(file_path)
            results.append(result)
            
            if result.get('success'):
                print(f"Risk Score: {result['risk_score']:.3f}")
                print(f"Threat Level: {result['threat_level']}")
                print(f"Flagged: {'YES' if result['flagged'] else 'NO'}")
                
                details = result.get('analysis_details', {})
                print(f"Entropy: {details.get('entropy', 0):.3f}")
                print(f"File Size: {details.get('file_size', 0):,} bytes")
                
                # Show PE analysis if available
                pe_analysis = details.get('pe_analysis', {})
                if pe_analysis.get('is_pe'):
                    suspicious = pe_analysis.get('suspicious_indicators', [])
                    print(f"PE Suspicious Indicators: {len(suspicious)}")
                    if suspicious:
                        print(f"  - {', '.join(suspicious)}")
            else:
                print(f"ERROR: {result.get('error', 'Unknown error')}")
    
    # Show summary statistics
    print(f"\n" + "="*60)
    print("SCAN SUMMARY")
    print("="*60)
    
    stats = engine.get_scan_statistics()
    print(f"Total files scanned: {len(results)}")
    print(f"Files flagged: {sum(1 for r in results if r.get('flagged', False))}")
    print(f"Average risk score: {sum(r.get('risk_score', 0) for r in results) / len(results):.3f}")
    
    # Show flagged files
    flagged_files = engine.get_flagged_files()
    if flagged_files:
        print(f"\nFlagged Files:")
        for flagged in flagged_files:
            print(f"  - {flagged['file_path']} (Risk: {flagged['risk_score']:.3f})")
    
    print(f"\nDatabase and logs created in 'data' and 'logs' directories.")
    print(f"Use 'python cli_dashboard.py --all' to view detailed results.")

def demonstrate_directory_scan():
    """Demonstrate directory scanning functionality"""
    print(f"\n" + "="*60)
    print("DIRECTORY SCAN DEMONSTRATION")
    print("="*60)
    
    engine = AntiVEngine()
    
    # Scan the test_files directory
    if os.path.exists('test_files'):
        print(f"Scanning 'test_files' directory...")
        batch_result = engine.scan_directory('test_files', recursive=False)
        
        if batch_result.get('success'):
            print(f"Directory: {batch_result['directory_path']}")
            print(f"Total files scanned: {batch_result['total_files_scanned']}")
            print(f"Flagged files: {batch_result['flagged_files']}")
            print(f"Errors: {batch_result['errors']}")
            
            # Show individual results
            print(f"\nIndividual Results:")
            for result in batch_result['scan_results']:
                if result.get('success'):
                    status = "FLAGGED" if result.get('flagged') else "CLEAN"
                    print(f"  {os.path.basename(result['file_path'])}: {status} (Risk: {result['risk_score']:.3f})")

def main():
    """Main test function"""
    if len(sys.argv) > 1 and sys.argv[1] == '--directory':
        demonstrate_directory_scan()
    else:
        run_test_scans()
        
        # Also demonstrate directory scan
        demonstrate_directory_scan()

if __name__ == "__main__":
    main()
