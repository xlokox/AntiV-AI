#!/usr/bin/env python3
"""
AntiV-AI Main Entry Point
AI-Powered Antivirus System - File Analysis Engine
"""

import os
import sys
import argparse
import asyncio

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from antiv_engine import AntiVEngine

async def scan_file(file_path: str):
    """Scan a single file"""
    engine = AntiVEngine()
    
    print(f"Scanning file: {file_path}")
    result = await engine.scan_file(file_path)
    
    if result.get('success'):
        print(f"✓ Scan completed successfully")
        print(f"  Risk Score: {result['risk_score']:.3f}")
        print(f"  Threat Level: {result['threat_level']}")
        print(f"  Flagged: {'YES' if result['flagged'] else 'NO'}")
        
        if result['flagged']:
            print(f"  ⚠️  ALERT: File flagged as potentially malicious!")
    else:
        print(f"✗ Scan failed: {result.get('error', 'Unknown error')}")

async def scan_directory(directory_path: str, recursive: bool = True):
    """Scan a directory"""
    engine = AntiVEngine()
    
    print(f"Scanning directory: {directory_path}")
    print(f"Recursive: {recursive}")
    
    result = await engine.scan_directory(directory_path, recursive=recursive)
    
    if result.get('success'):
        print(f"✓ Directory scan completed")
        print(f"  Total files: {result['total_files_scanned']}")
        print(f"  Flagged files: {result['flagged_files']}")
        print(f"  Errors: {result['errors']}")
        
        if result['flagged_files'] > 0:
            print(f"  ⚠️  {result['flagged_files']} files flagged as potentially malicious!")
    else:
        print(f"✗ Directory scan failed: {result.get('error', 'Unknown error')}")

def show_statistics():
    """Show system statistics"""
    engine = AntiVEngine()
    stats = engine.get_scan_statistics()
    
    print("=== AntiV-AI Statistics ===")
    print(f"Total scans: {stats.get('total_scans', 0)}")
    print(f"Flagged files: {stats.get('total_flagged', 0)}")
    print(f"Average risk score: {stats.get('average_risk_score', 0):.3f}")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='AntiV-AI: AI-Powered Antivirus File Analysis Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --file /path/to/suspicious/file.exe
  python main.py --directory /path/to/scan --recursive
  python main.py --stats
  python main.py --test
        """
    )
    
    parser.add_argument('--file', type=str, help='Scan a specific file')
    parser.add_argument('--directory', type=str, help='Scan a directory')
    parser.add_argument('--recursive', action='store_true', help='Scan directory recursively')
    parser.add_argument('--stats', action='store_true', help='Show system statistics')
    parser.add_argument('--test', action='store_true', help='Run test suite with sample files')
    parser.add_argument('--dashboard', action='store_true', help='Launch CLI dashboard')
    
    args = parser.parse_args()
    
    if args.file:
        asyncio.run(scan_file(args.file))
    elif args.directory:
        asyncio.run(scan_directory(args.directory, args.recursive))
    elif args.stats:
        show_statistics()
    elif args.test:
        # Import and run test
        import test_antiv
        test_antiv.main()
    elif args.dashboard:
        # Import and run dashboard
        import cli_dashboard
        cli_dashboard.main()
    else:
        parser.print_help()
        print("\nFor interactive dashboard, use: python cli_dashboard.py")
        print("For testing, use: python test_antiv.py")

if __name__ == "__main__":
    main()
