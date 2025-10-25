#!/usr/bin/env python3
"""
AntiV-AI CLI Dashboard
Simple command-line interface for viewing scan results and system status
"""

import argparse
import os
import sys
from datetime import datetime
from typing import List, Dict

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from tabulate import tabulate
    from colorama import init, Fore, Style
    init()  # Initialize colorama for Windows compatibility
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    print("Warning: tabulate and/or colorama not available. Install with: pip install tabulate colorama")

from antiv_engine import AntiVEngine

class CLIDashboard:
    """Command-line dashboard for AntiV-AI system"""
    
    def __init__(self):
        """Initialize the CLI dashboard"""
        self.engine = AntiVEngine()
        
    def colorize(self, text: str, color: str = '') -> str:
        """Add color to text if colors are available"""
        if not COLORS_AVAILABLE:
            return text
        
        color_map = {
            'red': Fore.RED,
            'yellow': Fore.YELLOW,
            'green': Fore.GREEN,
            'blue': Fore.BLUE,
            'cyan': Fore.CYAN,
            'magenta': Fore.MAGENTA
        }
        
        if color in color_map:
            return f"{color_map[color]}{text}{Style.RESET_ALL}"
        return text
    
    def format_risk_score(self, risk_score: float) -> str:
        """Format risk score with appropriate color"""
        if risk_score >= 0.8:
            return self.colorize(f"{risk_score:.3f}", 'red')
        elif risk_score >= 0.6:
            return self.colorize(f"{risk_score:.3f}", 'yellow')
        elif risk_score >= 0.3:
            return self.colorize(f"{risk_score:.3f}", 'blue')
        else:
            return self.colorize(f"{risk_score:.3f}", 'green')
    
    def format_threat_level(self, threat_level: str) -> str:
        """Format threat level with appropriate color"""
        color_map = {
            'HIGH': 'red',
            'MEDIUM': 'yellow',
            'LOW': 'blue',
            'CLEAN': 'green'
        }
        color = color_map.get(threat_level, '')
        return self.colorize(threat_level, color)
    
    def show_statistics(self):
        """Display system statistics"""
        print(self.colorize("\n=== AntiV-AI System Statistics ===", 'cyan'))
        
        stats = self.engine.get_scan_statistics()
        
        if 'error' in stats:
            print(self.colorize(f"Error retrieving statistics: {stats['error']}", 'red'))
            return
        
        print(f"Total Scans: {stats['total_scans']}")
        print(f"Flagged Files: {stats['total_flagged']}")
        print(f"Flagged Percentage: {stats['flagged_percentage']:.1f}%")
        print(f"Average Risk Score: {self.format_risk_score(stats['average_risk_score'])}")
        
        # Threat level distribution
        print(f"\nThreat Level Distribution:")
        for level, count in stats['threat_level_distribution'].items():
            formatted_level = self.format_threat_level(level)
            print(f"  {formatted_level}: {count}")
        
        # Recent flagged files
        if stats['recent_flagged_files']:
            print(f"\nRecent Flagged Files:")
            for file_path in stats['recent_flagged_files']:
                print(f"  {self.colorize(file_path, 'red')}")
    
    def show_recent_scans(self, limit: int = 20):
        """Display recent scan results"""
        print(self.colorize(f"\n=== Recent Scans (Last {limit}) ===", 'cyan'))
        
        scans = self.engine.get_recent_scans(limit)
        
        if not scans:
            print("No scan results found.")
            return
        
        # Prepare table data
        table_data = []
        for scan in scans:
            # Truncate file path for display
            file_path = scan['file_path']
            if len(file_path) > 50:
                file_path = "..." + file_path[-47:]
            
            # Format timestamp
            timestamp = scan.get('scan_timestamp', '')
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
                except:
                    pass
            
            table_data.append([
                file_path,
                self.format_risk_score(scan.get('risk_score', 0)),
                self.format_threat_level(scan.get('threat_level', 'UNKNOWN')),
                f"{scan.get('file_size', 0):,} bytes",
                timestamp
            ])
        
        headers = ['File Path', 'Risk Score', 'Threat Level', 'Size', 'Scan Time']
        
        if COLORS_AVAILABLE:
            print(tabulate(table_data, headers=headers, tablefmt='grid'))
        else:
            # Simple text table if tabulate not available
            print(f"{'File Path':<50} {'Risk':<8} {'Level':<8} {'Size':<12} {'Time':<20}")
            print("-" * 100)
            for row in table_data:
                print(f"{row[0]:<50} {row[1]:<8} {row[2]:<8} {row[3]:<12} {row[4]:<20}")
    
    def show_flagged_files(self):
        """Display all flagged files"""
        print(self.colorize("\n=== Flagged Files ===", 'red'))
        
        flagged = self.engine.get_flagged_files()
        
        if not flagged:
            print(self.colorize("No flagged files found.", 'green'))
            return
        
        # Prepare table data
        table_data = []
        for file_info in flagged:
            # Truncate file path for display
            file_path = file_info['file_path']
            if len(file_path) > 40:
                file_path = "..." + file_path[-37:]
            
            # Get PE analysis info
            pe_info = file_info.get('pe_analysis', {})
            if isinstance(pe_info, str):
                import json
                try:
                    pe_info = json.loads(pe_info)
                except:
                    pe_info = {}
            
            suspicious_count = len(pe_info.get('suspicious_indicators', []))
            
            table_data.append([
                file_path,
                self.format_risk_score(file_info.get('risk_score', 0)),
                self.format_threat_level(file_info.get('threat_level', 'UNKNOWN')),
                f"{file_info.get('entropy', 0):.3f}",
                str(suspicious_count),
                file_info.get('sha256', '')[:16] + "..."
            ])
        
        headers = ['File Path', 'Risk Score', 'Level', 'Entropy', 'PE Flags', 'SHA-256']
        
        if COLORS_AVAILABLE:
            print(tabulate(table_data, headers=headers, tablefmt='grid'))
        else:
            # Simple text table
            print(f"{'File Path':<40} {'Risk':<8} {'Level':<8} {'Entropy':<8} {'Flags':<6} {'SHA-256':<20}")
            print("-" * 92)
            for row in table_data:
                print(f"{row[0]:<40} {row[1]:<8} {row[2]:<8} {row[3]:<8} {row[4]:<6} {row[5]:<20}")
    
    def scan_file_interactive(self, file_path: str):
        """Perform interactive file scan"""
        print(self.colorize(f"\n=== Scanning File: {file_path} ===", 'cyan'))
        
        if not os.path.exists(file_path):
            print(self.colorize(f"Error: File not found: {file_path}", 'red'))
            return
        
        # Perform scan
        result = self.engine.scan_file(file_path)
        
        if not result.get('success', False):
            print(self.colorize(f"Scan failed: {result.get('error', 'Unknown error')}", 'red'))
            return
        
        # Display results
        print(f"File: {result['file_path']}")
        print(f"Risk Score: {self.format_risk_score(result['risk_score'])}")
        print(f"Threat Level: {self.format_threat_level(result['threat_level'])}")
        print(f"Flagged: {self.colorize('YES', 'red') if result['flagged'] else self.colorize('NO', 'green')}")
        
        # Show analysis details
        details = result.get('analysis_details', {})
        print(f"\nAnalysis Details:")
        print(f"  SHA-256: {details.get('sha256', 'N/A')}")
        print(f"  MD5: {details.get('md5', 'N/A')}")
        print(f"  Entropy: {details.get('entropy', 0):.3f}")
        print(f"  File Size: {details.get('file_size', 0):,} bytes")
        
        # PE analysis if available
        pe_analysis = details.get('pe_analysis', {})
        if pe_analysis and pe_analysis.get('is_pe'):
            print(f"  PE Analysis:")
            print(f"    Entry Point: {pe_analysis.get('entry_point', 'N/A')}")
            print(f"    Sections: {pe_analysis.get('sections', 0)}")
            suspicious = pe_analysis.get('suspicious_indicators', [])
            if suspicious:
                print(f"    Suspicious Indicators: {', '.join(suspicious)}")

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(description='AntiV-AI CLI Dashboard')
    parser.add_argument('--stats', action='store_true', help='Show system statistics')
    parser.add_argument('--recent', type=int, default=20, help='Show recent scans (default: 20)')
    parser.add_argument('--flagged', action='store_true', help='Show flagged files')
    parser.add_argument('--scan', type=str, help='Scan a specific file')
    parser.add_argument('--all', action='store_true', help='Show all information')
    
    args = parser.parse_args()
    
    dashboard = CLIDashboard()
    
    if args.scan:
        dashboard.scan_file_interactive(args.scan)
    elif args.stats:
        dashboard.show_statistics()
    elif args.flagged:
        dashboard.show_flagged_files()
    elif args.all:
        dashboard.show_statistics()
        dashboard.show_recent_scans(args.recent)
        dashboard.show_flagged_files()
    else:
        # Default: show recent scans
        dashboard.show_recent_scans(args.recent)

if __name__ == "__main__":
    main()
