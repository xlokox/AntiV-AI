"""
File Analysis Engine - Core component for malware detection
Handles file scanning, hash calculation, entropy analysis, and PE inspection
"""

import hashlib
import math
import os
import platform
import json
import logging
from datetime import datetime
from typing import Dict, Optional, Tuple
# NOTE: `random` was previously imported to fabricate a fake "ML" score here.
# It has been removed: the static risk score is now fully deterministic and the
# real ML signal comes from the EMBER-trained model in src/ml/detector.py.

# Import PE analysis library for Windows
try:
    import pefile
    PE_AVAILABLE = True
except ImportError:
    PE_AVAILABLE = False
    print("Warning: pefile not available. PE analysis will be disabled.")

class FileAnalyzer:
    """Main file analysis engine for threat detection"""
    
    def __init__(self, log_level=logging.INFO):
        """Initialize the file analyzer with logging configuration"""
        self.setup_logging(log_level)
        self.logger = logging.getLogger(__name__)
        
    def setup_logging(self, level):
        """Configure logging for the file analyzer"""
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/file_analysis.log'),
                logging.StreamHandler()
            ]
        )
        
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
    
    def calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """
        Calculate SHA-256 and MD5 hashes for a file
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Dictionary containing SHA-256 and MD5 hashes
        """
        try:
            sha256_hash = hashlib.sha256()
            md5_hash = hashlib.md5()
            
            with open(file_path, 'rb') as f:
                # Read file in chunks to handle large files efficiently
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
                    md5_hash.update(chunk)
            
            return {
                'sha256': sha256_hash.hexdigest(),
                'md5': md5_hash.hexdigest()
            }
            
        except Exception as e:
            self.logger.error(f"Error calculating hashes for {file_path}: {str(e)}")
            return {'sha256': '', 'md5': ''}
    
    def calculate_entropy(self, file_path: str) -> float:
        """
        Calculate Shannon entropy of a file to detect obfuscation/encryption
        
        Args:
            file_path: Path to the file to analyze
            
        Returns:
            Entropy value (0.0 to 8.0, normalized to 0.0-1.0)
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if not data:
                return 0.0
            
            # Count frequency of each byte value
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate Shannon entropy
            entropy = 0.0
            data_len = len(data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)
            
            # Normalize entropy to 0-1 scale (max entropy is 8.0)
            return entropy / 8.0
            
        except Exception as e:
            self.logger.error(f"Error calculating entropy for {file_path}: {str(e)}")
            return 0.0
    
    def analyze_pe_header(self, file_path: str) -> Dict:
        """
        Analyze PE header for Windows executables
        
        Args:
            file_path: Path to the PE file
            
        Returns:
            Dictionary containing PE analysis results
        """
        if not PE_AVAILABLE:
            return {'pe_analysis': 'unavailable', 'suspicious_indicators': []}
        
        try:
            pe = pefile.PE(file_path)
            
            analysis = {
                'is_pe': True,
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'sections': len(pe.sections),
                'imports': [],
                'suspicious_indicators': []
            }
            
            # Analyze sections
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                if section_name:
                    analysis['sections_info'] = analysis.get('sections_info', [])
                    analysis['sections_info'].append({
                        'name': section_name,
                        'virtual_size': section.Misc_VirtualSize,
                        'raw_size': section.SizeOfRawData
                    })
            
            # Check for suspicious indicators
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    analysis['imports'].append(dll_name)
                    
                    # Flag suspicious DLLs
                    suspicious_dlls = ['kernel32.dll', 'ntdll.dll', 'advapi32.dll']
                    if dll_name.lower() in suspicious_dlls:
                        analysis['suspicious_indicators'].append(f'imports_{dll_name}')
            
            # Check for packed executables (high entropy in code sections)
            if pe.sections:
                code_section = pe.sections[0]  # Usually .text section
                if code_section.SizeOfRawData > 0:
                    entropy_ratio = code_section.Misc_VirtualSize / code_section.SizeOfRawData
                    if entropy_ratio > 2.0:
                        analysis['suspicious_indicators'].append('possible_packing')
            
            pe.close()
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error analyzing PE header for {file_path}: {str(e)}")
            return {'is_pe': False, 'error': str(e), 'suspicious_indicators': []}
    
    def calculate_risk_score(self, file_metadata: Dict) -> float:
        """
        Calculate risk score based on heuristic analysis
        
        Args:
            file_metadata: Dictionary containing file analysis results
            
        Returns:
            Risk score between 0.0 and 1.0
        """
        risk_score = 0.0
        
        # Entropy-based scoring (high entropy = potential obfuscation)
        entropy = file_metadata.get('entropy', 0.0)
        if entropy > 0.8:
            risk_score += 0.3
        elif entropy > 0.6:
            risk_score += 0.2
        elif entropy > 0.4:
            risk_score += 0.1
        
        # PE analysis scoring
        pe_analysis = file_metadata.get('pe_analysis', {})
        suspicious_indicators = pe_analysis.get('suspicious_indicators', [])
        
        # Add risk for each suspicious indicator
        risk_score += len(suspicious_indicators) * 0.15
        
        # File size heuristics
        file_size = file_metadata.get('file_size', 0)
        if file_size < 1024:  # Very small files can be suspicious
            risk_score += 0.1
        elif file_size > 50 * 1024 * 1024:  # Very large files
            risk_score += 0.05
        
        # File extension heuristics
        file_path = file_metadata.get('file_path', '')
        suspicious_extensions = ['.exe', '.scr', '.bat', '.cmd', '.pif', '.com']
        if any(file_path.lower().endswith(ext) for ext in suspicious_extensions):
            risk_score += 0.1
        
        # IMPORTANT: No ML term is added to the static score here. This score is
        # now a PURELY DETERMINISTIC heuristic (entropy + PE suspicious indicators
        # + file size + extension), so the same file always yields the same score.
        # The real machine-learning signal is produced independently by the
        # EMBER-trained gradient-boosted model (src/ml/detector.py) and fused with
        # this static score inside the engine (src/antiv_engine.py). The previous
        # implementation added `random.uniform(-0.2, 0.2)` here, which made risk
        # scores non-reproducible and was not machine learning at all.

        # Cap the risk score at 1.0 so it stays a clean 0.0-1.0 probability-like value.
        return min(risk_score, 1.0)

    def analyze_file(self, file_path: str) -> Dict:
        """
        Perform comprehensive file analysis

        Args:
            file_path: Path to the file to analyze

        Returns:
            Dictionary containing complete analysis results
        """
        if not os.path.exists(file_path):
            self.logger.error(f"File not found: {file_path}")
            return {'error': 'File not found'}

        self.logger.info(f"Analyzing file: {file_path}")

        try:
            # Get basic file information
            file_stats = os.stat(file_path)

            # Perform all analyses
            hashes = self.calculate_hashes(file_path)
            entropy = self.calculate_entropy(file_path)

            # PE analysis (only for executable files)
            pe_analysis = {}
            if file_path.lower().endswith(('.exe', '.dll', '.sys', '.scr')):
                pe_analysis = self.analyze_pe_header(file_path)

            # Compile metadata
            file_metadata = {
                'file_path': file_path,
                'file_name': os.path.basename(file_path),
                'file_size': file_stats.st_size,
                'creation_time': datetime.fromtimestamp(file_stats.st_ctime).isoformat(),
                'modification_time': datetime.fromtimestamp(file_stats.st_mtime).isoformat(),
                'sha256': hashes['sha256'],
                'md5': hashes['md5'],
                'entropy': entropy,
                'pe_analysis': pe_analysis,
                'scan_timestamp': datetime.now().isoformat(),
                'platform': platform.system()
            }

            # Calculate risk score
            risk_score = self.calculate_risk_score(file_metadata)
            file_metadata['risk_score'] = risk_score

            # Determine threat level
            if risk_score >= 0.8:
                threat_level = 'HIGH'
            elif risk_score >= 0.6:
                threat_level = 'MEDIUM'
            elif risk_score >= 0.3:
                threat_level = 'LOW'
            else:
                threat_level = 'CLEAN'

            file_metadata['threat_level'] = threat_level

            self.logger.info(f"Analysis complete for {file_path}: Risk={risk_score:.3f}, Level={threat_level}")

            return file_metadata

        except Exception as e:
            self.logger.error(f"Error during file analysis: {str(e)}")
            return {'error': str(e), 'file_path': file_path}
