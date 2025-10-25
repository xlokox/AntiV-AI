"""
Database and Logging System for File Analysis Results
Handles SQLite database operations and JSON fallback logging
"""

import sqlite3
import json
import os
import logging
from datetime import datetime
from typing import Dict, List, Optional
from database_security import SecureDatabase, db_encryption

class ScanDatabase:
    """Database manager for storing scan results and file metadata"""
    
    def __init__(self, db_path: str = "data/antiv_ai.db", json_fallback: bool = True):
        """
        Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
            json_fallback: Whether to use JSON logging as fallback
        """
        self.db_path = db_path
        self.json_fallback = json_fallback
        self.json_log_path = "data/scan_results.json"
        
        # Create data directory
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        os.makedirs("data", exist_ok=True)

        # Setup logging first
        self.logger = logging.getLogger(__name__)

        # Initialize secure database
        self.secure_db = SecureDatabase(db_path)

        # Initialize database
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create scan_results table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL,
                        file_name TEXT NOT NULL,
                        file_size INTEGER,
                        sha256 TEXT,
                        md5 TEXT,
                        entropy REAL,
                        risk_score REAL,
                        threat_level TEXT,
                        scan_timestamp TEXT,
                        creation_time TEXT,
                        modification_time TEXT,
                        platform TEXT,
                        pe_analysis TEXT,
                        flagged BOOLEAN DEFAULT 0
                    )
                ''')
                
                # Create alerts table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        file_path TEXT NOT NULL,
                        risk_score REAL,
                        threat_level TEXT,
                        alert_timestamp TEXT,
                        alert_reason TEXT,
                        resolved BOOLEAN DEFAULT 0
                    )
                ''')
                
                # Create index for faster queries
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON scan_results(file_path)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON scan_results(threat_level)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_timestamp ON scan_results(scan_timestamp)')
                
                conn.commit()
                self.logger.info("Database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Error initializing database: {str(e)}")
            if self.json_fallback:
                self.logger.info("Falling back to JSON logging")
    
    def store_scan_result(self, file_metadata: Dict) -> bool:
        """
        Store scan result in database
        
        Args:
            file_metadata: Dictionary containing file analysis results
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Prepare data for insertion
                pe_analysis_json = json.dumps(file_metadata.get('pe_analysis', {}))
                flagged = file_metadata.get('risk_score', 0) > 0.6
                
                cursor.execute('''
                    INSERT INTO scan_results (
                        file_path, file_name, file_size, sha256, md5, entropy,
                        risk_score, threat_level, scan_timestamp, creation_time,
                        modification_time, platform, pe_analysis, flagged
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    file_metadata.get('file_path', ''),
                    file_metadata.get('file_name', ''),
                    file_metadata.get('file_size', 0),
                    file_metadata.get('sha256', ''),
                    file_metadata.get('md5', ''),
                    file_metadata.get('entropy', 0.0),
                    file_metadata.get('risk_score', 0.0),
                    file_metadata.get('threat_level', 'UNKNOWN'),
                    file_metadata.get('scan_timestamp', ''),
                    file_metadata.get('creation_time', ''),
                    file_metadata.get('modification_time', ''),
                    file_metadata.get('platform', ''),
                    pe_analysis_json,
                    flagged
                ))
                
                conn.commit()
                self.logger.debug(f"Stored scan result for {file_metadata.get('file_path', 'unknown')}")
                return True
                
        except Exception as e:
            self.logger.error(f"Error storing scan result: {str(e)}")
            
            # Fallback to JSON logging
            if self.json_fallback:
                return self.store_scan_result_json(file_metadata)
            
            return False
    
    def store_scan_result_json(self, file_metadata: Dict) -> bool:
        """
        Store scan result in JSON file as fallback
        
        Args:
            file_metadata: Dictionary containing file analysis results
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Load existing data
            scan_results = []
            if os.path.exists(self.json_log_path):
                with open(self.json_log_path, 'r') as f:
                    scan_results = json.load(f)
            
            # Add new result
            scan_results.append(file_metadata)
            
            # Write back to file
            with open(self.json_log_path, 'w') as f:
                json.dump(scan_results, f, indent=2)
            
            self.logger.debug(f"Stored scan result in JSON for {file_metadata.get('file_path', 'unknown')}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error storing scan result in JSON: {str(e)}")
            return False
    
    def create_alert(self, file_metadata: Dict, reason: str = "High risk score") -> bool:
        """
        Create an alert for a flagged file
        
        Args:
            file_metadata: File analysis results
            reason: Reason for the alert
            
        Returns:
            True if successful, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO alerts (
                        file_path, risk_score, threat_level, alert_timestamp, alert_reason
                    ) VALUES (?, ?, ?, ?, ?)
                ''', (
                    file_metadata.get('file_path', ''),
                    file_metadata.get('risk_score', 0.0),
                    file_metadata.get('threat_level', 'UNKNOWN'),
                    datetime.now().isoformat(),
                    reason
                ))
                
                conn.commit()
                self.logger.warning(f"ALERT: {reason} - {file_metadata.get('file_path', 'unknown')} (Risk: {file_metadata.get('risk_score', 0):.3f})")
                return True
                
        except Exception as e:
            self.logger.error(f"Error creating alert: {str(e)}")
            return False
    
    def get_scan_history(self, limit: int = 100) -> List[Dict]:
        """
        Retrieve recent scan history
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of scan results
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM scan_results 
                    ORDER BY scan_timestamp DESC 
                    LIMIT ?
                ''', (limit,))
                
                columns = [description[0] for description in cursor.description]
                results = []
                
                for row in cursor.fetchall():
                    result = dict(zip(columns, row))
                    # Parse PE analysis JSON
                    if result['pe_analysis']:
                        result['pe_analysis'] = json.loads(result['pe_analysis'])
                    results.append(result)
                
                return results
                
        except Exception as e:
            self.logger.error(f"Error retrieving scan history: {str(e)}")
            return []
    
    def get_flagged_files(self) -> List[Dict]:
        """
        Retrieve all flagged files
        
        Returns:
            List of flagged file results
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM scan_results 
                    WHERE flagged = 1 
                    ORDER BY risk_score DESC
                ''')
                
                columns = [description[0] for description in cursor.description]
                results = []
                
                for row in cursor.fetchall():
                    result = dict(zip(columns, row))
                    if result['pe_analysis']:
                        result['pe_analysis'] = json.loads(result['pe_analysis'])
                    results.append(result)
                
                return results
                
        except Exception as e:
            self.logger.error(f"Error retrieving flagged files: {str(e)}")
            return []
