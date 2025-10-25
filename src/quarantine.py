"""
Quarantine System for AntiV-AI
Automatically isolates high-risk files and blocks execution
"""

import os
import shutil
import hashlib
import json
import sqlite3
import logging
import platform
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass, asdict

@dataclass
class QuarantineEntry:
    """Quarantined file entry"""
    id: str
    original_path: str
    quarantine_path: str
    file_hash: str
    file_size: int
    risk_score: float
    threat_level: str
    quarantine_timestamp: str
    reason: str
    restored: bool = False
    restore_timestamp: Optional[str] = None

class QuarantineManager:
    """Manages file quarantine and isolation"""
    
    def __init__(self, quarantine_dir: str = "quarantine", db_path: str = "data/quarantine.db"):
        """
        Initialize quarantine manager
        
        Args:
            quarantine_dir: Directory to store quarantined files
            db_path: Path to quarantine database
        """
        self.logger = logging.getLogger(__name__)
        self.quarantine_dir = Path(quarantine_dir)
        self.db_path = db_path
        
        # Create quarantine directory
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Set restrictive permissions on quarantine directory
        if platform.system() != "Windows":
            os.chmod(self.quarantine_dir, 0o700)  # Owner read/write/execute only
        
        # Initialize database
        self._init_database()
        
        self.logger.info(f"Quarantine manager initialized: {self.quarantine_dir}")
    
    def _init_database(self):
        """Initialize quarantine database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quarantine_entries (
                        id TEXT PRIMARY KEY,
                        original_path TEXT NOT NULL,
                        quarantine_path TEXT NOT NULL,
                        file_hash TEXT NOT NULL,
                        file_size INTEGER,
                        risk_score REAL,
                        threat_level TEXT,
                        quarantine_timestamp TEXT,
                        reason TEXT,
                        restored BOOLEAN DEFAULT 0,
                        restore_timestamp TEXT
                    )
                ''')
                
                # Create index for faster queries
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_quarantine_timestamp ON quarantine_entries(quarantine_timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON quarantine_entries(threat_level)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_restored ON quarantine_entries(restored)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing quarantine database: {str(e)}")
    
    def should_quarantine(self, risk_score: float, threat_level: str) -> bool:
        """
        Determine if a file should be quarantined
        
        Args:
            risk_score: File risk score (0.0-1.0)
            threat_level: Threat level (HIGH, MEDIUM, LOW, CLEAN)
            
        Returns:
            True if file should be quarantined
        """
        # Quarantine HIGH risk files or files with risk score > 0.8
        return threat_level == 'HIGH' or risk_score >= 0.8
    
    def quarantine_file(self, file_path: str, risk_score: float, threat_level: str, reason: str = "High risk detected") -> Optional[QuarantineEntry]:
        """
        Quarantine a file
        
        Args:
            file_path: Path to file to quarantine
            risk_score: File risk score
            threat_level: Threat level
            reason: Reason for quarantine
            
        Returns:
            QuarantineEntry if successful, None otherwise
        """
        try:
            if not os.path.exists(file_path):
                self.logger.error(f"File not found for quarantine: {file_path}")
                return None
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # Generate unique quarantine ID
            quarantine_id = f"{file_hash}_{int(datetime.now().timestamp())}"
            
            # Create quarantine subdirectory based on date
            date_dir = self.quarantine_dir / datetime.now().strftime("%Y-%m-%d")
            date_dir.mkdir(exist_ok=True)
            
            # Quarantine file path (encrypted filename for security)
            quarantine_filename = f"{quarantine_id}.quarantined"
            quarantine_path = date_dir / quarantine_filename
            
            # Move file to quarantine (with encryption-like obfuscation)
            self._secure_move_file(file_path, quarantine_path)
            
            # Create quarantine entry
            entry = QuarantineEntry(
                id=quarantine_id,
                original_path=file_path,
                quarantine_path=str(quarantine_path),
                file_hash=file_hash,
                file_size=file_size,
                risk_score=risk_score,
                threat_level=threat_level,
                quarantine_timestamp=datetime.now().isoformat(),
                reason=reason
            )
            
            # Store in database
            self._store_quarantine_entry(entry)
            
            # Create metadata file
            self._create_metadata_file(entry)
            
            self.logger.warning(f"File quarantined: {file_path} -> {quarantine_path} (Risk: {risk_score:.3f})")
            
            return entry
            
        except Exception as e:
            self.logger.error(f"Error quarantining file {file_path}: {str(e)}")
            return None
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {str(e)}")
            return "unknown"
    
    def _secure_move_file(self, source_path: str, dest_path: str):
        """Securely move file to quarantine with basic obfuscation"""
        try:
            # Read original file
            with open(source_path, 'rb') as src:
                data = src.read()
            
            # Simple XOR obfuscation (not real encryption, but prevents accidental execution)
            key = b'AntiV-AI-Quarantine-Key-2024'
            obfuscated_data = bytes(a ^ key[i % len(key)] for i, a in enumerate(data))
            
            # Write obfuscated data to quarantine
            with open(dest_path, 'wb') as dst:
                dst.write(obfuscated_data)
            
            # Set restrictive permissions
            if platform.system() != "Windows":
                os.chmod(dest_path, 0o600)  # Owner read/write only
            
            # Remove original file
            os.remove(source_path)
            
        except Exception as e:
            self.logger.error(f"Error moving file to quarantine: {str(e)}")
            raise
    
    def _store_quarantine_entry(self, entry: QuarantineEntry):
        """Store quarantine entry in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO quarantine_entries (
                        id, original_path, quarantine_path, file_hash, file_size,
                        risk_score, threat_level, quarantine_timestamp, reason, restored
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry.id, entry.original_path, entry.quarantine_path,
                    entry.file_hash, entry.file_size, entry.risk_score,
                    entry.threat_level, entry.quarantine_timestamp,
                    entry.reason, entry.restored
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing quarantine entry: {str(e)}")
            raise
    
    def _create_metadata_file(self, entry: QuarantineEntry):
        """Create metadata file for quarantined item"""
        try:
            metadata_path = Path(entry.quarantine_path).with_suffix('.metadata.json')
            
            metadata = {
                'quarantine_entry': asdict(entry),
                'quarantine_system': 'AntiV-AI',
                'version': '1.0.0',
                'platform': platform.system(),
                'warning': 'This file has been quarantined due to security threats. Do not restore without proper analysis.'
            }
            
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Error creating metadata file: {str(e)}")
    
    def restore_file(self, quarantine_id: str, restore_path: Optional[str] = None) -> bool:
        """
        Restore a quarantined file
        
        Args:
            quarantine_id: ID of quarantined file
            restore_path: Optional custom restore path
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get quarantine entry
            entry = self.get_quarantine_entry(quarantine_id)
            if not entry:
                self.logger.error(f"Quarantine entry not found: {quarantine_id}")
                return False
            
            if entry.restored:
                self.logger.warning(f"File already restored: {quarantine_id}")
                return False
            
            # Determine restore path
            if restore_path is None:
                restore_path = entry.original_path
            
            # Ensure restore directory exists
            os.makedirs(os.path.dirname(restore_path), exist_ok=True)
            
            # Read and deobfuscate quarantined file
            with open(entry.quarantine_path, 'rb') as src:
                obfuscated_data = src.read()
            
            # Reverse XOR obfuscation
            key = b'AntiV-AI-Quarantine-Key-2024'
            original_data = bytes(a ^ key[i % len(key)] for i, a in enumerate(obfuscated_data))
            
            # Write restored file
            with open(restore_path, 'wb') as dst:
                dst.write(original_data)
            
            # Update database
            self._mark_as_restored(quarantine_id, restore_path)
            
            self.logger.info(f"File restored: {quarantine_id} -> {restore_path}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring file {quarantine_id}: {str(e)}")
            return False
    
    def _mark_as_restored(self, quarantine_id: str, restore_path: str):
        """Mark quarantine entry as restored"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE quarantine_entries 
                    SET restored = 1, restore_timestamp = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), quarantine_id))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error marking as restored: {str(e)}")
    
    def delete_quarantined_file(self, quarantine_id: str) -> bool:
        """
        Permanently delete a quarantined file
        
        Args:
            quarantine_id: ID of quarantined file
            
        Returns:
            True if successful, False otherwise
        """
        try:
            entry = self.get_quarantine_entry(quarantine_id)
            if not entry:
                return False
            
            # Remove quarantined file and metadata
            if os.path.exists(entry.quarantine_path):
                os.remove(entry.quarantine_path)
            
            metadata_path = Path(entry.quarantine_path).with_suffix('.metadata.json')
            if metadata_path.exists():
                metadata_path.unlink()
            
            # Remove from database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM quarantine_entries WHERE id = ?', (quarantine_id,))
                conn.commit()
            
            self.logger.info(f"Quarantined file permanently deleted: {quarantine_id}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error deleting quarantined file {quarantine_id}: {str(e)}")
            return False
    
    def get_quarantine_entry(self, quarantine_id: str) -> Optional[QuarantineEntry]:
        """Get quarantine entry by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT * FROM quarantine_entries WHERE id = ?', (quarantine_id,))
                row = cursor.fetchone()
                
                if row:
                    return QuarantineEntry(
                        id=row[0],
                        original_path=row[1],
                        quarantine_path=row[2],
                        file_hash=row[3],
                        file_size=row[4],
                        risk_score=row[5],
                        threat_level=row[6],
                        quarantine_timestamp=row[7],
                        reason=row[8],
                        restored=bool(row[9]),
                        restore_timestamp=row[10]
                    )
                
                return None
                
        except Exception as e:
            self.logger.error(f"Error getting quarantine entry: {str(e)}")
            return None
    
    def list_quarantined_files(self, include_restored: bool = False) -> List[QuarantineEntry]:
        """List all quarantined files"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                if include_restored:
                    cursor.execute('SELECT * FROM quarantine_entries ORDER BY quarantine_timestamp DESC')
                else:
                    cursor.execute('SELECT * FROM quarantine_entries WHERE restored = 0 ORDER BY quarantine_timestamp DESC')
                
                entries = []
                for row in cursor.fetchall():
                    entries.append(QuarantineEntry(
                        id=row[0],
                        original_path=row[1],
                        quarantine_path=row[2],
                        file_hash=row[3],
                        file_size=row[4],
                        risk_score=row[5],
                        threat_level=row[6],
                        quarantine_timestamp=row[7],
                        reason=row[8],
                        restored=bool(row[9]),
                        restore_timestamp=row[10]
                    ))
                
                return entries
                
        except Exception as e:
            self.logger.error(f"Error listing quarantined files: {str(e)}")
            return []
    
    def get_quarantine_statistics(self) -> Dict:
        """Get quarantine statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total quarantined files
                cursor.execute('SELECT COUNT(*) FROM quarantine_entries')
                total_quarantined = cursor.fetchone()[0]
                
                # Active quarantined files
                cursor.execute('SELECT COUNT(*) FROM quarantine_entries WHERE restored = 0')
                active_quarantined = cursor.fetchone()[0]
                
                # Restored files
                cursor.execute('SELECT COUNT(*) FROM quarantine_entries WHERE restored = 1')
                restored_files = cursor.fetchone()[0]
                
                # Threat level distribution
                cursor.execute('SELECT threat_level, COUNT(*) FROM quarantine_entries WHERE restored = 0 GROUP BY threat_level')
                threat_distribution = dict(cursor.fetchall())
                
                # Total quarantine size
                cursor.execute('SELECT SUM(file_size) FROM quarantine_entries WHERE restored = 0')
                total_size = cursor.fetchone()[0] or 0
                
                return {
                    'total_quarantined': total_quarantined,
                    'active_quarantined': active_quarantined,
                    'restored_files': restored_files,
                    'threat_distribution': threat_distribution,
                    'total_size_bytes': total_size,
                    'quarantine_directory': str(self.quarantine_dir)
                }
                
        except Exception as e:
            self.logger.error(f"Error getting quarantine statistics: {str(e)}")
            return {}
    
    def cleanup_old_quarantine(self, days_old: int = 30) -> int:
        """
        Clean up quarantine files older than specified days
        
        Args:
            days_old: Number of days after which to clean up
            
        Returns:
            Number of files cleaned up
        """
        try:
            from datetime import timedelta
            
            cutoff_date = datetime.now() - timedelta(days=days_old)
            cutoff_str = cutoff_date.isoformat()
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get old entries
                cursor.execute('''
                    SELECT id, quarantine_path FROM quarantine_entries 
                    WHERE quarantine_timestamp < ? AND restored = 1
                ''', (cutoff_str,))
                
                old_entries = cursor.fetchall()
                cleaned_count = 0
                
                for entry_id, quarantine_path in old_entries:
                    try:
                        # Remove files
                        if os.path.exists(quarantine_path):
                            os.remove(quarantine_path)
                        
                        metadata_path = Path(quarantine_path).with_suffix('.metadata.json')
                        if metadata_path.exists():
                            metadata_path.unlink()
                        
                        # Remove from database
                        cursor.execute('DELETE FROM quarantine_entries WHERE id = ?', (entry_id,))
                        cleaned_count += 1
                        
                    except Exception as e:
                        self.logger.error(f"Error cleaning up {entry_id}: {str(e)}")
                
                conn.commit()
                
                self.logger.info(f"Cleaned up {cleaned_count} old quarantine entries")
                return cleaned_count
                
        except Exception as e:
            self.logger.error(f"Error during quarantine cleanup: {str(e)}")
            return 0
