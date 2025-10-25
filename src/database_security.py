"""
Database Security and Encryption for AntiV-AI
Implements database encryption at rest, field-level encryption, and automated backups
"""

import os
import sqlite3
import json
import shutil
import gzip
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Encryption configuration
ENCRYPTION_KEY_FILE = "data/.encryption_key"
BACKUP_RETENTION_DAYS = 30
BACKUP_INTERVAL_HOURS = 6

class DatabaseEncryption:
    """Handles database and field-level encryption"""
    
    def __init__(self, key_file: str = ENCRYPTION_KEY_FILE):
        """Initialize database encryption"""
        self.logger = logging.getLogger(__name__)
        self.key_file = key_file
        self.fernet = self._initialize_encryption()
    
    def _initialize_encryption(self) -> Fernet:
        """Initialize encryption with key management"""
        try:
            # Ensure data directory exists
            os.makedirs(os.path.dirname(self.key_file), exist_ok=True)
            
            # Load or generate encryption key
            if os.path.exists(self.key_file):
                with open(self.key_file, 'rb') as f:
                    key = f.read()
                self.logger.info("Loaded existing encryption key")
            else:
                # Generate new key
                key = Fernet.generate_key()
                with open(self.key_file, 'wb') as f:
                    f.write(key)
                
                # Set restrictive permissions
                os.chmod(self.key_file, 0o600)
                self.logger.info("Generated new encryption key")
            
            return Fernet(key)
            
        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {str(e)}")
            raise
    
    def encrypt_field(self, data: str) -> str:
        """Encrypt a field value"""
        if not data:
            return data
        
        try:
            encrypted_data = self.fernet.encrypt(data.encode('utf-8'))
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            self.logger.error(f"Field encryption failed: {str(e)}")
            return data  # Return original data if encryption fails
    
    def decrypt_field(self, encrypted_data: str) -> str:
        """Decrypt a field value"""
        if not encrypted_data:
            return encrypted_data
        
        try:
            decoded_data = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.fernet.decrypt(decoded_data)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Field decryption failed: {str(e)}")
            return encrypted_data  # Return original data if decryption fails
    
    def encrypt_database_file(self, db_path: str) -> str:
        """Encrypt entire database file"""
        try:
            encrypted_path = f"{db_path}.encrypted"
            
            with open(db_path, 'rb') as infile:
                data = infile.read()
            
            encrypted_data = self.fernet.encrypt(data)
            
            with open(encrypted_path, 'wb') as outfile:
                outfile.write(encrypted_data)
            
            # Set restrictive permissions
            os.chmod(encrypted_path, 0o600)
            
            return encrypted_path
            
        except Exception as e:
            self.logger.error(f"Database file encryption failed: {str(e)}")
            raise
    
    def decrypt_database_file(self, encrypted_path: str, output_path: str):
        """Decrypt database file"""
        try:
            with open(encrypted_path, 'rb') as infile:
                encrypted_data = infile.read()
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            with open(output_path, 'wb') as outfile:
                outfile.write(decrypted_data)
            
            # Set restrictive permissions
            os.chmod(output_path, 0o600)
            
        except Exception as e:
            self.logger.error(f"Database file decryption failed: {str(e)}")
            raise

class SecureDatabase:
    """Secure database wrapper with encryption and backup"""
    
    def __init__(self, db_path: str):
        """Initialize secure database"""
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self.encryption = DatabaseEncryption()
        self.backup_dir = Path("backups")
        
        # Create backup directory
        self.backup_dir.mkdir(exist_ok=True)
        os.chmod(self.backup_dir, 0o700)
        
        # Ensure database file has secure permissions
        if os.path.exists(self.db_path):
            os.chmod(self.db_path, 0o600)
    
    def connect(self) -> sqlite3.Connection:
        """Create secure database connection"""
        try:
            # Ensure parent directory exists
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            # Create connection with security settings
            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                check_same_thread=False
            )
            
            # Enable WAL mode for better concurrency and crash recovery
            conn.execute("PRAGMA journal_mode=WAL")
            
            # Enable foreign key constraints
            conn.execute("PRAGMA foreign_keys=ON")
            
            # Set secure temp store
            conn.execute("PRAGMA temp_store=MEMORY")
            
            # Set page size for better performance
            conn.execute("PRAGMA page_size=4096")
            
            # Enable automatic checkpointing
            conn.execute("PRAGMA wal_autocheckpoint=1000")
            
            return conn
            
        except Exception as e:
            self.logger.error(f"Database connection failed: {str(e)}")
            raise
    
    def encrypt_sensitive_data(self, data: Dict) -> Dict:
        """Encrypt sensitive fields in data dictionary"""
        sensitive_fields = ['file_path', 'original_path', 'email', 'username']
        
        encrypted_data = data.copy()
        for field in sensitive_fields:
            if field in encrypted_data and encrypted_data[field]:
                encrypted_data[field] = self.encryption.encrypt_field(str(encrypted_data[field]))
        
        return encrypted_data
    
    def decrypt_sensitive_data(self, data: Dict) -> Dict:
        """Decrypt sensitive fields in data dictionary"""
        sensitive_fields = ['file_path', 'original_path', 'email', 'username']
        
        decrypted_data = data.copy()
        for field in sensitive_fields:
            if field in decrypted_data and decrypted_data[field]:
                decrypted_data[field] = self.encryption.decrypt_field(str(decrypted_data[field]))
        
        return decrypted_data
    
    def create_backup(self, backup_name: Optional[str] = None) -> str:
        """Create encrypted database backup"""
        try:
            if not backup_name:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_name = f"antiv_backup_{timestamp}"
            
            backup_path = self.backup_dir / f"{backup_name}.db.gz.enc"
            
            # Create compressed backup
            temp_backup = self.backup_dir / f"{backup_name}.db"
            shutil.copy2(self.db_path, temp_backup)
            
            # Compress backup
            compressed_backup = self.backup_dir / f"{backup_name}.db.gz"
            with open(temp_backup, 'rb') as f_in:
                with gzip.open(compressed_backup, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Encrypt compressed backup
            with open(compressed_backup, 'rb') as f:
                data = f.read()
            
            encrypted_data = self.encryption.fernet.encrypt(data)
            
            with open(backup_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Clean up temporary files
            temp_backup.unlink()
            compressed_backup.unlink()
            
            # Set secure permissions
            os.chmod(backup_path, 0o600)
            
            self.logger.info(f"Database backup created: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {str(e)}")
            raise
    
    def restore_backup(self, backup_path: str) -> bool:
        """Restore database from encrypted backup"""
        try:
            # Decrypt backup
            with open(backup_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted_data = self.encryption.fernet.decrypt(encrypted_data)
            
            # Decompress
            temp_compressed = self.backup_dir / "temp_restore.db.gz"
            with open(temp_compressed, 'wb') as f:
                f.write(decrypted_data)
            
            # Extract database
            temp_db = self.backup_dir / "temp_restore.db"
            with gzip.open(temp_compressed, 'rb') as f_in:
                with open(temp_db, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Replace current database
            backup_current = f"{self.db_path}.backup_before_restore"
            shutil.move(self.db_path, backup_current)
            shutil.move(temp_db, self.db_path)
            
            # Set secure permissions
            os.chmod(self.db_path, 0o600)
            
            # Clean up
            temp_compressed.unlink()
            
            self.logger.info(f"Database restored from: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup restoration failed: {str(e)}")
            return False
    
    def cleanup_old_backups(self, retention_days: int = BACKUP_RETENTION_DAYS) -> int:
        """Clean up old backup files"""
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            cleaned_count = 0
            
            for backup_file in self.backup_dir.glob("*.db.gz.enc"):
                try:
                    file_time = datetime.fromtimestamp(backup_file.stat().st_mtime)
                    if file_time < cutoff_date:
                        backup_file.unlink()
                        cleaned_count += 1
                        self.logger.debug(f"Removed old backup: {backup_file}")
                except Exception as e:
                    self.logger.warning(f"Failed to remove backup {backup_file}: {str(e)}")
            
            if cleaned_count > 0:
                self.logger.info(f"Cleaned up {cleaned_count} old backup files")
            
            return cleaned_count
            
        except Exception as e:
            self.logger.error(f"Backup cleanup failed: {str(e)}")
            return 0
    
    def get_backup_info(self) -> List[Dict]:
        """Get information about available backups"""
        try:
            backups = []
            
            for backup_file in self.backup_dir.glob("*.db.gz.enc"):
                stat = backup_file.stat()
                backups.append({
                    'name': backup_file.name,
                    'path': str(backup_file),
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            
            # Sort by creation time (newest first)
            backups.sort(key=lambda x: x['created'], reverse=True)
            
            return backups
            
        except Exception as e:
            self.logger.error(f"Failed to get backup info: {str(e)}")
            return []

class AutoBackupManager:
    """Manages automated database backups"""
    
    def __init__(self, databases: List[SecureDatabase]):
        """Initialize auto backup manager"""
        self.logger = logging.getLogger(__name__)
        self.databases = databases
        self.last_backup = {}
    
    def should_backup(self, db_path: str) -> bool:
        """Check if database should be backed up"""
        if db_path not in self.last_backup:
            return True
        
        last_backup_time = self.last_backup[db_path]
        time_since_backup = datetime.now() - last_backup_time
        
        return time_since_backup.total_seconds() > (BACKUP_INTERVAL_HOURS * 3600)
    
    def run_auto_backup(self):
        """Run automatic backup for all databases"""
        try:
            for db in self.databases:
                if self.should_backup(db.db_path):
                    try:
                        backup_path = db.create_backup()
                        self.last_backup[db.db_path] = datetime.now()
                        
                        # Clean up old backups
                        db.cleanup_old_backups()
                        
                        self.logger.info(f"Auto backup completed: {backup_path}")
                        
                    except Exception as e:
                        self.logger.error(f"Auto backup failed for {db.db_path}: {str(e)}")
                        
        except Exception as e:
            self.logger.error(f"Auto backup process failed: {str(e)}")

# Global encryption instance
db_encryption = DatabaseEncryption()
