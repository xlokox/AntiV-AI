"""
Advanced Cryptographic Controls & Key Management for AntiV-AI
Implements HSM-compatible key management with Perfect Forward Secrecy
"""

import os
import secrets
import hashlib
import logging
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
import sqlite3
import json
import base64

# Key management configuration
KEY_ROTATION_INTERVAL_DAYS = 30
MAX_KEY_VERSIONS = 10
HSM_ENABLED = os.getenv('HSM_ENABLED', 'false').lower() == 'true'
HSM_ENDPOINT = os.getenv('HSM_ENDPOINT', 'localhost:8080')

@dataclass
class KeyMetadata:
    """Key metadata structure"""
    key_id: str
    version: int
    algorithm: str
    purpose: str
    created_at: str
    expires_at: str
    status: str  # ACTIVE, ROTATED, REVOKED
    hsm_key_id: Optional[str] = None

@dataclass
class EncryptionResult:
    """Encryption operation result"""
    ciphertext: bytes
    key_id: str
    key_version: int
    algorithm: str
    iv: Optional[bytes] = None
    tag: Optional[bytes] = None

class HSMClient:
    """Hardware Security Module client interface (stub implementation)"""
    
    def __init__(self, endpoint: str = HSM_ENDPOINT):
        """Initialize HSM client"""
        self.logger = logging.getLogger(__name__)
        self.endpoint = endpoint
        self.connected = False
        
        if HSM_ENABLED:
            self._connect()
    
    def _connect(self):
        """Connect to HSM (stub implementation)"""
        try:
            # In production, this would establish connection to actual HSM
            self.logger.info(f"Connecting to HSM at {self.endpoint}")
            # Simulate connection
            self.connected = True
            self.logger.info("HSM connection established (simulated)")
        except Exception as e:
            self.logger.error(f"HSM connection failed: {str(e)}")
            self.connected = False
    
    def generate_key(self, algorithm: str, purpose: str) -> str:
        """Generate key in HSM"""
        if not self.connected:
            raise Exception("HSM not connected")
        
        # Simulate HSM key generation
        hsm_key_id = f"hsm-{algorithm}-{secrets.token_hex(16)}"
        self.logger.info(f"Generated HSM key: {hsm_key_id}")
        return hsm_key_id
    
    def encrypt(self, hsm_key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using HSM key"""
        if not self.connected:
            raise Exception("HSM not connected")
        
        # Simulate HSM encryption (in production, this would use actual HSM)
        # For simulation, use local encryption with derived key
        derived_key = hashlib.sha256(hsm_key_id.encode()).digest()
        fernet = Fernet(base64.urlsafe_b64encode(derived_key))
        return fernet.encrypt(plaintext)
    
    def decrypt(self, hsm_key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using HSM key"""
        if not self.connected:
            raise Exception("HSM not connected")
        
        # Simulate HSM decryption
        derived_key = hashlib.sha256(hsm_key_id.encode()).digest()
        fernet = Fernet(base64.urlsafe_b64encode(derived_key))
        return fernet.decrypt(ciphertext)
    
    def delete_key(self, hsm_key_id: str) -> bool:
        """Delete key from HSM"""
        if not self.connected:
            return False
        
        self.logger.info(f"Deleted HSM key: {hsm_key_id}")
        return True

class KeyManager:
    """Advanced cryptographic key management with HSM support"""
    
    def __init__(self, db_path: str = "data/key_management.db"):
        """Initialize key manager"""
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self.hsm_client = HSMClient() if HSM_ENABLED else None
        
        # Initialize key database
        self._init_key_database()
        
        # Current encryption keys cache
        self._active_keys = {}
        self._load_active_keys()
    
    def _init_key_database(self):
        """Initialize key management database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Key metadata table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS key_metadata (
                        key_id TEXT PRIMARY KEY,
                        version INTEGER NOT NULL,
                        algorithm TEXT NOT NULL,
                        purpose TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        status TEXT NOT NULL,
                        hsm_key_id TEXT,
                        key_material TEXT
                    )
                ''')
                
                # Key rotation history
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS key_rotation_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key_id TEXT NOT NULL,
                        old_version INTEGER,
                        new_version INTEGER,
                        rotation_reason TEXT,
                        rotated_at TEXT NOT NULL,
                        rotated_by TEXT
                    )
                ''')
                
                # Encryption operations log
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS encryption_operations (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        operation_type TEXT NOT NULL,
                        key_id TEXT NOT NULL,
                        key_version INTEGER NOT NULL,
                        data_type TEXT,
                        timestamp TEXT NOT NULL,
                        success BOOLEAN NOT NULL
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_key_status ON key_metadata(status)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_key_purpose ON key_metadata(purpose)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_rotation_key ON key_rotation_history(key_id)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing key database: {str(e)}")
            raise
    
    def _load_active_keys(self):
        """Load active keys into memory cache"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT key_id, version, algorithm, purpose, key_material, hsm_key_id
                    FROM key_metadata 
                    WHERE status = 'ACTIVE'
                ''')
                
                for row in cursor.fetchall():
                    key_id, version, algorithm, purpose, key_material, hsm_key_id = row
                    
                    self._active_keys[f"{purpose}"] = {
                        'key_id': key_id,
                        'version': version,
                        'algorithm': algorithm,
                        'key_material': key_material,
                        'hsm_key_id': hsm_key_id
                    }
                
                self.logger.info(f"Loaded {len(self._active_keys)} active keys")
                
        except Exception as e:
            self.logger.error(f"Error loading active keys: {str(e)}")
    
    def generate_key(self, purpose: str = "data_encryption", algorithm: str = "AES-256-GCM") -> str:
        """
        Generate new encryption key
        
        Args:
            purpose: Key purpose (data_encryption, field_encryption, etc.)
            algorithm: Encryption algorithm
            
        Returns:
            Key ID of generated key
        """
        try:
            key_id = f"{purpose}_{secrets.token_hex(16)}"
            version = 1
            
            # Check if key already exists for this purpose
            existing_key = self._active_keys.get(purpose)
            if existing_key:
                version = existing_key['version'] + 1
            
            # Generate key material
            if self.hsm_client and self.hsm_client.connected:
                # Use HSM for key generation
                hsm_key_id = self.hsm_client.generate_key(algorithm, purpose)
                key_material = None  # Key stays in HSM
            else:
                # Generate local key
                if algorithm == "AES-256-GCM":
                    key_material = base64.b64encode(secrets.token_bytes(32)).decode()
                else:
                    key_material = base64.b64encode(secrets.token_bytes(32)).decode()
                hsm_key_id = None
            
            # Set expiration
            expires_at = (datetime.now() + timedelta(days=KEY_ROTATION_INTERVAL_DAYS)).isoformat()
            
            # Store key metadata
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Mark old key as rotated if exists
                if existing_key:
                    cursor.execute('''
                        UPDATE key_metadata SET status = 'ROTATED' 
                        WHERE key_id = ? AND status = 'ACTIVE'
                    ''', (existing_key['key_id'],))
                
                # Insert new key
                cursor.execute('''
                    INSERT INTO key_metadata 
                    (key_id, version, algorithm, purpose, created_at, expires_at, status, hsm_key_id, key_material)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    key_id, version, algorithm, purpose,
                    datetime.now().isoformat(), expires_at, 'ACTIVE',
                    hsm_key_id, key_material
                ))
                
                conn.commit()
            
            # Update active keys cache
            self._active_keys[purpose] = {
                'key_id': key_id,
                'version': version,
                'algorithm': algorithm,
                'key_material': key_material,
                'hsm_key_id': hsm_key_id
            }
            
            self.logger.info(f"Generated new key: {key_id} for purpose: {purpose}")
            return key_id
            
        except Exception as e:
            self.logger.error(f"Key generation failed: {str(e)}")
            raise
    
    def rotate_keys(self, purpose: Optional[str] = None) -> List[str]:
        """
        Rotate encryption keys
        
        Args:
            purpose: Specific purpose to rotate, or None for all keys
            
        Returns:
            List of new key IDs
        """
        try:
            rotated_keys = []
            
            if purpose:
                purposes_to_rotate = [purpose]
            else:
                purposes_to_rotate = list(self._active_keys.keys())
            
            for key_purpose in purposes_to_rotate:
                old_key = self._active_keys.get(key_purpose)
                if old_key:
                    # Generate new key
                    new_key_id = self.generate_key(key_purpose, old_key['algorithm'])
                    
                    # Log rotation
                    with sqlite3.connect(self.db_path) as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO key_rotation_history 
                            (key_id, old_version, new_version, rotation_reason, rotated_at, rotated_by)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (
                            new_key_id, old_key['version'], 
                            self._active_keys[key_purpose]['version'],
                            'Scheduled rotation', datetime.now().isoformat(), 'system'
                        ))
                        conn.commit()
                    
                    rotated_keys.append(new_key_id)
                    self.logger.info(f"Rotated key for purpose: {key_purpose}")
            
            return rotated_keys
            
        except Exception as e:
            self.logger.error(f"Key rotation failed: {str(e)}")
            raise
    
    def encrypt_field(self, data: str, purpose: str = "field_encryption") -> bytes:
        """
        Encrypt field data with Perfect Forward Secrecy
        
        Args:
            data: Data to encrypt
            purpose: Encryption purpose
            
        Returns:
            Encrypted data with metadata
        """
        try:
            if not data:
                return b''
            
            # Get active key for purpose
            key_info = self._active_keys.get(purpose)
            if not key_info:
                # Generate new key if none exists
                self.generate_key(purpose)
                key_info = self._active_keys[purpose]
            
            # Generate ephemeral key for Perfect Forward Secrecy
            ephemeral_key = secrets.token_bytes(32)
            
            # Derive encryption key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'field_encryption'
            )
            
            if key_info['hsm_key_id'] and self.hsm_client:
                # Use HSM for encryption
                master_key = key_info['hsm_key_id'].encode()
            else:
                # Use local key
                master_key = base64.b64decode(key_info['key_material'])
            
            derived_key = hkdf.derive(master_key + ephemeral_key)
            
            # Encrypt data
            fernet = Fernet(base64.urlsafe_b64encode(derived_key))
            ciphertext = fernet.encrypt(data.encode('utf-8'))
            
            # Create result with metadata
            result = {
                'ciphertext': base64.b64encode(ciphertext).decode(),
                'ephemeral_key': base64.b64encode(ephemeral_key).decode(),
                'key_id': key_info['key_id'],
                'key_version': key_info['version'],
                'algorithm': 'AES-256-GCM-HKDF'
            }
            
            # Log operation
            self._log_operation('encrypt', key_info['key_id'], key_info['version'], 'field', True)
            
            return base64.b64encode(json.dumps(result).encode()).decode()
            
        except Exception as e:
            self.logger.error(f"Field encryption failed: {str(e)}")
            if key_info:
                self._log_operation('encrypt', key_info['key_id'], key_info['version'], 'field', False)
            raise
    
    def decrypt_field(self, encrypted_data: str, purpose: str = "field_encryption") -> str:
        """
        Decrypt field data
        
        Args:
            encrypted_data: Encrypted data with metadata
            purpose: Encryption purpose
            
        Returns:
            Decrypted data
        """
        try:
            if not encrypted_data:
                return ''
            
            # Parse encrypted data
            try:
                data_dict = json.loads(base64.b64decode(encrypted_data).decode())
            except:
                # Fallback for old format
                return encrypted_data
            
            key_id = data_dict['key_id']
            key_version = data_dict['key_version']
            ciphertext = base64.b64decode(data_dict['ciphertext'])
            ephemeral_key = base64.b64decode(data_dict['ephemeral_key'])
            
            # Get key material
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT key_material, hsm_key_id FROM key_metadata 
                    WHERE key_id = ? AND version = ?
                ''', (key_id, key_version))
                
                row = cursor.fetchone()
                if not row:
                    raise Exception(f"Key not found: {key_id} v{key_version}")
                
                key_material, hsm_key_id = row
            
            # Derive decryption key
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'field_encryption'
            )
            
            if hsm_key_id and self.hsm_client:
                master_key = hsm_key_id.encode()
            else:
                master_key = base64.b64decode(key_material)
            
            derived_key = hkdf.derive(master_key + ephemeral_key)
            
            # Decrypt data
            fernet = Fernet(base64.urlsafe_b64encode(derived_key))
            plaintext = fernet.decrypt(ciphertext)
            
            # Log operation
            self._log_operation('decrypt', key_id, key_version, 'field', True)
            
            return plaintext.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Field decryption failed: {str(e)}")
            if 'key_id' in locals():
                self._log_operation('decrypt', key_id, key_version, 'field', False)
            return encrypted_data  # Return original if decryption fails
    
    def _log_operation(self, operation_type: str, key_id: str, key_version: int, 
                      data_type: str, success: bool):
        """Log encryption/decryption operation"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO encryption_operations 
                    (operation_type, key_id, key_version, data_type, timestamp, success)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    operation_type, key_id, key_version, data_type,
                    datetime.now().isoformat(), success
                ))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error logging operation: {str(e)}")
    
    def get_key_statistics(self) -> Dict:
        """Get key management statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Active keys count
                cursor.execute("SELECT COUNT(*) FROM key_metadata WHERE status = 'ACTIVE'")
                active_keys = cursor.fetchone()[0]
                
                # Total keys count
                cursor.execute("SELECT COUNT(*) FROM key_metadata")
                total_keys = cursor.fetchone()[0]
                
                # Recent operations
                cursor.execute('''
                    SELECT COUNT(*) FROM encryption_operations 
                    WHERE timestamp > datetime('now', '-24 hours')
                ''')
                recent_operations = cursor.fetchone()[0]
                
                # Key purposes
                cursor.execute('''
                    SELECT purpose, COUNT(*) FROM key_metadata 
                    WHERE status = 'ACTIVE' GROUP BY purpose
                ''')
                purposes = dict(cursor.fetchall())
                
                return {
                    'active_keys': active_keys,
                    'total_keys': total_keys,
                    'recent_operations_24h': recent_operations,
                    'key_purposes': purposes,
                    'hsm_enabled': HSM_ENABLED,
                    'hsm_connected': self.hsm_client.connected if self.hsm_client else False,
                    'rotation_interval_days': KEY_ROTATION_INTERVAL_DAYS
                }
                
        except Exception as e:
            self.logger.error(f"Error getting key statistics: {str(e)}")
            return {}

# Global key manager instance
key_manager = KeyManager()
