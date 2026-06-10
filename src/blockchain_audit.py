"""
Immutable Blockchain Audit Trail for AntiV-AI
Implements tamper-proof logging using hash chains and append-only ledger
"""

import os
import json
import hashlib
import logging
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import sqlite3
import fcntl
from pathlib import Path

# Blockchain audit configuration
LEDGER_FILE_PATH = "data/audit_ledger.json"
BLOCKCHAIN_DB_PATH = "data/blockchain_audit.db"
HASH_ALGORITHM = "sha256"
BLOCK_SIZE_LIMIT = 1000  # Maximum entries per block

@dataclass
class AuditEntry:
    """Individual audit entry"""
    entry_id: str
    timestamp: str
    event_type: str
    user_id: Optional[str]
    username: Optional[str]
    action: str
    resource: str
    outcome: str
    details: Dict[str, Any]
    risk_score: float
    source_ip: str
    session_id: Optional[str]

@dataclass
class BlockchainBlock:
    """Blockchain block containing audit entries"""
    block_id: str
    block_number: int
    timestamp: str
    previous_hash: str
    merkle_root: str
    entries: List[AuditEntry]
    block_hash: str
    nonce: int = 0

@dataclass
class ChainVerificationResult:
    """Result of blockchain verification"""
    is_valid: bool
    total_blocks: int
    total_entries: int
    broken_chains: List[int]
    tampered_blocks: List[int]
    verification_timestamp: str
    details: Dict[str, Any]

class BlockchainAudit:
    """Immutable blockchain audit trail system"""
    
    def __init__(self):
        """Initialize blockchain audit system"""
        self.logger = logging.getLogger(__name__)
        self.ledger_path = LEDGER_FILE_PATH
        self.db_path = BLOCKCHAIN_DB_PATH
        
        # Initialize storage
        self._init_blockchain_storage()
        
        # Current block being built
        self.current_block_entries = []
        self.last_block_hash = self._get_last_block_hash()
        
        self.logger.info("Blockchain audit system initialized")
    
    def _init_blockchain_storage(self):
        """Initialize blockchain storage systems"""
        try:
            # Create data directory
            os.makedirs(os.path.dirname(self.ledger_path), exist_ok=True)
            
            # Initialize SQLite database for fast queries
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Blocks table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS blockchain_blocks (
                        block_number INTEGER PRIMARY KEY,
                        block_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        merkle_root TEXT NOT NULL,
                        block_hash TEXT NOT NULL,
                        entry_count INTEGER NOT NULL,
                        nonce INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                # Entries table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS blockchain_entries (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        entry_id TEXT UNIQUE NOT NULL,
                        block_number INTEGER NOT NULL,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        user_id TEXT,
                        username TEXT,
                        action TEXT NOT NULL,
                        resource TEXT NOT NULL,
                        outcome TEXT NOT NULL,
                        risk_score REAL NOT NULL,
                        source_ip TEXT,
                        entry_hash TEXT NOT NULL,
                        details TEXT NOT NULL,
                        FOREIGN KEY (block_number) REFERENCES blockchain_blocks (block_number)
                    )
                ''')
                
                # Verification log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS verification_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        verification_timestamp TEXT NOT NULL,
                        is_valid BOOLEAN NOT NULL,
                        total_blocks INTEGER NOT NULL,
                        total_entries INTEGER NOT NULL,
                        broken_chains TEXT,
                        tampered_blocks TEXT,
                        verification_details TEXT
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_entries_timestamp ON blockchain_entries(timestamp)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_entries_user ON blockchain_entries(user_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_entries_type ON blockchain_entries(event_type)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blockchain_blocks(block_hash)')
                
                conn.commit()
            
            # Initialize ledger file if it doesn't exist
            if not os.path.exists(self.ledger_path):
                self._create_genesis_block()
            
        except Exception as e:
            self.logger.error(f"Error initializing blockchain storage: {str(e)}")
            raise
    
    def _create_genesis_block(self):
        """Create the genesis block"""
        try:
            genesis_entry = AuditEntry(
                entry_id="genesis",
                timestamp=datetime.now().isoformat(),
                event_type="system",
                user_id=None,
                username="system",
                action="blockchain_initialized",
                resource="audit_system",
                outcome="SUCCESS",
                details={"message": "Blockchain audit system initialized"},
                risk_score=0.0,
                source_ip="127.0.0.1",
                session_id=None
            )
            
            genesis_block = BlockchainBlock(
                block_id="genesis",
                block_number=0,
                timestamp=datetime.now().isoformat(),
                previous_hash="0" * 64,  # Genesis block has no previous hash
                merkle_root=self._calculate_merkle_root([genesis_entry]),
                entries=[genesis_entry],
                block_hash="",
                nonce=0
            )
            
            # Calculate block hash
            genesis_block.block_hash = self._calculate_block_hash(genesis_block)
            
            # Write genesis block to ledger
            self._write_block_to_ledger(genesis_block)
            
            # Store in database
            self._store_block_in_db(genesis_block)
            
            self.logger.info("Genesis block created")
            
        except Exception as e:
            self.logger.error(f"Error creating genesis block: {str(e)}")
            raise
    
    def _calculate_hash(self, data: str) -> str:
        """Calculate hash of data"""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def _calculate_entry_hash(self, entry: AuditEntry) -> str:
        """Calculate hash of audit entry"""
        entry_data = json.dumps(asdict(entry), sort_keys=True)
        return self._calculate_hash(entry_data)
    
    def _calculate_merkle_root(self, entries: List[AuditEntry]) -> str:
        """Calculate Merkle root of entries"""
        if not entries:
            return "0" * 64
        
        # Calculate hash of each entry
        hashes = [self._calculate_entry_hash(entry) for entry in entries]
        
        # Build Merkle tree
        while len(hashes) > 1:
            next_level = []
            for i in range(0, len(hashes), 2):
                if i + 1 < len(hashes):
                    combined = hashes[i] + hashes[i + 1]
                else:
                    combined = hashes[i] + hashes[i]  # Duplicate if odd number
                next_level.append(self._calculate_hash(combined))
            hashes = next_level
        
        return hashes[0]
    
    def _calculate_block_hash(self, block: BlockchainBlock) -> str:
        """Calculate hash of blockchain block"""
        block_data = {
            'block_id': block.block_id,
            'block_number': block.block_number,
            'timestamp': block.timestamp,
            'previous_hash': block.previous_hash,
            'merkle_root': block.merkle_root,
            'nonce': block.nonce
        }
        
        block_string = json.dumps(block_data, sort_keys=True)
        return self._calculate_hash(block_string)
    
    def _get_last_block_hash(self) -> str:
        """Get hash of the last block in the chain"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT block_hash FROM blockchain_blocks 
                    ORDER BY block_number DESC LIMIT 1
                ''')
                
                row = cursor.fetchone()
                if row:
                    return row[0]
                else:
                    return "0" * 64  # No blocks yet
                    
        except Exception as e:
            self.logger.error(f"Error getting last block hash: {str(e)}")
            return "0" * 64
    
    def _get_next_block_number(self) -> int:
        """Get the next block number"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT MAX(block_number) FROM blockchain_blocks
                ''')
                
                row = cursor.fetchone()
                if row and row[0] is not None:
                    return row[0] + 1
                else:
                    return 0
                    
        except Exception as e:
            self.logger.error(f"Error getting next block number: {str(e)}")
            return 0
    
    def add_audit_entry(self, entry: AuditEntry):
        """Add audit entry to the blockchain"""
        try:
            # Add entry to current block
            self.current_block_entries.append(entry)
            
            # Check if we should finalize the current block
            if len(self.current_block_entries) >= BLOCK_SIZE_LIMIT:
                self._finalize_current_block()
            
        except Exception as e:
            self.logger.error(f"Error adding audit entry: {str(e)}")
    
    def _finalize_current_block(self):
        """Finalize the current block and add it to the chain"""
        if not self.current_block_entries:
            return
        
        try:
            # Create new block
            block_number = self._get_next_block_number()
            block_id = f"block_{block_number}_{int(time.time())}"
            
            new_block = BlockchainBlock(
                block_id=block_id,
                block_number=block_number,
                timestamp=datetime.now().isoformat(),
                previous_hash=self.last_block_hash,
                merkle_root=self._calculate_merkle_root(self.current_block_entries),
                entries=self.current_block_entries.copy(),
                block_hash="",
                nonce=0
            )
            
            # Calculate block hash
            new_block.block_hash = self._calculate_block_hash(new_block)
            
            # Write to ledger file
            self._write_block_to_ledger(new_block)
            
            # Store in database
            self._store_block_in_db(new_block)
            
            # Update last block hash
            self.last_block_hash = new_block.block_hash
            
            # Clear current block entries
            self.current_block_entries = []
            
            self.logger.info(f"Block {block_number} finalized with {len(new_block.entries)} entries")
            
        except Exception as e:
            self.logger.error(f"Error finalizing block: {str(e)}")
    
    def _write_block_to_ledger(self, block: BlockchainBlock):
        """Write block to append-only ledger file"""
        try:
            # Prepare block data for ledger
            ledger_entry = {
                'block_number': block.block_number,
                'block_id': block.block_id,
                'timestamp': block.timestamp,
                'previous_hash': block.previous_hash,
                'merkle_root': block.merkle_root,
                'block_hash': block.block_hash,
                'entry_count': len(block.entries),
                'nonce': block.nonce,
                'entries': [asdict(entry) for entry in block.entries]
            }
            
            # Write to file with exclusive lock
            with open(self.ledger_path, 'a') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                f.write(json.dumps(ledger_entry) + '\n')
                f.flush()
                os.fsync(f.fileno())  # Force write to disk
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
            
        except Exception as e:
            self.logger.error(f"Error writing block to ledger: {str(e)}")
            raise
    
    def _store_block_in_db(self, block: BlockchainBlock):
        """Store block in database for fast queries"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert block
                cursor.execute('''
                    INSERT INTO blockchain_blocks 
                    (block_number, block_id, timestamp, previous_hash, merkle_root, 
                     block_hash, entry_count, nonce, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    block.block_number,
                    block.block_id,
                    block.timestamp,
                    block.previous_hash,
                    block.merkle_root,
                    block.block_hash,
                    len(block.entries),
                    block.nonce,
                    datetime.now().isoformat()
                ))
                
                # Insert entries
                for entry in block.entries:
                    entry_hash = self._calculate_entry_hash(entry)
                    
                    cursor.execute('''
                        INSERT INTO blockchain_entries 
                        (entry_id, block_number, timestamp, event_type, user_id, username,
                         action, resource, outcome, risk_score, source_ip, entry_hash, details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        entry.entry_id,
                        block.block_number,
                        entry.timestamp,
                        entry.event_type,
                        entry.user_id,
                        entry.username,
                        entry.action,
                        entry.resource,
                        entry.outcome,
                        entry.risk_score,
                        entry.source_ip,
                        entry_hash,
                        json.dumps(entry.details)
                    ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing block in database: {str(e)}")
            raise
    
    def verify_integrity(self) -> ChainVerificationResult:
        """
        Verify the integrity of the entire blockchain

        Returns:
            ChainVerificationResult with verification details
        """
        try:
            broken_chains = []
            tampered_blocks = []
            total_blocks = 0
            total_entries = 0

            # Read all blocks from database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                cursor.execute('''
                    SELECT block_number, block_id, timestamp, previous_hash,
                           merkle_root, block_hash, entry_count, nonce
                    FROM blockchain_blocks
                    ORDER BY block_number
                ''')

                blocks = cursor.fetchall()
                total_blocks = len(blocks)

                if total_blocks == 0:
                    # No blocks to verify
                    return ChainVerificationResult(
                        is_valid=True,
                        total_blocks=0,
                        total_entries=0,
                        broken_chains=[],
                        tampered_blocks=[],
                        verification_timestamp=datetime.now().isoformat(),
                        details={'verification_method': 'empty_chain'}
                    )

                expected_previous_hash = "0" * 64  # Genesis block previous hash

                for i, block_data in enumerate(blocks):
                    block_number = block_data[0]
                    block_id = block_data[1]
                    timestamp = block_data[2]
                    stored_previous_hash = block_data[3]
                    merkle_root = block_data[4]
                    stored_block_hash = block_data[5]
                    entry_count = block_data[6]
                    nonce = block_data[7]

                    total_entries += entry_count

                    # Check chain integrity - previous hash should match expected
                    if stored_previous_hash != expected_previous_hash:
                        broken_chains.append(block_number)
                        self.logger.warning(f"Broken chain at block {block_number}: expected previous_hash {expected_previous_hash}, got {stored_previous_hash}")

                    # Verify block hash by recalculating
                    block_for_hash = BlockchainBlock(
                        block_id=block_id,
                        block_number=block_number,
                        timestamp=timestamp,
                        previous_hash=stored_previous_hash,
                        merkle_root=merkle_root,
                        entries=[],  # Not needed for hash calculation
                        block_hash="",
                        nonce=nonce
                    )

                    calculated_hash = self._calculate_block_hash(block_for_hash)
                    if calculated_hash != stored_block_hash:
                        tampered_blocks.append(block_number)
                        self.logger.warning(f"Tampered block {block_number}: expected hash {calculated_hash}, got {stored_block_hash}")

                    # Set expected previous hash for next block
                    expected_previous_hash = stored_block_hash
            
            is_valid = len(broken_chains) == 0 and len(tampered_blocks) == 0
            
            verification_result = ChainVerificationResult(
                is_valid=is_valid,
                total_blocks=total_blocks,
                total_entries=total_entries,
                broken_chains=broken_chains,
                tampered_blocks=tampered_blocks,
                verification_timestamp=datetime.now().isoformat(),
                details={
                    'ledger_file_size': os.path.getsize(self.ledger_path) if os.path.exists(self.ledger_path) else 0,
                    'database_size': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0,
                    'verification_method': 'full_chain_verification'
                }
            )
            
            # Store verification result
            self._store_verification_result(verification_result)
            
            return verification_result
            
        except Exception as e:
            self.logger.error(f"Error verifying blockchain integrity: {str(e)}")
            return ChainVerificationResult(
                is_valid=False,
                total_blocks=0,
                total_entries=0,
                broken_chains=[],
                tampered_blocks=[],
                verification_timestamp=datetime.now().isoformat(),
                details={'error': str(e)}
            )
    
    def _store_verification_result(self, result: ChainVerificationResult):
        """Store verification result in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO verification_log 
                    (verification_timestamp, is_valid, total_blocks, total_entries,
                     broken_chains, tampered_blocks, verification_details)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.verification_timestamp,
                    result.is_valid,
                    result.total_blocks,
                    result.total_entries,
                    json.dumps(result.broken_chains),
                    json.dumps(result.tampered_blocks),
                    json.dumps(result.details)
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing verification result: {str(e)}")
    
    def force_finalize_block(self):
        """Force finalization of current block (for shutdown/maintenance)"""
        if self.current_block_entries:
            self._finalize_current_block()
    
    def get_blockchain_statistics(self) -> Dict:
        """Get blockchain audit statistics"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total blocks and entries
                cursor.execute('SELECT COUNT(*) FROM blockchain_blocks')
                total_blocks = cursor.fetchone()[0]
                
                cursor.execute('SELECT COUNT(*) FROM blockchain_entries')
                total_entries = cursor.fetchone()[0]
                
                # Recent activity
                cursor.execute('''
                    SELECT COUNT(*) FROM blockchain_entries 
                    WHERE timestamp > datetime('now', '-24 hours')
                ''')
                recent_entries = cursor.fetchone()[0]
                
                # Last verification
                cursor.execute('''
                    SELECT verification_timestamp, is_valid 
                    FROM verification_log 
                    ORDER BY verification_timestamp DESC LIMIT 1
                ''')
                last_verification = cursor.fetchone()
                
                return {
                    'total_blocks': total_blocks,
                    'total_entries': total_entries,
                    'recent_entries_24h': recent_entries,
                    'pending_entries': len(self.current_block_entries),
                    'last_block_hash': self.last_block_hash,
                    'last_verification': {
                        'timestamp': last_verification[0] if last_verification else None,
                        'is_valid': bool(last_verification[1]) if last_verification else None
                    },
                    'ledger_file_size': os.path.getsize(self.ledger_path) if os.path.exists(self.ledger_path) else 0,
                    'database_size': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
                }
                
        except Exception as e:
            self.logger.error(f"Error getting blockchain statistics: {str(e)}")
            return {'error': str(e)}
    
    def create_audit_entry(self, event_type: str, action: str, resource: str, 
                          outcome: str, details: Dict = None, user_id: str = None,
                          username: str = None, risk_score: float = 0.0,
                          source_ip: str = None, session_id: str = None) -> AuditEntry:
        """
        Create an audit entry for blockchain logging
        
        Args:
            event_type: Type of event
            action: Action performed
            resource: Resource affected
            outcome: Outcome of action
            details: Additional details
            user_id: User ID if applicable
            username: Username if applicable
            risk_score: Risk score (0.0-1.0)
            source_ip: Source IP address
            session_id: Session ID if applicable
            
        Returns:
            AuditEntry object
        """
        import uuid
        
        return AuditEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            outcome=outcome,
            details=details or {},
            risk_score=risk_score,
            source_ip=source_ip or 'unknown',
            session_id=session_id
        )

# Global blockchain audit instance
blockchain_audit = BlockchainAudit()
