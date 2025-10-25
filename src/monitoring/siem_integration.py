"""
SIEM Integration for AntiV-AI
Implements security event forwarding to SIEM systems with batching and retry logic
"""

import os
import json
import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import deque
import sqlite3
import time

# SIEM Configuration
SIEM_ENDPOINT = os.getenv('SIEM_ENDPOINT', 'https://siem.example.com/api/events')
SIEM_API_KEY = os.getenv('SIEM_API_KEY', '')
SIEM_BATCH_SIZE = int(os.getenv('SIEM_BATCH_SIZE', '50'))
SIEM_BATCH_TIMEOUT = int(os.getenv('SIEM_BATCH_TIMEOUT', '30'))  # seconds
SIEM_RETRY_ATTEMPTS = int(os.getenv('SIEM_RETRY_ATTEMPTS', '3'))
SIEM_RETRY_DELAY = int(os.getenv('SIEM_RETRY_DELAY', '5'))  # seconds

@dataclass
class SecurityEvent:
    """Security event data structure for SIEM"""
    event_id: str
    timestamp: str
    event_type: str  # authentication, scan, alert, ddos, etc.
    severity: str    # LOW, MEDIUM, HIGH, CRITICAL
    source_ip: str
    user_id: Optional[str]
    username: Optional[str]
    action: str
    resource: str
    outcome: str     # SUCCESS, FAILURE, BLOCKED
    details: Dict[str, Any]
    risk_score: float
    threat_indicators: List[str]
    geolocation: Optional[Dict[str, str]]
    user_agent: Optional[str]
    session_id: Optional[str]

@dataclass
class SIEMMetrics:
    """SIEM integration metrics"""
    total_events_sent: int
    total_events_failed: int
    total_batches_sent: int
    total_batches_failed: int
    last_successful_send: Optional[str]
    last_failed_send: Optional[str]
    average_batch_size: float
    average_response_time: float

class SIEMIntegration:
    """SIEM integration with batching, retry logic, and failover"""
    
    def __init__(self, siem_endpoint: str = SIEM_ENDPOINT):
        """Initialize SIEM integration"""
        self.logger = logging.getLogger(__name__)
        self.siem_endpoint = siem_endpoint
        self.api_key = SIEM_API_KEY
        self.batch_size = SIEM_BATCH_SIZE
        self.batch_timeout = SIEM_BATCH_TIMEOUT
        
        # Event batching
        self.event_queue = deque()
        self.last_batch_time = time.time()
        
        # Retry and failover
        self.retry_queue = deque()
        self.failed_events = deque(maxlen=1000)  # Keep last 1000 failed events
        
        # Metrics
        self.metrics = SIEMMetrics(
            total_events_sent=0,
            total_events_failed=0,
            total_batches_sent=0,
            total_batches_failed=0,
            last_successful_send=None,
            last_failed_send=None,
            average_batch_size=0.0,
            average_response_time=0.0
        )
        
        # Initialize local storage for failover
        self._init_local_storage()
        
        # Start background batch processor
        self._start_batch_processor()
    
    def _init_local_storage(self):
        """Initialize local storage for event failover"""
        try:
            os.makedirs("data/siem", exist_ok=True)
            self.local_db_path = "data/siem/events.db"
            
            with sqlite3.connect(self.local_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS siem_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        event_data TEXT NOT NULL,
                        sent_to_siem BOOLEAN DEFAULT 0,
                        retry_count INTEGER DEFAULT 0,
                        created_at TEXT NOT NULL
                    )
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_siem_timestamp 
                    ON siem_events(timestamp)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_siem_sent 
                    ON siem_events(sent_to_siem)
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing SIEM local storage: {str(e)}")
    
    def _start_batch_processor(self):
        """Start background batch processor"""
        try:
            # In a real implementation, this would be a proper background task
            # For now, we'll process batches synchronously when needed
            self.logger.info("SIEM batch processor initialized")
        except Exception as e:
            self.logger.error(f"Error starting batch processor: {str(e)}")
    
    def add_security_event(self, event: SecurityEvent):
        """Add security event to the queue for SIEM forwarding"""
        try:
            # Store event locally first (failover)
            self._store_event_locally(event)
            
            # Add to batch queue
            self.event_queue.append(event)
            
            # Check if we should send batch immediately
            current_time = time.time()
            if (len(self.event_queue) >= self.batch_size or 
                current_time - self.last_batch_time >= self.batch_timeout):
                asyncio.create_task(self._process_batch())
            
        except Exception as e:
            self.logger.error(f"Error adding security event: {str(e)}")
    
    def _store_event_locally(self, event: SecurityEvent):
        """Store event in local database for failover"""
        try:
            with sqlite3.connect(self.local_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO siem_events 
                    (event_id, timestamp, event_type, severity, event_data, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    event.event_id,
                    event.timestamp,
                    event.event_type,
                    event.severity,
                    json.dumps(asdict(event)),
                    datetime.now().isoformat()
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing event locally: {str(e)}")
    
    async def _process_batch(self):
        """Process batch of events and send to SIEM"""
        if not self.event_queue:
            return
        
        # Extract batch from queue
        batch = []
        while self.event_queue and len(batch) < self.batch_size:
            batch.append(self.event_queue.popleft())
        
        if not batch:
            return
        
        self.last_batch_time = time.time()
        
        # Send batch to SIEM
        success = await self._send_batch_to_siem(batch)
        
        if success:
            self.metrics.total_events_sent += len(batch)
            self.metrics.total_batches_sent += 1
            self.metrics.last_successful_send = datetime.now().isoformat()
            
            # Mark events as sent in local storage
            for event in batch:
                self._mark_event_sent(event.event_id)
        else:
            self.metrics.total_events_failed += len(batch)
            self.metrics.total_batches_failed += 1
            self.metrics.last_failed_send = datetime.now().isoformat()
            
            # Add to retry queue
            self.retry_queue.extend(batch)
    
    async def _send_batch_to_siem(self, events: List[SecurityEvent]) -> bool:
        """Send batch of events to SIEM endpoint"""
        if not self.siem_endpoint or not events:
            return False
        
        try:
            # Prepare payload
            payload = {
                'events': [asdict(event) for event in events],
                'batch_id': f"antiv-ai-{int(time.time())}",
                'source': 'AntiV-AI',
                'version': '1.0',
                'timestamp': datetime.now().isoformat()
            }
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'AntiV-AI-SIEM/1.0'
            }
            
            if self.api_key:
                headers['Authorization'] = f'Bearer {self.api_key}'
            
            start_time = time.time()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.siem_endpoint,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    
                    response_time = time.time() - start_time
                    self._update_response_time_metric(response_time)
                    
                    if response.status == 200:
                        self.logger.info(f"Successfully sent {len(events)} events to SIEM")
                        return True
                    else:
                        error_text = await response.text()
                        self.logger.error(f"SIEM endpoint returned {response.status}: {error_text}")
                        return False
        
        except asyncio.TimeoutError:
            self.logger.error("SIEM request timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error sending batch to SIEM: {str(e)}")
            return False
    
    def _mark_event_sent(self, event_id: str):
        """Mark event as successfully sent to SIEM"""
        try:
            with sqlite3.connect(self.local_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE siem_events SET sent_to_siem = 1 
                    WHERE event_id = ?
                ''', (event_id,))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error marking event as sent: {str(e)}")
    
    def _update_response_time_metric(self, response_time: float):
        """Update average response time metric"""
        if self.metrics.average_response_time == 0.0:
            self.metrics.average_response_time = response_time
        else:
            # Exponential moving average
            self.metrics.average_response_time = (
                self.metrics.average_response_time * 0.9 + response_time * 0.1
            )
    
    async def forward_security_events(self, events: List[SecurityEvent]):
        """
        Forward multiple security events to SIEM
        
        Args:
            events: List of SecurityEvent objects to forward
        """
        for event in events:
            self.add_security_event(event)
        
        # Process any pending batches
        if self.event_queue:
            await self._process_batch()
    
    async def retry_failed_events(self):
        """Retry sending failed events"""
        if not self.retry_queue:
            return
        
        retry_batch = []
        while self.retry_queue and len(retry_batch) < self.batch_size:
            retry_batch.append(self.retry_queue.popleft())
        
        if retry_batch:
            self.logger.info(f"Retrying {len(retry_batch)} failed events")
            success = await self._send_batch_to_siem(retry_batch)
            
            if not success:
                # Add back to failed events if still failing
                self.failed_events.extend(retry_batch)
    
    def get_unsent_events(self) -> List[Dict]:
        """Get events that haven't been sent to SIEM"""
        try:
            with sqlite3.connect(self.local_db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT event_id, timestamp, event_type, severity, event_data
                    FROM siem_events 
                    WHERE sent_to_siem = 0
                    ORDER BY timestamp DESC
                    LIMIT 100
                ''')
                
                events = []
                for row in cursor.fetchall():
                    events.append({
                        'event_id': row[0],
                        'timestamp': row[1],
                        'event_type': row[2],
                        'severity': row[3],
                        'event_data': json.loads(row[4])
                    })
                
                return events
                
        except Exception as e:
            self.logger.error(f"Error getting unsent events: {str(e)}")
            return []
    
    def get_siem_metrics(self) -> Dict:
        """Get SIEM integration metrics"""
        try:
            # Update average batch size
            if self.metrics.total_batches_sent > 0:
                self.metrics.average_batch_size = (
                    self.metrics.total_events_sent / self.metrics.total_batches_sent
                )
            
            # Get queue sizes
            queue_size = len(self.event_queue)
            retry_queue_size = len(self.retry_queue)
            failed_events_count = len(self.failed_events)
            
            # Get unsent events count
            unsent_count = len(self.get_unsent_events())
            
            return {
                'siem_endpoint': self.siem_endpoint,
                'siem_enabled': bool(self.siem_endpoint and self.api_key),
                'metrics': asdict(self.metrics),
                'queue_status': {
                    'pending_events': queue_size,
                    'retry_queue_size': retry_queue_size,
                    'failed_events': failed_events_count,
                    'unsent_events': unsent_count
                },
                'configuration': {
                    'batch_size': self.batch_size,
                    'batch_timeout': self.batch_timeout,
                    'retry_attempts': SIEM_RETRY_ATTEMPTS,
                    'retry_delay': SIEM_RETRY_DELAY
                }
            }
            
        except Exception as e:
            self.logger.error(f"Error getting SIEM metrics: {str(e)}")
            return {'error': str(e)}
    
    def create_security_event(self, event_type: str, severity: str, action: str, 
                            resource: str, outcome: str, details: Dict = None,
                            source_ip: str = None, user_id: str = None, 
                            username: str = None, risk_score: float = 0.0,
                            threat_indicators: List[str] = None) -> SecurityEvent:
        """
        Create a SecurityEvent object with proper formatting
        
        Args:
            event_type: Type of security event
            severity: Event severity level
            action: Action performed
            resource: Resource affected
            outcome: Outcome of the action
            details: Additional event details
            source_ip: Source IP address
            user_id: User ID if applicable
            username: Username if applicable
            risk_score: Risk score (0.0-1.0)
            threat_indicators: List of threat indicators
            
        Returns:
            SecurityEvent object
        """
        import uuid
        
        return SecurityEvent(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            event_type=event_type,
            severity=severity,
            source_ip=source_ip or 'unknown',
            user_id=user_id,
            username=username,
            action=action,
            resource=resource,
            outcome=outcome,
            details=details or {},
            risk_score=risk_score,
            threat_indicators=threat_indicators or [],
            geolocation=None,  # Could be populated by GeoIP lookup
            user_agent=None,
            session_id=None
        )

# Global SIEM integration instance
siem_integration = SIEMIntegration()
