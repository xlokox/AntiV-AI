"""
Advanced DDoS Protection for AntiV-AI
Implements adaptive rate limiting, geolocation filtering, and IP reputation scoring
"""

import time
import asyncio
import aiohttp
import logging
import sqlite3
import json
import ipaddress
from typing import Dict, List, Optional, Tuple, Set
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
import os

# DDoS Protection Configuration
ADAPTIVE_RATE_LIMIT_WINDOW = 300  # 5 minutes
BASE_RATE_LIMIT = 100  # requests per window
BURST_THRESHOLD = 200  # requests that trigger burst detection
REPUTATION_CACHE_TTL = 3600  # 1 hour
GEOLOCATION_CACHE_TTL = 86400  # 24 hours

# IP Reputation Sources
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')

# Blocked countries (can be configured)
BLOCKED_COUNTRIES = set(os.getenv('BLOCKED_COUNTRIES', '').split(','))
ALLOWED_COUNTRIES = set(os.getenv('ALLOWED_COUNTRIES', 'US,CA,GB,DE,FR,AU,JP').split(','))

@dataclass
class IPReputationData:
    """IP reputation information"""
    ip_address: str
    reputation_score: float  # 0.0 = clean, 1.0 = malicious
    country_code: str
    is_tor: bool
    is_vpn: bool
    is_proxy: bool
    abuse_confidence: int
    last_seen: str
    threat_types: List[str]
    cached_at: str

@dataclass
class RateLimitInfo:
    """Rate limiting information for an IP"""
    ip_address: str
    requests_count: int
    window_start: float
    burst_count: int
    last_request: float
    blocked_until: Optional[float]
    adaptive_limit: int
    reputation_score: float

class IPReputationChecker:
    """Checks IP reputation using multiple sources"""
    
    def __init__(self):
        """Initialize IP reputation checker"""
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.cache_db = "data/ip_reputation_cache.db"
        self._init_cache_db()
    
    def _init_cache_db(self):
        """Initialize IP reputation cache database"""
        try:
            os.makedirs(os.path.dirname(self.cache_db), exist_ok=True)
            
            with sqlite3.connect(self.cache_db) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS ip_reputation (
                        ip_address TEXT PRIMARY KEY,
                        reputation_score REAL NOT NULL,
                        country_code TEXT,
                        is_tor BOOLEAN DEFAULT 0,
                        is_vpn BOOLEAN DEFAULT 0,
                        is_proxy BOOLEAN DEFAULT 0,
                        abuse_confidence INTEGER DEFAULT 0,
                        threat_types TEXT,
                        cached_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    )
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_ip_expires 
                    ON ip_reputation(expires_at)
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing IP reputation cache: {str(e)}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=10),
            headers={'User-Agent': 'AntiV-AI-Security/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _get_cached_reputation(self, ip_address: str) -> Optional[IPReputationData]:
        """Get cached IP reputation"""
        try:
            with sqlite3.connect(self.cache_db) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM ip_reputation 
                    WHERE ip_address = ? AND expires_at > ?
                ''', (ip_address, datetime.now().isoformat()))
                
                row = cursor.fetchone()
                if row:
                    return IPReputationData(
                        ip_address=row[0],
                        reputation_score=row[1],
                        country_code=row[2] or 'Unknown',
                        is_tor=bool(row[3]),
                        is_vpn=bool(row[4]),
                        is_proxy=bool(row[5]),
                        abuse_confidence=row[6],
                        threat_types=json.loads(row[7]) if row[7] else [],
                        last_seen=row[8],
                        cached_at=row[8]
                    )
                
        except Exception as e:
            self.logger.error(f"Error getting cached reputation: {str(e)}")
        
        return None
    
    def _cache_reputation(self, reputation_data: IPReputationData):
        """Cache IP reputation data"""
        try:
            expires_at = datetime.now() + timedelta(seconds=REPUTATION_CACHE_TTL)
            
            with sqlite3.connect(self.cache_db) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO ip_reputation 
                    (ip_address, reputation_score, country_code, is_tor, is_vpn, 
                     is_proxy, abuse_confidence, threat_types, cached_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    reputation_data.ip_address,
                    reputation_data.reputation_score,
                    reputation_data.country_code,
                    reputation_data.is_tor,
                    reputation_data.is_vpn,
                    reputation_data.is_proxy,
                    reputation_data.abuse_confidence,
                    json.dumps(reputation_data.threat_types),
                    datetime.now().isoformat(),
                    expires_at.isoformat()
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error caching reputation: {str(e)}")
    
    async def _check_abuseipdb(self, ip_address: str) -> Optional[Dict]:
        """Check IP reputation with AbuseIPDB"""
        if not ABUSEIPDB_API_KEY:
            return None
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': ABUSEIPDB_API_KEY,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('data', {})
                    
        except Exception as e:
            self.logger.warning(f"AbuseIPDB check failed: {str(e)}")
        
        return None
    
    async def _check_virustotal_ip(self, ip_address: str) -> Optional[Dict]:
        """Check IP reputation with VirusTotal"""
        if not VIRUSTOTAL_API_KEY:
            return None
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': VIRUSTOTAL_API_KEY,
                'ip': ip_address
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('response_code') == 1:
                        return data
                        
        except Exception as e:
            self.logger.warning(f"VirusTotal IP check failed: {str(e)}")
        
        return None
    
    async def check_ip_reputation(self, ip_address: str) -> IPReputationData:
        """
        Check IP reputation using multiple sources
        
        Args:
            ip_address: IP address to check
            
        Returns:
            IPReputationData with reputation information
        """
        # Check cache first
        cached_data = self._get_cached_reputation(ip_address)
        if cached_data:
            return cached_data
        
        # Initialize reputation data
        reputation_data = IPReputationData(
            ip_address=ip_address,
            reputation_score=0.0,
            country_code='Unknown',
            is_tor=False,
            is_vpn=False,
            is_proxy=False,
            abuse_confidence=0,
            threat_types=[],
            last_seen=datetime.now().isoformat(),
            cached_at=datetime.now().isoformat()
        )
        
        try:
            # Check if it's a private IP
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                reputation_data.reputation_score = 0.0
                reputation_data.country_code = 'Private'
                self._cache_reputation(reputation_data)
                return reputation_data
        except ValueError:
            # Invalid IP address
            reputation_data.reputation_score = 1.0
            reputation_data.threat_types = ['invalid_ip']
            self._cache_reputation(reputation_data)
            return reputation_data
        
        # Check AbuseIPDB
        abuse_data = await self._check_abuseipdb(ip_address)
        if abuse_data:
            reputation_data.abuse_confidence = abuse_data.get('abuseConfidencePercentage', 0)
            reputation_data.country_code = abuse_data.get('countryCode', 'Unknown')
            reputation_data.is_tor = abuse_data.get('isTor', False)
            reputation_data.is_vpn = 'VPN' in str(abuse_data.get('usageType', ''))
            
            # Calculate reputation score from abuse confidence
            if reputation_data.abuse_confidence >= 75:
                reputation_data.reputation_score = 0.9
            elif reputation_data.abuse_confidence >= 50:
                reputation_data.reputation_score = 0.7
            elif reputation_data.abuse_confidence >= 25:
                reputation_data.reputation_score = 0.4
            else:
                reputation_data.reputation_score = 0.1
        
        # Check VirusTotal
        vt_data = await self._check_virustotal_ip(ip_address)
        if vt_data:
            detected_urls = vt_data.get('detected_urls', [])
            detected_samples = vt_data.get('detected_communicating_samples', [])
            
            if detected_urls or detected_samples:
                reputation_data.reputation_score = max(reputation_data.reputation_score, 0.6)
                reputation_data.threat_types.append('malware_communication')
        
        # Apply geolocation filtering
        if reputation_data.country_code in BLOCKED_COUNTRIES:
            reputation_data.reputation_score = max(reputation_data.reputation_score, 0.8)
            reputation_data.threat_types.append('blocked_country')
        elif ALLOWED_COUNTRIES and reputation_data.country_code not in ALLOWED_COUNTRIES:
            reputation_data.reputation_score = max(reputation_data.reputation_score, 0.3)
            reputation_data.threat_types.append('restricted_country')
        
        # Cache the result
        self._cache_reputation(reputation_data)
        
        return reputation_data

class AdvancedRateLimiter:
    """Advanced DDoS protection with adaptive rate limiting"""
    
    def __init__(self):
        """Initialize advanced rate limiter"""
        self.logger = logging.getLogger(__name__)
        self.ip_data: Dict[str, RateLimitInfo] = {}
        self.reputation_checker = IPReputationChecker()
        
        # Adaptive rate limiting parameters
        self.base_limit = BASE_RATE_LIMIT
        self.burst_threshold = BURST_THRESHOLD
        self.window_size = ADAPTIVE_RATE_LIMIT_WINDOW
        
        # Blocked IPs and temporary blocks
        self.blocked_ips: Set[str] = set()
        self.temp_blocks: Dict[str, float] = {}  # IP -> unblock_time
        
        # Attack pattern detection
        self.attack_patterns = defaultdict(list)
        
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request"""
        # Check for forwarded headers (if behind proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to direct connection
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _calculate_adaptive_limit(self, ip_address: str, reputation_score: float) -> int:
        """Calculate adaptive rate limit based on IP reputation"""
        base_limit = self.base_limit
        
        # Adjust based on reputation
        if reputation_score >= 0.8:
            # High risk - very low limit
            return max(5, int(base_limit * 0.05))
        elif reputation_score >= 0.6:
            # Medium-high risk - low limit
            return max(10, int(base_limit * 0.1))
        elif reputation_score >= 0.4:
            # Medium risk - reduced limit
            return max(25, int(base_limit * 0.25))
        elif reputation_score >= 0.2:
            # Low-medium risk - slightly reduced
            return max(50, int(base_limit * 0.5))
        else:
            # Low risk - normal or increased limit
            return base_limit
    
    def _detect_attack_patterns(self, ip_address: str, request: Request) -> bool:
        """Detect DDoS attack patterns"""
        current_time = time.time()
        
        # Record request pattern
        self.attack_patterns[ip_address].append({
            'timestamp': current_time,
            'path': request.url.path,
            'method': request.method,
            'user_agent': request.headers.get('user-agent', '')
        })
        
        # Keep only recent requests (last 5 minutes)
        cutoff_time = current_time - 300
        self.attack_patterns[ip_address] = [
            req for req in self.attack_patterns[ip_address]
            if req['timestamp'] > cutoff_time
        ]
        
        requests = self.attack_patterns[ip_address]
        
        if len(requests) < 10:
            return False
        
        # Pattern 1: Too many requests to same endpoint
        path_counts = defaultdict(int)
        for req in requests:
            path_counts[req['path']] += 1
        
        if any(count > 50 for count in path_counts.values()):
            self.logger.warning(f"Attack pattern detected: endpoint flooding from {ip_address}")
            return True
        
        # Pattern 2: Rapid requests with same user agent
        user_agents = [req['user_agent'] for req in requests]
        if len(set(user_agents)) == 1 and len(requests) > 30:
            self.logger.warning(f"Attack pattern detected: bot-like behavior from {ip_address}")
            return True
        
        # Pattern 3: Burst of requests in short time
        recent_requests = [req for req in requests if req['timestamp'] > current_time - 60]
        if len(recent_requests) > 100:
            self.logger.warning(f"Attack pattern detected: burst attack from {ip_address}")
            return True
        
        return False
    
    async def check_rate_limit(self, request: Request) -> Tuple[bool, Optional[Dict]]:
        """
        Check if request should be rate limited
        
        Returns:
            (allowed, rate_limit_info)
        """
        ip_address = self._get_client_ip(request)
        current_time = time.time()
        
        # Check if IP is permanently blocked
        if ip_address in self.blocked_ips:
            return False, {
                'error': 'IP permanently blocked',
                'retry_after': None
            }
        
        # Check temporary blocks
        if ip_address in self.temp_blocks:
            if current_time < self.temp_blocks[ip_address]:
                retry_after = int(self.temp_blocks[ip_address] - current_time)
                return False, {
                    'error': 'IP temporarily blocked',
                    'retry_after': retry_after
                }
            else:
                # Block expired
                del self.temp_blocks[ip_address]
        
        # Get or create IP data
        if ip_address not in self.ip_data:
            # Get IP reputation
            async with self.reputation_checker as checker:
                reputation_data = await checker.check_ip_reputation(ip_address)
            
            adaptive_limit = self._calculate_adaptive_limit(ip_address, reputation_data.reputation_score)
            
            self.ip_data[ip_address] = RateLimitInfo(
                ip_address=ip_address,
                requests_count=0,
                window_start=current_time,
                burst_count=0,
                last_request=current_time,
                blocked_until=None,
                adaptive_limit=adaptive_limit,
                reputation_score=reputation_data.reputation_score
            )
        
        ip_info = self.ip_data[ip_address]
        
        # Reset window if expired
        if current_time - ip_info.window_start > self.window_size:
            ip_info.requests_count = 0
            ip_info.window_start = current_time
            ip_info.burst_count = 0
        
        # Detect attack patterns
        if self._detect_attack_patterns(ip_address, request):
            # Temporarily block IP for 1 hour
            self.temp_blocks[ip_address] = current_time + 3600
            self.logger.warning(f"IP {ip_address} temporarily blocked due to attack patterns")
            return False, {
                'error': 'Attack pattern detected - IP blocked',
                'retry_after': 3600
            }
        
        # Check burst detection
        time_since_last = current_time - ip_info.last_request
        if time_since_last < 1.0:  # Less than 1 second
            ip_info.burst_count += 1
            if ip_info.burst_count > 10:
                # Temporary block for burst
                self.temp_blocks[ip_address] = current_time + 300  # 5 minutes
                return False, {
                    'error': 'Burst limit exceeded',
                    'retry_after': 300
                }
        else:
            ip_info.burst_count = max(0, ip_info.burst_count - 1)
        
        # Check rate limit
        ip_info.requests_count += 1
        ip_info.last_request = current_time
        
        if ip_info.requests_count > ip_info.adaptive_limit:
            # Rate limit exceeded
            remaining_window = self.window_size - (current_time - ip_info.window_start)
            
            # For high reputation IPs, block temporarily
            if ip_info.reputation_score >= 0.6:
                self.temp_blocks[ip_address] = current_time + 1800  # 30 minutes
                return False, {
                    'error': 'Rate limit exceeded - suspicious IP blocked',
                    'retry_after': 1800
                }
            
            return False, {
                'error': 'Rate limit exceeded',
                'retry_after': int(remaining_window),
                'limit': ip_info.adaptive_limit,
                'remaining': 0,
                'reset_time': int(ip_info.window_start + self.window_size)
            }
        
        # Request allowed
        return True, {
            'limit': ip_info.adaptive_limit,
            'remaining': ip_info.adaptive_limit - ip_info.requests_count,
            'reset_time': int(ip_info.window_start + self.window_size),
            'reputation_score': ip_info.reputation_score
        }
    
    def block_ip(self, ip_address: str, permanent: bool = False):
        """Block an IP address"""
        if permanent:
            self.blocked_ips.add(ip_address)
            self.logger.warning(f"IP {ip_address} permanently blocked")
        else:
            self.temp_blocks[ip_address] = time.time() + 3600  # 1 hour
            self.logger.warning(f"IP {ip_address} temporarily blocked")
    
    def unblock_ip(self, ip_address: str):
        """Unblock an IP address"""
        self.blocked_ips.discard(ip_address)
        self.temp_blocks.pop(ip_address, None)
        self.logger.info(f"IP {ip_address} unblocked")
    
    def get_statistics(self) -> Dict:
        """Get DDoS protection statistics"""
        current_time = time.time()
        
        active_ips = len(self.ip_data)
        blocked_ips = len(self.blocked_ips)
        temp_blocked = len([ip for ip, unblock_time in self.temp_blocks.items() 
                           if unblock_time > current_time])
        
        # Calculate reputation distribution
        reputation_scores = [info.reputation_score for info in self.ip_data.values()]
        high_risk_ips = len([score for score in reputation_scores if score >= 0.6])
        
        return {
            'active_ips': active_ips,
            'permanently_blocked': blocked_ips,
            'temporarily_blocked': temp_blocked,
            'high_risk_ips': high_risk_ips,
            'total_requests': sum(info.requests_count for info in self.ip_data.values()),
            'attack_patterns_detected': len(self.attack_patterns),
            'adaptive_limits_active': True,
            'geolocation_filtering': bool(BLOCKED_COUNTRIES or ALLOWED_COUNTRIES)
        }

# Global DDoS protector instance
ddos_protector = AdvancedRateLimiter()
