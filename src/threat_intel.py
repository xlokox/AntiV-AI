"""
Advanced Threat Intelligence Integration for AntiV-AI
Integrates with VirusTotal, AlienVault OTX, and MalwareBazaar for reputation checking
"""

import os
import asyncio
import aiohttp
import hashlib
import json
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import sqlite3
from performance import redis_cache, parallel_processor, parallel_scanner

# Threat Intelligence Configuration
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
ALIENVAULT_API_KEY = os.getenv('ALIENVAULT_API_KEY', '')
MALWAREBAZAAR_API_KEY = os.getenv('MALWAREBAZAAR_API_KEY', '')

# API Endpoints
VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/vtapi/v2"
ALIENVAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
MALWAREBAZAAR_BASE_URL = "https://mb-api.abuse.ch/api/v1"

# Cache configuration
CACHE_EXPIRY_HOURS = 24
MAX_CACHE_ENTRIES = 10000

@dataclass
class ThreatIntelResult:
    """Threat intelligence result data structure"""
    file_hash: str
    source: str
    reputation_score: float  # 0.0 = clean, 1.0 = malicious
    threat_level: str  # CLEAN, SUSPICIOUS, MALICIOUS
    detections: int
    total_scans: int
    scan_date: str
    threat_names: List[str]
    additional_info: Dict[str, Any]
    cached: bool = False

@dataclass
class AggregatedThreatResult:
    """Aggregated threat intelligence from multiple sources"""
    file_hash: str
    overall_reputation_score: float
    overall_threat_level: str
    source_results: List[ThreatIntelResult]
    confidence_score: float
    recommendation: str
    last_updated: str

class ThreatIntelligenceCache:
    """Cache for threat intelligence results"""
    
    def __init__(self, db_path: str = "data/threat_intel_cache.db"):
        """Initialize threat intelligence cache"""
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self._init_cache_db()
    
    def _init_cache_db(self):
        """Initialize cache database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS threat_intel_cache (
                        file_hash TEXT PRIMARY KEY,
                        source TEXT NOT NULL,
                        reputation_score REAL NOT NULL,
                        threat_level TEXT NOT NULL,
                        detections INTEGER NOT NULL,
                        total_scans INTEGER NOT NULL,
                        threat_names TEXT NOT NULL,
                        additional_info TEXT NOT NULL,
                        cached_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL
                    )
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_cache_hash_source 
                    ON threat_intel_cache(file_hash, source)
                ''')
                
                cursor.execute('''
                    CREATE INDEX IF NOT EXISTS idx_cache_expires 
                    ON threat_intel_cache(expires_at)
                ''')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing threat intel cache: {str(e)}")
    
    def get_cached_result(self, file_hash: str, source: str) -> Optional[ThreatIntelResult]:
        """Get cached threat intelligence result"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM threat_intel_cache 
                    WHERE file_hash = ? AND source = ? AND expires_at > ?
                ''', (file_hash, source, datetime.now().isoformat()))
                
                row = cursor.fetchone()
                if row:
                    return ThreatIntelResult(
                        file_hash=row[0],
                        source=row[1],
                        reputation_score=row[2],
                        threat_level=row[3],
                        detections=row[4],
                        total_scans=row[5],
                        threat_names=json.loads(row[6]),
                        additional_info=json.loads(row[7]),
                        scan_date=row[8],
                        cached=True
                    )
                
        except Exception as e:
            self.logger.error(f"Error getting cached result: {str(e)}")
        
        return None
    
    def cache_result(self, result: ThreatIntelResult):
        """Cache threat intelligence result"""
        try:
            expires_at = datetime.now() + timedelta(hours=CACHE_EXPIRY_HOURS)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT OR REPLACE INTO threat_intel_cache 
                    (file_hash, source, reputation_score, threat_level, detections, 
                     total_scans, threat_names, additional_info, cached_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result.file_hash,
                    result.source,
                    result.reputation_score,
                    result.threat_level,
                    result.detections,
                    result.total_scans,
                    json.dumps(result.threat_names),
                    json.dumps(result.additional_info),
                    datetime.now().isoformat(),
                    expires_at.isoformat()
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error caching result: {str(e)}")
    
    def cleanup_expired_cache(self):
        """Remove expired cache entries"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    DELETE FROM threat_intel_cache 
                    WHERE expires_at < ?
                ''', (datetime.now().isoformat(),))
                
                deleted_count = cursor.rowcount
                
                # Also limit cache size
                cursor.execute('''
                    DELETE FROM threat_intel_cache 
                    WHERE rowid NOT IN (
                        SELECT rowid FROM threat_intel_cache 
                        ORDER BY cached_at DESC 
                        LIMIT ?
                    )
                ''', (MAX_CACHE_ENTRIES,))
                
                conn.commit()
                
                if deleted_count > 0:
                    self.logger.info(f"Cleaned up {deleted_count} expired cache entries")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up cache: {str(e)}")

class ThreatIntelligence:
    """Advanced threat intelligence integration"""
    
    def __init__(self):
        """Initialize threat intelligence system"""
        self.logger = logging.getLogger(__name__)
        self.cache = ThreatIntelligenceCache()
        self.session = None
        
        # API rate limiting
        self.last_api_call = {}
        self.api_delays = {
            'virustotal': 15,  # 4 requests per minute
            'alienvault': 1,   # 60 requests per minute
            'malwarebazaar': 1  # No strict limit
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'AntiV-AI/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    def _rate_limit(self, source: str):
        """Implement rate limiting for API calls"""
        now = time.time()
        last_call = self.last_api_call.get(source, 0)
        delay = self.api_delays.get(source, 1)
        
        time_since_last = now - last_call
        if time_since_last < delay:
            sleep_time = delay - time_since_last
            time.sleep(sleep_time)
        
        self.last_api_call[source] = time.time()
    
    async def _query_virustotal(self, file_hash: str) -> Optional[ThreatIntelResult]:
        """Query VirusTotal API for file reputation"""
        if not VIRUSTOTAL_API_KEY:
            self.logger.warning("VirusTotal API key not configured")
            return None
        
        try:
            self._rate_limit('virustotal')
            
            url = f"{VIRUSTOTAL_BASE_URL}/file/report"
            params = {
                'apikey': VIRUSTOTAL_API_KEY,
                'resource': file_hash,
                'allinfo': 1
            }
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('response_code') == 1:
                        positives = data.get('positives', 0)
                        total = data.get('total', 0)
                        
                        reputation_score = positives / total if total > 0 else 0.0
                        
                        if reputation_score >= 0.3:
                            threat_level = "MALICIOUS"
                        elif reputation_score >= 0.1:
                            threat_level = "SUSPICIOUS"
                        else:
                            threat_level = "CLEAN"
                        
                        # Extract threat names
                        threat_names = []
                        scans = data.get('scans', {})
                        for engine, result in scans.items():
                            if result.get('detected'):
                                threat_names.append(result.get('result', 'Unknown'))
                        
                        return ThreatIntelResult(
                            file_hash=file_hash,
                            source="VirusTotal",
                            reputation_score=reputation_score,
                            threat_level=threat_level,
                            detections=positives,
                            total_scans=total,
                            scan_date=data.get('scan_date', ''),
                            threat_names=threat_names,
                            additional_info={
                                'permalink': data.get('permalink', ''),
                                'scan_id': data.get('scan_id', ''),
                                'verbose_msg': data.get('verbose_msg', '')
                            }
                        )
                    
        except Exception as e:
            self.logger.error(f"VirusTotal query failed: {str(e)}")
        
        return None
    
    async def _query_alienvault(self, file_hash: str) -> Optional[ThreatIntelResult]:
        """Query AlienVault OTX for file reputation"""
        if not ALIENVAULT_API_KEY:
            self.logger.warning("AlienVault API key not configured")
            return None
        
        try:
            self._rate_limit('alienvault')
            
            url = f"{ALIENVAULT_BASE_URL}/indicators/file/{file_hash}/general"
            headers = {'X-OTX-API-KEY': ALIENVAULT_API_KEY}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    pulse_info = data.get('pulse_info', {})
                    pulses = pulse_info.get('pulses', [])
                    
                    # Calculate reputation based on pulse count and malware families
                    pulse_count = len(pulses)
                    malware_families = []
                    
                    for pulse in pulses:
                        families = pulse.get('malware_families', [])
                        malware_families.extend([f.get('display_name', '') for f in families])
                    
                    # Reputation scoring
                    if pulse_count >= 5 or malware_families:
                        reputation_score = 0.8
                        threat_level = "MALICIOUS"
                    elif pulse_count >= 2:
                        reputation_score = 0.4
                        threat_level = "SUSPICIOUS"
                    else:
                        reputation_score = 0.1
                        threat_level = "CLEAN"
                    
                    return ThreatIntelResult(
                        file_hash=file_hash,
                        source="AlienVault OTX",
                        reputation_score=reputation_score,
                        threat_level=threat_level,
                        detections=pulse_count,
                        total_scans=1,
                        scan_date=datetime.now().isoformat(),
                        threat_names=malware_families,
                        additional_info={
                            'pulse_count': pulse_count,
                            'pulses': [p.get('name', '') for p in pulses[:5]]
                        }
                    )
                    
        except Exception as e:
            self.logger.error(f"AlienVault query failed: {str(e)}")
        
        return None
    
    async def _query_malwarebazaar(self, file_hash: str) -> Optional[ThreatIntelResult]:
        """Query MalwareBazaar for file reputation"""
        try:
            self._rate_limit('malwarebazaar')
            
            url = f"{MALWAREBAZAAR_BASE_URL}/"
            data = {
                'query': 'get_info',
                'hash': file_hash
            }
            
            async with self.session.post(url, data=data) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    if result.get('query_status') == 'ok':
                        data = result.get('data', [])
                        if data:
                            sample = data[0]
                            
                            # MalwareBazaar presence indicates malicious
                            reputation_score = 0.9
                            threat_level = "MALICIOUS"
                            
                            signature = sample.get('signature', '')
                            threat_names = [signature] if signature else []
                            
                            return ThreatIntelResult(
                                file_hash=file_hash,
                                source="MalwareBazaar",
                                reputation_score=reputation_score,
                                threat_level=threat_level,
                                detections=1,
                                total_scans=1,
                                scan_date=sample.get('first_seen', ''),
                                threat_names=threat_names,
                                additional_info={
                                    'file_type': sample.get('file_type', ''),
                                    'file_size': sample.get('file_size', 0),
                                    'tags': sample.get('tags', []),
                                    'delivery_method': sample.get('delivery_method', '')
                                }
                            )
                    
        except Exception as e:
            self.logger.error(f"MalwareBazaar query failed: {str(e)}")
        
        return None
    
    async def check_reputation(self, file_hash: str) -> AggregatedThreatResult:
        """
        Check file reputation across multiple threat intelligence sources with enhanced caching

        Args:
            file_hash: SHA-256 hash of the file

        Returns:
            AggregatedThreatResult with combined intelligence
        """
        file_hash = file_hash.lower()

        # Check Redis cache first for aggregated result
        cache_key = f"threat_intel_aggregated:{file_hash}"
        cached_aggregated = await redis_cache.aget(cache_key)
        if cached_aggregated:
            self.logger.debug(f"Using cached aggregated result for {file_hash}")
            return cached_aggregated

        source_results = []

        # Clean up expired cache entries
        self.cache.cleanup_expired_cache()

        # Query each source (check cache first)
        sources = [
            ('virustotal', self._query_virustotal),
            ('alienvault', self._query_alienvault),
            ('malwarebazaar', self._query_malwarebazaar)
        ]

        # Use parallel processing for multiple sources
        async def query_source_with_enhanced_cache(source_info):
            source_name, query_func = source_info

            # Multi-level cache check: local -> Redis -> API

            # 1. Check local cache first
            cached_result = self.cache.get_cached_result(file_hash, source_name)
            if cached_result:
                self.logger.debug(f"Using local cached result from {source_name}")
                return cached_result

            # 2. Check Redis cache
            redis_key = f"threat_intel_source:{source_name}:{file_hash}"
            redis_cached = await redis_cache.aget(redis_key)
            if redis_cached:
                self.logger.debug(f"Using Redis cached result from {source_name}")
                # Also update local cache for faster future access
                self.cache.cache_result(redis_cached)
                return redis_cached

            # 3. Query API with rate limiting and error handling
            try:
                result = await query_func(file_hash)
                if result:
                    # Cache in both local and Redis with different TTLs
                    self.cache.cache_result(result)

                    # Use longer TTL for positive results, shorter for negative
                    ttl = 7200 if result.detections > 0 else 3600  # 2h vs 1h
                    await redis_cache.aset(redis_key, result, ttl)

                    self.logger.debug(f"Got fresh result from {source_name}: {result.detections} detections")
                    return result
                else:
                    # Cache negative results with shorter TTL
                    await redis_cache.aset(redis_key, None, 1800)  # 30 minutes

            except Exception as e:
                self.logger.error(f"Error querying {source_name}: {str(e)}")

            return None

        # Process sources in parallel with enhanced error handling
        try:
            source_results = await parallel_processor.process_parallel_async(
                query_source_with_enhanced_cache, sources
            )

            # Filter out None results
            source_results = [result for result in source_results if result is not None]

        except Exception as e:
            self.logger.error(f"Parallel threat intelligence processing failed: {str(e)}")
            # Fallback to sequential processing
            source_results = []
            for source_name, query_func in sources:
                try:
                    result = await query_source_with_enhanced_cache((source_name, query_func))
                    if result:
                        source_results.append(result)
                except Exception as e:
                    self.logger.error(f"Sequential fallback failed for {source_name}: {str(e)}")

        # Aggregate results
        aggregated_result = self._aggregate_results(file_hash, source_results)

        # Cache aggregated result in Redis with adaptive TTL
        # Longer TTL for high-confidence results
        if aggregated_result.overall_reputation_score >= 0.7:
            ttl = 3600  # 1 hour for high-risk files
        elif aggregated_result.overall_reputation_score >= 0.3:
            ttl = 1800  # 30 minutes for medium-risk files
        else:
            ttl = 900   # 15 minutes for low-risk files

        await redis_cache.aset(cache_key, aggregated_result, ttl)

        return aggregated_result

    async def check_multiple_reputations(self, file_hashes: List[str]) -> List[AggregatedThreatResult]:
        """
        Check reputation for multiple files in parallel

        Args:
            file_hashes: List of SHA-256 hashes to check

        Returns:
            List of AggregatedThreatResult objects
        """
        if not file_hashes:
            return []

        try:
            # Use parallel scanner for multiple file reputation checks
            results = await parallel_scanner.scan_files_async(
                self.check_reputation, file_hashes
            )

            return [result for result in results if result is not None]

        except Exception as e:
            self.logger.error(f"Batch reputation check failed: {str(e)}")
            # Fallback to sequential processing
            results = []
            for file_hash in file_hashes:
                try:
                    result = await self.check_reputation(file_hash)
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Individual reputation check failed for {file_hash}: {str(e)}")
                    results.append(None)

            return [result for result in results if result is not None]
    
    def _aggregate_results(self, file_hash: str, results: List[ThreatIntelResult]) -> AggregatedThreatResult:
        """Aggregate threat intelligence results from multiple sources"""
        if not results:
            return AggregatedThreatResult(
                file_hash=file_hash,
                overall_reputation_score=0.0,
                overall_threat_level="UNKNOWN",
                source_results=[],
                confidence_score=0.0,
                recommendation="No threat intelligence available",
                last_updated=datetime.now().isoformat()
            )
        
        # Calculate weighted average reputation score
        total_weight = 0
        weighted_score = 0
        
        # Source weights (VirusTotal gets highest weight)
        source_weights = {
            'VirusTotal': 0.5,
            'AlienVault OTX': 0.3,
            'MalwareBazaar': 0.2
        }
        
        for result in results:
            weight = source_weights.get(result.source, 0.1)
            weighted_score += result.reputation_score * weight
            total_weight += weight
        
        overall_score = weighted_score / total_weight if total_weight > 0 else 0.0
        
        # Determine overall threat level
        if overall_score >= 0.7:
            overall_threat_level = "MALICIOUS"
            recommendation = "BLOCK - High confidence malicious file"
        elif overall_score >= 0.4:
            overall_threat_level = "SUSPICIOUS"
            recommendation = "QUARANTINE - Suspicious file requires analysis"
        elif overall_score >= 0.1:
            overall_threat_level = "SUSPICIOUS"
            recommendation = "MONITOR - Low-level suspicious indicators"
        else:
            overall_threat_level = "CLEAN"
            recommendation = "ALLOW - No significant threats detected"
        
        # Calculate confidence score based on source agreement
        threat_levels = [r.threat_level for r in results]
        agreement = len(set(threat_levels))
        confidence_score = 1.0 - (agreement - 1) * 0.2  # Reduce confidence for disagreement
        
        return AggregatedThreatResult(
            file_hash=file_hash,
            overall_reputation_score=overall_score,
            overall_threat_level=overall_threat_level,
            source_results=results,
            confidence_score=max(0.0, confidence_score),
            recommendation=recommendation,
            last_updated=datetime.now().isoformat()
        )
    
    def get_cache_statistics(self) -> Dict:
        """Get threat intelligence cache statistics"""
        try:
            with sqlite3.connect(self.cache.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('SELECT COUNT(*) FROM threat_intel_cache')
                total_entries = cursor.fetchone()[0]
                
                cursor.execute('''
                    SELECT source, COUNT(*) FROM threat_intel_cache 
                    GROUP BY source
                ''')
                source_counts = dict(cursor.fetchall())
                
                cursor.execute('''
                    SELECT COUNT(*) FROM threat_intel_cache 
                    WHERE expires_at > ?
                ''', (datetime.now().isoformat(),))
                active_entries = cursor.fetchone()[0]
                
                return {
                    'total_entries': total_entries,
                    'active_entries': active_entries,
                    'source_breakdown': source_counts,
                    'cache_hit_rate': 'N/A',  # Would need to track hits/misses
                    'last_cleanup': datetime.now().isoformat()
                }
                
        except Exception as e:
            self.logger.error(f"Error getting cache statistics: {str(e)}")
            return {}

# Global threat intelligence instance
threat_intel = ThreatIntelligence()
