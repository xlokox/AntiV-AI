"""
Network Security and Rate Limiting for AntiV-AI
Implements HTTPS configuration, CORS hardening, and global rate limiting
"""

import time
import ssl
import logging
import yaml
import os
import aiohttp
import asyncio
import ipaddress
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
from fastapi import Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# GeoIP imports (with fallback)
try:
    import geoip2.database
    import geoip2.errors
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Rate limiting configuration
GLOBAL_RATE_LIMIT = 100  # requests per minute
RATE_LIMIT_WINDOW = 60  # seconds
AUTH_RATE_LIMIT = 10  # auth requests per minute
UPLOAD_RATE_LIMIT = 5  # upload requests per minute

# HTTPS configuration
SSL_CERT_PATH = "certs/server.crt"
SSL_KEY_PATH = "certs/server.key"
SSL_CA_PATH = "certs/ca.crt"

# Allowed origins (strict CORS)
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "https://localhost:3000",
    "http://127.0.0.1:3000",
    "https://127.0.0.1:3000"
]

# Blocked HTTP methods
BLOCKED_METHODS = ["TRACE", "CONNECT", "OPTIONS"]

# Load configuration
def load_config():
    """Load configuration from config.yaml"""
    try:
        config_path = "config.yaml"
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        else:
            return {}
    except Exception as e:
        logging.error(f"Error loading config: {str(e)}")
        return {}

CONFIG = load_config()

# GeoIP Configuration
GEOIP_API_KEY = os.getenv('GEOIP_API_KEY', '')
GEOIP_CACHE_TTL = 86400  # 24 hours

class GeoIPLookup:
    """Enhanced GeoIP lookup service using MaxMind GeoLite2 database"""

    def __init__(self, database_path: str = None):
        """Initialize GeoIP lookup"""
        self.logger = logging.getLogger(__name__)
        self.cache = {}
        self.database_path = database_path or "data/GeoLite2-Country.mmdb"
        self.geoip_reader = None

        # Initialize GeoIP database
        self._init_geoip_database()

    def _init_geoip_database(self):
        """Initialize GeoIP database reader"""
        if not GEOIP_AVAILABLE:
            self.logger.warning("GeoIP2 library not available, using fallback lookup")
            return

        try:
            if os.path.exists(self.database_path):
                self.geoip_reader = geoip2.database.Reader(self.database_path)
                self.logger.info(f"GeoIP database loaded: {self.database_path}")
            else:
                self.logger.warning(f"GeoIP database not found: {self.database_path}")
        except Exception as e:
            self.logger.error(f"Failed to load GeoIP database: {str(e)}")

    def get_country_info(self, ip_address: str) -> Dict[str, str]:
        """
        Get comprehensive country information for IP address

        Args:
            ip_address: IP address to lookup

        Returns:
            Dictionary with country_code, country_name, continent, region
        """
        # Check cache first
        cache_key = f"country_info_{ip_address}"
        if cache_key in self.cache:
            cache_entry = self.cache[cache_key]
            if time.time() - cache_entry['timestamp'] < GEOIP_CACHE_TTL:
                return cache_entry['data']

        try:
            # Check if it's a private IP
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                result = {
                    'country_code': 'Private',
                    'country_name': 'Private Network',
                    'continent': 'Private',
                    'region': 'Private'
                }
                self._cache_result(cache_key, result)
                return result
        except ValueError:
            result = {
                'country_code': 'Unknown',
                'country_name': 'Unknown',
                'continent': 'Unknown',
                'region': 'Unknown'
            }
            self._cache_result(cache_key, result)
            return result

        # Try MaxMind GeoIP2 database first
        if self.geoip_reader:
            try:
                response = self.geoip_reader.country(ip_address)
                result = {
                    'country_code': response.country.iso_code or 'Unknown',
                    'country_name': response.country.name or 'Unknown',
                    'continent': response.continent.name or 'Unknown',
                    'region': self._get_region_from_continent(response.continent.name)
                }
                self._cache_result(cache_key, result)
                return result
            except geoip2.errors.AddressNotFoundError:
                self.logger.debug(f"IP address not found in GeoIP database: {ip_address}")
            except Exception as e:
                self.logger.warning(f"GeoIP database lookup failed for {ip_address}: {str(e)}")

        # Fallback to online API (ip-api.com)
        try:
            import requests
            url = f"http://ip-api.com/json/{ip_address}?fields=countryCode,country,continent,status"
            response = requests.get(url, timeout=5)

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result = {
                        'country_code': data.get('countryCode', 'Unknown'),
                        'country_name': data.get('country', 'Unknown'),
                        'continent': data.get('continent', 'Unknown'),
                        'region': self._get_region_from_continent(data.get('continent', 'Unknown'))
                    }
                    self._cache_result(cache_key, result)
                    return result
        except Exception as e:
            self.logger.warning(f"Online GeoIP lookup failed for {ip_address}: {str(e)}")

        # Final fallback
        result = {
            'country_code': 'Unknown',
            'country_name': 'Unknown',
            'continent': 'Unknown',
            'region': 'Unknown'
        }
        self._cache_result(cache_key, result)
        return result

    def get_country_code(self, ip_address: str) -> str:
        """Get country code for IP address (backward compatibility)"""
        return self.get_country_info(ip_address)['country_code']

    def _get_region_from_continent(self, continent: str) -> str:
        """Map continent to region"""
        continent_to_region = {
            'North America': 'North America',
            'South America': 'South America',
            'Europe': 'Western Europe',  # Default, can be refined
            'Asia': 'Asia Pacific',
            'Africa': 'Africa',
            'Oceania': 'Asia Pacific',
            'Antarctica': 'Unknown'
        }
        return continent_to_region.get(continent, 'Unknown')

    def _cache_result(self, cache_key: str, data: Dict):
        """Cache GeoIP lookup result"""
        self.cache[cache_key] = {
            'data': data,
            'timestamp': time.time()
        }

        # Limit cache size
        if len(self.cache) > 10000:
            # Remove oldest entries
            oldest_entries = sorted(
                self.cache.items(),
                key=lambda x: x[1]['timestamp']
            )[:1000]

            for key, _ in oldest_entries:
                del self.cache[key]

    def __del__(self):
        """Cleanup GeoIP database reader"""
        if self.geoip_reader:
            try:
                self.geoip_reader.close()
            except:
                pass

class RateLimiter:
    """Advanced rate limiter with geolocation and reputation-based limits"""

    def __init__(self):
        """Initialize advanced rate limiter"""
        self.logger = logging.getLogger(__name__)

        # Request tracking by IP and endpoint
        self.request_history = defaultdict(lambda: defaultdict(deque))
        self.blocked_ips = {}  # IP -> block_until_timestamp

        # Load configuration
        rate_config = CONFIG.get('rate_limits', {})
        geo_config = rate_config.get('geo', {})

        # Initialize GeoIP lookup service
        geoip_db_path = geo_config.get('geoip_database_path', 'data/GeoLite2-Country.mmdb')
        self.geoip = GeoIPLookup(geoip_db_path)

        # Rate limit configurations from config
        self.limits = {
            'global': {
                'requests': rate_config.get('global', {}).get('requests_per_minute', GLOBAL_RATE_LIMIT),
                'window': rate_config.get('global', {}).get('window_seconds', RATE_LIMIT_WINDOW)
            },
            'auth': {
                'requests': rate_config.get('endpoints', {}).get('/auth/login', {}).get('requests_per_minute', AUTH_RATE_LIMIT),
                'window': RATE_LIMIT_WINDOW
            },
            'upload': {
                'requests': rate_config.get('endpoints', {}).get('/upload-scan', {}).get('requests_per_minute', UPLOAD_RATE_LIMIT),
                'window': RATE_LIMIT_WINDOW
            },
            'scan': {
                'requests': rate_config.get('endpoints', {}).get('/scan', {}).get('requests_per_minute', 20),
                'window': RATE_LIMIT_WINDOW
            },
        }

        # Geolocation-based configuration
        self.geo_enabled = geo_config.get('enabled', False)
        self.blocked_countries = set(geo_config.get('blocked_countries', []))
        self.allowed_countries = set(geo_config.get('allowed_countries', []))
        self.high_risk_countries = set(geo_config.get('high_risk_countries', []))
        self.country_limits = geo_config.get('limits_by_country', {})
        self.region_limits = geo_config.get('limits_by_region', {})

        # IP reputation configuration
        rep_config = rate_config.get('ip_reputation', {})
        self.reputation_enabled = rep_config.get('enabled', False)
        self.reputation_limits = rep_config.get('limits_by_reputation', {})
        self.reputation_thresholds = {
            'high_risk': rep_config.get('high_risk_threshold', 0.7),
            'medium_risk': rep_config.get('medium_risk_threshold', 0.4),
            'low_risk': rep_config.get('low_risk_threshold', 0.2)
        }

        # Statistics tracking
        self.geo_stats = {
            'total_lookups': 0,
            'cache_hits': 0,
            'blocked_countries': 0,
            'high_risk_countries': 0,
            'unknown_countries': 0
        }
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request"""
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
    
    def _get_endpoint_category(self, path: str) -> str:
        """Categorize endpoint for rate limiting"""
        if path.startswith("/auth/"):
            return "auth"
        elif path.startswith("/upload-scan"):
            return "upload"
        elif path.startswith("/scan"):
            return "scan"
        else:
            return "global"
    
    def _clean_old_requests(self, ip: str, category: str, current_time: float):
        """Remove old requests outside the time window"""
        window = self.limits[category]['window']
        cutoff_time = current_time - window
        
        while (self.request_history[ip][category] and 
               self.request_history[ip][category][0] < cutoff_time):
            self.request_history[ip][category].popleft()
    
    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        if ip in self.blocked_ips:
            if time.time() < self.blocked_ips[ip]:
                return True
            else:
                # Block expired, remove it
                del self.blocked_ips[ip]
        return False
    
    def block_ip(self, ip: str, duration: int = 300):
        """Block IP for specified duration (seconds)"""
        self.blocked_ips[ip] = time.time() + duration
        self.logger.warning(f"IP blocked for {duration}s: {ip}")
    
    def check_rate_limit(self, request: Request) -> bool:
        """
        Check if request should be rate limited
        
        Returns:
            True if request is allowed, False if rate limited
        """
        ip = self._get_client_ip(request)
        current_time = time.time()
        
        # Check if IP is blocked
        if self.is_blocked(ip):
            return False
        
        # Get endpoint category
        category = self._get_endpoint_category(request.url.path)
        
        # Clean old requests
        self._clean_old_requests(ip, category, current_time)
        
        # Check rate limit
        limit_config = self.limits[category]
        current_requests = len(self.request_history[ip][category])
        
        if current_requests >= limit_config['requests']:
            # Rate limit exceeded
            self.logger.warning(f"Rate limit exceeded for {ip} on {category}: {current_requests}/{limit_config['requests']}")
            
            # Block IP if severely exceeding limits
            if current_requests > limit_config['requests'] * 2:
                self.block_ip(ip, 300)  # 5 minute block
            
            return False
        
        # Record this request
        self.request_history[ip][category].append(current_time)
        
        return True

    def check_rate_limit_advanced(self, request: Request) -> Tuple[bool, Dict]:
        """
        Advanced rate limiting with geolocation and reputation

        Returns:
            (allowed, rate_limit_info)
        """
        ip = self._get_client_ip(request)
        current_time = time.time()

        # Check if IP is blocked
        if self.is_blocked(ip):
            return False, {'error': 'IP blocked', 'reason': 'blocked_ip'}

        # Get geolocation if enabled
        country_info = {'country_code': 'Unknown', 'region': 'Unknown'}
        if self.geo_enabled:
            try:
                self.geo_stats['total_lookups'] += 1
                country_info = self.geoip.get_country_info(ip)

                if country_info['country_code'] != 'Unknown':
                    self.geo_stats['cache_hits'] += 1
                else:
                    self.geo_stats['unknown_countries'] += 1

            except Exception as e:
                self.logger.warning(f"GeoIP lookup failed: {str(e)}")

        country_code = country_info['country_code']
        region = country_info['region']

        # Check country-based blocking
        if country_code in self.blocked_countries:
            self.geo_stats['blocked_countries'] += 1
            self.logger.warning(f"Blocked request from {country_code}: {ip}")
            return False, {
                'error': 'Country blocked',
                'reason': 'blocked_country',
                'country': country_code,
                'region': region
            }

        # Track high-risk countries
        if country_code in self.high_risk_countries:
            self.geo_stats['high_risk_countries'] += 1

        # Get endpoint category
        category = self._get_endpoint_category(request.url.path)

        # Calculate adaptive limit based on geolocation and reputation
        adaptive_limit, limit_reason = self._calculate_adaptive_limit(ip, country_info, category)

        # Clean old requests
        self._clean_old_requests(ip, category, current_time)

        # Check rate limit
        current_requests = len(self.request_history[ip][category])

        if current_requests >= adaptive_limit:
            # Rate limit exceeded
            self.logger.warning(f"Rate limit exceeded for {ip} ({country_code}) on {category}: {current_requests}/{adaptive_limit}")

            # Block IP if severely exceeding limits
            if current_requests > adaptive_limit * 2:
                self.block_ip(ip, 300)  # 5 minute block

            return False, {
                'error': 'Rate limit exceeded',
                'reason': 'rate_limit',
                'limit': adaptive_limit,
                'current': current_requests,
                'country': country_code,
                'region': region,
                'limit_reason': limit_reason
            }

        # Record this request
        self.request_history[ip][category].append(current_time)

        return True, {
            'limit': adaptive_limit,
            'remaining': adaptive_limit - current_requests - 1,
            'country': country_code,
            'region': region,
            'category': category,
            'limit_reason': limit_reason
        }

    def _calculate_adaptive_limit(self, ip: str, country_info, category: str) -> Tuple[int, str]:
        """
        Calculate adaptive rate limit based on geolocation and reputation

        Args:
            ip: IP address
            country_info: Either a dict with country_code/region or a string country code
            category: Rate limit category

        Returns:
            (limit, reason) - The calculated limit and the reason for the limit
        """
        base_limit = self.limits[category]['requests']

        # Handle both dict and string formats for country_info
        if isinstance(country_info, dict):
            country_code = country_info.get('country_code', 'Unknown')
            region = country_info.get('region', 'Unknown')
        else:
            # Assume it's a country code string
            country_code = str(country_info)
            region = 'Unknown'

        # Start with base limit
        current_limit = base_limit
        limit_reasons = []

        # Apply country-specific limits (highest priority)
        if country_code in self.country_limits:
            country_limit = self.country_limits[country_code]
            if country_limit < current_limit:
                current_limit = country_limit
                limit_reasons.append(f"country:{country_code}")
        elif country_code in self.high_risk_countries:
            high_risk_limit = self.country_limits.get('high_risk', base_limit // 4)
            if high_risk_limit < current_limit:
                current_limit = high_risk_limit
                limit_reasons.append("high_risk_country")
        elif country_code == 'Unknown':
            unknown_limit = self.country_limits.get('unknown', base_limit // 10)
            if unknown_limit < current_limit:
                current_limit = unknown_limit
                limit_reasons.append("unknown_country")
        elif self.allowed_countries and country_code not in self.allowed_countries:
            default_limit = self.country_limits.get('default', base_limit // 2)
            if default_limit < current_limit:
                current_limit = default_limit
                limit_reasons.append("not_in_allowlist")

        # Apply regional limits as fallback
        if not limit_reasons and region in self.region_limits:
            region_limit = self.region_limits[region]
            if region_limit < current_limit:
                current_limit = region_limit
                limit_reasons.append(f"region:{region}")

        # Apply reputation-based limits
        reputation_score = self._get_ip_reputation(ip)

        if reputation_score >= self.reputation_thresholds['high_risk']:
            reputation_limit = self.reputation_limits.get('high_risk', base_limit // 20)
            if reputation_limit < current_limit:
                current_limit = reputation_limit
                limit_reasons.append("high_risk_reputation")
        elif reputation_score >= self.reputation_thresholds['medium_risk']:
            reputation_limit = self.reputation_limits.get('medium_risk', base_limit // 4)
            if reputation_limit < current_limit:
                current_limit = reputation_limit
                limit_reasons.append("medium_risk_reputation")
        elif reputation_score >= self.reputation_thresholds['low_risk']:
            reputation_limit = self.reputation_limits.get('low_risk', base_limit // 2)
            if reputation_limit < current_limit:
                current_limit = reputation_limit
                limit_reasons.append("low_risk_reputation")

        # Ensure minimum limit
        final_limit = max(1, current_limit)

        # Create reason string
        if not limit_reasons:
            reason = "base_limit"
        else:
            reason = ",".join(limit_reasons)

        return final_limit, reason

    def _get_ip_reputation(self, ip: str) -> float:
        """
        Get IP reputation score (placeholder implementation)

        In production, this would integrate with threat intelligence services

        Returns:
            Reputation score (0.0 = clean, 1.0 = malicious)
        """
        # Placeholder implementation
        # In production, this would query threat intelligence APIs

        # Check if it's a private IP
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback:
                return 0.0  # Private IPs are clean
        except ValueError:
            return 0.5  # Invalid IP gets medium risk

        # For public IPs, return a low reputation score for testing
        # In production, this would query actual threat intelligence
        import hashlib
        ip_hash = hashlib.md5(ip.encode()).hexdigest()
        # Use hash to generate consistent but pseudo-random reputation
        hash_int = int(ip_hash[:8], 16)
        reputation = (hash_int % 100) / 1000.0  # 0.0 to 0.099
        return min(reputation, 0.1)  # Cap at low risk level

    def get_rate_limit_info(self, request: Request) -> Dict:
        """Get rate limit information for client"""
        ip = self._get_client_ip(request)
        category = self._get_endpoint_category(request.url.path)
        current_time = time.time()
        
        # Clean old requests
        self._clean_old_requests(ip, category, current_time)
        
        limit_config = self.limits[category]
        current_requests = len(self.request_history[ip][category])
        
        return {
            'limit': limit_config['requests'],
            'remaining': max(0, limit_config['requests'] - current_requests),
            'reset_time': int(current_time + limit_config['window']),
            'window': limit_config['window']
        }

    def get_rate_limit_stats(self) -> Dict:
        """Get comprehensive rate limiting statistics"""
        return {
            'blocked_ips': list(self.blocked_ips.keys()),
            'blocked_count': len(self.blocked_ips),
            'active_connections': len(self.request_history),
            'rate_limits': self.limits,
            'geo_enabled': self.geo_enabled,
            'geo_stats': self.geo_stats.copy(),
            'reputation_enabled': self.reputation_enabled,
            'blocked_countries': list(self.blocked_countries),
            'high_risk_countries': list(self.high_risk_countries),
            'allowed_countries': list(self.allowed_countries) if self.allowed_countries else None,
            'country_limits': self.country_limits,
            'region_limits': self.region_limits
        }

class SecurityMiddleware:
    """Security middleware for headers and protection"""
    
    def __init__(self, app):
        self.app = app
        self.logger = logging.getLogger(__name__)
    
    async def __call__(self, scope, receive, send):
        """ASGI middleware implementation"""
        if scope["type"] == "http":
            request = Request(scope, receive)
            
            # Block dangerous HTTP methods
            if request.method in BLOCKED_METHODS:
                response = JSONResponse(
                    status_code=405,
                    content={"detail": "Method not allowed"}
                )
                await response(scope, receive, send)
                return
            
            # Add security headers
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = dict(message.get("headers", []))
                    
                    # Security headers
                    security_headers = {
                        b"X-Content-Type-Options": b"nosniff",
                        b"X-Frame-Options": b"DENY",
                        b"X-XSS-Protection": b"1; mode=block",
                        b"Strict-Transport-Security": b"max-age=31536000; includeSubDomains",
                        b"Content-Security-Policy": b"default-src 'self'",
                        b"Referrer-Policy": b"strict-origin-when-cross-origin",
                        b"Permissions-Policy": b"geolocation=(), microphone=(), camera=()",
                    }
                    
                    # Add security headers
                    for header, value in security_headers.items():
                        headers[header] = value
                    
                    message["headers"] = list(headers.items())
                
                await send(message)
            
            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)

def create_ssl_context() -> Optional[ssl.SSLContext]:
    """Create SSL context for HTTPS"""
    try:
        import os
        
        # Check if SSL files exist
        if not all(os.path.exists(path) for path in [SSL_CERT_PATH, SSL_KEY_PATH]):
            logging.warning("SSL certificate files not found. Generating self-signed certificate...")
            generate_self_signed_cert()
        
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        
        # Load certificate and key
        context.load_cert_chain(SSL_CERT_PATH, SSL_KEY_PATH)
        
        # Security settings
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3
        context.options |= ssl.OP_NO_TLSv1
        context.options |= ssl.OP_NO_TLSv1_1
        context.options |= ssl.OP_SINGLE_DH_USE
        context.options |= ssl.OP_SINGLE_ECDH_USE
        
        logging.info("SSL context created successfully")
        return context
        
    except Exception as e:
        logging.error(f"Failed to create SSL context: {str(e)}")
        return None

def generate_self_signed_cert():
    """Generate self-signed certificate for development"""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        import os
        
        # Create certificates directory
        os.makedirs("certs", exist_ok=True)
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AntiV-AI"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # Write certificate
        with open(SSL_CERT_PATH, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Write private key
        with open(SSL_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Set restrictive permissions
        os.chmod(SSL_KEY_PATH, 0o600)
        os.chmod(SSL_CERT_PATH, 0o644)
        
        logging.info("Self-signed certificate generated successfully")
        
    except Exception as e:
        logging.error(f"Failed to generate self-signed certificate: {str(e)}")

def configure_cors(app):
    """Configure CORS with strict security"""
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE"],  # Only allowed methods
        allow_headers=[
            "Authorization",
            "Content-Type",
            "X-Requested-With",
            "Accept",
            "Origin",
            "User-Agent",
            "DNT",
            "Cache-Control",
            "X-Mx-ReqToken",
            "Keep-Alive",
            "X-Requested-With",
            "If-Modified-Since",
        ],
        expose_headers=[
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining", 
            "X-RateLimit-Reset"
        ]
    )

def create_secure_uvicorn_config(host: str = "127.0.0.1", port: int = 8000, ssl_enabled: bool = True) -> Dict:
    """Create secure Uvicorn configuration"""
    config = {
        "host": host,
        "port": port,
        "log_level": "info",
        "access_log": True,
        "server_header": False,  # Hide server header
        "date_header": False,    # Hide date header
    }
    
    if ssl_enabled:
        ssl_context = create_ssl_context()
        if ssl_context:
            config.update({
                "ssl_context": ssl_context,
                "ssl_keyfile": SSL_KEY_PATH,
                "ssl_certfile": SSL_CERT_PATH,
            })
            logging.info("HTTPS enabled")
        else:
            logging.warning("HTTPS disabled due to SSL configuration failure")
    
    return config

# Global rate limiter instance (with enhanced geo capabilities)
rate_limiter = RateLimiter()

# Alias for backward compatibility
AdvancedRateLimiter = RateLimiter
