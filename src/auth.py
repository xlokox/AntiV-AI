"""
Authentication and Authorization System for AntiV-AI
Implements JWT-based authentication with role-based access control
"""

import os
import jwt
import bcrypt
import sqlite3
import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import logging

# Security configuration
JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', secrets.token_urlsafe(32))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password requirements
MIN_PASSWORD_LENGTH = 12
REQUIRE_SPECIAL_CHARS = True
REQUIRE_NUMBERS = True
REQUIRE_UPPERCASE = True

@dataclass
class User:
    """User model"""
    id: int
    username: str
    email: str
    role: str  # 'admin' or 'user'
    is_active: bool
    created_at: str
    last_login: Optional[str] = None
    failed_attempts: int = 0
    locked_until: Optional[str] = None

@dataclass
class TokenData:
    """Token payload data"""
    user_id: int
    username: str
    role: str
    exp: int
    iat: int
    jti: str  # JWT ID for revocation

class AuthManager:
    """Manages authentication and authorization"""
    
    def __init__(self, db_path: str = "data/auth.db"):
        """Initialize authentication manager"""
        self.logger = logging.getLogger(__name__)
        self.db_path = db_path
        self.security = HTTPBearer()
        self.revoked_tokens = set()  # In production, use Redis
        
        # Initialize database
        self._init_auth_database()
        
        # Create default admin user if none exists
        self._create_default_admin()
    
    def _init_auth_database(self):
        """Initialize authentication database"""
        try:
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'user',
                        is_active BOOLEAN DEFAULT 1,
                        created_at TEXT NOT NULL,
                        last_login TEXT,
                        failed_attempts INTEGER DEFAULT 0,
                        locked_until TEXT,
                        password_changed_at TEXT,
                        mfa_secret TEXT,
                        mfa_backup_codes TEXT,
                        mfa_enabled BOOLEAN DEFAULT 0
                    )
                ''')
                
                # Sessions table for token tracking
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        jti TEXT UNIQUE NOT NULL,
                        token_type TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        expires_at TEXT NOT NULL,
                        revoked BOOLEAN DEFAULT 0,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                ''')
                
                # Audit log table
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS auth_audit (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        username TEXT,
                        action TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        success BOOLEAN,
                        timestamp TEXT NOT NULL,
                        details TEXT
                    )
                ''')
                
                # Create indexes
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_jti ON sessions(jti)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON auth_audit(timestamp)')
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error initializing auth database: {str(e)}")
            raise
    
    def _create_default_admin(self):
        """Create default admin user if none exists"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Check if any admin users exist
                cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                admin_count = cursor.fetchone()[0]
                
                if admin_count == 0:
                    # Create default admin
                    default_password = os.getenv('ADMIN_PASSWORD', 'AntiV-AI-Admin-2024!')
                    password_hash = self._hash_password(default_password)
                    
                    cursor.execute('''
                        INSERT INTO users (username, email, password_hash, role, created_at, password_changed_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        'admin',
                        'admin@antiv-ai.local',
                        password_hash,
                        'admin',
                        datetime.now().isoformat(),
                        datetime.now().isoformat()
                    ))
                    
                    conn.commit()
                    self.logger.info("Default admin user created")
                    
        except Exception as e:
            self.logger.error(f"Error creating default admin: {str(e)}")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception:
            return False
    
    def _validate_password_strength(self, password: str) -> Tuple[bool, List[str]]:
        """Validate password strength"""
        errors = []
        
        if len(password) < MIN_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")
        
        if REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
        
        if REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one number")
        
        if REQUIRE_SPECIAL_CHARS and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")
        
        return len(errors) == 0, errors
    
    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> Optional[User]:
        """Create a new user"""
        try:
            # Validate password strength
            is_strong, errors = self._validate_password_strength(password)
            if not is_strong:
                raise ValueError(f"Password validation failed: {', '.join(errors)}")
            
            # Validate role
            if role not in ['admin', 'user']:
                raise ValueError("Role must be 'admin' or 'user'")
            
            password_hash = self._hash_password(password)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, role, created_at, password_changed_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    username,
                    email,
                    password_hash,
                    role,
                    datetime.now().isoformat(),
                    datetime.now().isoformat()
                ))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                self.logger.info(f"User created: {username} (ID: {user_id}, Role: {role})")
                
                return User(
                    id=user_id,
                    username=username,
                    email=email,
                    role=role,
                    is_active=True,
                    created_at=datetime.now().isoformat()
                )
                
        except sqlite3.IntegrityError as e:
            if 'username' in str(e):
                raise ValueError("Username already exists")
            elif 'email' in str(e):
                raise ValueError("Email already exists")
            else:
                raise ValueError("User creation failed")
        except Exception as e:
            self.logger.error(f"Error creating user: {str(e)}")
            raise
    
    def authenticate_user(self, username: str, password: str, ip_address: str = None, user_agent: str = None) -> Optional[User]:
        """Authenticate user credentials"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get user
                cursor.execute('''
                    SELECT id, username, email, password_hash, role, is_active, 
                           created_at, last_login, failed_attempts, locked_until
                    FROM users WHERE username = ?
                ''', (username,))
                
                row = cursor.fetchone()
                if not row:
                    self._log_auth_event(None, username, 'login_failed', ip_address, user_agent, False, 'User not found')
                    return None
                
                user_data = {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'password_hash': row[3],
                    'role': row[4],
                    'is_active': bool(row[5]),
                    'created_at': row[6],
                    'last_login': row[7],
                    'failed_attempts': row[8],
                    'locked_until': row[9]
                }
                
                # Check if account is locked
                if user_data['locked_until']:
                    lock_time = datetime.fromisoformat(user_data['locked_until'])
                    if datetime.now() < lock_time:
                        self._log_auth_event(user_data['id'], username, 'login_failed', ip_address, user_agent, False, 'Account locked')
                        raise HTTPException(status_code=423, detail="Account is locked due to too many failed attempts")
                
                # Check if account is active
                if not user_data['is_active']:
                    self._log_auth_event(user_data['id'], username, 'login_failed', ip_address, user_agent, False, 'Account disabled')
                    raise HTTPException(status_code=403, detail="Account is disabled")
                
                # Verify password
                if not self._verify_password(password, user_data['password_hash']):
                    # Increment failed attempts
                    failed_attempts = user_data['failed_attempts'] + 1
                    locked_until = None
                    
                    # Lock account after 5 failed attempts
                    if failed_attempts >= 5:
                        locked_until = (datetime.now() + timedelta(minutes=30)).isoformat()
                    
                    cursor.execute('''
                        UPDATE users SET failed_attempts = ?, locked_until = ?
                        WHERE id = ?
                    ''', (failed_attempts, locked_until, user_data['id']))
                    
                    conn.commit()
                    
                    self._log_auth_event(user_data['id'], username, 'login_failed', ip_address, user_agent, False, 'Invalid password')
                    return None
                
                # Reset failed attempts on successful login
                cursor.execute('''
                    UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ?
                    WHERE id = ?
                ''', (datetime.now().isoformat(), user_data['id']))
                
                conn.commit()
                
                user = User(
                    id=user_data['id'],
                    username=user_data['username'],
                    email=user_data['email'],
                    role=user_data['role'],
                    is_active=user_data['is_active'],
                    created_at=user_data['created_at'],
                    last_login=datetime.now().isoformat()
                )
                
                self._log_auth_event(user.id, username, 'login_success', ip_address, user_agent, True, 'Successful login')
                
                return user
                
        except HTTPException:
            raise
        except Exception as e:
            self.logger.error(f"Error authenticating user: {str(e)}")
            return None
    
    def _log_auth_event(self, user_id: Optional[int], username: str, action: str, 
                       ip_address: str, user_agent: str, success: bool, details: str):
        """Log authentication events for audit"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO auth_audit (user_id, username, action, ip_address, user_agent, success, timestamp, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    username,
                    action,
                    ip_address,
                    user_agent,
                    success,
                    datetime.now().isoformat(),
                    details
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error logging auth event: {str(e)}")
    
    def create_access_token(self, user: User) -> str:
        """Create JWT access token"""
        jti = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        exp = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'exp': int(exp.timestamp()),
            'iat': int(now.timestamp()),
            'jti': jti,
            'type': 'access'
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Store session
        self._store_session(user.id, jti, 'access', exp)
        
        return token
    
    def create_refresh_token(self, user: User) -> str:
        """Create JWT refresh token"""
        jti = secrets.token_urlsafe(32)
        now = datetime.utcnow()
        exp = now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role,
            'exp': int(exp.timestamp()),
            'iat': int(now.timestamp()),
            'jti': jti,
            'type': 'refresh'
        }
        
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Store session
        self._store_session(user.id, jti, 'refresh', exp)
        
        return token
    
    def _store_session(self, user_id: int, jti: str, token_type: str, expires_at: datetime):
        """Store session in database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO sessions (user_id, jti, token_type, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    user_id,
                    jti,
                    token_type,
                    datetime.now().isoformat(),
                    expires_at.isoformat()
                ))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error storing session: {str(e)}")
    
    def verify_token(self, token: str) -> Optional[TokenData]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            jti = payload.get('jti')
            if not jti:
                return None
            
            # Check if token is revoked
            if jti in self.revoked_tokens:
                return None
            
            # Check session in database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT revoked, expires_at FROM sessions 
                    WHERE jti = ? AND revoked = 0
                ''', (jti,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                # Check if session is expired
                expires_at = datetime.fromisoformat(row[1])
                if datetime.now() > expires_at:
                    return None
            
            return TokenData(
                user_id=payload['user_id'],
                username=payload['username'],
                role=payload['role'],
                exp=payload['exp'],
                iat=payload['iat'],
                jti=jti
            )
            
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
        except Exception as e:
            self.logger.error(f"Error verifying token: {str(e)}")
            return None
    
    def revoke_token(self, jti: str):
        """Revoke a token"""
        try:
            self.revoked_tokens.add(jti)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    UPDATE sessions SET revoked = 1 
                    WHERE jti = ?
                ''', (jti,))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error revoking token: {str(e)}")
    
    def revoke_all_user_tokens(self, user_id: int):
        """Revoke all tokens for a user"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get all active JTIs for user
                cursor.execute('''
                    SELECT jti FROM sessions 
                    WHERE user_id = ? AND revoked = 0
                ''', (user_id,))
                
                jtis = [row[0] for row in cursor.fetchall()]
                
                # Add to revoked set
                self.revoked_tokens.update(jtis)
                
                # Mark as revoked in database
                cursor.execute('''
                    UPDATE sessions SET revoked = 1 
                    WHERE user_id = ? AND revoked = 0
                ''', (user_id,))
                
                conn.commit()
                
        except Exception as e:
            self.logger.error(f"Error revoking user tokens: {str(e)}")
    
    async def get_current_user(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> TokenData:
        """Dependency to get current authenticated user"""
        token_data = self.verify_token(credentials.credentials)
        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return token_data
    
    def require_role(self, required_role: str):
        """Dependency factory for role-based access control"""
        async def role_checker(current_user: TokenData = Depends(self.get_current_user)) -> TokenData:
            if required_role == 'admin' and current_user.role != 'admin':
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Insufficient permissions"
                )
            return current_user
        return role_checker

# Global auth manager instance
auth_manager = AuthManager()
