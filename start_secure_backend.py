#!/usr/bin/env python3
"""
Secure Backend Startup Script for AntiV-AI
Starts the FastAPI server with HTTPS, security middleware, and monitoring
"""

import os
import sys
import logging
import uvicorn
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def setup_logging():
    """Setup secure logging configuration"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Set restrictive permissions on log directory
    if os.name != 'nt':
        os.chmod(log_dir, 0o700)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / "antiv_api.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def check_security_requirements():
    """Check if security requirements are met"""
    print("🔒 Checking Security Requirements...")
    
    # Check if running as root (should not be)
    if os.name != 'nt' and os.geteuid() == 0:
        print("⚠️  WARNING: Running as root is not recommended for security!")
        print("   Consider creating a dedicated user for the AntiV-AI service")
    
    # Check data directory permissions
    data_dir = Path("data")
    if data_dir.exists():
        stat = data_dir.stat()
        if os.name != 'nt':
            perms = oct(stat.st_mode)[-3:]
            if perms != '700':
                print(f"⚠️  WARNING: Data directory permissions are {perms}, should be 700")
                try:
                    os.chmod(data_dir, 0o700)
                    print("   ✅ Fixed data directory permissions")
                except:
                    print("   ❌ Failed to fix data directory permissions")
    
    # Check environment variables
    security_vars = ['JWT_SECRET_KEY', 'ADMIN_PASSWORD']
    for var in security_vars:
        if not os.getenv(var):
            print(f"ℹ️  Environment variable {var} not set (using defaults)")
    
    print("✅ Security check completed")

def main():
    """Main startup function"""
    print("🚀 Starting AntiV-AI Secure Backend Server")
    print("=" * 50)
    
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Check security requirements
    check_security_requirements()
    
    # Import after path setup
    try:
        from network_security import create_secure_uvicorn_config
        from app import app
        
        # Configure secure server
        config = create_secure_uvicorn_config(
            host="127.0.0.1",  # Bind to localhost only for security
            port=8000,
            ssl_enabled=True
        )
        
        print(f"🌐 Server Configuration:")
        print(f"   • Host: {config['host']}")
        print(f"   • Port: {config['port']}")
        print(f"   • HTTPS: {'Enabled' if 'ssl_context' in config else 'Disabled'}")
        print(f"   • Security Headers: Enabled")
        print(f"   • Rate Limiting: Enabled")
        print(f"   • CORS: Restricted to localhost:3000")
        
        print("\n🔐 Security Features Active:")
        print("   • JWT Authentication with role-based access")
        print("   • File upload validation and rate limiting")
        print("   • Database encryption at rest")
        print("   • Comprehensive audit logging")
        print("   • Process monitoring and quarantine")
        
        print("\n📚 API Documentation:")
        if 'ssl_context' in config:
            print("   • https://localhost:8000/docs")
        else:
            print("   • http://localhost:8000/docs")
        
        print("\n🔑 Default Admin Credentials:")
        print("   • Username: admin")
        print("   • Password: AntiV-AI-Admin-2024!")
        print("   ⚠️  CHANGE DEFAULT PASSWORD IN PRODUCTION!")
        
        print("\n" + "=" * 50)
        print("🎯 Starting server...")
        
        # Start server
        uvicorn.run(
            app,
            **config
        )
        
    except ImportError as e:
        logger.error(f"Failed to import required modules: {str(e)}")
        print("❌ Failed to start server - missing dependencies")
        print("   Run: pip install -r requirements.txt")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Failed to start server: {str(e)}")
        print(f"❌ Server startup failed: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
