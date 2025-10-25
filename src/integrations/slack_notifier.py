"""
Slack/Teams Notification Integration for AntiV-AI
Sends real-time security alerts to Slack channels with rich formatting
"""

import os
import json
import asyncio
import aiohttp
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

# Notification configuration
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')
TEAMS_WEBHOOK_URL = os.getenv('TEAMS_WEBHOOK_URL', '')
NOTIFICATION_CHANNEL = os.getenv('NOTIFICATION_CHANNEL', '#security-alerts')
DASHBOARD_BASE_URL = os.getenv('DASHBOARD_BASE_URL', 'https://localhost:8000')

class AlertSeverity(Enum):
    """Alert severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class NotificationType(Enum):
    """Types of notifications"""
    SCAN_ALERT = "scan_alert"
    AUTHENTICATION_FAILURE = "auth_failure"
    DDOS_ATTACK = "ddos_attack"
    BLOCKCHAIN_INTEGRITY = "blockchain_integrity"
    SYSTEM_ERROR = "system_error"
    COMPLIANCE_VIOLATION = "compliance_violation"

@dataclass
class SecurityAlert:
    """Security alert data structure"""
    alert_id: str
    timestamp: str
    alert_type: NotificationType
    severity: AlertSeverity
    title: str
    description: str
    details: Dict[str, Any]
    source_ip: Optional[str]
    user_id: Optional[str]
    username: Optional[str]
    file_hash: Optional[str]
    risk_score: float
    recommended_action: str
    dashboard_link: str

class SlackNotifier:
    """Slack notification system for security alerts"""
    
    def __init__(self, webhook_url: str = SLACK_WEBHOOK_URL):
        """Initialize Slack notifier"""
        self.logger = logging.getLogger(__name__)
        self.webhook_url = webhook_url
        self.channel = NOTIFICATION_CHANNEL
        self.dashboard_base_url = DASHBOARD_BASE_URL
        
        # Notification settings
        self.enabled = bool(webhook_url)
        self.rate_limit_cache = {}  # Prevent spam
        self.max_notifications_per_hour = 50
        
        if not self.enabled:
            self.logger.warning("Slack webhook URL not configured - notifications disabled")
    
    def _get_severity_color(self, severity: AlertSeverity) -> str:
        """Get color code for alert severity"""
        color_map = {
            AlertSeverity.LOW: "#36a64f",      # Green
            AlertSeverity.MEDIUM: "#ff9500",   # Orange
            AlertSeverity.HIGH: "#ff0000",     # Red
            AlertSeverity.CRITICAL: "#8B0000"  # Dark Red
        }
        return color_map.get(severity, "#808080")  # Gray default
    
    def _get_severity_emoji(self, severity: AlertSeverity) -> str:
        """Get emoji for alert severity"""
        emoji_map = {
            AlertSeverity.LOW: "🟢",
            AlertSeverity.MEDIUM: "🟡",
            AlertSeverity.HIGH: "🔴",
            AlertSeverity.CRITICAL: "🚨"
        }
        return emoji_map.get(severity, "⚪")
    
    def _get_alert_type_emoji(self, alert_type: NotificationType) -> str:
        """Get emoji for alert type"""
        emoji_map = {
            NotificationType.SCAN_ALERT: "🦠",
            NotificationType.AUTHENTICATION_FAILURE: "🔐",
            NotificationType.DDOS_ATTACK: "⚡",
            NotificationType.BLOCKCHAIN_INTEGRITY: "⛓️",
            NotificationType.SYSTEM_ERROR: "💥",
            NotificationType.COMPLIANCE_VIOLATION: "📋"
        }
        return emoji_map.get(alert_type, "🔔")
    
    def _check_rate_limit(self, alert_type: NotificationType) -> bool:
        """Check if notification is rate limited"""
        current_time = datetime.now()
        hour_key = current_time.strftime("%Y-%m-%d-%H")
        
        if hour_key not in self.rate_limit_cache:
            self.rate_limit_cache[hour_key] = {}
        
        type_key = alert_type.value
        current_count = self.rate_limit_cache[hour_key].get(type_key, 0)
        
        if current_count >= self.max_notifications_per_hour:
            self.logger.warning(f"Rate limit exceeded for {alert_type.value}")
            return False
        
        self.rate_limit_cache[hour_key][type_key] = current_count + 1
        
        # Clean up old entries
        current_hour = current_time.hour
        keys_to_remove = []
        for key in self.rate_limit_cache:
            try:
                key_hour = int(key.split('-')[-1])
                if abs(current_hour - key_hour) > 1:
                    keys_to_remove.append(key)
            except:
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self.rate_limit_cache[key]
        
        return True
    
    def _create_slack_payload(self, alert: SecurityAlert) -> Dict:
        """Create Slack message payload"""
        severity_emoji = self._get_severity_emoji(alert.severity)
        type_emoji = self._get_alert_type_emoji(alert.alert_type)
        color = self._get_severity_color(alert.severity)
        
        # Create main attachment
        attachment = {
            "color": color,
            "title": f"{severity_emoji} {type_emoji} {alert.title}",
            "title_link": alert.dashboard_link,
            "text": alert.description,
            "fields": [
                {
                    "title": "Severity",
                    "value": alert.severity.value.upper(),
                    "short": True
                },
                {
                    "title": "Risk Score",
                    "value": f"{alert.risk_score:.2f}",
                    "short": True
                },
                {
                    "title": "Timestamp",
                    "value": alert.timestamp,
                    "short": True
                },
                {
                    "title": "Alert ID",
                    "value": alert.alert_id,
                    "short": True
                }
            ],
            "footer": "AntiV-AI Security System",
            "footer_icon": "https://cdn-icons-png.flaticon.com/512/2092/2092063.png",
            "ts": int(datetime.fromisoformat(alert.timestamp.replace('Z', '+00:00')).timestamp())
        }
        
        # Add optional fields
        if alert.source_ip:
            attachment["fields"].append({
                "title": "Source IP",
                "value": alert.source_ip,
                "short": True
            })
        
        if alert.username:
            attachment["fields"].append({
                "title": "User",
                "value": alert.username,
                "short": True
            })
        
        if alert.file_hash:
            attachment["fields"].append({
                "title": "File Hash",
                "value": f"`{alert.file_hash[:16]}...`",
                "short": True
            })
        
        # Add details as additional fields
        for key, value in alert.details.items():
            if len(attachment["fields"]) < 10:  # Slack limit
                attachment["fields"].append({
                    "title": key.replace('_', ' ').title(),
                    "value": str(value)[:100],  # Truncate long values
                    "short": True
                })
        
        # Add recommended action
        if alert.recommended_action:
            attachment["fields"].append({
                "title": "Recommended Action",
                "value": alert.recommended_action,
                "short": False
            })
        
        # Create action buttons
        actions = [
            {
                "type": "button",
                "text": "View Dashboard",
                "url": alert.dashboard_link,
                "style": "primary"
            }
        ]
        
        if alert.severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            actions.append({
                "type": "button",
                "text": "Investigate",
                "url": f"{self.dashboard_base_url}/security/alerts/{alert.alert_id}",
                "style": "danger"
            })
        
        attachment["actions"] = actions
        
        # Create main payload
        payload = {
            "channel": self.channel,
            "username": "AntiV-AI Security",
            "icon_emoji": ":shield:",
            "attachments": [attachment]
        }
        
        # Add mention for critical alerts
        if alert.severity == AlertSeverity.CRITICAL:
            payload["text"] = "<!channel> Critical security alert detected!"
        elif alert.severity == AlertSeverity.HIGH:
            payload["text"] = "<!here> High-priority security alert"
        
        return payload
    
    async def send_alert(self, alert: SecurityAlert) -> bool:
        """
        Send security alert to Slack
        
        Args:
            alert: SecurityAlert object to send
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.enabled:
            self.logger.debug("Slack notifications disabled")
            return False
        
        # Check rate limiting
        if not self._check_rate_limit(alert.alert_type):
            return False
        
        try:
            # Create Slack payload
            payload = self._create_slack_payload(alert)
            
            # Send to Slack
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    headers={'Content-Type': 'application/json'},
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    
                    if response.status == 200:
                        self.logger.info(f"Slack alert sent successfully: {alert.alert_id}")
                        return True
                    else:
                        error_text = await response.text()
                        self.logger.error(f"Slack webhook failed ({response.status}): {error_text}")
                        return False
        
        except asyncio.TimeoutError:
            self.logger.error("Slack webhook timeout")
            return False
        except Exception as e:
            self.logger.error(f"Error sending Slack alert: {str(e)}")
            return False
    
    def create_scan_alert(self, file_path: str, risk_score: float, threat_level: str,
                         file_hash: str, details: Dict = None) -> SecurityAlert:
        """Create a scan alert"""
        import uuid
        
        severity = AlertSeverity.LOW
        if risk_score >= 0.9:
            severity = AlertSeverity.CRITICAL
        elif risk_score >= 0.7:
            severity = AlertSeverity.HIGH
        elif risk_score >= 0.4:
            severity = AlertSeverity.MEDIUM
        
        return SecurityAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            alert_type=NotificationType.SCAN_ALERT,
            severity=severity,
            title=f"Malicious File Detected: {threat_level}",
            description=f"High-risk file detected during scan: {file_path}",
            details=details or {},
            source_ip=None,
            user_id=None,
            username=None,
            file_hash=file_hash,
            risk_score=risk_score,
            recommended_action="Quarantine file and investigate source",
            dashboard_link=f"{self.dashboard_base_url}/scans/{file_hash}"
        )
    
    def create_auth_failure_alert(self, username: str, source_ip: str, 
                                 failure_count: int, details: Dict = None) -> SecurityAlert:
        """Create an authentication failure alert"""
        import uuid
        
        severity = AlertSeverity.MEDIUM
        if failure_count >= 10:
            severity = AlertSeverity.HIGH
        elif failure_count >= 20:
            severity = AlertSeverity.CRITICAL
        
        return SecurityAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            alert_type=NotificationType.AUTHENTICATION_FAILURE,
            severity=severity,
            title=f"Authentication Failures: {username}",
            description=f"Multiple failed login attempts detected for user {username}",
            details=details or {},
            source_ip=source_ip,
            user_id=None,
            username=username,
            file_hash=None,
            risk_score=min(failure_count / 20.0, 1.0),
            recommended_action="Review user account and consider blocking IP",
            dashboard_link=f"{self.dashboard_base_url}/security/auth-logs"
        )
    
    def create_ddos_alert(self, source_ip: str, request_count: int, 
                         attack_type: str, details: Dict = None) -> SecurityAlert:
        """Create a DDoS attack alert"""
        import uuid
        
        severity = AlertSeverity.HIGH
        if request_count >= 1000:
            severity = AlertSeverity.CRITICAL
        
        return SecurityAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            alert_type=NotificationType.DDOS_ATTACK,
            severity=severity,
            title=f"DDoS Attack Detected: {attack_type}",
            description=f"DDoS attack detected from {source_ip} with {request_count} requests",
            details=details or {},
            source_ip=source_ip,
            user_id=None,
            username=None,
            file_hash=None,
            risk_score=min(request_count / 1000.0, 1.0),
            recommended_action="Block source IP and monitor for continued attacks",
            dashboard_link=f"{self.dashboard_base_url}/security/ddos"
        )
    
    def create_blockchain_alert(self, verification_result: Dict, 
                               details: Dict = None) -> SecurityAlert:
        """Create a blockchain integrity alert"""
        import uuid
        
        is_valid = verification_result.get('is_valid', True)
        severity = AlertSeverity.CRITICAL if not is_valid else AlertSeverity.LOW
        
        return SecurityAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.now().isoformat(),
            alert_type=NotificationType.BLOCKCHAIN_INTEGRITY,
            severity=severity,
            title="Blockchain Integrity Check",
            description="Blockchain audit trail integrity verification completed",
            details=details or {},
            source_ip=None,
            user_id=None,
            username=None,
            file_hash=None,
            risk_score=0.0 if is_valid else 1.0,
            recommended_action="Investigate audit trail tampering" if not is_valid else "No action required",
            dashboard_link=f"{self.dashboard_base_url}/security/blockchain"
        )
    
    async def send_test_alert(self) -> bool:
        """Send a test alert to verify configuration"""
        test_alert = SecurityAlert(
            alert_id="test-alert",
            timestamp=datetime.now().isoformat(),
            alert_type=NotificationType.SYSTEM_ERROR,
            severity=AlertSeverity.LOW,
            title="Test Alert - AntiV-AI Notifications",
            description="This is a test alert to verify Slack integration is working correctly.",
            details={"test": True, "system": "AntiV-AI"},
            source_ip="127.0.0.1",
            user_id="test",
            username="system",
            file_hash=None,
            risk_score=0.1,
            recommended_action="No action required - this is a test",
            dashboard_link=f"{self.dashboard_base_url}/test"
        )
        
        return await self.send_alert(test_alert)
    
    def get_notification_stats(self) -> Dict:
        """Get notification statistics"""
        total_sent = 0
        for hour_data in self.rate_limit_cache.values():
            for count in hour_data.values():
                total_sent += count
        
        return {
            "enabled": self.enabled,
            "webhook_configured": bool(self.webhook_url),
            "channel": self.channel,
            "total_sent_this_hour": total_sent,
            "rate_limit_per_hour": self.max_notifications_per_hour,
            "dashboard_base_url": self.dashboard_base_url
        }

# Global Slack notifier instance
slack_notifier = SlackNotifier()
