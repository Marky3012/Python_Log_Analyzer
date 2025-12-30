"""
Log schema and normalization for SOC Log Analyzer.
Defines the common log entry structure and normalization functions.
"""
from datetime import datetime
from typing import Dict, Any, Optional, TypedDict
import re

class LogEntry(TypedDict):
    """Type definition for normalized log entries."""
    timestamp: Optional[datetime]
    source: Optional[str]
    host: Optional[str]
    user: Optional[str]
    ip: Optional[str]
    event_type: Optional[str]
    status: Optional[str]
    severity: Optional[str]
    raw_log: Optional[str]

# Common schema for all normalized events
NORMALIZED_SCHEMA = {
    "timestamp": None,
    "source": None,
    "host": None,
    "user": None,
    "ip": None,
    "event_type": None,
    "status": None,
    "severity": None,
    "raw_log": None
}

def normalize_log(raw_log: str, source: str = "unknown") -> Dict[str, Any]:
    """
    Normalize a raw log line into the standard SOC event schema.
    
    Args:
        raw_log: The raw log line to normalize
        source: Source of the log (e.g., 'auth', 'web', 'firewall')
        
    Returns:
        Dict containing normalized log data
    """
    # Create a copy of the schema
    event = NORMALIZED_SCHEMA.copy()
    
    # Set basic fields
    event["raw_log"] = raw_log.strip()
    event["source"] = source
    event["severity"] = "low"
    event["timestamp"] = datetime.utcnow().isoformat()
    
    # Extract IP if present
    ip = _extract_ip(raw_log)
    if ip:
        event["ip"] = ip
    
    # Basic pattern matching for authentication events
    raw_lower = raw_log.lower()
    
    if "failed" in raw_lower:
        event["event_type"] = "auth_failure"
        event["status"] = "failed"
        event["severity"] = "medium"
    elif "success" in raw_lower:
        event["event_type"] = "auth_success"
        event["status"] = "success"
    
    # Extract username if possible (very basic pattern)
    user_match = re.search(r'user(?:name)?[=:\s]+([^\s,;]+)', raw_lower)
    if user_match:
        event["user"] = user_match.group(1)
    
    # Extract host if possible
    host_match = re.search(r'host[=:\s]+([^\s,;]+)', raw_lower)
    if host_match:
        event["host"] = host_match.group(1)
    
    return event

def _extract_ip(text: str) -> Optional[str]:
    """Extract the first IP address from a string."""
    # Match both IPv4 and IPv6 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'
    match = re.search(ip_pattern, text)
    return match.group(0) if match else None
