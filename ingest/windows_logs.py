"""
Windows Event Log ingestion module for SOC Log Analyzer.
Handles reading and parsing Windows Event Logs in EVTX and XML formats.
"""
import os
import sys
import platform
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator, Union
import xml.dom.minidom
import xmltodict
import pytz
from datetime import datetime

# Windows-specific imports (only on Windows)
if platform.system() == 'Windows':
    import win32evtlog
    import win32con
    import win32security
    import win32api

class WindowsEventLogs:
    """Handles Windows Event Log ingestion and processing."""
    
    # Default Windows Event Log paths
    DEFAULT_PATHS = [
        r"C:\Windows\System32\winevt\Logs\",
        r"C:\Windows\System32\config\"
    ]
    
    # Important Windows Event Log files
    IMPORTANT_LOGS = [
        "Security.evtx",
        "System.evtx", 
        "Application.evtx",
        "Microsoft-Windows-Sysmon%4Operational.evtx"
    ]
    
    # Windows Event ID to SOC event type mapping
    EVENT_ID_MAPPING = {
        # Authentication Events
        4624: "auth_success",        # Successful logon
        4625: "auth_failure",        # Failed logon
        4634: "auth_logoff",         # Account logged off
        4648: "auth_kerberos",       # A logon was attempted using explicit credentials
        
        # Account Management
        4720: "account_created",     # User account created
        4722: "account_enabled",     # User account enabled
        4725: "account_disabled",    # User account disabled
        4726: "account_deleted",     # User account deleted
        4738: "account_changed",     # User account changed
        
        # Privilege Assignment
        4672: "privilege_assigned",  # Special privileges assigned to new logon
        4673: "privilege_used",      # A privileged service was called
        4674: "privileged_operation",# An operation was performed on a privileged object
        
        # Process Creation
        4688: "process_created",     # A new process has been created
        4689: "process_exit",        # A process has exited
        
        # Service Installation
        4697: "service_install",     # A service was installed in the system
        4698: "scheduled_task",      # Scheduled task created
        
        # Sysmon Events
        1: "process_creation",       # Process creation
        3: "network_connection",     # Network connection
        7: "image_loaded",           # Image loaded
        8: "create_remote_thread",   # CreateRemoteThread detected
        11: "file_create",           # File created
        12: "registry_add",          # Registry object added or deleted
        13: "registry_set_value",    # Registry value set
        14: "registry_rename",       # Registry object renamed
        15: "file_stream_created",   # File stream created
        22: "dns_query"             # DNS query
    }
    
    def __init__(self):
        """Initialize Windows Event Log handler."""
        self.is_windows = platform.system() == 'Windows'
        self.is_admin = self._check_admin_privileges()
        self.timezone = pytz.timezone('UTC')
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with admin privileges."""
        if not self.is_windows:
            return False
            
        try:
            return bool(win32security.CheckTokenMembership(
                win32security.ImpersonateAnonymousToken(
                    win32security.GetCurrentProcessToken()
                ),
                win32security.ConvertSidToSidString(
                    win32security.GetSidSubAuthority(
                        win32security.GetSidSubAuthorityCount(
                            win32security.LookupAccountName(None, "Administrators")[0]
                        )[0], 0
                    )
                )
            ))
        except Exception:
            return False
    
    def find_windows_logs(self) -> List[str]:
        """
        Find Windows Event Log files on the system.
        
        Returns:
            List of paths to Windows Event Log files
        """
        found_logs = []
        
        # Check default paths
        for log_dir in self.DEFAULT_PATHS:
            if os.path.exists(log_dir):
                for log_file in os.listdir(log_dir):
                    if log_file in self.IMPORTANT_LOGS or log_file.endswith('.evtx'):
                        found_logs.append(os.path.join(log_dir, log_file))
        
        return found_logs
    
    def parse_evtx_file(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        """
        Parse an EVTX file and yield normalized events.
        
        Args:
            file_path: Path to the EVTX file
            
        Yields:
            Normalized event dictionaries
        """
        try:
            import Evtx.Evtx as evtx
            from bs4 import BeautifulSoup
            
            with evtx.Evtx(file_path) as log:
                for record in log.records():
                    try:
                        # Parse XML content
                        xml_content = record.xml()
                        soup = BeautifulSoup(xml_content, 'xml')
                        
                        # Extract basic event information
                        system = soup.find('System')
                        if not system:
                            continue
                            
                        event_data = {
                            'timestamp': self._parse_windows_timestamp(system.find('TimeCreated').get('SystemTime')),
                            'event_id': int(system.find('EventID').text),
                            'channel': system.find('Channel').text if system.find('Channel') else None,
                            'computer': system.find('Computer').text if system.find('Computer') else None,
                            'level': int(system.find('Level').text) if system.find('Level') else 0,
                        }
                        
                        # Extract user information if available
                        security = system.find('Security')
                        if security and 'UserID' in security.attrs:
                            event_data['user'] = security['UserID']
                        
                        # Extract event data
                        data = {}
                        event_data_node = soup.find('EventData')
                        if event_data_node:
                            for data_item in event_data_node.find_all('Data'):
                                name = data_item.get('Name', f'Data{len(data)}')
                                data[name] = data_item.text
                        
                        # Map to SOC schema
                        normalized = self._normalize_windows_event(event_data, data, file_path)
                        if normalized:
                            yield normalized
                            
                    except Exception as e:
                        print(f"[!] Error parsing event: {str(e)}", file=sys.stderr)
                        continue
                        
        except ImportError:
            print("[!] python-evtx module not found. Install with: pip install python-evtx", 
                  file=sys.stderr)
            return []
        except Exception as e:
            print(f"[!] Error reading EVTX file: {str(e)}", file=sys.stderr)
            return []
    
    def _parse_windows_timestamp(self, timestamp_str: str) -> str:
        """Convert Windows timestamp string to ISO format."""
        try:
            # Windows Event Log timestamp format: 2023-01-01T12:00:00.1234567Z
            dt = datetime.strptime(timestamp_str.split('.')[0], '%Y-%m-%dT%H:%M:%S')
            return dt.isoformat() + 'Z'
        except Exception:
            return datetime.utcnow().isoformat() + 'Z'
    
    def _normalize_windows_event(self, 
                               event_data: Dict[str, Any], 
                               event_fields: Dict[str, Any],
                               source: str) -> Dict[str, Any]:
        """
        Normalize Windows Event Log data to SOC schema.
        
        Args:
            event_data: Basic event data
            event_fields: Event-specific data fields
            source: Source log file/path
            
        Returns:
            Normalized event dictionary
        """
        # Get event type from mapping or default to 'unknown'
        event_id = event_data.get('event_id')
        event_type = self.EVENT_ID_MAPPING.get(event_id, 'unknown')
        
        # Determine severity based on event level
        level = event_data.get('level', 0)
        if level <= 2:
            severity = 'critical'
        elif level <= 3:
            severity = 'error'
        elif level == 4:
            severity = 'warning'
        else:
            severity = 'info'
        
        # Extract common fields
        normalized = {
            'timestamp': event_data.get('timestamp', datetime.utcnow().isoformat() + 'Z'),
            'source': 'windows_' + (event_data.get('channel', 'unknown').lower().replace(' ', '_')),
            'host': event_data.get('computer', 'unknown'),
            'user': event_data.get('user'),
            'ip': None,  # Will be extracted from event data if available
            'event_type': event_type,
            'status': 'success' if 'success' in event_type else 'failure' if 'failure' in event_type else 'info',
            'severity': severity,
            'event_id': event_id,
            'raw_log': str({**event_data, **event_fields}),
            'source_file': source
        }
        
        # Extract IP addresses if available
        for value in event_fields.values():
            if isinstance(value, str) and any(c.isdigit() for c in value):
                # Simple IP detection (this is very basic)
                if re.match(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', value):
                    normalized['ip'] = value
                    break
        
        return normalized

    def stream_windows_events(self, log_name: str = 'Security') -> Generator[Dict[str, Any], None, None]:
        """
        Stream events from a Windows Event Log in real-time.
        
        Args:
            log_name: Name of the Windows Event Log (e.g., 'Security', 'System')
            
        Yields:
            Normalized event dictionaries
        """
        if not self.is_windows:
            print("[!] Windows Event Log streaming is only available on Windows", file=sys.stderr)
            return
            
        if not self.is_admin:
            print("[!] Admin privileges required for live event streaming", file=sys.stderr)
            return
            
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if not events:
                    break
                    
                for event in events:
                    try:
                        event_data = {
                            'timestamp': event.TimeGenerated.isoformat() + 'Z',
                            'event_id': event.EventID,
                            'computer': event.ComputerName,
                            'level': event.EventType,
                            'source': event.SourceName,
                            'user': event.StringInserts[0] if event.StringInserts else None
                        }
                        
                        # Convert event data to dict
                        fields = {}
                        if event.StringInserts:
                            for i, value in enumerate(event.StringInserts):
                                fields[f'Field{i}'] = value
                        
                        normalized = self._normalize_windows_event(event_data, fields, f'live:{log_name}')
                        if normalized:
                            yield normalized
                            
                    except Exception as e:
                        print(f"[!] Error processing live event: {str(e)}", file=sys.stderr)
                        continue
                        
        except Exception as e:
            print(f"[!] Error reading live events: {str(e)}", file=sys.stderr)
        finally:
            if 'hand' in locals():
                win32evtlog.CloseEventLog(hand)

def load_windows_logs(log_path: str = None) -> List[Dict[str, Any]]:
    """
    Load and parse Windows Event Logs.
    
    Args:
        log_path: Path to a specific log file or directory
        
    Returns:
        List of parsed and normalized Windows events
    """
    windows_logs = WindowsEventLogs()
    events = []
    
    if log_path:
        if os.path.isfile(log_path):
            if log_path.lower().endswith('.evtx'):
                events.extend(list(windows_logs.parse_evtx_file(log_path)))
            # Add support for other formats (XML, CSV) here
        elif os.path.isdir(log_path):
            for root, _, files in os.walk(log_path):
                for file in files:
                    if file.lower().endswith('.evtx'):
                        file_path = os.path.join(root, file)
                        try:
                            events.extend(list(windows_logs.parse_evtx_file(file_path)))
                        except Exception as e:
                            print(f"[!] Error processing {file_path}: {str(e)}", file=sys.stderr)
    else:
        # Auto-detect and load all Windows logs
        for log_file in windows_logs.find_windows_logs():
            try:
                events.extend(list(windows_logs.parse_evtx_file(log_file)))
            except Exception as e:
                print(f"[!] Error processing {log_file}: {str(e)}", file=sys.stderr)
    
    return events

# Example usage
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Parse Windows Event Logs')
    parser.add_argument('--path', help='Path to EVTX file or directory')
    parser.add_argument('--output', help='Output file (JSON)')
    args = parser.parse_args()
    
    events = load_windows_logs(args.path)
    
    if args.output:
        import json
        with open(args.output, 'w') as f:
            json.dump(events, f, indent=2)
        print(f"[+] Saved {len(events)} events to {args.output}")
    else:
        for event in events[:10]:  # Print first 10 events as example
            print(f"[{event['timestamp']}] {event['event_type']} - {event.get('host', '')} - {event.get('user', '')}")
        print(f"\nTotal events: {len(events)}")
