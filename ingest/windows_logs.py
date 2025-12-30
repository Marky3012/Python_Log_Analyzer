"""
Windows Event Log ingestion module for SOC Log Analyzer.
Handles reading and parsing Windows Event Logs in EVTX and XML formats.
"""
import os
import sys
import re
import time
import platform
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Generator, Union

# Try to import python-evtx
try:
    from Evtx.Evtx import Evtx
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False
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
        r"C:\Windows\System32\winevt\Logs",
        r"C:\Windows\System32\config"
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
    
    def _is_valid_evtx(self, file_path: str) -> bool:
        """
        Check if a file is a valid EVTX file and can be read.
        
        Args:
            file_path: Path to the EVTX file to validate
            
        Returns:
            bool: True if the file is a valid EVTX file, False otherwise
        """
        try:
            # Check if file exists
            if not os.path.isfile(file_path):
                print(f"[!] File not found or not a regular file: {file_path}", file=sys.stderr)
                return False
                
            # Check file size
            try:
                file_size = os.path.getsize(file_path)
                if file_size < 4096:  # Minimum size for a valid EVTX file
                    print(f"[!] File is too small to be a valid EVTX: {file_path} ({file_size} bytes)", 
                          file=sys.stderr)
                    return False
            except (OSError, IOError) as e:
                print(f"[!] Error getting file size for {file_path}: {str(e)}", file=sys.stderr)
                return False
                
            # Check file permissions
            if not os.access(file_path, os.R_OK):
                print(f"[!] Insufficient permissions to read file: {file_path}", file=sys.stderr)
                if platform.system() == 'Windows':
                    print("    Try running the script as Administrator", file=sys.stderr)
                return False
                
            # Check EVTX header
            try:
                with open(file_path, 'rb') as f:
                    header = f.read(8)
                    if header != b'ElfFile\x00':
                        print(f"[!] Invalid EVTX header in {file_path}", file=sys.stderr)
                        return False
                    
                    # Read a bit more to verify the file isn't corrupted
                    f.seek(0, 2)  # Seek to end of file
                    file_size = f.tell()
                    if file_size < 128:  # EVTX files have at least 128-byte header
                        print(f"[!] File is too small to be a valid EVTX: {file_path}", file=sys.stderr)
                        return False
                        
            except (IOError, OSError) as e:
                print(f"[!] Error reading file {file_path}: {str(e)}", file=sys.stderr)
                if 'Permission denied' in str(e) and platform.system() == 'Windows':
                    print("    Try running the script as Administrator", file=sys.stderr)
                return False
                
            return True
            
        except Exception as e:
            print(f"[!] Unexpected error validating EVTX file {file_path}: {str(e)}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            return False
    
    def _get_evtx_record_count(self, file_path: str, max_retries: int = 3) -> int:
        """
        Safely get the number of records in an EVTX file with retry logic.
        
        Args:
            file_path: Path to the EVTX file
            max_retries: Maximum number of retry attempts
            
        Returns:
            Number of records in the EVTX file, or 0 if it can't be determined
        """
        if not EVTX_AVAILABLE or not file_path:
            return 0
            
        last_error = None
        for attempt in range(max_retries):
            try:
                with Evtx(file_path) as evtx:
                    # Try to get an accurate count, but limit to 1M records to avoid excessive memory usage
                    count = 0
                    for _ in evtx.records():
                        count += 1
                        if count >= 1_000_000:  # Safety limit
                            print(f"[!] Warning: File has more than 1,000,000 records, using estimate")
                            break
                    return count
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:  # Don't sleep on the last attempt
                    time.sleep(0.5 * (attempt + 1))  # Exponential backoff
        
        print(f"[!] Warning: Could not get record count for {file_path} after {max_retries} attempts")
        if last_error:
            print(f"     Last error: {str(last_error)}")
        return 0  # Return 0 to indicate we couldn't determine the count
    
    def parse_evtx_file(self, file_path: str) -> Generator[Dict[str, Any], None, None]:
        """
        Parse an EVTX file and yield normalized events with robust error handling.
        
        Args:
            file_path: Path to the EVTX file
            
        Yields:
            Normalized event dictionaries
        """
        if not EVTX_AVAILABLE:
            print("[!] python-evtx module not found. Install with: pip install python-evtx", 
                  file=sys.stderr)
            return
            
        if not self._is_valid_evtx(file_path):
            return

        # Get record count with retry logic
        max_retries = 3
        record_count = 0
        for attempt in range(max_retries):
            try:
                record_count = self._get_evtx_record_count(file_path)
                break
            except Exception as e:
                if attempt == max_retries - 1:
                    print(f"[!] Failed to get record count after {max_retries} attempts: {str(e)}")
                    return
                time.sleep(1)  # Wait before retry
        
        if record_count > 0:
            print(f"[+] Found {record_count} records in {os.path.basename(file_path)}")
        else:
            print(f"[!] No records found in {os.path.basename(file_path)} or could not read file")
            return

        success_count = 0
        error_count = 0
        max_errors = min(100, record_count // 10)  # Allow up to 10% errors or 100, whichever is smaller
        
        try:
            # Open the EVTX file for processing
            with Evtx(file_path) as evtx:
                for i, record in enumerate(evtx.records(), 1):
                    # If we hit too many errors, bail out
                    if error_count > max_errors and max_errors > 0:
                        print(f"[!] Too many errors ({error_count} out of {i} records). Stopping processing of {file_path}")
                        break
                        
                    try:
                        # Parse the XML content with error handling for malformed XML
                        try:
                            xml_data = record.xml()
                            root = ET.fromstring(xml_data)
                        except ET.ParseError as e:
                            print(f"[!] XML parsing error in record {i}: {str(e)}")
                            error_count += 1
                            continue
                            
                        # Extract basic event data with robust error handling
                        ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
                        event_data = {}
                        
                        try:
                            event_data = {
                                'timestamp': self._safe_xml_find(root, './/evt:TimeCreated', ns, 'SystemTime'),
                                'event_id': int(self._safe_xml_find(root, './/evt:EventID', ns, 'text') or 0),
                                'level': int(self._safe_xml_find(root, './/evt:Level', ns, 'text') or 0),
                                'provider': self._safe_xml_find(root, './/evt:Provider', ns, 'Name'),
                                'computer': self._safe_xml_find(root, './/evt:Computer', ns, 'text'),
                                'channel': self._safe_xml_find(root, './/evt:Channel', ns, 'text'),
                            }
                        except (AttributeError, ValueError, TypeError) as e:
                            print(f"[!] Error extracting fields from record {i}: {str(e)}")
                            error_count += 1
                            continue
                        
                        # Extract event data with error handling
                        data = {}
                        try:
                            data_items = root.findall('.//evt:EventData/evt:Data', ns) or []
                            for idx, data_item in enumerate(data_items):
                                try:
                                    name = data_item.get('Name', f'Data{idx}')
                                    data[name] = data_item.text if data_item.text else ''
                                except Exception as e:
                                    print(f"[!] Warning: Error processing data item {idx} in record {i}: {str(e)}")
                        except Exception as e:
                            print(f"[!] Warning: Error extracting event data from record {i}: {str(e)}")
                        
                        # Map to SOC schema with error handling
                        try:
                            normalized = self._normalize_windows_event(event_data, data, file_path) 
                            if normalized:
                                success_count += 1
                                # Show progress every 1000 records
                                if success_count % 1000 == 0:
                                    print(f"[+] Processed {success_count}/{record_count} records...")
                                yield normalized
                        except Exception as e:
                            print(f"[!] Error normalizing event {i}: {str(e)}")
                            error_count += 1
                            
                    except Exception as e:
                        error_count += 1
                        print(f"[!] Error parsing record {i} in {file_path}: {str(e)}")
                        # For debugging specific records, uncomment the following:
                        # if i == 1714:  # The record that was previously failing
                        #     print(f"[DEBUG] Problematic record {i} offset: {record.offset()}")
                        continue
                
                # Print final statistics
                processed_count = success_count + error_count
                print(f"[+] Processed {processed_count} records from {os.path.basename(file_path)}:")
                print(f"    - Success: {success_count}")
                print(f"    - Errors: {error_count}")
                if processed_count > 0:
                    print(f"    - Success rate: {(success_count/processed_count)*100:.1f}%")
                
                if success_count == 0 and error_count > 0:
                    print(f"[!] Warning: No valid records found in {os.path.basename(file_path)}")
                    
        except PermissionError as e:
            print(f"[!] Permission denied when accessing {file_path}. Try running as administrator.", file=sys.stderr)
            if platform.system() == 'Windows':
                print("    Try running the command prompt as Administrator and then run this script.")
        except Exception as e:
            print(f"[!] Critical error processing EVTX file {file_path}: {str(e)}", file=sys.stderr)
            if hasattr(e, '__traceback__'):
                import traceback
                print(f"[!] Error details: {traceback.format_exc()}", file=sys.stderr)
    
    def _safe_xml_find(self, root, xpath, namespaces, attr=None):
        """Safely find and extract data from XML with error handling."""
        try:
            element = root.find(xpath, namespaces)
            if element is None:
                return None
            if attr == 'text':
                return element.text
            return element.get(attr) if attr else element
        except Exception:
            return None
    
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
