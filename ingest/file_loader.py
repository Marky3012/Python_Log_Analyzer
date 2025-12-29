"""
Log file loader module for SOC Log Analyzer.
Handles reading log files from various sources including Windows Event Logs.
"""
import os
import platform
import sys
from typing import List, Dict, Any, Union, Generator
from pathlib import Path

# Import Windows-specific modules if available
WINDOWS_LOGS_SUPPORT = False
if platform.system() == 'Windows':
    try:
        from . import windows_logs
        WINDOWS_LOGS_SUPPORT = True
    except ImportError:
        print("[!] Windows Event Log support requires additional modules. Install with: pip install python-evtx pywin32", 
              file=sys.stderr)

def load_logs(path: str, log_type: str = None) -> List[Union[str, Dict[str, Any]]]:
    """
    Load logs from a file, directory, or Windows Event Logs.
    
    Args:
        path: Path to a log file, directory, or special value 'auto' for auto-detection
        log_type: Type of logs ('windows', 'auth', 'web', etc.) or 'auto' for detection
        
    Returns:
        List of log entries (strings or dictionaries for structured logs)
    """
    # Handle Windows Event Logs
    if path.lower() == 'auto' or (log_type and log_type.lower() == 'windows'):
        if not WINDOWS_LOGS_SUPPORT:
            print("[!] Windows Event Log support not available", file=sys.stderr)
            return []
        return windows_logs.load_windows_logs()
    
    # Handle file paths
    if os.path.isfile(path):
        return _read_file(path, log_type)
    elif os.path.isdir(path):
        return _read_directory(path, log_type)
    
    print(f"[!] Path not found: {path}", file=sys.stderr)
    return []

def _read_file(filepath: str, log_type: str = None) -> List[Union[str, Dict[str, Any]]]:
    """
    Read a single log file, handling different formats.
    
    Args:
        filepath: Path to the log file
        log_type: Optional hint about the log format
        
    Returns:
        List of log entries (strings or dictionaries for structured logs)
    """
    filepath = str(filepath)  # Ensure string for Path objects
    
    # Handle Windows Event Logs (.evtx)
    if filepath.lower().endswith('.evtx'):
        if not WINDOWS_LOGS_SUPPORT:
            print("[!] Windows Event Log support not available", file=sys.stderr)
            return []
        return list(windows_logs.parse_evtx_file(filepath))
    
    # Handle other text-based logs
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except UnicodeDecodeError:
        # Try with different encodings for non-UTF-8 files
        try:
            with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error reading {filepath}: {str(e)}", file=sys.stderr)
            return []
    except Exception as e:
        print(f"[!] Error reading {filepath}: {str(e)}", file=sys.stderr)
        return []

def _read_directory(directory: str, log_type: str = None) -> List[Union[str, Dict[str, Any]]]:
    """
    Read all log files from a directory.
    
    Args:
        directory: Path to directory containing log files
        log_type: Optional filter for log types
        
    Returns:
        List of log entries from all files
    """
    logs = []
    
    # Define file extensions to process based on log type
    extensions = ['.log', '.txt', '.json', '.csv', '.evtx']
    
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if any(file.lower().endswith(ext) for ext in extensions):
                try:
                    file_logs = _read_file(filepath, log_type)
                    if file_logs:
                        logs.extend(file_logs)
                except Exception as e:
                    print(f"[!] Error processing {filepath}: {str(e)}", file=sys.stderr)
    
    return logs

def stream_windows_events(log_name: str = 'Security') -> Generator[Dict[str, Any], None, None]:
    """
    Stream Windows Event Logs in real-time.
    
    Args:
        log_name: Name of the Windows Event Log (e.g., 'Security', 'System')
        
    Yields:
        Normalized Windows events as they occur
    """
    if not WINDOWS_LOGS_SUPPORT:
        print("[!] Windows Event Log streaming not available", file=sys.stderr)
        return
    
    windows_logs = windows_logs.WindowsEventLogs()
    yield from windows_logs.stream_windows_events(log_name)
