"""
SOC Log Analyzer - A tool for analyzing security logs and detecting potential threats.
Supports Windows Event Logs, text logs, and other common log formats.
"""
import argparse
import json
import sys
import os
import platform
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from datetime import datetime

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent.absolute()))

from ingest.file_loader import load_logs, stream_windows_events
from normalize.schema import normalize_log
from detection.rules_engine import load_rules_from_dir, run_detection
from output.console import ConsoleOutput
from output.json_writer import JSONOutput

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="""
    SOC Log Analyzer - A tool for analyzing security logs and detecting potential threats.
    Supports Windows Event Logs, text logs, and other common log formats.
    """, formatter_class=argparse.RawDescriptionHelpFormatter)
    
    # Input source arguments
    input_group = parser.add_argument_group('Input Options')
    input_group.add_argument(
        "--input", 
        default="auto",
        help="Input file, directory, or 'auto' for automatic detection (default: auto)"
    )
    
    # Windows-specific arguments
    windows_group = parser.add_argument_group('Windows Event Log Options')
    windows_group.add_argument(
        "--windows-security",
        action="store_true",
        help="Analyze Windows Security logs"
    )
    windows_group.add_argument(
        "--windows-system",
        action="store_true",
        help="Analyze Windows System logs"
    )
    windows_group.add_argument(
        "--windows-application",
        action="store_true",
        help="Analyze Windows Application logs"
    )
    windows_group.add_argument(
        "--windows-sysmon",
        action="store_true",
        help="Analyze Windows Sysmon logs"
    )
    windows_group.add_argument(
        "--live",
        action="store_true",
        help="Monitor Windows Event Logs in real-time"
    )
    
    # Analysis options
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument(
        "--log-type", 
        default="auto",
        choices=["auto", "windows", "auth", "web", "firewall", "syslog"],
        help="Type of logs being analyzed (default: auto-detect)"
    )
    analysis_group.add_argument(
        "--rules", 
        default="detection/rules",
        help="Directory containing detection rules (YAML files)"
    )
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        "--output", 
        default="analysis_results.json",
        help="Output file for JSON results (default: analysis_results.json)"
    )
    output_group.add_argument(
        "--export-json",
        action="store_true",
        help="Export normalized logs to JSON format"
    )
    output_group.add_argument(
        "--console", 
        action="store_true",
        help="Display results in the console"
    )
    output_group.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser.parse_args()

def detect_log_type(filepath: str, content: str = "") -> str:
    """
    Attempt to detect the log type based on filename and content.
    
    Args:
        filepath: Path to the log file
        content: Optional content of the log file for more accurate detection
        
    Returns:
        Detected log type as a string
    """
    filename = str(filepath).lower()
    
    # Windows Event Log detection
    if filename.endswith('.evtx') or 'windows' in filename or 'event' in filename:
        return 'windows'
    
    # Check file content for additional hints
    if not content and os.path.isfile(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(4096)  # Read first 4KB for analysis
        except Exception:
            content = ""
    
    # Content-based detection
    content = content.lower()
    if any(x in content for x in ['failed password', 'accepted password']):
        return 'auth'
    elif any(x in content for x in ['http', 'https', 'get /', 'post /']):
        return 'web'
    elif any(x in content for x in ['drop', 'block', 'allow', 'accept', 'deny']):
        return 'firewall'
    
    # Filename-based detection
    if any(x in filename for x in ['auth', 'login', 'secure']):
        return 'auth'
    elif any(x in filename for x in ['access', 'web', 'http', 'nginx', 'apache']):
        return 'web'
    elif any(x in filename for x in ['firewall', 'fw', 'iptables', 'ufw']):
        return 'firewall'
    elif any(x in filename for x in ['syslog', 'messages']):
        return 'syslog'
    
    return 'unknown'

def analyze_logs(logs: List[Union[str, Dict[str, Any]]], log_type: str, rules: List[Dict[str, Any]], 
                verbose: bool = False) -> Dict[str, Any]:
    """
    Analyze logs using the provided detection rules.
    
    Args:
        logs: List of log entries (strings or pre-parsed dictionaries)
        log_type: Type of logs being analyzed
        rules: List of detection rules
        verbose: Enable verbose output
        
    Returns:
        Dictionary containing analysis results
    """
    if not logs:
        print("[!] No logs to analyze")
        return {"alerts": [], "stats": {}, "normalized_logs": []}
    
    # Normalize logs (skip if already in normalized format)
    print("[*] Processing log entries...")
    normalized_logs = []
    
    for log in logs:
        try:
            if isinstance(log, dict) and 'event_type' in log:
                # Already normalized
                normalized_logs.append(log)
            else:
                # Need to normalize
                normalized = normalize_log(str(log), log_type)
                if normalized:
                    normalized_logs.append(normalized)
        except Exception as e:
            if verbose:
                print(f"[!] Error normalizing log entry: {str(e)}")
    
    if not normalized_logs:
        print("[!] No valid log entries found after normalization")
        return {"alerts": [], "stats": {}, "normalized_logs": []}
    
    print(f"[+] Processed {len(normalized_logs)} log entries")
    
    # Run detection rules
    print("[*] Running detection rules...")
    alerts = run_detection(normalized_logs, rules)
    
    # Calculate statistics
    stats = {
        "total_logs": len(normalized_logs),
        "total_alerts": len(alerts),
        "log_type": log_type,
        "alerts_by_severity": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        },
        "alerts_by_rule": {},
        "event_types": {}
    }
    
    # Process alerts and gather statistics
    for alert in alerts:
        severity = alert.get("severity", "medium").lower()
        rule_id = alert.get("rule_id", "unknown")
        
        # Update severity counts
        if severity in stats["alerts_by_severity"]:
            stats["alerts_by_severity"][severity] += 1
        
        # Update rule-based counts
        if rule_id not in stats["alerts_by_rule"]:
            stats["alerts_by_rule"][rule_id] = 0
        stats["alerts_by_rule"][rule_id] += 1
    
    # Count event types
    for log in normalized_logs:
        event_type = log.get('event_type', 'unknown')
        if event_type not in stats["event_types"]:
            stats["event_types"][event_type] = 0
        stats["event_types"][event_type] += 1
    
    return {
        "alerts": alerts,
        "stats": stats,
        "normalized_logs": normalized_logs[:1000] if len(normalized_logs) <= 1000 else []
    }

def process_windows_logs(args) -> Dict[str, Any]:
    """Process Windows Event Logs based on command-line arguments."""
    from ingest.windows_logs import WindowsEventLogs
    
    windows_logs = WindowsEventLogs()
    all_events = []
    
    # Determine which logs to process
    logs_to_process = []
    if args.windows_security or not any([args.windows_security, args.windows_system, 
                                       args.windows_application, args.windows_sysmon]):
        logs_to_process.append('Security')
    if args.windows_system:
        logs_to_process.append('System')
    if args.windows_application:
        logs_to_process.append('Application')
    if args.windows_sysmon:
        logs_to_process.append('Microsoft-Windows-Sysmon/Operational')
    
    print(f"[+] Processing Windows Event Logs: {', '.join(logs_to_process)}")
    
    # Load logs from each source
    for log_name in logs_to_process:
        try:
            if args.live:
                print(f"[+] Starting live monitoring of {log_name} log...")
                # For live monitoring, we'll handle it differently
                return {"live_mode": True, "log_name": log_name}
            else:
                print(f"[+] Loading {log_name} events...")
                events = list(windows_logs.parse_evtx_file(
                    f"C:\\Windows\\System32\\winevt\\Logs\\{log_name}.evtx"
                ))
                all_events.extend(events)
                print(f"    • Loaded {len(events)} events from {log_name}")
        except Exception as e:
            print(f"[!] Error processing {log_name}: {str(e)}")
    
    return {"events": all_events, "log_type": "windows"}

def main():
    """Main entry point for the SOC Log Analyzer."""
    args = parse_arguments()
    
    # Initialize output handlers
    console = ConsoleOutput(verbose=args.verbose)
    json_output = JSONOutput(args.output)
    
    try:
        # Handle Windows Event Logs
        if args.log_type == 'windows' or any([args.windows_security, args.windows_system, 
                                            args.windows_application, args.windows_sysmon]):
            windows_data = process_windows_logs(args)
            
            if windows_data.get('live_mode'):
                # Handle live monitoring
                print("\n[+] Starting live monitoring mode (press Ctrl+C to stop)...")
                try:
                    for event in stream_windows_events(windows_data['log_name']):
                        # Here you could add real-time alerting
                        if args.console:
                            console.print_event(event)
                        if args.export_json:
                            json_output.write_event(event)
                except KeyboardInterrupt:
                    print("\n[!] Monitoring stopped by user")
                return
            
            logs = windows_data.get('events', [])
            log_type = 'windows'
        else:
            # Handle file-based logs
            print(f"[+] Loading logs from: {args.input}")
            logs = load_logs(args.input, args.log_type)
            
            if not logs:
                print("[!] No logs found in the specified path.")
                return
            
            # Detect log type if auto
            log_type = args.log_type
            if log_type == "auto":
                log_type = detect_log_type(args.input, str(logs[:5]))
                print(f"[i] Auto-detected log type: {log_type}")
        
        if not logs:
            print("[!] No log entries to process.")
            return
            
        print(f"[+] Loaded {len(logs)} log entries")
        
        # Load detection rules
        print(f"[+] Loading detection rules from: {args.rules}")
        rules = load_rules_from_dir(args.rules)
        
        if not rules:
            print("[!] No rules loaded. Please check the rules directory.")
            return
            
        print(f"[+] Loaded {len(rules)} detection rules")
        
        # Analyze logs
        print("[+] Analyzing logs...")
        results = analyze_logs(logs, log_type, rules, args.verbose)
        
        # Output results
        if args.console:
            console.print_detections(results["alerts"])
            console.print_summary(results["stats"])
        
        # Write JSON output
        if args.export_json or args.output:
            json_output.write_detections(results["alerts"])
            json_output.write_summary(results["stats"])
        
        # Print summary
        print("\n[+] Analysis complete!")
        print(f"   • Logs processed: {results['stats']['total_logs']}")
        print(f"   • Alerts generated: {results['stats']['total_alerts']}")
        if args.output:
            print(f"   • Results written to: {args.output}")
        
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {str(e)}", file=sys.stderr)
        if args.verbose and hasattr(e, '__traceback__'):
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()