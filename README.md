# SOC Log Analyzer

A powerful log analysis tool for Security Operations Centers (SOC) with built-in support for Windows Event Logs, authentication logs, web server logs, and more.

## Features

- **Windows Event Log Support**
  - Parse EVTX files and live Windows Event Logs
  - Support for Security, System, Application, and Sysmon logs
  - Real-time monitoring of Windows Event Logs
  - Automatic log type detection

- **Log Normalization**
  - Convert diverse log formats to a standard schema
  - Preserve raw log data for forensics
  - Extract key fields (IPs, users, timestamps, etc.)

- **Threat Detection**
  - Rule-based detection engine
  - Support for YAML-based detection rules
  - Built-in rules for common attack patterns

- **Flexible Output**
  - Console output with color-coded alerts
  - JSON export for further analysis
  - Summary statistics and metrics

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/soc-log-analyzer.git
   cd soc-log-analyzer
   ```

2. Create and activate a virtual environment (recommended):
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # On Windows
   # or
   source venv/bin/activate  # On Linux/Mac
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

   For Windows Event Log support, install additional dependencies:
   ```bash
   pip install python-evtx pywin32
   ```

## Usage

### Basic Usage

```bash
# Analyze logs from a file or directory
python main.py --input path/to/logs --log-type auto --console

# Export results to JSON
python main.py --input path/to/logs --output results.json
```

### Windows Event Logs

```bash
# Analyze Windows Security logs
python main.py --windows-security --console

# Analyze multiple Windows logs
python main.py --windows-security --windows-sysmon --console

# Real-time monitoring of Security logs
python main.py --windows-security --live --console

# Parse EVTX files
python main.py --input C:\Windows\System32\winevt\Logs\Security.evtx --log-type windows
```

### Advanced Options

```bash
# Use custom rules directory
python main.py --input logs/ --rules my_rules/

# Enable verbose output
python main.py --input logs/ --verbose

# Export normalized logs
python main.py --input logs/ --export-json
```

## Windows Event Log Support

The SOC Log Analyzer provides comprehensive support for Windows Event Logs:

### Supported Logs
- **Security.evtx**: Authentication, logon, and security-related events
- **System.evtx**: System events and service status
- **Application.evtx**: Application-specific events
- **Microsoft-Windows-Sysmon/Operational.evtx**: Sysmon process and network events

### Event ID Mapping
Common Windows Security Events:
- 4624: Successful logon
- 4625: Failed logon
- 4634: Account logged off
- 4648: Logon with explicit credentials
- 4672: Special privileges assigned
- 4688: Process creation
- 4697: Service installation

### Live Monitoring
Monitor Windows Event Logs in real-time with the `--live` flag. This is useful for:
- Real-time security monitoring
- Incident response
- Threat hunting

## Detection Rules

Detection rules are defined in YAML format in the `detection/rules` directory. Example rule for detecting brute force attempts:

```yaml
id: BF-001
name: Brute Force Authentication Attempt
description: Detects multiple failed login attempts from same IP
severity: high
enabled: true
type: brute_force

log_source:
  event_type: auth_failure

threshold:
  count: 5
  timeframe_minutes: 5

group_by:
  - ip

response:
  alert: true
  quarantine: false
```

## Output Formats

### Console Output
```
[+] Analysis complete!
   • Logs processed: 1,245
   • Alerts generated: 8
   • High severity: 3
   • Medium severity: 5
   • Results written to: analysis_results.json
```

### JSON Output
```json
{
  "alerts": [
    {
      "rule_id": "BF-001",
      "rule_name": "Brute Force Authentication Attempt",
      "severity": "high",
      "message": "5+ failed logins from 192.168.1.100",
      "timestamp": "2023-01-01T12:00:00Z",
      "source_ip": "192.168.1.100",
      "target_user": "admin"
    }
  ],
  "stats": {
    "total_logs": 1245,
    "total_alerts": 8,
    "alerts_by_severity": {
      "high": 3,
      "medium": 5,
      "low": 0,
      "info": 0
    }
  }
}
```

## Requirements

- Python 3.8+
- Windows 7+ (for Windows Event Log support)
- Administrator privileges (for live monitoring and some log access)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting pull requests.

## Acknowledgments

- [python-evtx](https://github.com/williballenthin/python-evtx) - For EVTX file parsing
- [pywin32](https://github.com/mhammond/pywin32) - For Windows API access
- [PyYAML](https://pyyaml.org/) - For YAML rule parsing
