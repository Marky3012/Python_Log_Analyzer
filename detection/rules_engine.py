"""
Rules engine for detecting security events in logs.
"""
import os
import yaml
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, DefaultDict
from collections import defaultdict


def load_rule(rule_path: str) -> Dict[str, Any]:
    """
    Load a single rule from a YAML file.
    
    Args:
        rule_path: Path to the rule YAML file
        
    Returns:
        Dictionary containing the rule configuration
    """
    with open(rule_path, 'r') as f:
        return yaml.safe_load(f)


def load_rules_from_dir(rules_dir: str) -> List[Dict[str, Any]]:
    """
    Load all rules from a directory.
    
    Args:
        rules_dir: Path to directory containing rule YAML files
        
    Returns:
        List of rule configurations
    """
    rules = []
    if not os.path.isdir(rules_dir):
        print(f"[!] Rules directory not found: {rules_dir}")
        return rules
        
    for filename in os.listdir(rules_dir):
        if filename.endswith(('.yaml', '.yml')):
            try:
                rule = load_rule(os.path.join(rules_dir, filename))
                rules.append(rule)
                print(f"[+] Loaded rule: {rule.get('id')} - {rule.get('name')}")
            except Exception as e:
                print(f"[!] Error loading rule from {filename}: {str(e)}")
    
    return rules


def detect_bruteforce(events: List[Dict[str, Any]], rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Detect brute force attempts based on the given rule.
    
    Args:
        events: List of normalized log events
        rule: Brute force detection rule configuration
        
    Returns:
        List of alerts generated
    """
    alerts = []
    grouped_events: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    # Filter and group events by the specified field (default: ip)
    group_field = rule.get('group_by', ['ip'])[0]
    
    for event in events:
        # Check if event matches the rule's log source criteria
        if _matches_log_source(event, rule.get('log_source', {})):
            key = event.get(group_field, 'unknown')
            grouped_events[key].append(event)
    
    # Check each group against the threshold
    for key, event_group in grouped_events.items():
        event_count = len(event_group)
        threshold = rule.get('threshold', {}).get('count', 5)
        
        if event_count >= threshold:
            # Get the most recent event for context
            latest_event = max(event_group, key=lambda x: x.get('timestamp', ''))
            
            alert = {
                'rule_id': rule['id'],
                'rule_name': rule['name'],
                'severity': rule['severity'],
                'message': rule['description'],
                'count': event_count,
                'group_field': group_field,
                'group_value': key,
                'first_seen': min(e.get('timestamp') for e in event_group),
                'last_seen': latest_event.get('timestamp'),
                'sample_event': latest_event
            }
            alerts.append(alert)
    
    return alerts


def _matches_log_source(event: Dict[str, Any], log_source: Dict[str, Any]) -> bool:
    """
    Check if an event matches the log source criteria.
    
    Args:
        event: The log event to check
        log_source: Log source criteria from the rule
        
    Returns:
        bool: True if the event matches the criteria, False otherwise
    """
    for field, expected_value in log_source.items():
        if event.get(field) != expected_value:
            return False
    return True


def run_detection(events: List[Dict[str, Any]], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Run all detection rules against the given events.
    
    Args:
        events: List of normalized log events
        rules: List of rule configurations
        
    Returns:
        List of all alerts generated
    """
    all_alerts = []
    
    for rule in rules:
        if rule.get('enabled', True):
            rule_type = rule.get('type', 'brute_force')
            
            if rule_type == 'brute_force':
                alerts = detect_bruteforce(events, rule)
                all_alerts.extend(alerts)
            # Add more rule types here as needed
    
    return all_alerts
