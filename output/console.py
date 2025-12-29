"""
Console output handler for SOC Log Analyzer.
Provides colored, formatted output for the command line.
"""
from typing import List, Dict, Any
from rich.console import Console
from rich.table import Table
from rich import box

class ConsoleOutput:
    """Handles console output with rich formatting."""
    
    def __init__(self):
        self.console = Console()
    
    def print_detections(self, detections: List[Dict[str, Any]]) -> None:
        """Print detection results to the console.
        
        Args:
            detections: List of detection results
        """
        if not detections:
            self.console.print("[green]No security detections found.[/green]")
            return
            
        table = Table(title="Security Detections", box=box.ROUNDED)
        
        # Define columns
        table.add_column("Severity", style="cyan", no_wrap=True)
        table.add_column("Rule ID", style="magenta")
        table.add_column("Rule Name", style="white")
        table.add_column("Source", style="green")
        table.add_column("Details", style="yellow")
        
        # Add rows
        for detection in detections:
            log_entry = detection['log_entry']
            severity = detection['severity'].upper()
            
            # Color code severity
            if severity == 'CRITICAL':
                severity_style = "bold red"
            elif severity == 'HIGH':
                severity_style = "red"
            elif severity == 'MEDIUM':
                severity_style = "yellow"
            else:
                severity_style = "white"
            
            # Add row to table
            table.add_row(
                f"[{severity_style}]{severity}[/{severity_style}]",
                detection['rule_id'],
                detection['rule_name'],
                f"{log_entry.get('source', 'unknown')} ({log_entry.get('host', 'N/A')})",
                f"{log_entry.get('event_type', 'N/A')} - {log_entry.get('user', 'N/A')}@{log_entry.get('ip', 'N/A')}"
            )
        
        # Print the table
        self.console.print(table)
        self.console.print(f"\n[bold]Total detections:[/bold] {len(detections)}")
    
    def print_summary(self, stats: Dict[str, int]) -> None:
        """Print analysis summary to the console.
        
        Args:
            stats: Dictionary containing analysis statistics
        """
        self.console.print("\n[bold]Analysis Summary[/bold]")
        self.console.print("=" * 50)
        
        for key, value in stats.items():
            self.console.print(f"[cyan]{key.replace('_', ' ').title()}:[/cyan] {value}")
        
        self.console.print("=" * 50)
