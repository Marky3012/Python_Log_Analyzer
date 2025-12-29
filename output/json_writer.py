"""
JSON output handler for SOC Log Analyzer.
Handles writing analysis results to JSON files.
"""
import json
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

class JSONOutput:
    """Handles writing analysis results to JSON files."""
    
    def __init__(self, output_file: str):
        """Initialize the JSON output handler.
        
        Args:
            output_file: Path to the output JSON file
        """
        self.output_file = output_file
        
        # Create output directory if it doesn't exist
        output_dir = Path(output_file).parent
        output_dir.mkdir(parents=True, exist_ok=True)
    
    def write_detections(self, detections: List[Dict[str, Any]]) -> None:
        """Write detection results to a JSON file.
        
        Args:
            detections: List of detection results
        """
        # Prepare output data
        output_data = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "detection_count": len(detections)
            },
            "detections": detections
        }
        
        # Write to file with pretty-printing
        with open(self.output_file, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
    
    def write_summary(self, stats: Dict[str, Any], filename: str = None) -> None:
        """Write analysis summary to a JSON file.
        
        Args:
            stats: Dictionary containing analysis statistics
            filename: Optional custom output filename
        """
        output_file = filename or self.output_file.replace('.json', '_summary.json')
        
        # Prepare summary data
        summary_data = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "analysis_summary": True
            },
            "statistics": stats
        }
        
        # Write to file with pretty-printing
        with open(output_file, 'w') as f:
            json.dump(summary_data, f, indent=2, default=str)
