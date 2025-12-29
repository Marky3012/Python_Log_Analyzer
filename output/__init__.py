"""Output module for SOC Log Analyzer."""

from .console import ConsoleOutput
from .json_writer import JSONOutput

__all__ = ['ConsoleOutput', 'JSONOutput']
