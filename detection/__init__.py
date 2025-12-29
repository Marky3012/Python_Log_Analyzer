"""Detection module for SOC Log Analyzer."""

from .rules_engine import RulesEngine, load_rules_from_dir

__all__ = ['RulesEngine', 'load_rules_from_dir']
