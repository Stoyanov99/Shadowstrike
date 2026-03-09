"""
Base module — All scan modules inherit from this.
Provides common structure: check_requirements(), run(), parse_results().
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """A single security finding."""
    title: str
    severity: Severity
    description: str
    business_impact: str = ""
    evidence: str = ""
    recommendation: str = ""
    module: str = ""
    
    @property
    def icon(self) -> str:
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🔵",
            Severity.INFO: "⚪",
        }
        return icons.get(self.severity, "⚪")


@dataclass
class ModuleResult:
    """Result from a scan module."""
    module_name: str
    success: bool
    findings: list = field(default_factory=list)
    raw_output: str = ""
    duration: float = 0.0
    error: str = ""
    data: dict = field(default_factory=dict)  # Module-specific structured data


class BaseModule(ABC):
    """Base class for all ShadowStrike modules."""
    
    name: str = "base"
    description: str = "Base module"
    icon: str = "🔧"
    
    def __init__(self, runner, target: str, output_dir: str = "results"):
        self.runner = runner
        self.target = target
        self.output_dir = output_dir
    
    @abstractmethod
    def check_requirements(self) -> bool:
        """Check if required tools are installed."""
        pass
    
    @abstractmethod
    def run(self) -> ModuleResult:
        """Execute the module scan."""
        pass
    
    def _tool_available(self, tool_name: str) -> bool:
        """Check if a specific tool is installed."""
        return self.runner.is_installed(tool_name)
