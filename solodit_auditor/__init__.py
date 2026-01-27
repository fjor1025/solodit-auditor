"""
Solodit Auditor - Smart Contract Security Audit Helper
Powered by Cyfrin Solodit API

Find real vulnerabilities in your Solidity smart contracts by cross-referencing
with 50,000+ documented findings from top audit firms.
"""

from .auditor import SoloditAuditor, create_auditor, AuditReport, PotentialVulnerability
from .api_client import SoloditAPIClient, create_client, Finding, SearchResult
from .analyzer import SolidityAnalyzer, AnalysisResult, CodeMatch
from .patterns import Severity, VulnerabilityPattern, VULNERABILITY_PATTERNS

__version__ = "1.0.0"
__author__ = "Security Auditor"

__all__ = [
    # Main classes
    "SoloditAuditor",
    "SoloditAPIClient", 
    "SolidityAnalyzer",
    
    # Factory functions
    "create_auditor",
    "create_client",
    
    # Data classes
    "AuditReport",
    "PotentialVulnerability",
    "Finding",
    "SearchResult",
    "AnalysisResult",
    "CodeMatch",
    
    # Patterns
    "Severity",
    "VulnerabilityPattern",
    "VULNERABILITY_PATTERNS",
]
