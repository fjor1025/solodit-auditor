"""
Main Auditor Module

Combines code analysis with Solodit API queries to identify real vulnerabilities.
"""

import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from pathlib import Path
from datetime import datetime

from .analyzer import SolidityAnalyzer, AnalysisResult, CodeMatch
from .api_client import SoloditAPIClient, Finding, SearchResult, create_client
from .patterns import Severity


@dataclass
class PotentialVulnerability:
    """Represents a potential vulnerability found in the code with supporting evidence."""
    code_match: CodeMatch
    related_findings: List[Finding]
    confidence: str  # "HIGH", "MEDIUM", "LOW"
    recommendation: str
    
    def format_for_display(self) -> str:
        """Format vulnerability for terminal display."""
        severity_colors = {
            Severity.CRITICAL: '\033[91m',  # Red
            Severity.HIGH: '\033[93m',      # Yellow
            Severity.MEDIUM: '\033[94m',    # Blue
        }
        reset = '\033[0m'
        bold = '\033[1m'
        
        color = severity_colors.get(self.code_match.severity, '')
        
        output = []
        output.append(f"\n{'#'*80}")
        output.append(f"{bold}{color}POTENTIAL VULNERABILITY: {self.code_match.pattern_name}{reset}")
        output.append(f"{'#'*80}")
        output.append(f"Severity: {color}{self.code_match.severity.value}{reset}")
        output.append(f"Confidence: {self.confidence}")
        
        if self.code_match.file_path:
            output.append(f"File: {self.code_match.file_path}")
        output.append(f"Line: {self.code_match.line_number}")
        
        if self.code_match.function_name:
            output.append(f"Function: {self.code_match.function_name}()")
        
        output.append(f"\n{bold}Vulnerable Code:{reset}")
        output.append("-" * 40)
        
        # Show context
        for line in self.code_match.context_before:
            output.append(f"  {line}")
        output.append(f"{color}→ {self.code_match.line_content}{reset}")  # Highlight the vulnerable line
        for line in self.code_match.context_after:
            output.append(f"  {line}")
        
        output.append("-" * 40)
        
        output.append(f"\n{bold}Recommendation:{reset}")
        output.append(self.recommendation)
        
        if self.related_findings:
            output.append(f"\n{bold}Similar Real-World Vulnerabilities ({len(self.related_findings)} found):{reset}")
            for i, finding in enumerate(self.related_findings[:3], 1):
                output.append(f"\n  {i}. [{finding.impact}] {finding.title}")
                output.append(f"     Firm: {finding.firm_name} | Protocol: {finding.protocol_name}")
                output.append(f"     Quality: {finding.quality_score:.1f}/5")
                if finding.summary:
                    summary = finding.summary[:200] + "..." if len(finding.summary) > 200 else finding.summary
                    output.append(f"     Summary: {summary}")
                output.append(f"     🔗 {finding.url}")
        
        return '\n'.join(output)
    
    def to_markdown(self) -> str:
        """Convert to markdown format for reports."""
        md = []
        md.append(f"## 🔴 {self.code_match.pattern_name}")
        md.append("")
        md.append(f"**Severity:** {self.code_match.severity.value}")
        md.append(f"**Confidence:** {self.confidence}")
        
        if self.code_match.file_path:
            md.append(f"**File:** `{self.code_match.file_path}`")
        md.append(f"**Line:** {self.code_match.line_number}")
        
        if self.code_match.function_name:
            md.append(f"**Function:** `{self.code_match.function_name}()`")
        
        md.append("")
        md.append("### Vulnerable Code")
        md.append("```solidity")
        for line in self.code_match.context_before:
            md.append(line)
        md.append(f"// >>> VULNERABILITY BELOW <<<")
        md.append(self.code_match.line_content)
        for line in self.code_match.context_after:
            md.append(line)
        md.append("```")
        
        md.append("")
        md.append("### Recommendation")
        md.append(self.recommendation)
        
        if self.related_findings:
            md.append("")
            md.append(f"### Similar Real-World Vulnerabilities ({len(self.related_findings)} found)")
            for finding in self.related_findings[:3]:
                md.append("")
                md.append(finding.to_markdown())
        
        return '\n'.join(md)


@dataclass
class AuditReport:
    """Complete audit report with all findings."""
    target: str
    timestamp: datetime
    vulnerabilities: List[PotentialVulnerability] = field(default_factory=list)
    total_files_analyzed: int = 0
    total_lines_analyzed: int = 0
    
    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.code_match.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.code_match.severity == Severity.HIGH)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.code_match.severity == Severity.MEDIUM)
    
    def format_summary(self) -> str:
        """Format summary for display."""
        output = []
        output.append("\n" + "=" * 80)
        output.append("AUDIT SUMMARY")
        output.append("=" * 80)
        output.append(f"Target: {self.target}")
        output.append(f"Date: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        output.append(f"Files Analyzed: {self.total_files_analyzed}")
        output.append(f"Lines Analyzed: {self.total_lines_analyzed}")
        output.append("")
        output.append("FINDINGS:")
        output.append(f"  🔴 CRITICAL: {self.critical_count}")
        output.append(f"  🟠 HIGH: {self.high_count}")
        output.append(f"  🟡 MEDIUM: {self.medium_count}")
        output.append(f"  📊 TOTAL: {len(self.vulnerabilities)}")
        output.append("=" * 80)
        
        return '\n'.join(output)
    
    def to_markdown(self) -> str:
        """Generate full markdown report."""
        md = []
        md.append("# Smart Contract Security Audit Report")
        md.append("")
        md.append(f"**Target:** {self.target}")
        md.append(f"**Date:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**Powered by:** Solodit API (Cyfrin)")
        md.append("")
        md.append("## Summary")
        md.append("")
        md.append("| Severity | Count |")
        md.append("|----------|-------|")
        md.append(f"| 🔴 Critical | {self.critical_count} |")
        md.append(f"| 🟠 High | {self.high_count} |")
        md.append(f"| 🟡 Medium | {self.medium_count} |")
        md.append(f"| **Total** | **{len(self.vulnerabilities)}** |")
        md.append("")
        md.append(f"Files analyzed: {self.total_files_analyzed}")
        md.append(f"Lines analyzed: {self.total_lines_analyzed}")
        md.append("")
        md.append("---")
        md.append("")
        md.append("## Detailed Findings")
        
        # Sort by severity
        sorted_vulns = sorted(
            self.vulnerabilities,
            key=lambda v: (
                {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}[v.code_match.severity],
                -len(v.related_findings)
            )
        )
        
        for vuln in sorted_vulns:
            md.append("")
            md.append(vuln.to_markdown())
            md.append("")
            md.append("---")
        
        return '\n'.join(md)
    
    def to_json(self) -> str:
        """Export report as JSON."""
        data = {
            "target": self.target,
            "timestamp": self.timestamp.isoformat(),
            "summary": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "total": len(self.vulnerabilities)
            },
            "files_analyzed": self.total_files_analyzed,
            "lines_analyzed": self.total_lines_analyzed,
            "vulnerabilities": []
        }
        
        for vuln in self.vulnerabilities:
            vuln_data = {
                "pattern": vuln.code_match.pattern_name,
                "severity": vuln.code_match.severity.value,
                "confidence": vuln.confidence,
                "file": vuln.code_match.file_path,
                "line": vuln.code_match.line_number,
                "function": vuln.code_match.function_name,
                "code": vuln.code_match.line_content,
                "recommendation": vuln.recommendation,
                "related_findings": [
                    {
                        "title": f.title,
                        "impact": f.impact,
                        "firm": f.firm_name,
                        "url": f.url
                    }
                    for f in vuln.related_findings[:3]
                ]
            }
            data["vulnerabilities"].append(vuln_data)
        
        return json.dumps(data, indent=2)


class SoloditAuditor:
    """
    Main auditor class that combines static analysis with Solodit intelligence.
    """
    
    # Recommendations for each vulnerability pattern
    RECOMMENDATIONS = {
        "reentrancy": "Apply the Checks-Effects-Interactions (CEI) pattern. Update state BEFORE external calls. Consider using OpenZeppelin's ReentrancyGuard modifier.",
        "delegatecall_injection": "Never delegatecall to untrusted addresses. Use EIP-1967 storage slots for proxy patterns. Validate implementation addresses.",
        "unprotected_selfdestruct": "Remove selfdestruct if not needed. Add strict access controls (onlyOwner + timelock) if required.",
        "arbitrary_external_call": "Validate target addresses against a whitelist. Sanitize calldata. Consider using specific interfaces instead of raw calls.",
        "access_control": "Implement role-based access control (OpenZeppelin AccessControl). Use modifiers consistently. Consider timelocks for sensitive operations.",
        "oracle_manipulation": "Use TWAP oracles instead of spot prices. Add staleness checks for Chainlink. Implement price deviation bounds.",
        "flash_loan_vulnerability": "Validate state consistency in callbacks. Use access controls on callback functions. Consider flash loan-resistant pricing.",
        "signature_replay": "Include nonces, chain ID, and contract address in signed messages. Use EIP-712 typed data. Increment nonces after use.",
        "unchecked_return_value": "Always check return values. Use SafeERC20 for token transfers. Revert on failure.",
        "frontrunning": "Implement commit-reveal schemes. Add slippage protection with minimum output amounts. Use private mempools for sensitive transactions.",
        "integer_overflow": "Use Solidity 0.8+ with built-in overflow checks. Be cautious with unchecked blocks. Validate inputs.",
        "dos_gas_limit": "Implement pull-over-push patterns. Add pagination for loops. Set upper bounds on array sizes.",
        "timestamp_dependence": "Avoid using block.timestamp for critical logic. Use block numbers with sufficient buffer. Consider Chainlink Keepers.",
        "unsafe_erc20": "Use OpenZeppelin's SafeERC20 library. Handle non-standard tokens (USDT, etc.). Check for fee-on-transfer tokens.",
        "centralization_risk": "Implement multi-sig requirements. Add timelocks for admin functions. Consider progressive decentralization.",
        "missing_zero_address_check": "Add require(address != address(0)) checks in constructors and setters. Use custom errors for gas efficiency.",
        "reentrancy_readonly": "Be aware of read-only reentrancy in cross-contract calls. Cache values before external calls. Use reentrancy locks across related contracts.",
        "precision_loss": "Multiply before dividing. Use sufficient decimal precision. Consider fixed-point math libraries.",
        "storage_collision": "Use EIP-1967 storage slots. Maintain __gap arrays in upgradeable contracts. Test storage layouts.",
        "cross_chain": "Validate source chain and sender. Implement replay protection. Use established bridges (LayerZero, CCIP).",
        "erc721_erc1155_callback": "Apply reentrancy guards on mint/transfer functions. Update state before safe transfers.",
        "permit_dos": "Don't rely solely on permit for allowance. Implement fallback with regular approve. Handle permit failures gracefully.",
        "first_deposit_inflation": "Mint initial shares to zero address or use virtual shares. Set minimum deposit amounts. Consider ERC4626 best practices.",
    }
    
    def __init__(
        self,
        api_key: Optional[str] = None,
        include_medium: bool = True,
        enable_cache: bool = True,
        min_quality: int = 3
    ):
        """
        Initialize the auditor.
        
        Args:
            api_key: Solodit API key
            include_medium: Whether to include MEDIUM severity findings
            enable_cache: Cache API results
            min_quality: Minimum quality score for findings
        """
        self.analyzer = SolidityAnalyzer(include_medium=include_medium)
        self.client = create_client(api_key=api_key, enable_cache=enable_cache)
        self.min_quality = min_quality
        self.include_medium = include_medium
    
    def audit_code(self, code: str, target_name: str = "code snippet") -> AuditReport:
        """
        Audit a code snippet.
        
        Args:
            code: Solidity source code
            target_name: Name for the report
            
        Returns:
            AuditReport with findings
        """
        report = AuditReport(
            target=target_name,
            timestamp=datetime.now(),
            total_files_analyzed=1,
            total_lines_analyzed=len(code.split('\n'))
        )
        
        # Analyze code
        analysis = self.analyzer.analyze_code(code)
        
        # Query Solodit for each unique pattern found
        report.vulnerabilities = self._enrich_with_findings(analysis)
        
        return report
    
    def audit_file(self, file_path: str) -> AuditReport:
        """
        Audit a single Solidity file.
        
        Args:
            file_path: Path to the .sol file
            
        Returns:
            AuditReport with findings
        """
        path = Path(file_path)
        code = path.read_text(encoding='utf-8')
        
        report = self.audit_code(code, target_name=str(path.name))
        report.target = str(path.absolute())
        
        return report
    
    def audit_directory(self, dir_path: str, recursive: bool = True) -> AuditReport:
        """
        Audit all Solidity files in a directory.
        
        Args:
            dir_path: Path to directory
            recursive: Search subdirectories
            
        Returns:
            Combined AuditReport
        """
        report = AuditReport(
            target=dir_path,
            timestamp=datetime.now()
        )
        
        # Analyze all files
        analyses = self.analyzer.analyze_directory(dir_path, recursive=recursive)
        
        total_lines = 0
        for analysis in analyses:
            if analysis.file_path:
                try:
                    lines = Path(analysis.file_path).read_text().count('\n')
                    total_lines += lines
                except:
                    pass
            
            vulns = self._enrich_with_findings(analysis)
            report.vulnerabilities.extend(vulns)
        
        report.total_files_analyzed = len(analyses)
        report.total_lines_analyzed = total_lines
        
        return report
    
    def _enrich_with_findings(self, analysis: AnalysisResult) -> List[PotentialVulnerability]:
        """Query Solodit API to enrich code matches with real findings."""
        vulnerabilities = []
        
        # Group matches by pattern to reduce API calls
        pattern_matches: Dict[str, List[CodeMatch]] = {}
        for match in analysis.matches:
            if match.pattern_name not in pattern_matches:
                pattern_matches[match.pattern_name] = []
            pattern_matches[match.pattern_name].append(match)
        
        # Query API for each pattern
        pattern_findings: Dict[str, List[Finding]] = {}
        
        for pattern_name, matches in pattern_matches.items():
            if pattern_name in pattern_findings:
                continue
            
            # Use the first match's keywords and tags
            match = matches[0]
            
            try:
                result = self.client.search_by_pattern(
                    pattern_name=pattern_name,
                    keywords=match.keywords,
                    tags=match.solodit_tags,
                    severity=match.severity,
                    page_size=5
                )
                pattern_findings[pattern_name] = result.findings
                
                print(f"  📡 Found {result.total_results} Solodit findings for '{pattern_name}'")
                
            except Exception as e:
                print(f"  ⚠️  API error for '{pattern_name}': {e}")
                pattern_findings[pattern_name] = []
        
        # Create vulnerability entries
        for match in analysis.matches:
            findings = pattern_findings.get(match.pattern_name, [])
            
            # Determine confidence based on findings
            if len(findings) >= 3 and any(f.quality_score >= 4 for f in findings):
                confidence = "HIGH"
            elif len(findings) >= 1:
                confidence = "MEDIUM"
            else:
                confidence = "LOW"
            
            recommendation = self.RECOMMENDATIONS.get(
                match.pattern_name,
                "Review the code for potential security issues. Consult the related findings for mitigation strategies."
            )
            
            vuln = PotentialVulnerability(
                code_match=match,
                related_findings=findings,
                confidence=confidence,
                recommendation=recommendation
            )
            
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def quick_search(self, query: str, page_size: int = 10) -> SearchResult:
        """
        Quick search for findings without code analysis.
        
        Args:
            query: Search query (e.g., "reentrancy withdraw")
            page_size: Number of results
            
        Returns:
            SearchResult
        """
        impact = ["CRITICAL", "HIGH"]
        if self.include_medium:
            impact.append("MEDIUM")
        
        return self.client.search(
            keywords=query,
            impact=impact,
            min_quality=self.min_quality,
            page_size=page_size,
            sort_by="Quality"
        )


def create_auditor(
    api_key: Optional[str] = None,
    include_medium: bool = True,
    enable_cache: bool = True
) -> SoloditAuditor:
    """
    Factory function to create an auditor instance.
    
    Args:
        api_key: Solodit API key (or set SOLODIT_API_KEY env var)
        include_medium: Include MEDIUM severity findings
        enable_cache: Cache API results
        
    Returns:
        Configured SoloditAuditor
    """
    return SoloditAuditor(
        api_key=api_key,
        include_medium=include_medium,
        enable_cache=enable_cache
    )
