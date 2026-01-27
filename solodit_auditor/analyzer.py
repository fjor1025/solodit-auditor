"""
Solidity Code Analyzer

Extracts vulnerability patterns and suspicious code segments from Solidity files.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Set, Tuple, Optional
from pathlib import Path
from .patterns import VULNERABILITY_PATTERNS, VulnerabilityPattern, Severity


@dataclass
class CodeMatch:
    """Represents a matched vulnerability pattern in code."""
    pattern_name: str
    line_number: int
    line_content: str
    context_before: List[str]
    context_after: List[str]
    severity: Severity
    keywords: List[str]
    solodit_tags: List[str]
    file_path: Optional[str] = None
    function_name: Optional[str] = None


@dataclass
class AnalysisResult:
    """Complete analysis result for a Solidity file or snippet."""
    file_path: Optional[str]
    matches: List[CodeMatch] = field(default_factory=list)
    extracted_keywords: Set[str] = field(default_factory=set)
    function_signatures: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    contract_names: List[str] = field(default_factory=list)
    
    def get_search_queries(self) -> List[Dict]:
        """Generate optimized search queries for Solodit API."""
        queries = []
        
        # Group matches by pattern for consolidated queries
        pattern_groups: Dict[str, List[CodeMatch]] = {}
        for match in self.matches:
            if match.pattern_name not in pattern_groups:
                pattern_groups[match.pattern_name] = []
            pattern_groups[match.pattern_name].append(match)
        
        for pattern_name, matches in pattern_groups.items():
            # Collect all keywords and tags from this pattern group
            all_keywords = set()
            all_tags = set()
            severities = set()
            
            for m in matches:
                all_keywords.update(m.keywords)
                all_tags.update(m.solodit_tags)
                severities.add(m.severity)
            
            # Determine the highest severity
            if Severity.CRITICAL in severities:
                severity = Severity.CRITICAL
            elif Severity.HIGH in severities:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM
            
            queries.append({
                "pattern_name": pattern_name,
                "keywords": list(all_keywords)[:5],  # Limit keywords
                "tags": list(all_tags),
                "severity": severity,
                "match_count": len(matches),
                "sample_lines": [m.line_content.strip() for m in matches[:3]]
            })
        
        return queries


class SolidityAnalyzer:
    """Analyzes Solidity code for vulnerability patterns."""
    
    # Patterns to skip for Solidity 0.8+ (built-in overflow protection)
    SKIP_FOR_SOLIDITY_08 = {'integer_overflow'}
    
    # Patterns that generate too many false positives
    DISABLED_PATTERNS = {'missing_zero_address_check'}
    
    def __init__(self, include_medium: bool = True):
        """
        Initialize analyzer.
        
        Args:
            include_medium: Whether to include MEDIUM severity patterns
        """
        self.patterns = VULNERABILITY_PATTERNS
        self.include_medium = include_medium
        
        # Pre-compile all regex patterns
        self._compiled_patterns: Dict[str, List[re.Pattern]] = {}
        for name, pattern in self.patterns.items():
            self._compiled_patterns[name] = pattern.compile_patterns()
    
    def _detect_solidity_version(self, code: str) -> Optional[Tuple[int, int]]:
        """Detect Solidity version from pragma statement."""
        pragma_match = re.search(r'pragma\s+solidity\s*[\^>=<]*\s*(\d+)\.(\d+)', code)
        if pragma_match:
            return (int(pragma_match.group(1)), int(pragma_match.group(2)))
        return None
    
    def _is_solidity_08_plus(self, code: str) -> bool:
        """Check if code uses Solidity 0.8.0 or higher."""
        version = self._detect_solidity_version(code)
        if version:
            major, minor = version
            return major >= 1 or (major == 0 and minor >= 8)
        return False
    
    def analyze_code(self, code: str, file_path: Optional[str] = None) -> AnalysisResult:
        """
        Analyze Solidity code for vulnerability patterns.
        
        Args:
            code: Solidity source code
            file_path: Optional path to the source file
            
        Returns:
            AnalysisResult with all findings
        """
        result = AnalysisResult(file_path=file_path)
        lines = code.split('\n')
        
        # Extract metadata
        result.contract_names = self._extract_contracts(code)
        result.imports = self._extract_imports(code)
        result.function_signatures = self._extract_functions(code)
        
        # Detect Solidity version for smart pattern filtering
        is_solidity_08 = self._is_solidity_08_plus(code)
        
        # Find current function for each line
        function_map = self._build_function_map(code)
        
        # Scan for vulnerability patterns
        for pattern_name, vuln_pattern in self.patterns.items():
            # Skip disabled patterns (e.g., zero address check)
            if pattern_name in self.DISABLED_PATTERNS:
                continue
            
            # Skip overflow checks for Solidity 0.8+ (built-in protection)
            if is_solidity_08 and pattern_name in self.SKIP_FOR_SOLIDITY_08:
                continue
            
            # Skip MEDIUM if not included
            if not self.include_medium and vuln_pattern.severity_hint == Severity.MEDIUM:
                continue
            
            for compiled_regex in self._compiled_patterns[pattern_name]:
                for match in compiled_regex.finditer(code):
                    # Find line number
                    line_num = code[:match.start()].count('\n') + 1
                    
                    # Get context
                    context_before = lines[max(0, line_num-4):line_num-1]
                    context_after = lines[line_num:min(len(lines), line_num+3)]
                    
                    # Find which function this is in
                    func_name = function_map.get(line_num)
                    
                    code_match = CodeMatch(
                        pattern_name=pattern_name,
                        line_number=line_num,
                        line_content=lines[line_num-1] if line_num <= len(lines) else "",
                        context_before=context_before,
                        context_after=context_after,
                        severity=vuln_pattern.severity_hint,
                        keywords=vuln_pattern.keywords,
                        solodit_tags=vuln_pattern.solodit_tags,
                        file_path=file_path,
                        function_name=func_name
                    )
                    
                    result.matches.append(code_match)
                    result.extracted_keywords.update(vuln_pattern.keywords)
        
        # Deduplicate matches on same line
        result.matches = self._deduplicate_matches(result.matches)
        
        return result
    
    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Analyze a Solidity file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        code = path.read_text(encoding='utf-8')
        return self.analyze_code(code, file_path=str(path.absolute()))
    
    def analyze_directory(self, dir_path: str, recursive: bool = True) -> List[AnalysisResult]:
        """Analyze all Solidity files in a directory."""
        path = Path(dir_path)
        if not path.exists():
            raise FileNotFoundError(f"Directory not found: {dir_path}")
        
        results = []
        pattern = "**/*.sol" if recursive else "*.sol"
        
        for sol_file in path.glob(pattern):
            # Skip common non-source directories
            if any(skip in str(sol_file) for skip in ['node_modules', 'lib/', 'test/', 'mock', 'Mock']):
                continue
            
            try:
                result = self.analyze_file(str(sol_file))
                if result.matches:  # Only include files with findings
                    results.append(result)
            except Exception as e:
                print(f"Warning: Failed to analyze {sol_file}: {e}")
        
        return results
    
    def _extract_contracts(self, code: str) -> List[str]:
        """Extract contract/interface/library names."""
        pattern = r'(?:contract|interface|library|abstract\s+contract)\s+(\w+)'
        return re.findall(pattern, code)
    
    def _extract_imports(self, code: str) -> List[str]:
        """Extract import statements."""
        pattern = r'import\s+["\']([^"\']+)["\']'
        return re.findall(pattern, code)
    
    def _extract_functions(self, code: str) -> List[str]:
        """Extract function signatures."""
        pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(?:public|external|internal|private)?[^{]*'
        return re.findall(pattern, code)
    
    def _build_function_map(self, code: str) -> Dict[int, str]:
        """Build a map of line numbers to function names."""
        func_map = {}
        current_func = None
        brace_count = 0
        in_function = False
        
        lines = code.split('\n')
        func_pattern = re.compile(r'function\s+(\w+)')
        
        for i, line in enumerate(lines, 1):
            # Check for function start
            func_match = func_pattern.search(line)
            if func_match and not in_function:
                current_func = func_match.group(1)
                in_function = True
                brace_count = 0
            
            # Track braces
            if in_function:
                brace_count += line.count('{') - line.count('}')
                func_map[i] = current_func
                
                if brace_count <= 0 and '{' in code[:sum(len(l)+1 for l in lines[:i])]:
                    in_function = False
                    current_func = None
        
        return func_map
    
    def _deduplicate_matches(self, matches: List[CodeMatch]) -> List[CodeMatch]:
        """Remove duplicate matches - one per pattern per function."""
        seen = set()
        unique = []
        
        for match in matches:
            # Deduplicate by function + pattern (only one finding per pattern per function)
            # This reduces noise significantly
            func_key = match.function_name or f"global_{match.file_path}"
            key = (func_key, match.pattern_name)
            if key not in seen:
                seen.add(key)
                unique.append(match)
        
        # Sort by severity (CRITICAL first), then line number
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        unique.sort(key=lambda m: (severity_order[m.severity], m.line_number))
        
        return unique


def quick_analyze(code: str) -> Tuple[List[str], List[str]]:
    """
    Quick analysis returning keywords and tags for API query.
    
    Returns:
        Tuple of (keywords, tags)
    """
    analyzer = SolidityAnalyzer()
    result = analyzer.analyze_code(code)
    
    keywords = list(result.extracted_keywords)
    tags = []
    for match in result.matches:
        tags.extend(match.solodit_tags)
    
    return keywords, list(set(tags))
