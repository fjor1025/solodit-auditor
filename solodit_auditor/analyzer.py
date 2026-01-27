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
    DISABLED_PATTERNS = {
        'missing_zero_address_check',  # Too noisy, most code handles this
        'access_control',  # Flags functions that already have checks
        'centralization_risk',  # Informational, not actual vulnerabilities
        'timestamp_dependence',  # Too common, low-risk in most cases
        'unchecked_return_value',  # Can't distinguish checked vs unchecked
        'precision_loss',  # Too many false positives
    }
    
    # Patterns to validate with context (only report if context looks suspicious)
    CONTEXT_SENSITIVE_PATTERNS = {
        'dos_gas_limit', 
        'delegatecall_injection',
        'reentrancy',
        'cross_chain',
        'unsafe_erc20',
    }
    
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
                    
                    # Context-sensitive validation to reduce false positives
                    if pattern_name in self.CONTEXT_SENSITIVE_PATTERNS:
                        if not self._validate_pattern_context(pattern_name, lines[line_num-1] if line_num <= len(lines) else "", context_before, context_after):
                            continue
                    
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
    
    def _validate_pattern_context(self, pattern_name: str, line: str, context_before: List[str], context_after: List[str]) -> bool:
        """
        Validate if a pattern match is likely a true positive based on context.
        Returns False for likely false positives.
        """
        full_context = '\n'.join(context_before) + '\n' + line + '\n' + '\n'.join(context_after)
        
        if pattern_name == 'dos_gas_limit':
            # Skip byte-copy loops (payload[i] = data[i]) - these are bounded by calldata
            if re.search(r'payload\[\w+\]\s*=\s*data\[', full_context):
                return False
            # Skip loops with clear bounds from function parameters (bounded by calldata)
            if 'SELECTOR_DATA_LENGTH' in full_context or 'data.length' in full_context:
                if re.search(r'\w+\[\w+\]\s*=\s*\w+\[\w+\s*\+', full_context):
                    return False
            # Skip if there's an explicit length check nearby
            if re.search(r'require.*\.length\s*(<|<=|>)', full_context):
                return False
            # Skip loops over function parameters (bounded by calldata)
            if re.search(r'for.*targets\.length|for.*selectors\.length|for.*callDatas\.length', full_context):
                return False
            return True
        
        if pattern_name == 'delegatecall_injection':
            # Skip if target comes from trusted storage (bridgeParams, verifier, etc.)
            if re.search(r'(bridgeParams|verifier|implementation|_implementation)\.\w+\.delegatecall', full_context):
                return False
            # Skip if it's clearly a proxy pattern
            if 'EIP1967' in full_context or 'IMPLEMENTATION_SLOT' in full_context:
                return False
            # Only flag if target appears to be user-controlled
            if re.search(r'delegatecall.*\(\s*\w+\s*\)', full_context):
                # Check for any validation
                if not re.search(r'(require|if|mapping|onlyOwner|onlyAdmin)', full_context):
                    return True
            return False  # Default: don't report delegatecall (too many false positives)
        
        if pattern_name == 'reentrancy':
            # Skip if sender is validated (bridge patterns)
            if re.search(r'(msg\.sender\s*!=|msg\.sender\s*==)\s*\w*(Proxy|Bridge|Mediator|Relayer|Contract)', full_context, re.IGNORECASE):
                return False
            # Skip if there's access control
            if re.search(r'(onlyOwner|onlyAdmin|onlyRole|onlyBridge|onlyRelayer|modifier)', full_context):
                return False
            # Skip if in a function that validates sender at the start
            if re.search(r'require\s*\(\s*msg\.sender\s*==', '\n'.join(context_before)):
                return False
            # Skip if return value is checked (not blind call)
            if re.search(r'\(\s*bool\s+success.*\)\s*=.*\.call', line) and re.search(r'if\s*\(\s*!?\s*success', full_context):
                return False
            return True
        
        if pattern_name == 'cross_chain':
            # Skip interface definitions
            if re.search(r'interface\s+\w+', full_context):
                return False
            # Skip if just a function declaration in interface
            if 'function' in line and 'external' in line and '{' not in full_context:
                return False
            # Only flag actual implementations with missing validation
            if re.search(r'function\s+\w+.*\{', full_context):
                # Check if there's sender validation
                if re.search(r'(msg\.sender\s*==|require.*sender|onlyBridge|onlyRelayer)', full_context):
                    return False
                return True
            return False
        
        if pattern_name == 'unsafe_erc20':
            # Skip if return value is captured and checked
            if re.search(r'bool\s+success\s*=.*\.(transfer|transferFrom|approve)', line):
                if re.search(r'if\s*\(\s*!?\s*success', full_context):
                    return False
            # Skip if using SafeERC20
            if 'safeTransfer' in full_context or 'SafeERC20' in full_context:
                return False
            return True
        
        return True  # Default: report the finding
    
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
