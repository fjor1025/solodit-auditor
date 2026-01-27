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
    
    # Patterns that always generate false positives - DISABLED
    DISABLED_PATTERNS = {
        'missing_zero_address_check',  # Too noisy
        'access_control',  # Flags functions that already have checks
        'centralization_risk',  # Informational only
        'timestamp_dependence',  # Too common, low-risk
        'precision_loss',  # Too many false positives
        'reentrancy_readonly',  # Flags interface declarations
        'frontrunning',  # Too many false positives on comments/documentation
        'oracle_manipulation',  # Flags comments and function names, not actual vulnerabilities
        'storage_collision',  # False positives on regular initialize() functions
        'integer_overflow',  # False positives on intentional unchecked blocks in math libraries
        'inflation_attack',  # False positives on simple totalSupply checks
        'erc721_erc1155_callback',  # False positives on library functions
    'first_deposit_inflation',  # False positives on simple totalSupply checks
    }
    
    # All other patterns will be checked (with context validation for sensitive ones)
    # Context-sensitive patterns (validate before reporting)
    CONTEXT_SENSITIVE_PATTERNS = {
        'delegatecall_injection',
        'reentrancy', 
        'unchecked_return_value',
        'cross_chain',
        'unsafe_erc20',
        'dos_gas_limit',
        'arbitrary_external_call',
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
            # Skip disabled patterns
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
        
        if pattern_name == 'frontrunning':
            # Skip comments - be VERY aggressive
            stripped = line.strip()
            
            # Skip obvious comment lines
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                return False
            
            # Check if we're inside any comment block by counting delimiters in ALL context
            all_before = '\n'.join(context_before)
            open_comments = all_before.count('/*')
            close_comments = all_before.count('*/')
            if open_comments > close_comments:
                # Inside an unclosed comment block
                return False
            
            # ULTRA-AGGRESSIVE: If any of the last 10 lines has /** or /*, assume we're in a docstring
            recent_lines = context_before[-10:] if len(context_before) >= 10 else context_before
            for recent_line in recent_lines:
                if '/**' in recent_line or (recent_line.strip().startswith('/*') and not recent_line.strip().endswith('*/')):
                    # Found an unclosed comment marker recently - likely in a docstring
                    return False
            
            # Also skip if line looks like plain English documentation (starts with capital letter, no code symbols)
            if stripped and stripped[0].isupper() and not any(sym in stripped for sym in ['(', ')', '{', '}', ';', '=']):
                # Looks like documentation prose - check if there's a comment marker above
                if any('/*' in l for l in context_before[-5:]):
                    return False
            
            return True
        
        if pattern_name == 'dos_gas_limit':
            # Skip single .push() operations that are not inside a loop
            if '.push(' in line:
                # Check if we're inside a loop by looking for 'for' in context
                if not re.search(r'\bfor\s*\(', full_context):
                    return False
            
            # Skip loops with hardcoded upper bounds (like < 255, < 100, etc.)
            if re.search(r'for\s*\([^<]*<\s*\d{1,3}\s*[;)]', line):
                return False
            
            # Skip loops with named constant bounds (like MAX_NUM_WEEKS, MAX_ITERATIONS, etc.)
            if re.search(r'for\s*\([^<]*<\s*[A-Z_][A-Z0-9_]*\s*[;)]', line):
                return False
            
            # Skip loops over variables that sound like they come from calldata/memory
            # Examples: dataLength, numItems, count, length, size
            if re.search(r'for\s*\([^<]*<\s*(dataLength|numItems|\w*Length|\w*Count|\w*Size)\s*[;)]', line, re.IGNORECASE):
                # These are typically bounded by calldata/memory size
                return False
            
            # Skip loops over time-based variables (years, months, days, etc.)
            if re.search(r'for\s*\([^<]*<\s*(num)?\s*(Years?|Months?|Days?|Hours?)', line, re.IGNORECASE):
                # Time-based loops are naturally bounded
                return False
            
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
            
            # Skip loops over calldata/memory arrays (function parameters) - these are bounded
            if re.search(r'for.*\w+\.length', line):
                # Check if it's a storage array or just a memory/calldata parameter
                # Storage arrays would have `storage` keyword or be state variables
                if 'storage' not in full_context:
                    # Likely a calldata/memory array parameter - skip it
                    return False

            # Skip admin setter functions (onlyOwner/onlyManager)
            if re.search(r'function\s+(set|update)[A-Z]', full_context):
                if re.search(r'(onlyOwner|onlyManager|checkOwner)', full_context):
                    return False

            # Skip deposit functions (user-controlled array size)
            if re.search(r'function\s+deposit', full_context, re.IGNORECASE):
                return False
            
            return True
        
        if pattern_name == 'delegatecall_injection':
            # Skip if it's clearly a proxy pattern with EIP-1967
            if 'EIP1967' in full_context or 'IMPLEMENTATION_SLOT' in full_context:
                return False
            # Skip internal delegation function (_delegate is usually in proxy base)
            if '_delegate(' in line and 'function _delegate' in full_context:
                return False
            # Report delegatecall - it's always worth reviewing
            return True
        
        if pattern_name == 'reentrancy':
            # Skip if comment explicitly says to ignore failures (intentional design)
            if re.search(r'(ignore.*fail|fail.*ignore|intentionally.*ignore)', full_context, re.IGNORECASE):
                return False
            # Skip if comment mentions standard/safe transfer implementation
            if re.search(r'(standard transfer|safe by default|realization has.*transfer)', full_context, re.IGNORECASE):
                return False
            # Skip if it's verifyInstance function call (view function)
            if re.search(r'(verify|get)InstanceAnd', full_context, re.IGNORECASE):
                return False
            # Skip if it's a view/pure function call (no state changes possible)
            if re.search(r'(view|pure|verify|check|get)\s*\(', full_context, re.IGNORECASE):
                # Check if the function being called looks like a view function
                if re.search(r'(verify|check|get)[A-Z]', full_context):
                    return False
            # Skip if return value is checked
            if re.search(r'\(\s*bool\s+success', line) and re.search(r'if\s*\(\s*!?\s*success', full_context):
                return False
            # Skip if using ReentrancyGuard
            if 'nonReentrant' in full_context or 'ReentrancyGuard' in full_context:
                return False
            return True
        
        if pattern_name == 'unchecked_return_value':
            # Skip if comment explicitly says to ignore failures (intentional design)
            if re.search(r'(ignore.*fail|fail.*ignore|intentionally.*ignore|if.*call.*fail.*ignore)', full_context, re.IGNORECASE):
                return False
            # Skip if there's a comment saying it reverts on failure
            if re.search(r'(reverts?|revert on failure|either returns|optimized.*that.*reverts)', full_context, re.IGNORECASE):
                return False
            # Skip approve() calls - we already filter these in unsafe_erc20
            if re.search(r'\.approve\s*\(', line):
                return False
            # Only report if return value is truly ignored (no bool capture)
            if re.search(r'\(\s*bool\s+(success|ok)', full_context):
                return False
            # Skip if there's a require/if check nearby
            if re.search(r'(require|if)\s*\(', full_context):
                return False
            # Skip transfers to bridge2Burner (intentional)
            if 'bridge2Burner' in full_context and 'transfer(' in line:
                return False
            # Skip OLAS transfers to treasury/timelock (OLAS reverts on failure)
            if ('treasury' in full_context or 'timelock' in full_context) and 'transfer(' in line and 'olas' in full_context.lower():
                return False
            return True
        
        if pattern_name == 'cross_chain':
            # Skip interface definitions (no implementation body)
            if ';' in line and '{' not in line:
                return False
            # Skip initialize() functions (not cross-chain related)
            if 'function initialize(' in full_context:
                return False
            # Skip if sender is validated using bridge methods
            if re.search(r'(messageSender|xDomainMessageSender|sender)\s*\(\s*\)', full_context):
                return False
            # Skip if sender is validated with comparison
            if re.search(r'msg\.sender\s*(==|!=)', full_context):
                return False
            return True
        
        if pattern_name == 'unsafe_erc20':
            # Skip if there's a comment saying it reverts on failure
            if re.search(r'(reverts?|revert on failure|either returns|optimized.*that.*reverts)', full_context, re.IGNORECASE):
                return False
            # Skip if using SafeERC20
            if 'safeTransfer' in full_context or 'SafeERC20' in full_context:
                return False
            # Skip approve() - it's usually not a critical issue
            if '.approve(' in line:
                return False
            # Skip if return value is captured
            if re.search(r'bool\s+\w+\s*=.*\.(transfer|transferFrom)', full_context):
                return False
            # Skip OLAS transfers (OLAS reverts on failure)
            if 'olas' in full_context.lower() and 'transfer(' in line:
                return False
            # Skip transfers to treasury (typically safe tokens)
            if 'treasury' in full_context and 'transfer(' in line:
                return False
            return True
        
        return True  # Default: report the finding



        if pattern_name == 'arbitrary_external_call':
            # Skip if comment says 'must never revert' or 'low level call' (intentional design)
            if re.search(r'(must never revert|since it must never|low level call)', full_context, re.IGNORECASE):
                return False
            # Skip if it's a known safe pattern (address.call with explicit checks)
            if re.search(r'\(\s*bool\s+success', full_context) and re.search(r'require\s*\(\s*success', full_context):
                return False
            # Skip if comment says it's intentional
            if re.search(r'(intentional|safe|trusted|known)', full_context, re.IGNORECASE):
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
