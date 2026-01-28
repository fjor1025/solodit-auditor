"""
Semantic Validator Module

Advanced context-aware validation to eliminate false positives.
Performs deep analysis of Solidity code patterns.
"""

import re
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple, Set
from enum import Enum


class ValidationResult(Enum):
    """Result of semantic validation."""
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MANUAL_REVIEW = "needs_review"


@dataclass
class ValidationContext:
    """Context information for validation."""
    line: str
    line_number: int
    context_before: List[str]
    context_after: List[str]
    function_name: Optional[str]
    contract_name: Optional[str]
    solidity_version: Optional[Tuple[int, int]]
    full_code: str


class SemanticValidator:
    """
    Performs semantic validation to eliminate false positives.
    
    This validator understands:
    - CEI (Checks-Effects-Interactions) pattern
    - UUPS/Transparent proxy patterns
    - Loop bound analysis
    - Access control patterns
    - View/pure function safety
    """
    
    # Known safe proxy storage slots (EIP-1967 and common patterns)
    SAFE_PROXY_SLOTS = {
        '0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',  # EIP-1967 impl
        '0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103',  # EIP-1967 admin
        '0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3',  # beacon
    }
    
    # Common reentrancy guard patterns
    REENTRANCY_GUARD_PATTERNS = [
        r'nonReentrant',
        r'ReentrancyGuard',
        r'_locked\s*>\s*1',
        r'_status\s*==\s*_ENTERED',
        r'locked\s*==\s*true',
        r'reentrancyLock',
    ]
    
    # CEI violation indicators (state update AFTER external call)
    CEI_STATE_UPDATE_PATTERNS = [
        r'(?:balances?|_balances?)\s*\[.*\]\s*[-+]?=',
        r'(?:amounts?|_amounts?)\s*\[.*\]\s*[-+]?=',
        r'(?:supply|totalSupply|_totalSupply)\s*[-+]?=',
        r'(?:state|_state)\s*=',
        r'mapping.*=\s*(?!0)',        # Map patterns with various prefixes
        r'\bmap\w*\s*\[.*\]\s*[-+]?=',
        # Any state variable with -= or += or =
        r'\b\w+Reserves?\s*\[.*\]\s*[-+]?=',
        r'\b\w+Balances?\s*\[.*\]\s*[-+]?=',
        r'\b\w+Count\s*[-+]?=',
        r'\b\w+Total\s*[-+]?=',
        # Decrement/increment patterns
        r'\w+\s*-=\s*\w+',
        r'\w+\s*\+=\s*\w+',
        # Delete or reset
        r'\bdelete\s+\w+',    ]
    
    def __init__(self):
        """Initialize the semantic validator."""
        self._compiled_reentrancy_guards = [
            re.compile(p, re.IGNORECASE) for p in self.REENTRANCY_GUARD_PATTERNS
        ]
        self._compiled_state_updates = [
            re.compile(p, re.IGNORECASE) for p in self.CEI_STATE_UPDATE_PATTERNS
        ]
    
    def validate_finding(
        self,
        pattern_name: str,
        ctx: ValidationContext
    ) -> Tuple[ValidationResult, str]:
        """
        Validate a potential finding using semantic analysis.
        
        Args:
            pattern_name: Name of the vulnerability pattern
            ctx: Validation context with code information
            
        Returns:
            Tuple of (ValidationResult, reason)
        """
        validators = {
            'reentrancy': self._validate_reentrancy,
            'delegatecall_injection': self._validate_delegatecall,
            'dos_gas_limit': self._validate_dos_loop,
            'unchecked_return_value': self._validate_unchecked_return,
            'arbitrary_external_call': self._validate_arbitrary_call,
            'access_control': self._validate_access_control,
            'unsafe_erc20': self._validate_unsafe_erc20,
            'cross_chain': self._validate_cross_chain,
        }
        
        validator = validators.get(pattern_name)
        if validator:
            return validator(ctx)
        
        # Default: needs manual review
        return ValidationResult.NEEDS_MANUAL_REVIEW, "No specific validator available"
    
    def _validate_reentrancy(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """
        Validate reentrancy finding.
        
        Checks:
        1. Is there a reentrancy guard?
        2. Is CEI pattern followed (state updated BEFORE external call)?
        3. Is this a view/pure function callback?
        4. Is return value checked?
        """
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check 1: Reentrancy guard present
        for pattern in self._compiled_reentrancy_guards:
            if pattern.search(full_context):
                return ValidationResult.FALSE_POSITIVE, "Reentrancy guard detected"
        
        # Check 2: CEI Pattern - is state updated BEFORE the external call?
        # Find the position of the external call
        call_patterns = [
            r'\.call\{.*\}\s*\(',
            r'\.call\s*\(',
            r'\.transfer\s*\(',
            r'\.send\s*\(',
            r'IERC20.*\.transfer\s*\(',
        ]
        
        for call_pattern in call_patterns:
            if re.search(call_pattern, line):
                # Found external call - check if state was updated BEFORE this line
                context_before_str = '\n'.join(ctx.context_before)
                context_after_str = '\n'.join(ctx.context_after)
                
                # Look for state updates in context BEFORE (good - CEI followed)
                state_updated_before = False
                for state_pattern in self._compiled_state_updates:
                    if state_pattern.search(context_before_str):
                        state_updated_before = True
                        break
                
                # Look for state updates AFTER (bad - CEI violated)
                state_updated_after = False
                for state_pattern in self._compiled_state_updates:
                    if state_pattern.search(context_after_str):
                        state_updated_after = True
                        break
                
                # If state is updated before and not after, CEI is followed
                if state_updated_before and not state_updated_after:
                    return ValidationResult.FALSE_POSITIVE, "CEI pattern correctly followed - state updated before external call"
                
                # Check if it's the LAST operation in function (also safe)
                remaining_code = context_after_str.strip()
                if not remaining_code or remaining_code == '}' or re.match(r'^\s*\}?\s*$', remaining_code):
                    return ValidationResult.FALSE_POSITIVE, "External call is last operation in function"
        
        # Check 3: View/pure function (no state changes possible)
        if re.search(r'\bfunction\s+\w+[^{]*\b(view|pure)\b', full_context):
            return ValidationResult.FALSE_POSITIVE, "View/pure function - no state changes possible"
        
        # Check 4: Return value checked
        if re.search(r'\(\s*bool\s+success', line) and re.search(r'(require|if)\s*\(\s*(!?\s*)?success', full_context):
            # Need to check if state update happens after the check
            pass  # Continue to manual review
        
        # Check 5: Is this a known safe pattern (comments indicate intentional design)?
        safe_comment_patterns = [
            r'CEI\s*pattern',
            r'state\s*(?:is\s*)?updated?\s*(?:before|first)',
            r'no\s*reentrancy',
            r'safe\s*(?:by|because)',
            r'last\s*operation',
        ]
        for pattern in safe_comment_patterns:
            if re.search(pattern, full_context, re.IGNORECASE):
                return ValidationResult.FALSE_POSITIVE, "Code comments indicate safe design"
        
        # Could be a real issue - needs review
        return ValidationResult.NEEDS_MANUAL_REVIEW, "External call detected - verify CEI pattern manually"
    
    def _validate_delegatecall(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """
        Validate delegatecall finding.
        
        False positive if:
        1. In a constructor (proxy initialization)
        2. Using EIP-1967 storage slots
        3. Implementation is validated (zero address check)
        4. Standard proxy pattern (UUPS, Transparent)
        """
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check 1: Is this in a constructor?
        if re.search(r'constructor\s*\([^)]*\)\s*\{', full_context):
            # Constructor delegatecall is safe (only deployer controls it)
            
            # Verify there's address validation
            if re.search(r'(require|if)\s*\([^)]*==\s*address\(0\)', full_context) or \
               re.search(r'(require|if)\s*\([^)]*!=\s*address\(0\)', full_context) or \
               re.search(r'revert.*Zero', full_context):
                return ValidationResult.FALSE_POSITIVE, "Constructor delegatecall with address validation - standard proxy pattern"
            
            return ValidationResult.FALSE_POSITIVE, "Constructor delegatecall - only deployer controls implementation"
        
        # Check 2: EIP-1967 pattern
        eip1967_patterns = [
            r'EIP1967',
            r'EIP-1967',
            r'IMPLEMENTATION_SLOT',
            r'0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc',
            r'StorageSlot\.getAddressSlot',
        ]
        for pattern in eip1967_patterns:
            if re.search(pattern, full_context):
                return ValidationResult.FALSE_POSITIVE, "EIP-1967 compliant proxy pattern"
        
        # Check 3: Standard proxy patterns
        proxy_patterns = [
            r'UUPS',
            r'TransparentUpgradeableProxy',
            r'ERC1967',
            r'Proxy\s*\{',
            r'_delegate\s*\(',  # Internal delegate function
        ]
        for pattern in proxy_patterns:
            if re.search(pattern, full_context):
                return ValidationResult.FALSE_POSITIVE, "Standard upgradeable proxy pattern"
        
        # Check 4: Fallback function (expected in proxies)
        if re.search(r'fallback\s*\(\s*\)\s*external', full_context):
            # Check if it's loading implementation from storage
            if re.search(r'sload\s*\(', full_context) or re.search(r'StorageSlot', full_context):
                return ValidationResult.FALSE_POSITIVE, "Proxy fallback with storage-based implementation"
        
        # Could be unsafe - needs review
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Delegatecall to potentially untrusted address"
    
    def _validate_dos_loop(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """
        Validate DoS/gas limit finding.
        
        False positive if:
        1. Loop has constant bound (< 100, < MAX_ITERATIONS, etc.)
        2. View/pure function (off-chain call)
        3. Admin-only function (owner controls gas)
        4. Iterating over calldata/memory (bounded by calldata size)
        5. Time-bounded loop (years, epochs, etc.)
        """
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check 1: Constant upper bound
        constant_bound_patterns = [
            r'for\s*\([^;]*;\s*\w+\s*<\s*(\d+)\s*;',  # < 100
            r'for\s*\([^;]*;\s*\w+\s*<\s*([A-Z_][A-Z0-9_]*)\s*;',  # < MAX_CONSTANT
            r'for\s*\([^;]*;\s*\w+\s*<=\s*(\d+)\s*;',  # <= 100
        ]
        for pattern in constant_bound_patterns:
            match = re.search(pattern, line)
            if match:
                bound = match.group(1)
                # If numeric and < 1000, likely safe
                if bound.isdigit() and int(bound) < 1000:
                    return ValidationResult.FALSE_POSITIVE, f"Loop bounded by constant ({bound})"
                # If constant name, check common safe patterns
                if bound.isupper() or '_' in bound:
                    safe_constants = ['MAX', 'LIMIT', 'CAP', 'BOUND', 'SIZE', 'LENGTH']
                    if any(s in bound for s in safe_constants):
                        return ValidationResult.FALSE_POSITIVE, f"Loop bounded by constant ({bound})"
        
        # Check 2: View/pure function
        func_context = '\n'.join(ctx.context_before[-20:])  # Get function signature
        if re.search(r'function\s+\w+[^{]*(view|pure)\s*(external|public)?[^{]*\{', func_context + '\n' + line):
            return ValidationResult.FALSE_POSITIVE, "View/pure function - called off-chain, no gas limit issue"
        
        # Check 3: Admin-only function
        admin_patterns = [
            r'onlyOwner',
            r'onlyAdmin',
            r'onlyRole',
            r'onlyManager',
            r'msg\.sender\s*==\s*owner',
            r'require\s*\([^)]*owner',
            r'OwnerOnly',
            r'AdminOnly',
        ]
        for pattern in admin_patterns:
            if re.search(pattern, full_context):
                return ValidationResult.FALSE_POSITIVE, "Admin-only function - owner controls gas costs"
        
        # Check 4: Iterating over function parameters (bounded by calldata)
        if re.search(r'for\s*\([^;]*;\s*\w+\s*<\s*\w+\.length\s*;', line):
            # Check if it's a memory/calldata array (function parameter)
            param_patterns = [
                r'function\s+\w+\s*\([^)]*\w+\[\]\s*(memory|calldata)',
                r'function\s+\w+\s*\([^)]*\w+\s+\w+\[\]',  # array parameter
            ]
            for pattern in param_patterns:
                if re.search(pattern, full_context):
                    return ValidationResult.FALSE_POSITIVE, "Iterating over function parameter - bounded by calldata"
        
        # Check 5: Time-bounded loops
        time_patterns = [
            r'(year|month|week|day|hour|epoch|period)',
            r'(Year|Month|Week|Day|Hour|Epoch|Period)',
            r'numYears',
            r'numEpochs',
        ]
        for pattern in time_patterns:
            if re.search(pattern, line):
                return ValidationResult.FALSE_POSITIVE, "Time-bounded loop - naturally limited"
        
        # Check 6: Length check nearby
        if re.search(r'require\s*\([^)]*\.length\s*[<>]=?\s*\d+', full_context):
            return ValidationResult.FALSE_POSITIVE, "Array length is validated"
        
        # Check 7: Internal function (called with controlled data)
        if re.search(r'function\s+\w+[^{]*internal', func_context):
            return ValidationResult.NEEDS_MANUAL_REVIEW, "Internal function - check callers"
        
        # Could be an issue
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Unbounded loop - verify array size limits"
    
    def _validate_unchecked_return(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """Validate unchecked return value finding."""
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check if return value is captured
        if re.search(r'\(\s*bool\s+\w+', full_context):
            return ValidationResult.FALSE_POSITIVE, "Return value is captured"
        
        # Check for require/if check
        if re.search(r'(require|if|assert)\s*\(', full_context):
            return ValidationResult.FALSE_POSITIVE, "Return value is checked"
        
        # Check for safe token patterns
        safe_patterns = [
            r'safeTransfer',
            r'SafeERC20',
            r'reverts?\s*(on\s*)?fail',
            r'OLAS',  # OLAS token reverts on failure
        ]
        for pattern in safe_patterns:
            if re.search(pattern, full_context, re.IGNORECASE):
                return ValidationResult.FALSE_POSITIVE, "Safe transfer pattern or reverting token"
        
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Return value may be unchecked"
    
    def _validate_arbitrary_call(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """Validate arbitrary external call finding."""
        full_context = self._get_full_context(ctx)
        
        # Check for target validation
        validation_patterns = [
            r'require\s*\([^)]*target',
            r'require\s*\([^)]*address',
            r'whitelist',
            r'allowlist',
            r'approved',
            r'registered',
        ]
        for pattern in validation_patterns:
            if re.search(pattern, full_context, re.IGNORECASE):
                return ValidationResult.FALSE_POSITIVE, "Target address is validated"
        
        # Check for known safe contracts
        if re.search(r'(dispenser|treasury|tokenomics|registry)\.(call|staticcall)', full_context, re.IGNORECASE):
            return ValidationResult.FALSE_POSITIVE, "Call to known protocol contract"
        
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Arbitrary call target should be validated"
    
    def _validate_access_control(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """Validate access control finding."""
        full_context = self._get_full_context(ctx)
        
        # Check for access modifiers
        access_patterns = [
            r'onlyOwner',
            r'onlyAdmin',
            r'onlyRole\s*\(',
            r'require\s*\([^)]*msg\.sender\s*==',
            r'msg\.sender\s*!=\s*\w+.*revert',
            r'AccessControl',
        ]
        for pattern in access_patterns:
            if re.search(pattern, full_context):
                return ValidationResult.FALSE_POSITIVE, "Access control is present"
        
        # View/pure functions don't need access control
        if re.search(r'\b(view|pure)\b', full_context):
            return ValidationResult.FALSE_POSITIVE, "View/pure function - no access control needed"
        
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Verify access control requirements"
    
    def _validate_unsafe_erc20(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """Validate unsafe ERC20 operation finding."""
        full_context = self._get_full_context(ctx)
        
        # Check for safe wrappers
        safe_patterns = [
            r'safeTransfer',
            r'SafeERC20',
            r'SafeTransferLib',
        ]
        for pattern in safe_patterns:
            if re.search(pattern, full_context):
                return ValidationResult.FALSE_POSITIVE, "Using safe transfer wrapper"
        
        # Check for return value handling
        if re.search(r'bool\s+\w+\s*=.*\.(transfer|transferFrom)', full_context):
            return ValidationResult.FALSE_POSITIVE, "Return value is captured"
        
        # Check for known safe tokens
        if re.search(r'OLAS|olas', full_context):
            return ValidationResult.FALSE_POSITIVE, "OLAS token reverts on failure"
        
        return ValidationResult.NEEDS_MANUAL_REVIEW, "ERC20 operation may fail silently"
    
    def _validate_cross_chain(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """Validate cross-chain vulnerability finding."""
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check if it's an interface definition (no implementation)
        if ';' in line and '{' not in line and 'function' in line:
            return ValidationResult.FALSE_POSITIVE, "Interface definition - not an implementation"
        
        # Check for sender validation
        validation_patterns = [
            r'msg\.sender\s*(==|!=)',
            r'require\s*\([^)]*sender',
            r'onlyBridge',
            r'onlyEndpoint',
            r'onlyRouter',
            r'onlyRelayer',
            r'messageSender\s*\(',
            r'xDomainMessageSender',
        ]
        for pattern in validation_patterns:
            if re.search(pattern, full_context):
                return ValidationResult.FALSE_POSITIVE, "Sender/source is validated"
        
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Cross-chain message should validate source"
    
    def _get_full_context(self, ctx: ValidationContext) -> str:
        """Get full context as a single string, including full_code if available."""
        local_context = '\n'.join(ctx.context_before) + '\n' + ctx.line + '\n' + '\n'.join(ctx.context_after)
        if ctx.full_code:
            return ctx.full_code + '\n' + local_context
        return local_context


def create_validator() -> SemanticValidator:
    """Create a semantic validator instance."""
    return SemanticValidator()
