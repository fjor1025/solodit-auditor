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
    - Interface-only files
    - Standard library patterns (OpenZeppelin)
    - Self-delegatecall multicall patterns
    """
    
    # OpenZeppelin and other standard safe imports
    SAFE_STANDARD_IMPORTS = [
        r'@openzeppelin/contracts',
        r'@openzeppelin/contracts-upgradeable',
        r'ERC20Permit',
        r'ERC2612',
        r'draft-IERC20Permit',
        r'solmate/src/tokens',
        r'SafeERC20',
        r'ReentrancyGuard',
    ]
    
    # Standard interfaces from external protocols (not your implementation)
    EXTERNAL_PROTOCOL_INTERFACES = [
        r'IJoe',       # Trader Joe
        r'IUniswap',   # Uniswap
        r'ILB',        # Liquidity Book (Trader Joe V2)
        r'IAave',      # Aave
        r'ICompound',  # Compound
        r'ICurve',     # Curve
        r'ISushi',     # Sushiswap
        r'IBalancer',  # Balancer
        r'IGMX',       # GMX
        r'IChainlink', # Chainlink
        r'IYearn',     # Yearn
    ]
    
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
        # FIRST: Check for universal false positive conditions
        
        # Check if this is an interface-only file
        is_interface, interface_reason = self._is_interface_only(ctx)
        if is_interface:
            return ValidationResult.FALSE_POSITIVE, interface_reason
        
        # Check for standard library usage (OpenZeppelin, etc.)
        uses_stdlib, stdlib_reason = self._uses_standard_library(pattern_name, ctx)
        if uses_stdlib:
            return ValidationResult.FALSE_POSITIVE, stdlib_reason
        
        # Pattern-specific validators
        validators = {
            'reentrancy': self._validate_reentrancy,
            'delegatecall_injection': self._validate_delegatecall,
            'dos_gas_limit': self._validate_dos_loop,
            'unchecked_return_value': self._validate_unchecked_return,
            'arbitrary_external_call': self._validate_arbitrary_call,
            'access_control': self._validate_access_control,
            'unsafe_erc20': self._validate_unsafe_erc20,
            'cross_chain': self._validate_cross_chain,
            'signature_replay': self._validate_signature_replay,
            'permit_dos': self._validate_permit_dos,
            'flash_loan_vulnerability': self._validate_flash_loan,
        }
        
        validator = validators.get(pattern_name)
        if validator:
            return validator(ctx)
        
        # Default: needs manual review
        return ValidationResult.NEEDS_MANUAL_REVIEW, "No specific validator available"
    
    def _is_interface_only(self, ctx: ValidationContext) -> Tuple[bool, str]:
        """
        Check if the code is from an interface-only file.
        
        Interface files contain no implementation, so vulnerabilities
        flagged in them are always false positives.
        """
        full_code = ctx.full_code
        line = ctx.line
        
        if not full_code:
            # Check if line is just a function signature (interface pattern)
            if re.match(r'\s*function\s+\w+\s*\([^)]*\)[^{]*;', line):
                return True, "Interface function declaration - no implementation"
            return False, ""
        
        # Check if file is primarily interface definitions
        # Count interface vs contract definitions
        interface_count = len(re.findall(r'\binterface\s+\w+', full_code))
        contract_count = len(re.findall(r'\bcontract\s+\w+', full_code))
        abstract_count = len(re.findall(r'\babstract\s+contract\s+\w+', full_code))
        
        # If only interfaces, it's an interface file
        if interface_count > 0 and contract_count == 0:
            return True, "Interface-only file - no implementation to audit"
        
        # Check for external protocol interface patterns
        for pattern in self.EXTERNAL_PROTOCOL_INTERFACES:
            if re.search(pattern, full_code):
                # If the contract NAME starts with I (interface convention)
                if ctx.contract_name and ctx.contract_name.startswith('I'):
                    return True, f"External protocol interface ({ctx.contract_name}) - implementation is in external audited contract"
        
        # Check if the specific line is in an interface block
        if re.search(r'\binterface\s+\w+[^{]*\{[^}]*' + re.escape(line.strip()[:30]), full_code, re.DOTALL):
            return True, "Code is within interface definition"
        
        # Check for function declarations without bodies (interface style)
        if re.match(r'\s*function\s+\w+\s*\([^)]*\)\s*(external|public)[^{]*;', line):
            return True, "Interface function signature - no implementation"
        
        # Check for event declarations (often in interfaces)
        if re.match(r'\s*event\s+\w+\s*\([^)]*\)\s*;', line):
            return True, "Event declaration - no vulnerability in event definition"
        
        return False, ""
    
    def _uses_standard_library(self, pattern_name: str, ctx: ValidationContext) -> Tuple[bool, str]:
        """
        Check if the code uses standard libraries that handle the vulnerability.
        
        For example:
        - OpenZeppelin ERC20Permit handles signature replay with nonces
        - SafeERC20 handles unsafe token operations
        - ReentrancyGuard handles reentrancy
        """
        full_code = ctx.full_code
        full_context = self._get_full_context(ctx)
        
        # Check for OpenZeppelin imports
        for import_pattern in self.SAFE_STANDARD_IMPORTS:
            if re.search(import_pattern, full_code or full_context):
                # Match specific patterns to specific vulnerabilities
                if pattern_name == 'signature_replay' and 'ERC20Permit' in (full_code or full_context):
                    return True, "Uses OpenZeppelin ERC20Permit - nonces, chainId, and EIP-712 are handled"
                
                if pattern_name == 'permit_dos' and 'ERC20Permit' in (full_code or full_context):
                    return True, "Uses OpenZeppelin ERC20Permit - standard implementation"
                
                if pattern_name == 'unsafe_erc20' and 'SafeERC20' in (full_code or full_context):
                    return True, "Uses OpenZeppelin SafeERC20"
                    
                if pattern_name == 'reentrancy' and 'ReentrancyGuard' in (full_code or full_context):
                    return True, "Uses OpenZeppelin ReentrancyGuard"
        
        return False, ""

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
        5. Self-delegatecall (multicall pattern) - address(this).delegatecall()
        """
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check 0: Self-delegatecall (multicall pattern)
        # address(this).delegatecall() is safe - it only calls methods on itself
        if re.search(r'address\s*\(\s*this\s*\)\s*\.\s*delegatecall', line):
            # This is the standard multicall pattern (Uniswap, OpenZeppelin)
            # Check if it's in a multicall function
            if re.search(r'function\s+multicall', full_context, re.IGNORECASE) or \
               re.search(r'BasicMulticall|Multicall', full_context):
                return ValidationResult.FALSE_POSITIVE, "Self-delegatecall in multicall pattern - standard safe pattern (Uniswap/OZ style)"
            
            # Even without multicall name, self-delegatecall is generally safe
            return ValidationResult.FALSE_POSITIVE, "Self-delegatecall (address(this).delegatecall) - only calls own methods"
        
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
    
    def _validate_signature_replay(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """
        Validate signature replay vulnerability finding.
        
        False positive if:
        1. Using OpenZeppelin ERC20Permit (has nonces)
        2. Contract has nonces mapping
        3. DOMAIN_SEPARATOR includes chainId
        4. EIP-712 typed data is used
        5. It's just an interface definition
        """
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check if it's an interface definition
        if re.match(r'\s*function\s+\w+\s*\([^)]*\)[^{]*;', line):
            return ValidationResult.FALSE_POSITIVE, "Interface function declaration - implementation handles replay protection"
        
        # Check for OpenZeppelin ERC20Permit
        if re.search(r'ERC20Permit|ERC2612|IERC20Permit', full_context):
            return ValidationResult.FALSE_POSITIVE, "Uses ERC20Permit standard - nonces and EIP-712 are implemented"
        
        # Check for nonces
        nonce_patterns = [
            r'\bnonces?\s*\[',
            r'\bnonces?\s*\(',
            r'mapping.*nonce',
            r'_nonces',
            r'_useNonce',
            r'nonce\s*\+\+',
            r'\+\+\s*nonce',
        ]
        for pattern in nonce_patterns:
            if re.search(pattern, full_context, re.IGNORECASE):
                return ValidationResult.FALSE_POSITIVE, "Nonces are used for replay protection"
        
        # Check for DOMAIN_SEPARATOR with chain ID
        if re.search(r'DOMAIN_SEPARATOR', full_context):
            if re.search(r'chainId|chain\.id|block\.chainid', full_context, re.IGNORECASE):
                return ValidationResult.FALSE_POSITIVE, "DOMAIN_SEPARATOR includes chainId"
        
        # Check for EIP-712 
        if re.search(r'EIP712|EIP-712|_domainSeparatorV4|_hashTypedDataV4', full_context):
            return ValidationResult.FALSE_POSITIVE, "Uses EIP-712 typed data structure"
        
        # Check for constructor inheriting permit functionality
        if re.search(r'constructor[^{]*ERC20Permit\s*\(', full_context):
            return ValidationResult.FALSE_POSITIVE, "Inherits ERC20Permit - replay protection built-in"
        
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Verify signature includes nonce, chainId, and contract address"
    
    def _validate_permit_dos(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """
        Validate permit DoS vulnerability finding.
        
        False positive if:
        1. It's an interface definition (not implementation)
        2. Uses OpenZeppelin ERC20Permit (standard implementation)
        3. Has fallback to regular approve
        4. Is a nonces() view function (not vulnerable)
        """
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check if it's an interface definition
        if re.match(r'\s*function\s+\w+\s*\([^)]*\)[^{]*;', line):
            return ValidationResult.FALSE_POSITIVE, "Interface function declaration - not an implementation"
        
        # Check for nonces view function (not a vulnerability)
        if re.search(r'function\s+nonces?\s*\(.*\)\s*(external|public)?\s*view', line):
            return ValidationResult.FALSE_POSITIVE, "nonces() is a standard view function - not vulnerable"
        
        # Check for OpenZeppelin ERC20Permit
        if re.search(r'ERC20Permit|@openzeppelin.*Permit', full_context):
            return ValidationResult.FALSE_POSITIVE, "Uses OpenZeppelin ERC20Permit - standard implementation"
        
        # Check for try/catch around permit (handles failures)
        if re.search(r'try\s+.*permit\s*\(', full_context):
            return ValidationResult.FALSE_POSITIVE, "Permit call wrapped in try/catch"
        
        # Check for fallback to approve
        if re.search(r'(permit|Permit).*\|\|.*(approve|Approve)', full_context) or \
           re.search(r'(approve|Approve).*\|\|.*(permit|Permit)', full_context):
            return ValidationResult.FALSE_POSITIVE, "Has fallback to regular approve"
        
        # Check if it's external protocol interface
        if ctx.contract_name and ctx.contract_name.startswith('I'):
            return ValidationResult.FALSE_POSITIVE, f"External protocol interface ({ctx.contract_name})"
        
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Verify permit has fallback mechanism"
    
    def _validate_flash_loan(self, ctx: ValidationContext) -> Tuple[ValidationResult, str]:
        """
        Validate flash loan vulnerability finding.
        
        False positive if:
        1. It's an interface definition or event
        2. It's an external protocol interface (Aave, Balancer, etc.)
        3. The contract has reentrancy protection
        4. State consistency checks are present
        """
        full_context = self._get_full_context(ctx)
        line = ctx.line
        
        # Check if it's an event declaration
        if re.match(r'\s*event\s+\w+', line):
            return ValidationResult.FALSE_POSITIVE, "Event declaration - not a vulnerability"
        
        # Check if it's an interface definition
        if re.match(r'\s*function\s+\w+\s*\([^)]*\)[^{]*;', line):
            return ValidationResult.FALSE_POSITIVE, "Interface function declaration - implementation handles flash loan safety"
        
        # Check if it's external protocol interface
        for pattern in self.EXTERNAL_PROTOCOL_INTERFACES:
            if re.search(pattern, ctx.contract_name or ''):
                return ValidationResult.FALSE_POSITIVE, f"External protocol interface - flash loan security is in the external contract"
        
        # Check interface naming convention
        if ctx.contract_name and ctx.contract_name.startswith('I') and ctx.contract_name[1].isupper():
            return ValidationResult.FALSE_POSITIVE, f"External protocol interface ({ctx.contract_name}) - not your implementation"
        
        # Check for reentrancy guards in flash loan context
        if re.search(r'nonReentrant|ReentrancyGuard|_locked', full_context):
            return ValidationResult.FALSE_POSITIVE, "Flash loan callback has reentrancy protection"
        
        # Check for state consistency checks
        consistency_patterns = [
            r'require.*balance.*>=',
            r'require.*==.*before',
            r'invariant',
            r'_checkInvariant',
        ]
        for pattern in consistency_patterns:
            if re.search(pattern, full_context, re.IGNORECASE):
                return ValidationResult.FALSE_POSITIVE, "State consistency checks present"
        
        return ValidationResult.NEEDS_MANUAL_REVIEW, "Verify flash loan callback has proper state validation"
    
    def _get_full_context(self, ctx: ValidationContext) -> str:
        """Get full context as a single string, including full_code if available."""
        local_context = '\n'.join(ctx.context_before) + '\n' + ctx.line + '\n' + '\n'.join(ctx.context_after)
        if ctx.full_code:
            return ctx.full_code + '\n' + local_context
        return local_context


def create_validator() -> SemanticValidator:
    """Create a semantic validator instance."""
    return SemanticValidator()
