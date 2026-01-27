"""
Vulnerability Pattern Definitions for Smart Contract Analysis

Each pattern includes:
- keywords: Terms to search in Solodit API
- regex_patterns: Patterns to detect in Solidity code
- description: What the vulnerability is about
- severity_hint: Likely severity if found
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Pattern
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"


@dataclass
class VulnerabilityPattern:
    name: str
    keywords: List[str]
    regex_patterns: List[str]
    description: str
    severity_hint: Severity
    solodit_tags: List[str] = field(default_factory=list)
    
    def compile_patterns(self) -> List[Pattern]:
        return [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in self.regex_patterns]


# Comprehensive vulnerability patterns based on real audit findings
VULNERABILITY_PATTERNS: Dict[str, VulnerabilityPattern] = {
    
    # ============== CRITICAL PATTERNS ==============
    
    "reentrancy": VulnerabilityPattern(
        name="Reentrancy",
        keywords=["reentrancy", "reentrant", "CEI pattern", "checks effects interactions"],
        regex_patterns=[
            r'\.call\{.*value.*\}.*\(\s*""\s*\).*\n.*(?:balances|balance|_balance)',  # call before state update
            r'(?:transfer|send|call)\s*\(.*\).*\n.*(?:\-=|\+=|=)',  # external call before state change
            r'\.call\{.*\}\s*\([^)]*\)(?!.*nonReentrant)',  # call without nonReentrant
            r'payable\s*\(.*\)\.(?:transfer|send)',  # ETH transfers
            r'IERC20.*\.(?:transfer|transferFrom).*\n.*(?:\-=|\+=)',  # token transfer before state
        ],
        description="External calls before state updates allow attackers to re-enter and drain funds",
        severity_hint=Severity.CRITICAL,
        solodit_tags=["Reentrancy", "External-Call", "CEI"]
    ),
    
    "delegatecall_injection": VulnerabilityPattern(
        name="Delegatecall Injection",
        keywords=["delegatecall", "proxy", "storage collision", "implementation"],
        regex_patterns=[
            r'\.delegatecall\s*\(',
            r'address\s*\(.*\)\.delegatecall',
            r'_delegate\s*\(',
            r'delegatecall.*msg\.data',
        ],
        description="Delegatecall to untrusted contracts can lead to storage corruption or takeover",
        severity_hint=Severity.CRITICAL,
        solodit_tags=["Delegatecall", "Proxy", "Storage"]
    ),
    
    "unprotected_selfdestruct": VulnerabilityPattern(
        name="Unprotected Selfdestruct",
        keywords=["selfdestruct", "suicide", "contract destruction"],
        regex_patterns=[
            r'selfdestruct\s*\(',
            r'suicide\s*\(',
        ],
        description="Unprotected selfdestruct can permanently destroy contract and drain funds",
        severity_hint=Severity.CRITICAL,
        solodit_tags=["Selfdestruct", "Access-Control"]
    ),
    
    "arbitrary_external_call": VulnerabilityPattern(
        name="Arbitrary External Call",
        keywords=["arbitrary call", "external call", "call injection"],
        regex_patterns=[
            r'\.call\s*\(\s*abi\.encode',
            r'address\s*\([^)]+\)\.call\{',
            r'target\.call\s*\(',
            r'\.call\s*\(\s*data\s*\)',
        ],
        description="Arbitrary external calls can be exploited for various attacks",
        severity_hint=Severity.CRITICAL,
        solodit_tags=["External-Call", "Arbitrary-Call"]
    ),
    
    # ============== HIGH PATTERNS ==============
    
    "access_control": VulnerabilityPattern(
        name="Access Control Issues",
        keywords=["access control", "authorization", "privilege", "onlyOwner", "admin"],
        regex_patterns=[
            r'function\s+\w+.*public(?!.*(?:onlyOwner|onlyAdmin|onlyRole|require\s*\(\s*msg\.sender))',
            r'function\s+\w+.*external(?!.*(?:onlyOwner|onlyAdmin|onlyRole|modifier))',
            r'msg\.sender\s*==\s*owner(?!\s*\|\|)',  # simple owner check without fallback
            r'require\s*\(\s*msg\.sender\s*==',
            r'function\s+set\w+.*(?:public|external)(?!.*only)',  # setter without protection
        ],
        description="Missing or weak access controls allow unauthorized actions",
        severity_hint=Severity.HIGH,
        solodit_tags=["Access-Control", "Authorization", "Privilege"]
    ),
    
    "oracle_manipulation": VulnerabilityPattern(
        name="Oracle/Price Manipulation",
        keywords=["oracle manipulation", "price manipulation", "TWAP", "spot price", "flash loan"],
        regex_patterns=[
            r'getReserves\s*\(',  # Uniswap spot price
            r'balanceOf.*\/.*balanceOf',  # ratio-based pricing
            r'price.*=.*reserve',  # price from reserves
            r'slot0\s*\(',  # Uniswap V3 spot price
            r'latestAnswer\s*\(',  # Chainlink without staleness check
            r'latestRoundData.*(?!.*updatedAt)',  # Chainlink without timestamp validation
        ],
        description="Price oracles can be manipulated via flash loans or liquidity attacks",
        severity_hint=Severity.HIGH,
        solodit_tags=["Oracle", "Price-Manipulation", "Flash-Loan"]
    ),
    
    "flash_loan_vulnerability": VulnerabilityPattern(
        name="Flash Loan Attack Vector",
        keywords=["flash loan", "flashloan", "atomic arbitrage", "same block"],
        regex_patterns=[
            r'flashLoan\s*\(',
            r'flash\s*\(',
            r'IFlash',
            r'onFlashLoan',
            r'executeOperation',  # Aave flash loan callback
            r'uniswapV2Call',  # Uniswap flash swap
        ],
        description="Flash loan callbacks may be exploited if state isn't properly validated",
        severity_hint=Severity.HIGH,
        solodit_tags=["Flash-Loan", "Callback"]
    ),
    
    "signature_replay": VulnerabilityPattern(
        name="Signature Replay/Malleability",
        keywords=["signature replay", "signature malleability", "ecrecover", "EIP712"],
        regex_patterns=[
            r'ecrecover\s*\(',
            r'ECDSA\.recover',
            r'SignatureChecker',
            r'_hashTypedDataV4',
            r'permit\s*\(',
        ],
        description="Signatures without proper nonces or domain separation can be replayed",
        severity_hint=Severity.HIGH,
        solodit_tags=["Signature", "Replay", "ECDSA"]
    ),
    
    "unchecked_return_value": VulnerabilityPattern(
        name="Unchecked Return Values",
        keywords=["unchecked return", "return value", "silent failure"],
        regex_patterns=[
            r'\.transfer\s*\([^;]*\)\s*;(?!\s*require)',
            r'\.send\s*\([^;]*\)\s*;(?!\s*(?:require|if))',
            r'\.call\{[^}]*\}\s*\([^)]*\)\s*;(?!\s*require)',
            r'IERC20.*\.transfer\s*\([^;]*\)\s*;(?!\s*require)',  # ERC20 without check
            r'\.approve\s*\([^;]*\)\s*;(?!\s*require)',
        ],
        description="Unchecked return values can lead to silent failures",
        severity_hint=Severity.HIGH,
        solodit_tags=["Return-Value", "Error-Handling"]
    ),
    
    "frontrunning": VulnerabilityPattern(
        name="Front-Running/MEV",
        keywords=["frontrunning", "front-running", "MEV", "sandwich", "slippage"],
        regex_patterns=[
            r'swap.*(?:amountOutMin|minOut)\s*[=:]\s*0',  # zero slippage
            r'deadline.*=.*block\.timestamp',  # deadline same as current block
            r'swapExact.*\([^)]*,\s*0\s*,',  # min amount = 0
            r'approve.*type\(uint256\)\.max',  # infinite approval
            r'(?:commit|reveal)(?!.*block\.number)',  # commit-reveal without block check
        ],
        description="Transactions can be front-run or sandwich attacked without proper protection",
        severity_hint=Severity.HIGH,
        solodit_tags=["Front-Running", "MEV", "Slippage"]
    ),
    
    "integer_overflow": VulnerabilityPattern(
        name="Integer Overflow/Underflow",
        keywords=["overflow", "underflow", "integer", "unchecked arithmetic"],
        regex_patterns=[
            r'unchecked\s*\{[^}]*[\+\-\*][^}]*\}',
            r'assembly\s*\{[^}]*(?:add|sub|mul|div)[^}]*\}',
            r'uint\d*\s+\w+\s*=.*\+',  # addition without SafeMath (pre-0.8)
        ],
        description="Arithmetic operations without overflow checks can wrap around",
        severity_hint=Severity.HIGH,
        solodit_tags=["Overflow", "Underflow", "Arithmetic"]
    ),
    
    # ============== MEDIUM PATTERNS ==============
    
    "dos_gas_limit": VulnerabilityPattern(
        name="Denial of Service (Gas/Loop)",
        keywords=["denial of service", "DoS", "gas limit", "unbounded loop"],
        regex_patterns=[
            r'for\s*\([^)]*\.length',  # loop over dynamic array
            r'while\s*\([^)]*<.*\.length',
            r'for\s*\(.*;\s*\w+\s*<\s*\w+\s*;',  # unbounded loop
            r'\.push\s*\([^)]*\)\s*;(?!.*pop)',  # only push, no pop (growing array)
        ],
        description="Unbounded loops or growing arrays can exceed gas limits",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["DoS", "Gas", "Loop"]
    ),
    
    "timestamp_dependence": VulnerabilityPattern(
        name="Timestamp Dependence",
        keywords=["timestamp manipulation", "block.timestamp", "time-based"],
        regex_patterns=[
            r'block\.timestamp\s*(?:==|<|>|<=|>=)',
            r'now\s*(?:==|<|>|<=|>=)',  # deprecated 'now' keyword
            r'require.*block\.timestamp',
            r'if.*block\.timestamp',
        ],
        description="Miners can manipulate block.timestamp within ~15 second window",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["Timestamp", "Time"]
    ),
    
    "unsafe_erc20": VulnerabilityPattern(
        name="Unsafe ERC20 Operations",
        keywords=["ERC20", "safeTransfer", "approve race", "USDT approve"],
        regex_patterns=[
            r'IERC20.*\.transfer\s*\(',  # direct transfer instead of safeTransfer
            r'IERC20.*\.transferFrom\s*\(',
            r'\.approve\s*\([^)]+,\s*[^0][^)]*\)',  # approve non-zero (race condition)
            r'token\.transfer(?!.*safe)',
        ],
        description="ERC20 operations without safe wrappers can fail silently (USDT, etc.)",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["ERC20", "Token", "Transfer"]
    ),
    
    "centralization_risk": VulnerabilityPattern(
        name="Centralization Risk",
        keywords=["centralization", "admin", "owner", "privilege", "single point of failure"],
        regex_patterns=[
            r'onlyOwner',
            r'onlyAdmin',
            r'require.*owner',
            r'function\s+pause.*onlyOwner',
            r'function\s+set.*Fee.*onlyOwner',
            r'function\s+withdraw.*onlyOwner(?!.*timelock)',
        ],
        description="Excessive admin privileges create centralization and trust issues",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["Centralization", "Admin", "Privilege"]
    ),
    
    "missing_zero_address_check": VulnerabilityPattern(
        name="Missing Zero Address Validation",
        keywords=["zero address", "address(0)", "null address validation"],
        regex_patterns=[
            r'function\s+\w+\s*\([^)]*address\s+\w+[^)]*\)(?![^{]*require.*!=\s*address\(0\))',
            r'=\s*address\s+\w+(?!.*require.*address\(0\))',
            r'constructor\s*\([^)]*address[^)]*\)(?![^{]*require)',
        ],
        description="Missing zero address checks can lock funds or break functionality",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["Validation", "Zero-Address"]
    ),
    
    "reentrancy_readonly": VulnerabilityPattern(
        name="Read-Only Reentrancy",
        keywords=["read-only reentrancy", "view reentrancy", "cross-contract reentrancy"],
        regex_patterns=[
            r'function\s+\w+.*view.*external',
            r'getPrice.*view',
            r'balanceOf.*view',
            r'totalSupply.*external.*view',
        ],
        description="Read-only functions called during reentrancy can return stale values",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["Reentrancy", "View", "Cross-Contract"]
    ),
    
    "precision_loss": VulnerabilityPattern(
        name="Precision Loss / Rounding",
        keywords=["precision loss", "rounding", "division before multiplication"],
        regex_patterns=[
            r'\/.*\*',  # division before multiplication
            r'\/\s*10\*\*',
            r'amount\s*\/\s*\w+\s*\*',
            r'1e18',
            r'10\*\*18',
        ],
        description="Division before multiplication or improper decimal handling loses precision",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["Precision", "Rounding", "Math"]
    ),
    
    "storage_collision": VulnerabilityPattern(
        name="Storage Collision (Proxy)",
        keywords=["storage collision", "proxy", "upgradeable", "EIP-1967"],
        regex_patterns=[
            r'Initializable',
            r'UUPSUpgradeable',
            r'TransparentUpgradeableProxy',
            r'initialize\s*\(',
            r'__gap',
            r'StorageSlot',
        ],
        description="Proxy patterns can have storage collisions between implementation versions",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["Proxy", "Storage", "Upgradeable"]
    ),
    
    "cross_chain": VulnerabilityPattern(
        name="Cross-Chain Vulnerabilities",
        keywords=["cross-chain", "bridge", "LayerZero", "Chainlink CCIP", "message passing"],
        regex_patterns=[
            r'lzReceive',
            r'ccipReceive',
            r'onMessageReceived',
            r'bridge.*\(',
            r'sourceChain',
            r'destinationChain',
        ],
        description="Cross-chain messaging can be exploited via replay or source spoofing",
        severity_hint=Severity.HIGH,
        solodit_tags=["Cross-Chain", "Bridge", "LayerZero"]
    ),
    
    "erc721_erc1155_callback": VulnerabilityPattern(
        name="NFT Callback Reentrancy",
        keywords=["ERC721 reentrancy", "ERC1155 reentrancy", "onERC721Received", "safeTransferFrom"],
        regex_patterns=[
            r'_safeMint\s*\(',
            r'safeTransferFrom\s*\(',
            r'onERC721Received',
            r'onERC1155Received',
            r'_safeTransfer\s*\(',
        ],
        description="Safe transfer callbacks (onERC721Received) enable reentrancy attacks",
        severity_hint=Severity.HIGH,
        solodit_tags=["ERC721", "ERC1155", "Reentrancy", "Callback"]
    ),
    
    "permit_dos": VulnerabilityPattern(
        name="Permit/Approval DoS",
        keywords=["permit DoS", "permit front-run", "EIP-2612"],
        regex_patterns=[
            r'permit\s*\(',
            r'IERC20Permit',
            r'nonces\s*\(',
        ],
        description="Permit can be front-run causing DoS on legitimate transactions",
        severity_hint=Severity.MEDIUM,
        solodit_tags=["Permit", "DoS", "EIP-2612"]
    ),
    
    "first_deposit_inflation": VulnerabilityPattern(
        name="First Deposit / Inflation Attack",
        keywords=["first deposit", "inflation attack", "vault share", "ERC4626"],
        regex_patterns=[
            r'totalSupply\s*\(\)\s*==\s*0',
            r'if\s*\(\s*totalSupply',
            r'ERC4626',
            r'convertToShares',
            r'previewDeposit',
        ],
        description="First depositor can manipulate share price to steal from subsequent depositors",
        severity_hint=Severity.HIGH,
        solodit_tags=["Vault", "Inflation", "ERC4626", "First-Deposit"]
    ),
}


def get_all_patterns() -> Dict[str, VulnerabilityPattern]:
    """Return all vulnerability patterns."""
    return VULNERABILITY_PATTERNS


def get_patterns_by_severity(severity: Severity) -> Dict[str, VulnerabilityPattern]:
    """Filter patterns by severity level."""
    return {
        k: v for k, v in VULNERABILITY_PATTERNS.items() 
        if v.severity_hint == severity
    }
