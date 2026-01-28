# 🛡️ Fjor Auditor

**Smart Contract Security Auditor powered by Cyfrin Solodit API**

Find real vulnerabilities in your Solidity smart contracts by cross-referencing with 50,000+ documented findings from top audit firms like Cyfrin, Code4rena, Sherlock, and more.

![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)
![License MIT](https://img.shields.io/badge/license-MIT-green.svg)

## ✨ Features

- 🔍 **Pattern Detection**: Identifies 20+ vulnerability patterns (reentrancy, access control, oracle manipulation, etc.)
- 📡 **Real-World Intelligence**: Queries Solodit API for matching findings from actual audits
- 🎯 **Severity Filtering**: Focus on CRITICAL, HIGH, and MEDIUM severity issues (no noise from LOW/INFO)
- 📊 **Rich Reports**: Generate markdown and JSON audit reports
- 💾 **Smart Caching**: Reduce API calls with intelligent result caching
- 🖥️ **CLI & Library**: Use from command line or integrate into your Python tools

## 🚀 Quick Start

### 1. Get Your Free API Key

1. Visit [solodit.cyfrin.io](https://solodit.cyfrin.io)
2. Create a free account
3. Go to top-right menu → **API Keys**
4. Generate and copy your key

### 2. Installation

```bash
# Clone or download
cd ~/solodit-auditor

# Install
pip install -e .

# Or just install dependencies
pip install -r requirements.txt
```

### 3. Set Your API Key

```bash
# Option 1: Environment variable (recommended)
export SOLODIT_API_KEY="your_api_key_here"

# Option 2: Pass via CLI flag
solodit-auditor audit contracts/ --api-key "your_key"
```

### 4. Run Your First Audit

```bash
# Audit a single file
solodit-auditor audit contracts/Vault.sol

# Audit the In-Scope folder
solodit-auditor audit ./contracts

# Audit entire directory
solodit-auditor audit ./contracts --output-md report.md

# Search for specific vulnerabilities
solodit-auditor search "reentrancy withdraw function"

# Interactive mode - paste code directly
solodit-auditor interactive
```

## 📖 Usage

### Command Line Interface

```bash
# Full audit with markdown report
solodit-auditor audit contracts/ --output-md audit-report.md --output-json audit.json

# Search Solodit for findings
solodit-auditor search "flash loan oracle manipulation" --limit 20

# Static analysis only (no API calls - offline mode)
solodit-auditor analyze contracts/ --show-queries

# Focus on critical/high only
solodit-auditor audit contracts/ --high-only

# Interactive code analysis
solodit-auditor interactive
```

### Python Library

```python
from solodit_auditor import create_auditor

# Initialize auditor
auditor = create_auditor(api_key="your_key")  # or use SOLODIT_API_KEY env var

# Audit a code snippet
code = """
function withdraw(uint amount) external {
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
    balances[msg.sender] -= amount;  // Reentrancy vulnerability!
}
"""

report = auditor.audit_code(code)

# Print findings
print(report.format_summary())
for vuln in report.vulnerabilities:
    print(vuln.format_for_display())

# Export reports
with open("report.md", "w") as f:
    f.write(report.to_markdown())

# Quick search
results = auditor.quick_search("price oracle manipulation")
for finding in results.findings:
    print(f"[{finding.impact}] {finding.title}")
    print(f"  URL: {finding.url}")
```

### Integrate with Your Audit Workflow

```python
from solodit_auditor import create_auditor
from pathlib import Path

auditor = create_auditor()

# Audit all contracts in a project
report = auditor.audit_directory("./contracts", recursive=True)

# Check for critical issues (CI/CD integration)
if report.critical_count > 0:
    print("❌ CRITICAL vulnerabilities found!")
    exit(1)

# Generate report for client
Path("audit-report.md").write_text(report.to_markdown())
```

## 🎯 Detected Vulnerability Patterns

| Category | Patterns |
|----------|----------|
| **Critical** | Reentrancy, Delegatecall Injection, Arbitrary External Call, Unprotected Selfdestruct |
| **High** | Access Control, Oracle Manipulation, Flash Loan Vectors, Signature Replay, Unchecked Returns, Front-running, Integer Overflow, NFT Callback Reentrancy, First Deposit Inflation, Cross-Chain |
| **Medium** | DoS (Gas/Loop), Timestamp Dependence, Unsafe ERC20, Centralization Risk, Zero Address Checks, Read-Only Reentrancy, Precision Loss, Storage Collision, Permit DoS |

## 📊 Example Output

```
================================================================================
AUDIT SUMMARY
================================================================================
Target: contracts/Vault.sol
Date: 2026-01-27 10:30:00
Files Analyzed: 1
Lines Analyzed: 150

FINDINGS:
  🔴 CRITICAL: 1
  🟠 HIGH: 2
  🟡 MEDIUM: 1
  📊 TOTAL: 4
================================================================================

################################################################################
POTENTIAL VULNERABILITY: Reentrancy
################################################################################
Severity: CRITICAL
Confidence: HIGH
File: contracts/Vault.sol
Line: 45
Function: withdraw()

Vulnerable Code:
----------------------------------------
    function withdraw(uint amount) external {
→       (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        balances[msg.sender] -= amount;
----------------------------------------

Recommendation:
Apply the Checks-Effects-Interactions (CEI) pattern. Update state BEFORE 
external calls. Consider using OpenZeppelin's ReentrancyGuard modifier.

Similar Real-World Vulnerabilities (12 found):

  1. [HIGH] Reentrancy in withdraw allows draining of vault
     Firm: Code4rena | Protocol: SomeDeFi
     Quality: 4.5/5
     Summary: External call before state update enables fund drainage...
     🔗 https://solodit.cyfrin.io/issues/...
```

## 🔧 Configuration

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SOLODIT_API_KEY` | Your Solodit API key |

### CLI Options

| Flag | Description |
|------|-------------|
| `--api-key`, `-k` | API key (alternative to env var) |
| `--high-only` | Only CRITICAL and HIGH severity |
| `--no-cache` | Disable result caching |
| `--output-md`, `-o` | Export markdown report |
| `--output-json`, `-j` | Export JSON report |
| `--quiet`, `-q` | Suppress banner |

## 🤝 Integration with GitHub Copilot

After running an audit, use the findings with GitHub Copilot:

```
@workspace I found this reentrancy vulnerability in my contract:

[Paste the vulnerability details from solodit-auditor]

Based on the real-world finding from Code4rena showing this pattern 
caused fund drainage, please:
1. Confirm if my code is vulnerable
2. Rewrite the function using the CEI pattern
3. Add OpenZeppelin's ReentrancyGuard
```

## 📚 API Reference

### `SoloditAuditor`

```python
auditor = create_auditor(
    api_key=None,           # Uses SOLODIT_API_KEY env var if None
    include_medium=True,    # Include MEDIUM severity
    enable_cache=True       # Cache API results
)

# Methods
auditor.audit_code(code: str, target_name: str) -> AuditReport
auditor.audit_file(file_path: str) -> AuditReport
auditor.audit_directory(dir_path: str, recursive: bool) -> AuditReport
auditor.quick_search(query: str, page_size: int) -> SearchResult
```

### `AuditReport`

```python
report.target                 # Target file/directory
report.vulnerabilities        # List[PotentialVulnerability]
report.critical_count         # Number of CRITICAL findings
report.high_count            # Number of HIGH findings
report.medium_count          # Number of MEDIUM findings
report.format_summary()      # Terminal-formatted summary
report.to_markdown()         # Full markdown report
report.to_json()             # JSON export
```

## 🙏 Credits

- **[Cyfrin](https://cyfrin.io)** - For building and maintaining the Solodit platform
- **[Solodit](https://solodit.cyfrin.io)** - Aggregating 50,000+ vulnerabilities from top audit firms
- Audit firms: Code4rena, Sherlock, Spearbit, Trail of Bits, OpenZeppelin, and many more

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

**⚠️ Disclaimer**: This tool assists with security audits but does not replace manual review by experienced auditors. Always conduct thorough manual audits for production contracts.
