#!/usr/bin/env python3
"""
Solodit Auditor CLI

Command-line interface for smart contract security auditing powered by Solodit API.
"""

import argparse
import sys
import os
from pathlib import Path
from typing import Optional

from .auditor import create_auditor, SoloditAuditor
from .api_client import create_client


def print_banner():
    """Print CLI banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ███████╗ ██████╗ ██╗      ██████╗ ██████╗ ██╗████████╗                      ║
║   ██╔════╝██╔═══██╗██║     ██╔═══██╗██╔══██╗██║╚══██╔══╝                      ║
║   ███████╗██║   ██║██║     ██║   ██║██║  ██║██║   ██║                         ║
║   ╚════██║██║   ██║██║     ██║   ██║██║  ██║██║   ██║                         ║
║   ███████║╚██████╔╝███████╗╚██████╔╝██████╔╝██║   ██║                         ║
║   ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝                         ║
║                                                                               ║
║   Smart Contract Security Auditor - Powered by Cyfrin Solodit API             ║
║   🔍 50,000+ Real Vulnerabilities | 🏆 Top Audit Firms | 🚀 AI-Enhanced       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def cmd_audit(args, auditor: SoloditAuditor):
    """Handle audit command."""
    target = args.target
    path = Path(target)
    
    if not path.exists():
        print(f"❌ Error: Target not found: {target}")
        sys.exit(1)
    
    print(f"\n🔍 Analyzing: {target}")
    print("-" * 60)
    
    if path.is_file():
        if not path.suffix == '.sol':
            print(f"⚠️  Warning: {target} may not be a Solidity file")
        report = auditor.audit_file(str(path))
    else:
        report = auditor.audit_directory(str(path), recursive=not args.no_recursive)
    
    # Print summary
    print(report.format_summary())
    
    # Print detailed findings
    if report.vulnerabilities:
        print("\n📋 DETAILED FINDINGS:")
        for vuln in report.vulnerabilities:
            print(vuln.format_for_display())
    else:
        print("\n✅ No potential vulnerabilities detected!")
        print("   Note: This doesn't guarantee the code is secure. Manual review is still recommended.")
    
    # Export reports if requested
    if args.output_md:
        md_path = Path(args.output_md)
        md_path.write_text(report.to_markdown())
        print(f"\n📄 Markdown report saved to: {md_path}")
    
    if args.output_json:
        json_path = Path(args.output_json)
        json_path.write_text(report.to_json())
        print(f"\n📄 JSON report saved to: {json_path}")
    
    # Save individual findings if requested
    if args.findings_dir:
        created_files = report.save_individual_findings(args.findings_dir)
        if created_files:
            print(f"\n📁 Saved {len(created_files)} individual findings to: {args.findings_dir}/")
            for f in created_files[:5]:
                print(f"   - {Path(f).name}")
            if len(created_files) > 5:
                print(f"   ... and {len(created_files) - 5} more")
    
    # Return exit code based on findings
    if report.critical_count > 0:
        return 2
    elif report.high_count > 0:
        return 1
    return 0


def cmd_search(args, auditor: SoloditAuditor):
    """Handle search command."""
    query = args.query
    
    print(f"\n🔍 Searching Solodit for: '{query}'")
    print("-" * 60)
    
    result = auditor.quick_search(query, page_size=args.limit)
    
    if not result:
        print("❌ No findings matched your query.")
        print("   Try broader keywords or different terms.")
        return 1
    
    print(f"📊 Found {result.total_results} total matches (showing {len(result.findings)})")
    print(f"⏱️  Query time: {result.query_time:.2f}s")
    
    for finding in result.findings:
        print(finding.format_for_display(
            include_content=args.show_content,
            max_content_length=args.content_length
        ))
    
    return 0


def cmd_analyze(args, auditor: SoloditAuditor):
    """Handle analyze command (code analysis only, no API)."""
    from .analyzer import SolidityAnalyzer
    
    target = args.target
    path = Path(target)
    
    if not path.exists():
        print(f"❌ Error: Target not found: {target}")
        sys.exit(1)
    
    print(f"\n🔍 Static Analysis: {target}")
    print("-" * 60)
    
    analyzer = SolidityAnalyzer(include_medium=not args.high_only)
    
    if path.is_file():
        result = analyzer.analyze_file(str(path))
        results = [result]
    else:
        results = analyzer.analyze_directory(str(path), recursive=not args.no_recursive)
    
    total_matches = sum(len(r.matches) for r in results)
    print(f"📊 Files analyzed: {len(results)}")
    print(f"🎯 Patterns matched: {total_matches}")
    
    for result in results:
        if not result.matches:
            continue
        
        print(f"\n📁 {result.file_path or 'Code snippet'}")
        print(f"   Contracts: {', '.join(result.contract_names) or 'N/A'}")
        print(f"   Functions: {len(result.function_signatures)}")
        
        for match in result.matches:
            severity_icons = {
                "CRITICAL": "🔴",
                "HIGH": "🟠",
                "MEDIUM": "🟡"
            }
            icon = severity_icons.get(match.severity.value, "⚪")
            print(f"   {icon} [{match.severity.value}] {match.pattern_name} - Line {match.line_number}")
            if match.function_name:
                print(f"      Function: {match.function_name}()")
            print(f"      Code: {match.line_content.strip()[:80]}...")
    
    # Generate queries for manual API use
    if args.show_queries:
        print("\n📝 Suggested API Queries:")
        all_keywords = set()
        all_tags = set()
        for result in results:
            for match in result.matches:
                all_keywords.update(match.keywords[:3])
                all_tags.update(match.solodit_tags[:2])
        
        print(f"   Keywords: {' '.join(list(all_keywords)[:10])}")
        print(f"   Tags: {', '.join(list(all_tags)[:5])}")
    
    return 0


def cmd_interactive(args, auditor: SoloditAuditor):
    """Handle interactive mode."""
    print("\n🎮 Interactive Mode")
    print("   Paste your Solidity code below.")
    print("   Enter 'END' on a new line when done.")
    print("   Type 'quit' to exit.")
    print("-" * 60)
    
    while True:
        print("\n📝 Paste your code:")
        lines = []
        
        try:
            while True:
                line = input()
                if line.strip().upper() == 'END':
                    break
                if line.strip().lower() == 'quit':
                    print("👋 Goodbye!")
                    return 0
                lines.append(line)
        except EOFError:
            break
        except KeyboardInterrupt:
            print("\n👋 Goodbye!")
            return 0
        
        if not lines:
            continue
        
        code = '\n'.join(lines)
        
        if len(code.strip()) < 10:
            print("⚠️  Code too short. Please paste more content.")
            continue
        
        print("\n🔍 Analyzing...")
        report = auditor.audit_code(code, target_name="interactive snippet")
        
        print(report.format_summary())
        
        for vuln in report.vulnerabilities:
            print(vuln.format_for_display())
        
        if not report.vulnerabilities:
            print("✅ No patterns matched. Code may still have issues - manual review recommended.")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog='solodit-auditor',
        description='Smart Contract Security Auditor powered by Solodit API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Audit a single file
  solodit-auditor audit contracts/Token.sol

  # Audit a directory
  solodit-auditor audit ./contracts --output-md report.md

  # Search for findings
  solodit-auditor search "reentrancy withdraw" --limit 20

  # Static analysis only (no API)
  solodit-auditor analyze contracts/ --show-queries

  # Interactive mode
  solodit-auditor interactive

Environment Variables:
  SOLODIT_API_KEY    Your Solodit API key (get free at solodit.cyfrin.io)
        """
    )
    
    # Global options
    parser.add_argument('--api-key', '-k', 
                        help='Solodit API key (or set SOLODIT_API_KEY env var)')
    parser.add_argument('--no-cache', action='store_true',
                        help='Disable result caching')
    parser.add_argument('--high-only', action='store_true',
                        help='Only show CRITICAL and HIGH severity (exclude MEDIUM)')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='Suppress banner and verbose output')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Audit command
    audit_parser = subparsers.add_parser('audit', help='Audit Solidity files/directories')
    audit_parser.add_argument('target', help='File or directory to audit')
    audit_parser.add_argument('--no-recursive', action='store_true',
                              help='Don\'t scan subdirectories')
    audit_parser.add_argument('--output-md', '-o', metavar='FILE',
                              help='Export markdown report')
    audit_parser.add_argument('--output-json', '-j', metavar='FILE',
                              help='Export JSON report')
    audit_parser.add_argument('--findings-dir', '-f', metavar='DIR',
                              help='Save each finding to individual markdown files in this directory')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Search Solodit for findings')
    search_parser.add_argument('query', help='Search keywords')
    search_parser.add_argument('--limit', '-n', type=int, default=10,
                               help='Number of results (default: 10, max: 100)')
    search_parser.add_argument('--show-content', '-c', action='store_true',
                               help='Show full finding content')
    search_parser.add_argument('--content-length', type=int, default=500,
                               help='Max content length to display')
    
    # Analyze command (offline)
    analyze_parser = subparsers.add_parser('analyze', 
                                           help='Static analysis only (no API calls)')
    analyze_parser.add_argument('target', help='File or directory to analyze')
    analyze_parser.add_argument('--no-recursive', action='store_true',
                                help='Don\'t scan subdirectories')
    analyze_parser.add_argument('--show-queries', action='store_true',
                                help='Show suggested API queries')
    
    # Interactive command
    interactive_parser = subparsers.add_parser('interactive', 
                                                help='Interactive code analysis mode')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    if not args.quiet:
        print_banner()
    
    # Create auditor (may need API key for some commands)
    api_key = args.api_key or os.environ.get('SOLODIT_API_KEY')
    
    # Commands that need API
    needs_api = args.command in ['audit', 'search', 'interactive']
    
    if needs_api and not api_key:
        print("❌ Error: API key required.")
        print("   Set SOLODIT_API_KEY environment variable or use --api-key flag.")
        print("   Get your free API key at: https://solodit.cyfrin.io")
        sys.exit(1)
    
    try:
        auditor = create_auditor(
            api_key=api_key,
            include_medium=not args.high_only,
            enable_cache=not args.no_cache
        ) if needs_api else None
        
        if args.command == 'audit':
            exit_code = cmd_audit(args, auditor)
        elif args.command == 'search':
            exit_code = cmd_search(args, auditor)
        elif args.command == 'analyze':
            exit_code = cmd_analyze(args, auditor)
        elif args.command == 'interactive':
            exit_code = cmd_interactive(args, auditor)
        else:
            parser.print_help()
            exit_code = 0
        
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted. Goodbye!")
        sys.exit(130)
    except ValueError as e:
        print(f"\n❌ Configuration Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        if not args.quiet:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
