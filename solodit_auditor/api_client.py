"""
Solodit API Client

Handles all communication with the Cyfrin Solodit Findings API.
"""

import os
import json
import time
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
import requests

from .patterns import Severity


@dataclass
class Finding:
    """Represents a single finding from Solodit."""
    id: str
    title: str
    impact: str
    content: str
    summary: Optional[str]
    firm_name: Optional[str]
    protocol_name: Optional[str]
    report_date: Optional[str]
    quality_score: float
    rarity_score: float
    tags: List[str]
    slug: str
    github_link: Optional[str]
    url: str
    
    @classmethod
    def from_api_response(cls, data: Dict) -> 'Finding':
        """Create Finding from API response data."""
        # Extract tags from nested structure
        tags = []
        for tag_entry in data.get('issues_issuetagscore', []):
            if 'tags_tag' in tag_entry and 'title' in tag_entry['tags_tag']:
                tags.append(tag_entry['tags_tag']['title'])
        
        return cls(
            id=data.get('id', ''),
            title=data.get('title', 'Untitled'),
            impact=data.get('impact', 'UNKNOWN'),
            content=data.get('content', ''),
            summary=data.get('summary'),
            firm_name=data.get('firm_name'),
            protocol_name=data.get('protocol_name'),
            report_date=data.get('report_date'),
            quality_score=float(data.get('quality_score', 0)),
            rarity_score=float(data.get('general_score', 0)),
            tags=tags,
            slug=data.get('slug', ''),
            github_link=data.get('github_link'),
            url=f"https://solodit.cyfrin.io/issues/{data.get('slug', '')}"
        )
    
    def format_for_display(self, include_content: bool = True, max_content_length: int = 1000) -> str:
        """Format finding for terminal display."""
        severity_colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
        }
        reset = '\033[0m'
        
        color = severity_colors.get(self.impact.upper(), '')
        
        output = []
        output.append(f"\n{'='*80}")
        output.append(f"{color}[{self.impact}]{reset} {self.title}")
        output.append(f"{'='*80}")
        output.append(f"Quality: {self.quality_score:.1f}/5 | Rarity: {self.rarity_score:.1f}/5")
        output.append(f"Firm: {self.firm_name or 'N/A'} | Protocol: {self.protocol_name or 'N/A'}")
        output.append(f"Date: {self.report_date or 'N/A'}")
        
        if self.tags:
            output.append(f"Tags: {', '.join(self.tags)}")
        
        if self.summary:
            output.append(f"\nSummary: {self.summary}")
        
        if include_content and self.content:
            content = self.content[:max_content_length]
            if len(self.content) > max_content_length:
                content += "..."
            output.append(f"\nContent:\n{content}")
        
        output.append(f"\n🔗 Link: {self.url}")
        if self.github_link:
            output.append(f"📁 GitHub: {self.github_link}")
        
        return '\n'.join(output)
    
    def to_markdown(self) -> str:
        """Convert finding to markdown format for reports."""
        md = []
        md.append(f"### [{self.impact}] {self.title}")
        md.append("")
        md.append(f"**Quality Score:** {self.quality_score:.1f}/5 | **Rarity:** {self.rarity_score:.1f}/5")
        md.append(f"**Audit Firm:** {self.firm_name or 'N/A'} | **Protocol:** {self.protocol_name or 'N/A'}")
        md.append(f"**Date:** {self.report_date or 'N/A'}")
        md.append("")
        
        if self.tags:
            md.append(f"**Tags:** {', '.join(self.tags)}")
            md.append("")
        
        if self.summary:
            md.append(f"**Summary:** {self.summary}")
            md.append("")
        
        if self.content:
            md.append("**Details:**")
            md.append(self.content)
            md.append("")
        
        md.append(f"[View on Solodit]({self.url})")
        if self.github_link:
            md.append(f" | [GitHub Report]({self.github_link})")
        
        return '\n'.join(md)


@dataclass
class SearchResult:
    """Represents search results from Solodit API."""
    total_results: int
    page: int
    page_size: int
    findings: List[Finding]
    query_keywords: str
    query_time: float
    
    def __bool__(self):
        return len(self.findings) > 0


class SoloditAPIClient:
    """Client for interacting with the Solodit API."""
    
    BASE_URL = "https://solodit.cyfrin.io/api/v1/solodit/findings"
    RATE_LIMIT_REQUESTS = 20  # API limit: 20 requests per 60s
    RATE_LIMIT_WINDOW = 60  # seconds
    
    # Valid impact levels in the API (no CRITICAL - maps to HIGH)
    VALID_IMPACTS = ["HIGH", "MEDIUM", "LOW", "GAS"]
    
    def __init__(self, api_key: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        Initialize the API client.
        
        Args:
            api_key: Solodit API key. If not provided, looks for SOLODIT_API_KEY env var.
            cache_dir: Directory for caching results. If None, caching is disabled.
        """
        self.api_key = api_key or os.environ.get('SOLODIT_API_KEY')
        if not self.api_key:
            raise ValueError(
                "API key required. Set SOLODIT_API_KEY environment variable or pass api_key parameter.\n"
                "Get your free API key at: https://solodit.cyfrin.io (top-right menu → API Keys)"
            )
        
        self.session = requests.Session()
        self.session.headers.update({
            'X-Cyfrin-API-Key': self.api_key,
            'Content-Type': 'application/json'
        })
        
        # Rate limiting
        self._request_times: List[float] = []
        
        # Caching
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def _check_rate_limit(self):
        """Enforce rate limiting."""
        now = time.time()
        # Remove old request times
        self._request_times = [t for t in self._request_times if now - t < self.RATE_LIMIT_WINDOW]
        
        if len(self._request_times) >= self.RATE_LIMIT_REQUESTS:
            wait_time = self.RATE_LIMIT_WINDOW - (now - self._request_times[0])
            if wait_time > 0:
                print(f"Rate limit approaching. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time)
        
        self._request_times.append(now)
    
    def _get_cache_key(self, params: Dict) -> str:
        """Generate cache key for query parameters."""
        param_str = json.dumps(params, sort_keys=True)
        return hashlib.md5(param_str.encode()).hexdigest()
    
    def _get_cached(self, cache_key: str) -> Optional[Dict]:
        """Get cached result if available and fresh."""
        if not self.cache_dir:
            return None
        
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text())
                # Cache valid for 24 hours
                cached_time = datetime.fromisoformat(data.get('_cached_at', '2000-01-01'))
                if datetime.now() - cached_time < timedelta(hours=24):
                    return data
            except (json.JSONDecodeError, ValueError):
                pass
        
        return None
    
    def _save_cache(self, cache_key: str, data: Dict):
        """Save result to cache."""
        if not self.cache_dir:
            return
        
        data['_cached_at'] = datetime.now().isoformat()
        cache_file = self.cache_dir / f"{cache_key}.json"
        cache_file.write_text(json.dumps(data, indent=2))
    
    def search(
        self,
        keywords: str,
        impact: Optional[List[str]] = None,
        min_quality: int = 3,
        min_rarity: int = 1,
        tags: Optional[List[str]] = None,
        firms: Optional[List[str]] = None,
        protocol_category: Optional[str] = None,
        days_ago: Optional[int] = None,
        page: int = 1,
        page_size: int = 10,
        sort_by: str = "Quality",
        sort_direction: str = "Desc",
        use_cache: bool = True
    ) -> SearchResult:
        """
        Search Solodit for findings.
        
        Args:
            keywords: Search keywords (e.g., "reentrancy external call")
            impact: List of severity levels ["CRITICAL", "HIGH", "MEDIUM"]
            min_quality: Minimum quality score (1-5)
            min_rarity: Minimum rarity score (1-5)
            tags: Filter by tags (e.g., ["Reentrancy", "Access-Control"])
            firms: Filter by audit firms (e.g., ["Cyfrin", "Code4rena"])
            protocol_category: Filter by protocol type (e.g., "DeFi", "NFT")
            days_ago: Only findings from last N days
            page: Page number
            page_size: Results per page (max 100)
            sort_by: Sort field ("Quality", "Recency", "Rarity")
            sort_direction: "Asc" or "Desc"
            use_cache: Whether to use cached results
            
        Returns:
            SearchResult with findings
        """
        # Default to HIGH and MEDIUM if not specified (no LOW/GAS as per requirement)
        # Note: Solodit API uses HIGH/MEDIUM/LOW/GAS (no CRITICAL level)
        # We map CRITICAL -> HIGH internally
        if impact is None:
            impact = ["HIGH", "MEDIUM"]
        else:
            # Map CRITICAL to HIGH and filter to valid values only
            mapped_impact = []
            for i in impact:
                if i.upper() == "CRITICAL":
                    if "HIGH" not in mapped_impact:
                        mapped_impact.append("HIGH")
                elif i.upper() in self.VALID_IMPACTS:
                    if i.upper() not in mapped_impact:
                        mapped_impact.append(i.upper())
            impact = mapped_impact if mapped_impact else ["HIGH", "MEDIUM"]
        
        # Build payload
        payload = {
            "page": page,
            "pageSize": min(page_size, 100),
            "filters": {
                "keywords": keywords,
                "impact": impact,
                "qualityScore": min_quality,
                "rarityScore": min_rarity,
                "sortField": sort_by,
                "sortDirection": sort_direction
            }
        }
        
        if tags:
            payload["filters"]["tags"] = [{"value": t} for t in tags]
        
        if firms:
            payload["filters"]["firms"] = [{"value": f} for f in firms]
        
        if protocol_category:
            payload["filters"]["protocolCategory"] = [{"value": protocol_category}]
        
        if days_ago:
            payload["filters"]["reported"] = {"value": str(days_ago)}
        
        # Check cache
        cache_key = self._get_cache_key(payload)
        if use_cache:
            cached = self._get_cached(cache_key)
            if cached:
                return self._parse_response(cached, keywords, 0)
        
        # Make request
        self._check_rate_limit()
        start_time = time.time()
        
        try:
            response = self.session.post(self.BASE_URL, json=payload)
            response.raise_for_status()
            data = response.json()
            
            # Cache successful response
            if use_cache:
                self._save_cache(cache_key, data)
            
            query_time = time.time() - start_time
            return self._parse_response(data, keywords, query_time)
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                print("Rate limit hit. Waiting 60 seconds...")
                time.sleep(60)
                return self.search(
                    keywords, impact, min_quality, min_rarity, tags, firms,
                    protocol_category, days_ago, page, page_size, sort_by, sort_direction, False
                )
            elif e.response.status_code == 401:
                raise ValueError("Invalid API key. Please check your SOLODIT_API_KEY.")
            else:
                raise
    
    def _parse_response(self, data: Dict, keywords: str, query_time: float) -> SearchResult:
        """Parse API response into SearchResult."""
        findings = [
            Finding.from_api_response(f) 
            for f in data.get('findings', [])
        ]
        
        metadata = data.get('metadata', {})
        
        return SearchResult(
            total_results=metadata.get('totalResults', len(findings)),
            page=metadata.get('page', 1),
            page_size=metadata.get('pageSize', len(findings)),
            findings=findings,
            query_keywords=keywords,
            query_time=query_time
        )
    
    def search_by_pattern(
        self,
        pattern_name: str,
        keywords: List[str],
        tags: List[str],
        severity: Severity,
        page_size: int = 5
    ) -> SearchResult:
        """
        Search for findings matching a specific vulnerability pattern.
        
        Args:
            pattern_name: Name of the vulnerability pattern
            keywords: Keywords extracted from pattern
            tags: Solodit tags from pattern
            severity: Expected severity level
            page_size: Number of results
            
        Returns:
            SearchResult
        """
        # Build keyword string from list - use just the first keyword for better results
        keyword_str = keywords[0] if keywords else pattern_name
        
        # Map severity to impact filter 
        # Note: API only has HIGH/MEDIUM/LOW/GAS (no CRITICAL)
        impact_map = {
            Severity.CRITICAL: ["HIGH"],  # CRITICAL maps to HIGH
            Severity.HIGH: ["HIGH"],
            Severity.MEDIUM: ["HIGH", "MEDIUM"]
        }
        
        return self.search(
            keywords=keyword_str,
            impact=impact_map.get(severity, ["HIGH", "MEDIUM"]),
            tags=None,  # Don't filter by tags - reduces results too much
            min_quality=3,
            page_size=page_size,
            sort_by="Quality"
        )
    
    def get_finding_by_id(self, finding_id: str) -> Optional[Finding]:
        """
        Get a specific finding by its ID.
        
        Args:
            finding_id: The unique finding ID
            
        Returns:
            Finding or None if not found
        """
        self._check_rate_limit()
        
        try:
            response = self.session.get(f"{self.BASE_URL}/{finding_id}")
            response.raise_for_status()
            data = response.json()
            return Finding.from_api_response(data)
        except requests.exceptions.HTTPError:
            return None


def create_client(api_key: Optional[str] = None, enable_cache: bool = True) -> SoloditAPIClient:
    """
    Factory function to create a Solodit API client.
    
    Args:
        api_key: API key (or set SOLODIT_API_KEY env var)
        enable_cache: Whether to enable result caching
        
    Returns:
        Configured SoloditAPIClient
    """
    cache_dir = None
    if enable_cache:
        cache_dir = str(Path.home() / '.cache' / 'solodit-auditor')
    
    return SoloditAPIClient(api_key=api_key, cache_dir=cache_dir)
