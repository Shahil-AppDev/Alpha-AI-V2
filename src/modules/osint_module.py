"""
OSINT Module for Open Source Intelligence gathering.
Implements various OSINT techniques including web scraping, WHOIS, DNS queries, and data extraction.
"""

import re
import json
import time
import logging
import socket
import subprocess
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass

import requests
from bs4 import BeautifulSoup
import dns.resolver
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class OSINTResult:
    """Structured result for OSINT operations."""
    query: str
    timestamp: str
    domains: List[str]
    ip_addresses: List[str]
    email_addresses: List[str]
    phone_numbers: List[str]
    social_media_profiles: List[str]
    subdomains: List[str]
    technologies: List[str]
    whois_info: Dict[str, Any]
    dns_records: Dict[str, List[str]]
    web_content: Dict[str, Any]
    error_messages: List[str]


class OSINTModule:
    """
    OSINT module for gathering intelligence from open sources.
    """
    
    def __init__(self, delay_between_requests: float = 1.0, timeout: int = 30):
        """
        Initialize the OSINT module.
        
        Args:
            delay_between_requests: Delay between requests to avoid rate limiting
            timeout: Request timeout in seconds
        """
        self.delay = delay_between_requests
        self.timeout = timeout
        self.session = self._create_session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy."""
        session = requests.Session()
        
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _make_request(self, url: str, headers: Optional[Dict] = None) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling and rate limiting.
        
        Args:
            url: URL to request
            headers: Optional headers
            
        Returns:
            Response object or None if failed
        """
        try:
            time.sleep(self.delay)
            
            default_headers = {
                'User-Agent': self.user_agents[0],
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            if headers:
                default_headers.update(headers)
            
            response = self.session.get(url, headers=default_headers, timeout=self.timeout)
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            return None
    
    def _extract_emails(self, text: str) -> List[str]:
        """Extract email addresses from text."""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(email_pattern, text, re.IGNORECASE)))
    
    def _extract_phone_numbers(self, text: str) -> List[str]:
        """Extract phone numbers from text."""
        phone_patterns = [
            r'\b\d{3}-\d{3}-\d{4}\b',  # 555-555-5555
            r'\b\(\d{3}\)\s*\d{3}-\d{4}\b',  # (555) 555-5555
            r'\b\d{3}\.\d{3}\.\d{4}\b',  # 555.555.5555
            r'\b\d{10}\b',  # 5555555555
            r'\+\d{1,3}\s*\d{3,}\s*\d{3,}\s*\d{4}\b'  # +1 555 555 5555
        ]
        
        phones = []
        for pattern in phone_patterns:
            phones.extend(re.findall(pattern, text))
        
        return list(set(phones))
    
    def _extract_ip_addresses(self, text: str) -> List[str]:
        """Extract IP addresses from text."""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, text)
        
        # Filter out invalid IPs
        valid_ips = []
        for ip in ips:
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                valid_ips.append(ip)
        
        return list(set(valid_ips))
    
    def _extract_domains(self, text: str) -> List[str]:
        """Extract domain names from text."""
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        return list(set(re.findall(domain_pattern, text, re.IGNORECASE)))
    
    def _extract_social_media_profiles(self, text: str) -> List[str]:
        """Extract social media profile URLs."""
        social_patterns = [
            r'https?://(?:www\.)?facebook\.com/[^\s]+',
            r'https?://(?:www\.)?twitter\.com/[^\s]+',
            r'https?://(?:www\.)?linkedin\.com/[^\s]+',
            r'https?://(?:www\.)?instagram\.com/[^\s]+',
            r'https?://(?:www\.)?youtube\.com/[^\s]+',
            r'https?://(?:www\.)?github\.com/[^\s]+',
        ]
        
        profiles = []
        for pattern in social_patterns:
            profiles.extend(re.findall(pattern, text, re.IGNORECASE))
        
        return list(set(profiles))
    
    def _perform_whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup for a domain."""
        try:
            # Try using system whois command
            result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                whois_data = result.stdout
                
                # Parse key information
                info = {
                    'registrar': self._extract_whois_field(whois_data, ['Registrar:', 'registrar:']),
                    'creation_date': self._extract_whois_field(whois_data, ['Creation Date:', 'created:', 'registered:']),
                    'expiration_date': self._extract_whois_field(whois_data, ['Expiration Date:', 'expires:']),
                    'updated_date': self._extract_whois_field(whois_data, ['Updated Date:', 'last updated:']),
                    'name_servers': self._extract_name_servers(whois_data),
                    'status': self._extract_whois_field(whois_data, ['Status:', 'status:']),
                    'raw_data': whois_data[:1000] + '...' if len(whois_data) > 1000 else whois_data
                }
                
                return info
            else:
                return {'error': 'WHOIS command failed', 'raw_data': result.stderr}
                
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return {'error': str(e)}
    
    def _extract_whois_field(self, data: str, field_names: List[str]) -> Optional[str]:
        """Extract specific field from WHOIS data."""
        for field_name in field_names:
            pattern = f'{field_name}\\s*(.+?)(?=\\n|$)'
            match = re.search(pattern, data, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return None
    
    def _extract_name_servers(self, data: str) -> List[str]:
        """Extract name servers from WHOIS data."""
        ns_pattern = r'Name Server:\s*([^\n]+)'
        return [ns.strip() for ns in re.findall(ns_pattern, data, re.IGNORECASE)]
    
    def _perform_dns_query(self, domain: str) -> Dict[str, List[str]]:
        """Perform DNS queries for a domain."""
        dns_records = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'NS': [],
            'TXT': [],
            'CNAME': [],
            'SOA': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            resolver.lifetime = 10
            
            for record_type in dns_records.keys():
                try:
                    answers = resolver.resolve(domain, record_type)
                    dns_records[record_type] = [str(answer) for answer in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, Exception) as e:
                    logger.debug(f"DNS {record_type} query failed for {domain}: {e}")
                    dns_records[record_type] = []
                    
        except Exception as e:
            logger.error(f"DNS query failed for {domain}: {e}")
            
        return dns_records
    
    def _search_google_dorks(self, query: str) -> Dict[str, Any]:
        """Perform Google dork searches (simulated)."""
        # Note: This is a simulated implementation
        # Real Google scraping would require more sophisticated handling
        
        dorks = [
            f'site:{query}',
            f'site:{query} ext:php',
            f'site:{query} ext:asp',
            f'site:{query} ext:jsp',
            f'inurl:admin {query}',
            f'inurl:login {query}',
            f'filetype:pdf {query}',
            f'filetype:doc {query}',
            f'filetype:xls {query}'
        ]
        
        results = {
            'dorks_used': dorks,
            'findings': [],
            'note': 'Google dork search is simulated. Real implementation would require proper API access or scraping techniques.'
        }
        
        # Simulate findings based on query patterns
        if '.' in query:
            results['findings'].extend([
                f'Potential admin panel: admin.{query}',
                f'Potential login page: login.{query}',
                f'Potential API endpoint: api.{query}'
            ])
        
        return results
    
    def _analyze_web_content(self, url: str) -> Dict[str, Any]:
        """Analyze web content for information."""
        try:
            response = self._make_request(url)
            if not response:
                return {'error': 'Failed to fetch content'}
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract text content
            text = soup.get_text()
            
            # Extract meta information
            meta_info = {}
            for meta in soup.find_all('meta'):
                name = meta.get('name') or meta.get('property')
                content = meta.get('content')
                if name and content:
                    meta_info[name] = content
            
            # Extract technologies
            technologies = []
            
            # Check for common technologies
            if 'wordpress' in text.lower():
                technologies.append('WordPress')
            if 'joomla' in text.lower():
                technologies.append('Joomla')
            if 'drupal' in text.lower():
                technologies.append('Drupal')
            if 'bootstrap' in text.lower():
                technologies.append('Bootstrap')
            if 'jquery' in text.lower():
                technologies.append('jQuery')
            if 'react' in text.lower():
                technologies.append('React')
            if 'angular' in text.lower():
                technologies.append('Angular')
            if 'vue' in text.lower():
                technologies.append('Vue.js')
            
            # Extract links
            links = []
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http'):
                    links.append(href)
            
            # Extract scripts
            scripts = []
            for script in soup.find_all('script', src=True):
                src = script['src']
                if src.startswith('http') or src.startswith('//'):
                    scripts.append(src)
            
            return {
                'title': soup.title.string if soup.title else 'No title',
                'meta_info': meta_info,
                'technologies': list(set(technologies)),
                'links_count': len(links),
                'scripts_count': len(scripts),
                'content_length': len(text),
                'emails': self._extract_emails(text),
                'phones': self._extract_phone_numbers(text),
                'ips': self._extract_ip_addresses(text),
                'domains': self._extract_domains(text),
                'social_profiles': self._extract_social_media_profiles(text)
            }
            
        except Exception as e:
            logger.error(f"Web content analysis failed for {url}: {e}")
            return {'error': str(e)}
    
    def osint_search(self, query: str) -> Dict[str, Any]:
        """
        Perform comprehensive OSINT search.
        
        Args:
            query: Search query (domain, company name, etc.)
            
        Returns:
            Dictionary with structured OSINT findings
        """
        from datetime import datetime
        
        logger.info(f"Starting OSINT search for: {query}")
        
        result = OSINTResult(
            query=query,
            timestamp=datetime.now().isoformat(),
            domains=[],
            ip_addresses=[],
            email_addresses=[],
            phone_numbers=[],
            social_media_profiles=[],
            subdomains=[],
            technologies=[],
            whois_info={},
            dns_records={},
            web_content={},
            error_messages=[]
        )
        
        try:
            # Clean and normalize query
            query = query.strip().lower()
            
            # Extract potential domain from query
            potential_domain = None
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', query):
                potential_domain = query
            elif '.' in query:
                # Try to extract domain from longer query
                domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', query)
                if domain_match:
                    potential_domain = domain_match.group(1)
            
            # 1. Google Dorks Search
            logger.info("Performing Google dorks search...")
            google_results = self._search_google_dorks(query)
            result.web_content['google_dorks'] = google_results
            
            # 2. Web Content Analysis (if domain found)
            if potential_domain:
                logger.info(f"Analyzing web content for {potential_domain}...")
                
                # Analyze main domain
                web_analysis = self._analyze_web_content(f"https://{potential_domain}")
                result.web_content['main_domain'] = web_analysis
                
                # Analyze www subdomain
                www_analysis = self._analyze_web_content(f"https://www.{potential_domain}")
                result.web_content['www_domain'] = www_analysis
                
                # Extract data from web content
                for analysis in [web_analysis, www_analysis]:
                    if 'error' not in analysis:
                        result.email_addresses.extend(analysis.get('emails', []))
                        result.phone_numbers.extend(analysis.get('phones', []))
                        result.ip_addresses.extend(analysis.get('ips', []))
                        result.domains.extend(analysis.get('domains', []))
                        result.social_media_profiles.extend(analysis.get('social_profiles', []))
                        result.technologies.extend(analysis.get('technologies', []))
                
                # 3. WHOIS Lookup
                logger.info(f"Performing WHOIS lookup for {potential_domain}...")
                result.whois_info = self._perform_whois_lookup(potential_domain)
                
                # 4. DNS Query
                logger.info(f"Performing DNS queries for {potential_domain}...")
                result.dns_records = self._perform_dns_query(potential_domain)
                
                # Extract IPs from DNS records
                if 'A' in result.dns_records:
                    result.ip_addresses.extend(result.dns_records['A'])
                if 'AAAA' in result.dns_records:
                    result.ip_addresses.extend(result.dns_records['AAAA'])
                
                # Extract subdomains from DNS records
                if 'NS' in result.dns_records:
                    result.subdomains.extend(result.dns_records['NS'])
            
            # 5. Remove duplicates and clean data
            result.email_addresses = list(set(result.email_addresses))
            result.phone_numbers = list(set(result.phone_numbers))
            result.ip_addresses = list(set(result.ip_addresses))
            result.domains = list(set(result.domains))
            result.social_media_profiles = list(set(result.social_media_profiles))
            result.technologies = list(set(result.technologies))
            result.subdomains = list(set(result.subdomains))
            
            # 6. Generate summary
            summary = {
                'total_findings': len(result.email_addresses) + len(result.phone_numbers) + 
                                len(result.ip_addresses) + len(result.domains) + 
                                len(result.social_media_profiles),
                'emails_found': len(result.email_addresses),
                'phones_found': len(result.phone_numbers),
                'ips_found': len(result.ip_addresses),
                'domains_found': len(result.domains),
                'social_profiles_found': len(result.social_media_profiles),
                'technologies_found': len(result.technologies),
                'has_whois_info': bool(result.whois_info and 'error' not in result.whois_info),
                'has_dns_info': any(result.dns_records.values()),
                'web_analyzed': bool(result.web_content.get('main_domain') or result.web_content.get('www_domain'))
            }
            
            logger.info(f"OSINT search completed for {query}")
            logger.info(f"Summary: {summary}")
            
            return {
                'query': query,
                'timestamp': result.timestamp,
                'summary': summary,
                'findings': {
                    'email_addresses': result.email_addresses,
                    'phone_numbers': result.phone_numbers,
                    'ip_addresses': result.ip_addresses,
                    'domains': result.domains,
                    'social_media_profiles': result.social_media_profiles,
                    'subdomains': result.subdomains,
                    'technologies': result.technologies
                },
                'whois_info': result.whois_info,
                'dns_records': result.dns_records,
                'web_content': result.web_content,
                'status': 'completed',
                'error_messages': result.error_messages
            }
            
        except Exception as e:
            error_msg = f"OSINT search failed: {str(e)}"
            logger.error(error_msg)
            result.error_messages.append(error_msg)
            
            return {
                'query': query,
                'timestamp': result.timestamp,
                'status': 'failed',
                'error': error_msg,
                'error_messages': result.error_messages
            }


# Global OSINT module instance
_osint_module = None

def get_osint_module() -> OSINTModule:
    """Get or create the global OSINT module instance."""
    global _osint_module
    if _osint_module is None:
        _osint_module = OSINTModule()
    return _osint_module

def osint_search(query: str) -> Dict[str, Any]:
    """
    OSINT search function for ToolManager integration.
    
    Args:
        query: Search query (domain, company name, etc.)
        
    Returns:
        Dictionary with OSINT findings
    """
    try:
        osint = get_osint_module()
        return osint.osint_search(query)
    except Exception as e:
        logger.error(f"OSINT search error: {e}")
        return {
            'query': query,
            'status': 'failed',
            'error': str(e)
        }


# Test function
if __name__ == "__main__":
    # Test the OSINT module
    osint = OSINTModule()
    
    # Test with a domain
    result = osint.osint_search("example.com")
    print("=== OSINT Search Results ===")
    print(json.dumps(result, indent=2))
    
    # Test with a company name
    result2 = osint.osint_search("test company")
    print("\n=== Company Search Results ===")
    print(json.dumps(result2, indent=2))
