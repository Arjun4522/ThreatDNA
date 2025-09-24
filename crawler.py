#!/usr/bin/env python3
"""
CTI Report Crawler - Recursively crawls and scrapes public CTI reports
"""

import os
import re
import json
import time
import requests
import logging
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import BeautifulSoup
from datetime import datetime
from pathlib import Path
from typing import Set, List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cti_crawler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CTICrawler:
    def __init__(self, base_urls: List[str], max_depth: int = 3, max_workers: int = 5):
        self.base_urls = base_urls
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.visited_urls: Set[str] = set()
        self.data_dir = Path("./data")
        self.data_dir.mkdir(exist_ok=True)
        
        # Common CTI report patterns and indicators
        self.report_patterns = [
            r'report', r'analysis', r'threat', r'malware', r'apt', 
            r'intelligence', r'advisory', r'bulletin', r'whitepaper',
            r'\.pdf$', r'\.docx?$', r'\.txt$', r'\.html?$'
        ]
        
        # Common CTI sources (can be extended)
        self.known_cti_sources = [
            'mandiant', 'fireeye', 'crowdstrike', 'paloalto', 'unit42',
            'securelist', 'kaspersky', 'symantec', 'broadcom',
            'microsoft', 'securitycenter', 'blog', 'research',
            'threatpost', 'threatconnect', 'recordedfuture',
            'alienvault', 'otx', 'virustotal', 'ibm', 'x-force',
            'proofpoint', 'trendmicro', 'talos', 'cisco'
        ]

    def is_cti_report_url(self, url: str) -> bool:
        """Check if URL likely points to a CTI report"""
        url_lower = url.lower()
        
        # Check for common CTI indicators in URL
        for pattern in self.report_patterns:
            if re.search(pattern, url_lower):
                return True
        
        # Check for known CTI sources in domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        for source in self.known_cti_sources:
            if source in domain:
                return True
        
        return False

    def generate_filename(self, url: str, content: str = None) -> str:
        """Generate a meaningful filename for the HTML content"""
        parsed_url = urlparse(url)
        path = parsed_url.path.strip('/')
        
        # Extract meaningful parts from URL
        path_parts = [p for p in path.split('/') if p and len(p) > 2]
        
        if path_parts:
            # Use the last meaningful part of the path
            base_name = path_parts[-1]
        else:
            # Use domain name if path is empty
            base_name = parsed_url.netloc.split('.')[-2] if '.' in parsed_url.netloc else parsed_url.netloc
        
        # Clean the filename
        base_name = re.sub(r'[^a-zA-Z0-9_-]', '_', base_name)
        base_name = base_name.strip('_')
        
        # Add timestamp for uniqueness
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Add content hash for deduplication
        if content:
            content_hash = hashlib.md5(content.encode()).hexdigest()[:8]
            return f"{base_name}_{timestamp}_{content_hash}.html"
        else:
            return f"{base_name}_{timestamp}.html"

    def fetch_url(self, url: str) -> Optional[requests.Response]:
        """Fetch URL with proper headers and error handling"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            response.raise_for_status()
            
            # Check if content is HTML
            content_type = response.headers.get('content-type', '').lower()
            if 'text/html' not in content_type:
                return None
                
            return response
            
        except requests.RequestException as e:
            logger.warning(f"Failed to fetch {url}: {e}")
            return None

    def extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract all links from the page"""
        links = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            
            # Handle relative URLs
            full_url = urljoin(base_url, href)
            
            # Clean URL (remove fragments, etc.)
            parsed = urlparse(full_url)
            cleaned_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                ''
            ))
            
            # Only process HTTP/HTTPS URLs
            if cleaned_url.startswith(('http://', 'https://')):
                links.append(cleaned_url)
        
        return links

    def save_content(self, url: str, content: str):
        """Save HTML content to file"""
        filename = self.generate_filename(url, content)
        filepath = self.data_dir / filename
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"<!-- Source URL: {url} -->\n")
                f.write(f"<!-- Crawled: {datetime.now().isoformat()} -->\n")
                f.write(content)
            logger.info(f"Saved: {filename}")
        except IOError as e:
            logger.error(f"Failed to save {filename}: {e}")

    def process_url(self, url: str, depth: int = 0):
        """Process a single URL"""
        if depth > self.max_depth:
            return []
        
        if url in self.visited_urls:
            return []
        
        self.visited_urls.add(url)
        logger.info(f"Processing: {url} (depth: {depth})")
        
        response = self.fetch_url(url)
        if not response:
            return []
        
        content = response.text
        soup = BeautifulSoup(content, 'html.parser')
        
        # Check if this is a CTI report
        if self.is_cti_report_url(url):
            self.save_content(url, content)
        
        # Extract links for further crawling
        new_links = self.extract_links(soup, url)
        return new_links

    def crawl(self):
        """Main crawling function"""
        logger.info("Starting CTI report crawler...")
        
        # Initial URLs to process
        urls_to_process = self.base_urls.copy()
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            depth = 0
            
            while urls_to_process and depth <= self.max_depth:
                logger.info(f"Depth {depth}: Processing {len(urls_to_process)} URLs")
                
                # Process current level URLs
                future_to_url = {
                    executor.submit(self.process_url, url, depth): url 
                    for url in urls_to_process
                }
                
                # Collect results and new URLs
                new_urls = []
                for future in as_completed(future_to_url):
                    try:
                        links = future.result()
                        new_urls.extend(links)
                    except Exception as e:
                        url = future_to_url[future]
                        logger.error(f"Error processing {url}: {e}")
                
                # Prepare for next depth level
                urls_to_process = list(set(new_urls) - self.visited_urls)
                depth += 1
                
                # Small delay to be respectful
                time.sleep(1)
        
        logger.info("Crawling completed!")

    def run_realtime(self, interval_minutes: int = 60):
        """Run crawler in real-time mode with periodic execution"""
        logger.info(f"Starting real-time crawler (interval: {interval_minutes} minutes)")
        
        while True:
            try:
                self.crawl()
                logger.info(f"Sleeping for {interval_minutes} minutes...")
                time.sleep(interval_minutes * 60)
                
                # Clear visited URLs for next run (but keep data)
                self.visited_urls.clear()
                
            except KeyboardInterrupt:
                logger.info("Crawler stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in real-time loop: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying

def main():
    parser = argparse.ArgumentParser(description='CTI Report Crawler')
    parser.add_argument('--urls', nargs='+', help='Base URLs to start crawling from')
    parser.add_argument('--depth', type=int, default=3, help='Maximum crawl depth')
    parser.add_argument('--workers', type=int, default=5, help='Number of concurrent workers')
    parser.add_argument('--realtime', action='store_true', help='Run in real-time mode')
    parser.add_argument('--interval', type=int, default=60, help='Interval in minutes for real-time mode')
    
    args = parser.parse_args()
    
    # Default CTI sources if none provided
    default_urls = [
        'https://www.mandiant.com/resources/blog',
        'https://unit42.paloaltonetworks.com/',
        'https://www.securelist.com/',
        'https://www.crowdstrike.com/blog/',
        'https://www.microsoft.com/security/blog/',
        'https://www.proofpoint.com/us/threat-insight',
        'https://blog.talosintelligence.com/',
        'https://www.ibm.com/security/security-intelligence'
    ]
    
    urls = args.urls if args.urls else default_urls
    
    crawler = CTICrawler(urls, max_depth=args.depth, max_workers=args.workers)
    
    if args.realtime:
        crawler.run_realtime(args.interval)
    else:
        crawler.crawl()

if __name__ == "__main__":
    main()