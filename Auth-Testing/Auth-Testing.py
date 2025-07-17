#!/usr/bin/env python3
"""
Cookie Authentication Testing Script for Burp Suite XML Files
Extracts cookies from Cookie headers in HTTP requests for auth testing
"""

import xml.etree.ElementTree as ET
import argparse
import os
from pathlib import Path
from collections import defaultdict
import json
import re
import base64


class BurpCookieAuthTester:
    def __init__(self, xml1_path, xml2_path, debug=False):
        self.xml1_path = xml1_path
        self.xml2_path = xml2_path
        self.xml1_name = Path(xml1_path).stem
        self.xml2_name = Path(xml2_path).stem
        self.debug = debug
        
        # Data structures for analysis
        self.endpoints1 = {}  # {endpoint: {index: {cookie_name: cookie_value}}}
        self.endpoints2 = {}
        self.shared_endpoints = set()
        self.unique_endpoints1 = set()
        self.unique_endpoints2 = set()
        self.shared_cookies = defaultdict(set)  # {endpoint: {cookie_names}}
        
    def extract_cookies_from_header(self, cookie_header):
        """Extract cookies from Cookie header value"""
        cookies = {}
        if not cookie_header:
            return cookies
            
        # Split by semicolon and parse each cookie
        cookie_pairs = cookie_header.split(';')
        for pair in cookie_pairs:
            pair = pair.strip()
            if '=' in pair:
                name, value = pair.split('=', 1)
                cookies[name.strip()] = value.strip()
        
        return cookies
    
    def parse_burp_xml(self, xml_path):
        """Parse Burp Suite XML file and extract endpoint and cookie information"""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        endpoints = {}
        
        if self.debug:
            print(f"\nParsing Burp Suite XML: {xml_path}")
        
        # Burp Suite uses <item> elements
        items = root.findall('.//item')
        
        if self.debug:
            print(f"Found {len(items)} items in Burp XML")
        
        for idx, item in enumerate(items):
            # Extract URL/endpoint
            url_elem = item.find('.//url')
            if url_elem is None or not url_elem.text:
                if self.debug:
                    print(f"  Item {idx}: No URL found, skipping")
                continue
            
            endpoint = url_elem.text.strip()
            
            # Extract just the path and host for endpoint matching
            # This helps match endpoints even if query parameters differ
            from urllib.parse import urlparse
            parsed = urlparse(endpoint)
            endpoint_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            if self.debug:
                print(f"  Item {idx}: Endpoint = {endpoint_key}")
            
            # Extract cookies from request
            cookies = {}
            
            # Get the request element
            request_elem = item.find('.//request')
            if request_elem is not None:
                request_text = request_elem.text
                
                # Decode if base64 encoded
                if request_elem.get('base64') == 'true':
                    try:
                        request_text = base64.b64decode(request_text).decode('utf-8', errors='ignore')
                    except:
                        if self.debug:
                            print(f"    Failed to decode base64 request")
                        continue
                
                if request_text:
                    # Extract Cookie header from raw HTTP request
                    # Look for "Cookie: " at the beginning of a line
                    cookie_matches = re.findall(r'^Cookie:\s*(.+)$', request_text, re.MULTILINE | re.IGNORECASE)
                    
                    for cookie_line in cookie_matches:
                        # Remove any trailing HTTP line endings
                        cookie_line = cookie_line.rstrip('\r\n')
                        extracted = self.extract_cookies_from_header(cookie_line)
                        cookies.update(extracted)
                        
                        if self.debug and extracted:
                            print(f"    Found cookies: {list(extracted.keys())}")
            
            # Only store if we found cookies
            if cookies:
                if endpoint_key not in endpoints:
                    endpoints[endpoint_key] = {}
                endpoints[endpoint_key][idx] = cookies
            elif self.debug:
                print(f"    No cookies found in request")
        
        if self.debug:
            print(f"\nTotal endpoints with cookies: {len(endpoints)}")
            total_cookies = sum(len(cookies) for ep_data in endpoints.values() for cookies in ep_data.values())
            print(f"Total cookie values found: {total_cookies}")
        
        return endpoints
    
    def analyze_endpoints(self):
        """Analyze shared and unique endpoints between the two XML files"""
        endpoints1_set = set(self.endpoints1.keys())
        endpoints2_set = set(self.endpoints2.keys())
        
        self.shared_endpoints = endpoints1_set & endpoints2_set
        self.unique_endpoints1 = endpoints1_set - endpoints2_set
        self.unique_endpoints2 = endpoints2_set - endpoints1_set
        
        # Analyze shared cookies on shared endpoints
        for endpoint in self.shared_endpoints:
            cookies1 = set()
            cookies2 = set()
            
            for idx_data in self.endpoints1[endpoint].values():
                cookies1.update(idx_data.keys())
            
            for idx_data in self.endpoints2[endpoint].values():
                cookies2.update(idx_data.keys())
            
            self.shared_cookies[endpoint] = cookies1 & cookies2
            
            if self.debug and self.shared_cookies[endpoint]:
                print(f"Shared cookies on {endpoint}: {self.shared_cookies[endpoint]}")
    
    def generate_wordlists(self):
        """Generate wordlists for authentication testing"""
        base_dir = Path("Auth-Testing")
        base_dir.mkdir(exist_ok=True)
        
        # Create subdirectories for each XML file
        xml1_dir = base_dir / self.xml1_name
        xml2_dir = base_dir / self.xml2_name
        xml1_dir.mkdir(exist_ok=True)
        xml2_dir.mkdir(exist_ok=True)
        
        # Process XML1 indices
        all_indices1 = set()
        for endpoint_data in self.endpoints1.values():
            all_indices1.update(endpoint_data.keys())
        
        if self.debug:
            print(f"\nGenerating wordlists for {len(all_indices1)} indices from {self.xml1_name}")
        
        for idx in all_indices1:
            idx_dir = xml1_dir / str(idx)
            idx_dir.mkdir(exist_ok=True)
            
            # Collect cookie values for wordlist
            # For XML1 index, collect values from XML2
            wordlist_from_xml2 = set()
            
            # Get all cookie values from XML2
            for endpoint in self.endpoints2:
                for idx2, cookies2 in self.endpoints2[endpoint].items():
                    wordlist_from_xml2.update(cookies2.values())
            
            # Write wordlist with values from XML2
            wordlist_path = idx_dir / f"wordlist_from_{self.xml2_name}.txt"
            with open(wordlist_path, 'w') as f:
                for value in sorted(wordlist_from_xml2):
                    if value and value.strip():  # Skip empty values
                        f.write(f"{value}\n")
            
            if self.debug:
                print(f"  Index {idx}: Created wordlist with {len(wordlist_from_xml2)} values from {self.xml2_name}")
        
        # Process XML2 indices
        all_indices2 = set()
        for endpoint_data in self.endpoints2.values():
            all_indices2.update(endpoint_data.keys())
        
        if self.debug:
            print(f"\nGenerating wordlists for {len(all_indices2)} indices from {self.xml2_name}")
        
        for idx in all_indices2:
            idx_dir = xml2_dir / str(idx)
            idx_dir.mkdir(exist_ok=True)
            
            # Collect cookie values for wordlist
            # For XML2 index, collect values from XML1
            wordlist_from_xml1 = set()
            
            # Get all cookie values from XML1
            for endpoint in self.endpoints1:
                for idx1, cookies1 in self.endpoints1[endpoint].items():
                    wordlist_from_xml1.update(cookies1.values())
            
            # Write wordlist with values from XML1
            wordlist_path = idx_dir / f"wordlist_from_{self.xml1_name}.txt"
            with open(wordlist_path, 'w') as f:
                for value in sorted(wordlist_from_xml1):
                    if value and value.strip():  # Skip empty values
                        f.write(f"{value}\n")
            
            if self.debug:
                print(f"  Index {idx}: Created wordlist with {len(wordlist_from_xml1)} values from {self.xml1_name}")
    
    def generate_report(self):
        """Generate analysis report"""
        report_path = Path("Auth-Testing") / "analysis_report.txt"
        
        with open(report_path, 'w') as f:
            f.write("Burp Suite Cookie Authentication Testing Analysis\n")
            f.write("=" * 50 + "\n\n")
            
            f.write(f"XML File 1: {self.xml1_name}\n")
            f.write(f"XML File 2: {self.xml2_name}\n\n")
            
            f.write(f"Total endpoints with cookies in {self.xml1_name}: {len(self.endpoints1)}\n")
            f.write(f"Total endpoints with cookies in {self.xml2_name}: {len(self.endpoints2)}\n\n")
            
            # Count total cookies and unique cookie names
            cookies1_names = set()
            cookies1_count = 0
            for ep_data in self.endpoints1.values():
                for cookies in ep_data.values():
                    cookies1_names.update(cookies.keys())
                    cookies1_count += len(cookies)
            
            cookies2_names = set()
            cookies2_count = 0
            for ep_data in self.endpoints2.values():
                for cookies in ep_data.values():
                    cookies2_names.update(cookies.keys())
                    cookies2_count += len(cookies)
            
            f.write(f"Unique cookie names in {self.xml1_name}: {len(cookies1_names)}\n")
            f.write(f"  Cookie names: {', '.join(sorted(cookies1_names))}\n")
            f.write(f"Total cookie values in {self.xml1_name}: {cookies1_count}\n\n")
            
            f.write(f"Unique cookie names in {self.xml2_name}: {len(cookies2_names)}\n")
            f.write(f"  Cookie names: {', '.join(sorted(cookies2_names))}\n")
            f.write(f"Total cookie values in {self.xml2_name}: {cookies2_count}\n\n")
            
            f.write(f"Shared endpoints: {len(self.shared_endpoints)}\n")
            if self.shared_endpoints:
                for endpoint in sorted(self.shared_endpoints)[:10]:
                    f.write(f"  - {endpoint}\n")
                    if endpoint in self.shared_cookies and self.shared_cookies[endpoint]:
                        f.write(f"    Shared cookie names: {', '.join(sorted(self.shared_cookies[endpoint]))}\n")
                if len(self.shared_endpoints) > 10:
                    f.write(f"  ... and {len(self.shared_endpoints) - 10} more\n")
            
            f.write(f"\nUnique endpoints in {self.xml1_name}: {len(self.unique_endpoints1)}\n")
            if self.unique_endpoints1:
                for endpoint in sorted(self.unique_endpoints1)[:5]:
                    f.write(f"  - {endpoint}\n")
                if len(self.unique_endpoints1) > 5:
                    f.write(f"  ... and {len(self.unique_endpoints1) - 5} more\n")
            
            f.write(f"\nUnique endpoints in {self.xml2_name}: {len(self.unique_endpoints2)}\n")
            if self.unique_endpoints2:
                for endpoint in sorted(self.unique_endpoints2)[:5]:
                    f.write(f"  - {endpoint}\n")
                if len(self.unique_endpoints2) > 5:
                    f.write(f"  ... and {len(self.unique_endpoints2) - 5} more\n")
            
            f.write("\nWordlist Structure:\n")
            f.write(f"  Auth-Testing/{self.xml1_name}/<index>/wordlist_from_{self.xml2_name}.txt\n")
            f.write(f"  Auth-Testing/{self.xml2_name}/<index>/wordlist_from_{self.xml1_name}.txt\n")
        
        # Also save as JSON for programmatic access
        report_json = {
            "xml1": self.xml1_name,
            "xml2": self.xml2_name,
            "shared_endpoints": list(self.shared_endpoints),
            "unique_endpoints1": list(self.unique_endpoints1),
            "unique_endpoints2": list(self.unique_endpoints2),
            "shared_cookies": {ep: list(cookies) for ep, cookies in self.shared_cookies.items()},
            "cookie_names1": list(cookies1_names),
            "cookie_names2": list(cookies2_names),
            "total_cookie_values1": cookies1_count,
            "total_cookie_values2": cookies2_count
        }
        
        with open(Path("Auth-Testing") / "analysis_report.json", 'w') as f:
            json.dump(report_json, f, indent=2)
    
    def run(self):
        """Execute the complete analysis"""
        print(f"Parsing Burp Suite XML: {self.xml1_path}...")
        self.endpoints1 = self.parse_burp_xml(self.xml1_path)
        
        print(f"Parsing Burp Suite XML: {self.xml2_path}...")
        self.endpoints2 = self.parse_burp_xml(self.xml2_path)
        
        print("Analyzing endpoints...")
        self.analyze_endpoints()
        
        print("Generating wordlists...")
        self.generate_wordlists()
        
        print("Generating report...")
        self.generate_report()
        
        print("\nAnalysis complete!")
        print(f"Results saved in ./Auth-Testing/")
        print(f"  - Wordlists: ./Auth-Testing/{self.xml1_name}/ and ./Auth-Testing/{self.xml2_name}/")
        print(f"  - Report: ./Auth-Testing/analysis_report.txt")
        print(f"  - JSON Report: ./Auth-Testing/analysis_report.json")


def main():
    parser = argparse.ArgumentParser(
        description="Extract cookies from Burp Suite XML files for auth testing"
    )
    parser.add_argument(
        "xml1",
        help="Path to the first Burp Suite XML file"
    )
    parser.add_argument(
        "xml2", 
        help="Path to the second Burp Suite XML file"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output to see what's being parsed"
    )
    
    args = parser.parse_args()
    
    # Validate input files
    if not os.path.exists(args.xml1):
        print(f"Error: File {args.xml1} not found")
        return 1
    
    if not os.path.exists(args.xml2):
        print(f"Error: File {args.xml2} not found")
        return 1
    
    # Run analysis
    tester = BurpCookieAuthTester(args.xml1, args.xml2, debug=args.debug)
    tester.run()
    
    return 0


if __name__ == "__main__":
    exit(main())
