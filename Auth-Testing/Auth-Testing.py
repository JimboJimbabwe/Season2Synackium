#!/usr/bin/env python3
"""
Cookie Authentication Testing Script for Burp Suite XML Files
Generates per-request wordlists based on matching endpoints between two XML files
"""

import xml.etree.ElementTree as ET
import argparse
import os
from pathlib import Path
from collections import defaultdict
import json
import re
import base64
from urllib.parse import urlparse, parse_qs


class BurpCookieAuthTester:
    def __init__(self, xml1_path, xml2_path, debug=False):
        self.xml1_path = xml1_path
        self.xml2_path = xml2_path
        self.xml1_name = Path(xml1_path).stem
        self.xml2_name = Path(xml2_path).stem
        self.debug = debug
        
        # Data structures for analysis
        # Structure: {endpoint: {index: {"cookies": {name: value}, "raw_endpoint": original_url}}}
        self.endpoints1 = {}
        self.endpoints2 = {}
        self.shared_endpoints = set()
        self.unique_endpoints1 = set()
        self.unique_endpoints2 = set()
        
        # Track endpoint matches and cookie analysis
        self.endpoint_matches = {}  # {endpoint: {"shared_cookies": set, "unique_xml1": set, "unique_xml2": set}}
        
        # Common file extensions to check
        self.file_extensions = {'.php', '.aspx', '.html', '.htm', '.jsp', '.asp', 
                               '.cfm', '.cgi', '.pl', '.py', '.rb', '.do', '.action'}
        
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
    
    def has_url_parameters(self, url):
        """Check if URL has query parameters"""
        parsed = urlparse(url)
        return bool(parsed.query)
    
    def has_file_extension(self, url):
        """Check if URL ends with a known file extension"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for ext in self.file_extensions:
            if path.endswith(ext):
                return True
        return False
    
    def has_numeric_id_in_path(self, url):
        """Check if URL path contains numeric IDs (2-20 digits)"""
        parsed = urlparse(url)
        path = parsed.path
        
        patterns = [
            r'/(\d{2,20})/',
            r'/(\d{2,20})$',
            r'/\w+[_-](\d{2,20})',
            r'/(\d{2,20})[_-]\w+',
        ]
        
        for pattern in patterns:
            if re.search(pattern, path):
                return True
        return False
    
    def extract_body_parameters(self, body, content_type):
        """Check if request body has parameters"""
        if not body:
            return False
            
        if 'application/x-www-form-urlencoded' in content_type.lower():
            return '=' in body
        
        if 'multipart/form-data' in content_type.lower():
            return 'Content-Disposition' in body
        
        if 'application/json' in content_type.lower() or body.strip().startswith('{'):
            return True
        
        if 'xml' in content_type.lower() or body.strip().startswith('<?xml'):
            return True
            
        return '=' in body or '{' in body
    
    def should_include_endpoint(self, method, url, body, content_type):
        """Determine if endpoint should be included based on filtering criteria"""
        method = method.upper()
        
        # Case 1: GET with URL parameters
        if method == 'GET' and self.has_url_parameters(url):
            return True, "GET_WITH_PARAMS"
        
        # Case 2: POST with body parameters
        if method == 'POST' and self.extract_body_parameters(body, content_type):
            return True, "POST_WITH_BODY"
        
        # Case 3: URL ends with file extension
        if self.has_file_extension(url):
            return True, "FILE_EXTENSION"
        
        # Case 4: URL has numeric ID in path
        if self.has_numeric_id_in_path(url):
            return True, "NUMERIC_ID"
        
        return False, None
    
    def normalize_endpoint(self, url):
        """Normalize URL to create endpoint key for matching"""
        parsed = urlparse(url)
        # Use scheme, netloc, and path for matching (ignore query parameters)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def parse_burp_xml(self, xml_path):
        """Parse Burp Suite XML file with filtering"""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        endpoints = {}
        
        if self.debug:
            print(f"\nParsing Burp Suite XML: {xml_path}")
        
        items = root.findall('.//item')
        total_items = len(items)
        included_items = 0
        
        for idx, item in enumerate(items):
            url_elem = item.find('.//url')
            if url_elem is None or not url_elem.text:
                continue
            
            url = url_elem.text.strip()
            
            request_elem = item.find('.//request')
            if request_elem is None:
                continue
            
            request_text = request_elem.text
            
            # Decode if base64 encoded
            if request_elem.get('base64') == 'true':
                try:
                    request_text = base64.b64decode(request_text).decode('utf-8', errors='ignore')
                except:
                    continue
            
            if not request_text:
                continue
            
            # Parse request
            lines = request_text.split('\n')
            if not lines:
                continue
            
            first_line_parts = lines[0].strip().split(' ')
            if len(first_line_parts) < 2:
                continue
            
            method = first_line_parts[0]
            
            # Find headers and body
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if not line.strip():
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            body = '\n'.join(lines[body_start:]).strip() if body_start < len(lines) else ""
            content_type = headers.get('Content-Type', '')
            
            # Apply filtering
            should_include, reason = self.should_include_endpoint(method, url, body, content_type)
            
            if not should_include:
                continue
            
            included_items += 1
            
            # Extract cookies
            cookies = {}
            cookie_matches = re.findall(r'^Cookie:\s*(.+)$', request_text, re.MULTILINE | re.IGNORECASE)
            
            for cookie_line in cookie_matches:
                cookie_line = cookie_line.rstrip('\r\n')
                extracted = self.extract_cookies_from_header(cookie_line)
                cookies.update(extracted)
            
            # Only store if cookies were found
            if cookies:
                endpoint_key = self.normalize_endpoint(url)
                
                if endpoint_key not in endpoints:
                    endpoints[endpoint_key] = {}
                
                endpoints[endpoint_key][idx] = {
                    "cookies": cookies,
                    "raw_endpoint": url  # Store original URL for reference
                }
                
                if self.debug and included_items <= 5:
                    print(f"  Item {idx}: {method} {endpoint_key}")
                    print(f"    Cookies: {list(cookies.keys())}")
        
        if self.debug:
            print(f"\nSummary: {included_items} items included out of {total_items}")
            print(f"Endpoints with cookies: {len(endpoints)}")
        
        return endpoints
    
    def analyze_endpoints(self):
        """Analyze shared endpoints and their cookies"""
        endpoints1_set = set(self.endpoints1.keys())
        endpoints2_set = set(self.endpoints2.keys())
        
        self.shared_endpoints = endpoints1_set & endpoints2_set
        self.unique_endpoints1 = endpoints1_set - endpoints2_set
        self.unique_endpoints2 = endpoints2_set - endpoints1_set
        
        # Analyze cookies for each shared endpoint
        for endpoint in self.shared_endpoints:
            # Get all cookie names from both XML files for this endpoint
            cookies1_names = set()
            for idx_data in self.endpoints1[endpoint].values():
                cookies1_names.update(idx_data["cookies"].keys())
            
            cookies2_names = set()
            for idx_data in self.endpoints2[endpoint].values():
                cookies2_names.update(idx_data["cookies"].keys())
            
            # Find shared and unique cookies
            shared_cookies = cookies1_names & cookies2_names
            unique_xml1 = cookies1_names - cookies2_names
            unique_xml2 = cookies2_names - cookies1_names
            
            self.endpoint_matches[endpoint] = {
                "shared_cookies": shared_cookies,
                "unique_xml1": unique_xml1,
                "unique_xml2": unique_xml2
            }
            
            if self.debug and (shared_cookies or unique_xml1 or unique_xml2):
                print(f"\nEndpoint: {endpoint}")
                print(f"  Shared cookies: {shared_cookies}")
                print(f"  Unique to XML1: {unique_xml1}")
                print(f"  Unique to XML2: {unique_xml2}")
    
    def generate_wordlists(self):
        """Generate per-request wordlists based on matching endpoints"""
        base_dir = Path("Auth-Testing")
        base_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        xml1_dir = base_dir / self.xml1_name
        xml2_dir = base_dir / self.xml2_name
        xml1_dir.mkdir(exist_ok=True)
        xml2_dir.mkdir(exist_ok=True)
        
        # Statistics
        total_wordlists_created = 0
        
        # Process shared endpoints for XML1 requests
        for endpoint in self.shared_endpoints:
            # For each request in XML1 with this endpoint
            for idx1, data1 in self.endpoints1[endpoint].items():
                idx_dir = xml1_dir / str(idx1)
                idx_dir.mkdir(exist_ok=True)
                
                # Collect cookie values from XML2 for THIS SPECIFIC ENDPOINT
                wordlist_values = set()
                
                # Get ALL cookie values from XML2 requests with the same endpoint
                for idx2, data2 in self.endpoints2[endpoint].items():
                    for cookie_name, cookie_value in data2["cookies"].items():
                        # Add ALL cookie values from XML2, regardless of whether they're shared or unique
                        wordlist_values.add(cookie_value)
                
                # Write wordlist for this specific request
                wordlist_path = idx_dir / f"wordlist_from_{self.xml2_name}.txt"
                with open(wordlist_path, 'w') as f:
                    for value in sorted(wordlist_values):
                        if value and value.strip():
                            f.write(f"{value}\n")
                
                if wordlist_values:
                    total_wordlists_created += 1
                
                # Also create an info file for this request
                info_path = idx_dir / "request_info.txt"
                with open(info_path, 'w') as f:
                    f.write(f"Endpoint: {endpoint}\n")
                    f.write(f"Original URL: {data1['raw_endpoint']}\n")
                    f.write(f"Request Index: {idx1}\n")
                    f.write(f"Cookies in this request: {', '.join(data1['cookies'].keys())}\n")
                    f.write(f"Wordlist contains {len(wordlist_values)} values from {self.xml2_name}\n")
        
        # Process shared endpoints for XML2 requests
        for endpoint in self.shared_endpoints:
            # For each request in XML2 with this endpoint
            for idx2, data2 in self.endpoints2[endpoint].items():
                idx_dir = xml2_dir / str(idx2)
                idx_dir.mkdir(exist_ok=True)
                
                # Collect cookie values from XML1 for THIS SPECIFIC ENDPOINT
                wordlist_values = set()
                
                # Get ALL cookie values from XML1 requests with the same endpoint
                for idx1, data1 in self.endpoints1[endpoint].items():
                    for cookie_name, cookie_value in data1["cookies"].items():
                        # Add ALL cookie values from XML1, regardless of whether they're shared or unique
                        wordlist_values.add(cookie_value)
                
                # Write wordlist for this specific request
                wordlist_path = idx_dir / f"wordlist_from_{self.xml1_name}.txt"
                with open(wordlist_path, 'w') as f:
                    for value in sorted(wordlist_values):
                        if value and value.strip():
                            f.write(f"{value}\n")
                
                if wordlist_values:
                    total_wordlists_created += 1
                
                # Also create an info file for this request
                info_path = idx_dir / "request_info.txt"
                with open(info_path, 'w') as f:
                    f.write(f"Endpoint: {endpoint}\n")
                    f.write(f"Original URL: {data2['raw_endpoint']}\n")
                    f.write(f"Request Index: {idx2}\n")
                    f.write(f"Cookies in this request: {', '.join(data2['cookies'].keys())}\n")
                    f.write(f"Wordlist contains {len(wordlist_values)} values from {self.xml1_name}\n")
        
        if self.debug:
            print(f"\nCreated {total_wordlists_created} wordlists")
    
    def generate_report(self):
        """Generate analysis report"""
        report_path = Path("Auth-Testing") / "analysis_report.txt"
        
        with open(report_path, 'w') as f:
            f.write("Cookie Authentication Testing Analysis Report\n")
            f.write("=" * 60 + "\n\n")
            
            f.write(f"XML File 1: {self.xml1_name}\n")
            f.write(f"XML File 2: {self.xml2_name}\n\n")
            
            f.write("ENDPOINT ANALYSIS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total endpoints in {self.xml1_name}: {len(self.endpoints1)}\n")
            f.write(f"Total endpoints in {self.xml2_name}: {len(self.endpoints2)}\n")
            f.write(f"Shared endpoints: {len(self.shared_endpoints)}\n")
            f.write(f"Unique to {self.xml1_name}: {len(self.unique_endpoints1)}\n")
            f.write(f"Unique to {self.xml2_name}: {len(self.unique_endpoints2)}\n\n")
            
            f.write("SHARED ENDPOINT COOKIE ANALYSIS\n")
            f.write("-" * 40 + "\n")
            
            for endpoint in sorted(self.shared_endpoints):
                match_info = self.endpoint_matches.get(endpoint, {})
                if match_info.get("shared_cookies") or match_info.get("unique_xml1") or match_info.get("unique_xml2"):
                    f.write(f"\nEndpoint: {endpoint}\n")
                    
                    # Count requests
                    xml1_requests = len(self.endpoints1[endpoint])
                    xml2_requests = len(self.endpoints2[endpoint])
                    f.write(f"  Requests in {self.xml1_name}: {xml1_requests}\n")
                    f.write(f"  Requests in {self.xml2_name}: {xml2_requests}\n")
                    
                    if match_info.get("shared_cookies"):
                        f.write(f"  Shared cookies: {', '.join(sorted(match_info['shared_cookies']))}\n")
                    if match_info.get("unique_xml1"):
                        f.write(f"  Unique to {self.xml1_name}: {', '.join(sorted(match_info['unique_xml1']))}\n")
                    if match_info.get("unique_xml2"):
                        f.write(f"  Unique to {self.xml2_name}: {', '.join(sorted(match_info['unique_xml2']))}\n")
            
            f.write("\n\nWORDLIST GENERATION NOTES\n")
            f.write("-" * 40 + "\n")
            f.write("Each request gets a wordlist containing ALL cookie values from the OTHER XML file\n")
            f.write("but ONLY from requests to the SAME endpoint.\n\n")
            f.write("This includes:\n")
            f.write("  - Values from shared cookies (e.g., sessionId that both have)\n")
            f.write("  - Values from unique cookies (e.g., adminToken that only one has)\n\n")
            f.write("Example:\n")
            f.write("  - User request to /api/data has cookies: sessionId=123, userToken=abc\n")
            f.write("  - Admin request to /api/data has cookies: sessionId=456, adminToken=xyz\n")
            f.write("  - User's wordlist gets: 456, xyz (ALL values from admin)\n")
            f.write("  - Admin's wordlist gets: 123, abc (ALL values from user)\n")
        
        # Generate JSON report
        report_json = {
            "xml1": self.xml1_name,
            "xml2": self.xml2_name,
            "statistics": {
                "endpoints_xml1": len(self.endpoints1),
                "endpoints_xml2": len(self.endpoints2),
                "shared_endpoints": len(self.shared_endpoints),
                "unique_endpoints_xml1": len(self.unique_endpoints1),
                "unique_endpoints_xml2": len(self.unique_endpoints2)
            },
            "shared_endpoints": list(self.shared_endpoints),
            "endpoint_matches": {}
        }
        
        # Add detailed endpoint match information
        for endpoint, match_info in self.endpoint_matches.items():
            report_json["endpoint_matches"][endpoint] = {
                "shared_cookies": list(match_info["shared_cookies"]),
                "unique_xml1": list(match_info["unique_xml1"]),
                "unique_xml2": list(match_info["unique_xml2"]),
                "requests_xml1": len(self.endpoints1[endpoint]),
                "requests_xml2": len(self.endpoints2[endpoint])
            }
        
        with open(Path("Auth-Testing") / "analysis_report.json", 'w') as f:
            json.dump(report_json, f, indent=2)
    
    def run(self):
        """Execute the complete analysis"""
        print(f"Parsing {self.xml1_path}...")
        self.endpoints1 = self.parse_burp_xml(self.xml1_path)
        
        print(f"Parsing {self.xml2_path}...")
        self.endpoints2 = self.parse_burp_xml(self.xml2_path)
        
        print("Analyzing shared endpoints and cookies...")
        self.analyze_endpoints()
        
        print("Generating per-request wordlists...")
        self.generate_wordlists()
        
        print("Generating report...")
        self.generate_report()
        
        print("\nAnalysis complete!")
        print(f"Results saved in ./Auth-Testing/")
        print("\nKey points:")
        print("- Each request gets its own wordlist")
        print("- Wordlists contain cookie values ONLY from the matching endpoint")
        print("- Check request_info.txt in each folder for details")


def main():
    parser = argparse.ArgumentParser(
        description="Generate per-request wordlists from matching endpoints in Burp Suite XML files"
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
        help="Enable debug output"
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
