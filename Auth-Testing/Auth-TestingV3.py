#!/usr/bin/env python3
"""
Advanced Cookie Authorization Testing Script for Burp Suite XML Files
Implements layered authorization testing with index-based organization
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


class AdvancedAuthTester:
    def __init__(self, lower_xml_path, higher_xml_path, debug=False, path_tolerance=2):
        self.lower_xml_path = lower_xml_path
        self.higher_xml_path = higher_xml_path
        self.lower_name = Path(lower_xml_path).stem
        self.higher_name = Path(higher_xml_path).stem
        self.debug = debug
        self.path_tolerance = path_tolerance
        
        # Data structures - now storing by index
        self.requests_lower = {}  # {index: {"url": url, "cookies": {name: value}, "method": method}}
        self.requests_higher = {}
        
        # Endpoint matching results
        self.shared_matches = []  # [(lower_idx, higher_idx, normalized_endpoint)]
        self.unique_lower_indexes = set()
        self.unique_higher_indexes = set()
        
        # Cookie analysis structures
        self.all_cookies_lower = {}  # {cookie_name: {value: [indexes]}}
        self.all_cookies_higher = {}
        
        # Repository data for JSON
        self.repository_data = {
            "lower_file": self.lower_name,
            "higher_file": self.higher_name,
            "shared": {"indexes": []},
            "u_higher": {"indexes": []},
            "u_lower": {"indexes": []},
            "statistics": {}
        }
        
        # Common file extensions
        self.file_extensions = {'.php', '.aspx', '.html', '.htm', '.jsp', '.asp', 
                               '.cfm', '.cgi', '.pl', '.py', '.rb', '.do', '.action'}
    
    def normalize_path_segments(self, path):
        """Split path into segments and normalize numeric IDs"""
        segments = [s for s in path.split('/') if s]
        normalized = []
        
        for segment in segments:
            # Replace numeric IDs with placeholder
            if re.match(r'^\d{2,20}$', segment):
                normalized.append('{ID}')
            # Replace UUIDs with placeholder
            elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', segment, re.I):
                normalized.append('{UUID}')
            # Replace common ID patterns
            elif re.match(r'^[a-zA-Z]+[-_]\d+$', segment):
                normalized.append('{PREFIXED_ID}')
            else:
                normalized.append(segment)
        
        return normalized
    
    def match_endpoints_flexible(self, url1, url2):
        """
        Flexible endpoint matching that allows for path differences
        Returns (is_match, match_score, normalized_endpoint)
        """
        parsed1 = urlparse(url1)
        parsed2 = urlparse(url2)
        
        # Must have same scheme and netloc
        if parsed1.scheme != parsed2.scheme or parsed1.netloc != parsed2.netloc:
            return False, 0, None
        
        # Normalize path segments
        segments1 = self.normalize_path_segments(parsed1.path)
        segments2 = self.normalize_path_segments(parsed2.path)
        
        # If lengths differ too much, no match
        if abs(len(segments1) - len(segments2)) > self.path_tolerance:
            return False, 0, None
        
        # Count matching segments
        matches = 0
        mismatches = 0
        
        for i in range(min(len(segments1), len(segments2))):
            if segments1[i] == segments2[i]:
                matches += 1
            else:
                mismatches += 1
                if mismatches > self.path_tolerance:
                    return False, 0, None
        
        # Calculate match score
        total_segments = max(len(segments1), len(segments2))
        match_score = matches / total_segments if total_segments > 0 else 0
        
        # Create normalized endpoint if match
        if match_score > 0.5:
            norm_path = '/'.join(segments1)  # Use first URL's normalized path
            normalized = f"{parsed1.scheme}://{parsed1.netloc}/{norm_path}"
            return True, match_score, normalized
        
        return False, 0, None
    
    def extract_cookies_from_header(self, cookie_header):
        """Extract cookies from Cookie header value"""
        cookies = {}
        if not cookie_header:
            return cookies
            
        cookie_pairs = cookie_header.split(';')
        for pair in cookie_pairs:
            pair = pair.strip()
            if '=' in pair:
                name, value = pair.split('=', 1)
                cookies[name.strip()] = value.strip()
        
        return cookies
    
    def should_include_endpoint(self, method, url, body, content_type):
        """Determine if endpoint should be included based on filtering criteria"""
        method = method.upper()
        
        # GET with parameters
        if method == 'GET' and '?' in url and '=' in url.split('?', 1)[1]:
            return True, "GET_WITH_PARAMS"
        
        # POST with body
        if method == 'POST' and body and ('=' in body or '{' in body):
            return True, "POST_WITH_BODY"
        
        # Has file extension
        parsed = urlparse(url)
        for ext in self.file_extensions:
            if parsed.path.lower().endswith(ext):
                return True, "FILE_EXTENSION"
        
        # Has numeric ID
        if re.search(r'/\d{2,20}(/|$)', parsed.path):
            return True, "NUMERIC_ID"
        
        return False, None
    
    def parse_burp_xml(self, xml_path):
        """Parse Burp Suite XML file and return requests by index"""
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        requests = {}
        
        if self.debug:
            print(f"\nParsing: {xml_path}")
        
        items = root.findall('.//item')
        
        for item in items:
            # Get index from item
            index = None
            # Try to find index in different ways
            if 'index' in item.attrib:
                index = int(item.attrib['index'])
            else:
                # Try to extract from number tag
                number_elem = item.find('.//number')
                if number_elem is not None and number_elem.text:
                    index = int(number_elem.text)
            
            if index is None:
                continue
            
            url_elem = item.find('.//url')
            if url_elem is None or not url_elem.text:
                continue
            
            url = url_elem.text.strip()
            
            request_elem = item.find('.//request')
            if request_elem is None:
                continue
            
            request_text = request_elem.text
            
            # Decode if base64
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
            
            # Extract cookies
            cookies = {}
            cookie_matches = re.findall(r'^Cookie:\s*(.+)$', request_text, re.MULTILINE | re.IGNORECASE)
            
            for cookie_line in cookie_matches:
                cookie_line = cookie_line.rstrip('\r\n')
                extracted = self.extract_cookies_from_header(cookie_line)
                cookies.update(extracted)
            
            # Store if cookies found
            if cookies:
                requests[index] = {
                    "url": url,
                    "cookies": cookies,
                    "method": method,
                    "path": urlparse(url).path
                }
        
        if self.debug:
            print(f"  Found {len(requests)} requests with cookies")
        
        return requests
    
    def find_matches_and_uniques(self):
        """Find matching requests between XMLs and unique requests"""
        # Track which indexes have been matched
        matched_lower = set()
        matched_higher = set()
        
        # Find all matches
        for lower_idx, lower_data in self.requests_lower.items():
            best_match_idx = None
            best_score = 0
            best_normalized = None
            
            for higher_idx, higher_data in self.requests_higher.items():
                if higher_idx in matched_higher:
                    continue
                
                is_match, score, normalized = self.match_endpoints_flexible(
                    lower_data["url"], 
                    higher_data["url"]
                )
                
                if is_match and score > best_score:
                    best_match_idx = higher_idx
                    best_score = score
                    best_normalized = normalized
            
            if best_match_idx is not None:
                matched_lower.add(lower_idx)
                matched_higher.add(best_match_idx)
                self.shared_matches.append((lower_idx, best_match_idx, best_normalized))
        
        # Find uniques
        self.unique_lower_indexes = set(self.requests_lower.keys()) - matched_lower
        self.unique_higher_indexes = set(self.requests_higher.keys()) - matched_higher
        
        if self.debug:
            print(f"\nMatching Results:")
            print(f"  Shared matches: {len(self.shared_matches)}")
            print(f"  Unique to lower: {len(self.unique_lower_indexes)}")
            print(f"  Unique to higher: {len(self.unique_higher_indexes)}")
    
    def collect_all_cookies(self):
        """Collect all cookies and track which indexes use them"""
        # Collect from lower
        for idx, data in self.requests_lower.items():
            for cookie_name, cookie_value in data["cookies"].items():
                if cookie_name not in self.all_cookies_lower:
                    self.all_cookies_lower[cookie_name] = {}
                if cookie_value not in self.all_cookies_lower[cookie_name]:
                    self.all_cookies_lower[cookie_name][cookie_value] = []
                self.all_cookies_lower[cookie_name][cookie_value].append(idx)
        
        # Collect from higher
        for idx, data in self.requests_higher.items():
            for cookie_name, cookie_value in data["cookies"].items():
                if cookie_name not in self.all_cookies_higher:
                    self.all_cookies_higher[cookie_name] = {}
                if cookie_value not in self.all_cookies_higher[cookie_name]:
                    self.all_cookies_higher[cookie_name][cookie_value] = []
                self.all_cookies_higher[cookie_name][cookie_value].append(idx)
    
    def generate_shared_wordlists(self, base_dir):
        """Generate wordlists for shared endpoint matches"""
        shared_dir = base_dir / "Shared"
        shared_dir.mkdir(parents=True, exist_ok=True)
        
        # Create EmptyIntersection directory
        empty_intersection_dir = base_dir / "EmptyIntersection"
        empty_intersection_count = 0
        
        # Process each match
        for lower_idx, higher_idx, normalized in self.shared_matches:
            # Get cookies from both requests
            lower_cookies = self.requests_lower[lower_idx]["cookies"]
            higher_cookies = self.requests_higher[higher_idx]["cookies"]
            
            # Analyze cookies
            lower_names = set(lower_cookies.keys())
            higher_names = set(higher_cookies.keys())
            
            shared_cookie_names = lower_names & higher_names
            unique_to_lower = lower_names - higher_names
            unique_to_higher = higher_names - lower_names
            
            # Check if this is an empty intersection case
            if len(shared_cookie_names) == 0:
                # This is a critical security case - same endpoint, NO shared cookies
                empty_intersection_count += 1
                empty_intersection_dir.mkdir(parents=True, exist_ok=True)
                
                # Create folder for this empty intersection case
                empty_match_dir = empty_intersection_dir / f"H{higher_idx}_L{lower_idx}_EMPTY"
                empty_match_dir.mkdir(parents=True, exist_ok=True)
                
                # Generate union wordlist (ALL cookies from both)
                all_cookies_wordlist = set()
                
                # Add all lower cookies with values
                for cookie_name, cookie_value in lower_cookies.items():
                    all_cookies_wordlist.add(cookie_value)
                    all_cookies_wordlist.add(f"{cookie_name}={cookie_value}")
                
                # Add all higher cookies with values
                for cookie_name, cookie_value in higher_cookies.items():
                    all_cookies_wordlist.add(cookie_value)
                    all_cookies_wordlist.add(f"{cookie_name}={cookie_value}")
                
                # Write comprehensive wordlist
                with open(empty_match_dir / "wordlist_all_cookies.txt", 'w') as f:
                    for value in sorted(all_cookies_wordlist):
                        f.write(f"{value}\n")
                
                # Generate unique values wordlist (just the unique cookie values)
                unique_values_wordlist = set()
                
                # Add unique cookie values from lower
                for cookie_name in unique_to_lower:
                    unique_values_wordlist.add(lower_cookies[cookie_name])
                    unique_values_wordlist.add(f"{cookie_name}={lower_cookies[cookie_name]}")
                
                # Add unique cookie values from higher
                for cookie_name in unique_to_higher:
                    unique_values_wordlist.add(higher_cookies[cookie_name])
                    unique_values_wordlist.add(f"{cookie_name}={higher_cookies[cookie_name]}")
                
                # Write unique values wordlist
                with open(empty_match_dir / "wordlist_unique_values.txt", 'w') as f:
                    for value in sorted(unique_values_wordlist):
                        f.write(f"{value}\n")
                
                # Create warning file
                with open(empty_match_dir / "CRITICAL_SECURITY_WARNING.txt", 'w') as f:
                    f.write("CRITICAL SECURITY FINDING: Empty Cookie Intersection\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(f"Endpoint: {normalized}\n")
                    f.write(f"Lower URL: {self.requests_lower[lower_idx]['url']}\n")
                    f.write(f"Higher URL: {self.requests_higher[higher_idx]['url']}\n\n")
                    f.write("This endpoint is accessed by both privilege levels but shares NO common cookies!\n\n")
                    f.write("SECURITY IMPLICATIONS:\n")
                    f.write("- Possible missing authorization checks\n")
                    f.write("- Endpoint might accept ANY valid session\n")
                    f.write("- High risk of privilege escalation\n\n")
                    f.write("COOKIES ANALYSIS:\n")
                    f.write(f"Lower user cookies: {', '.join(lower_names)}\n")
                    f.write(f"Higher user cookies: {', '.join(higher_names)}\n\n")
                    f.write("TEST RECOMMENDATIONS:\n")
                    f.write("1. Test with wordlist_all_cookies.txt - contains ALL cookies from both users\n")
                    f.write("2. Test with wordlist_unique_values.txt - contains unique cookie values\n")
                    f.write("3. Manually verify if endpoint performs ANY authorization checks\n")
                
                # Create info JSON
                with open(empty_match_dir / "empty_intersection_info.json", 'w') as f:
                    info = {
                        "type": "EMPTY_INTERSECTION",
                        "severity": "CRITICAL",
                        "lower_index": lower_idx,
                        "higher_index": higher_idx,
                        "endpoint": normalized,
                        "lower_url": self.requests_lower[lower_idx]["url"],
                        "higher_url": self.requests_higher[higher_idx]["url"],
                        "lower_cookies": list(lower_names),
                        "higher_cookies": list(higher_names),
                        "shared_cookies": [],
                        "security_risk": "No shared cookies between privilege levels - possible authorization bypass"
                    }
                    json.dump(info, f, indent=2)
                
                # Update repository data
                if "empty_intersection" not in self.repository_data:
                    self.repository_data["empty_intersection"] = {"indexes": []}
                
                self.repository_data["empty_intersection"]["indexes"].append({
                    "folder": f"H{higher_idx}_L{lower_idx}_EMPTY",
                    "lower_index": lower_idx,
                    "higher_index": higher_idx,
                    "endpoint": normalized,
                    "risk": "CRITICAL"
                })
                
                # Skip normal processing for this match
                continue
            
            # Normal processing for non-empty intersections
            # Create folder H{higher_idx}_L{lower_idx}
            match_dir = shared_dir / f"H{higher_idx}_L{lower_idx}"
            test_lower_dir = match_dir / "Test_Lower"
            test_higher_dir = match_dir / "Test_Higher"
            
            test_lower_dir.mkdir(parents=True, exist_ok=True)
            test_higher_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate Test_Lower wordlist (for escalation)
            escalation_values = set()
            
            # Add higher's values for shared cookies
            for cookie_name in shared_cookie_names:
                escalation_values.add(higher_cookies[cookie_name])
            
            # Add all unique cookies from higher with their names
            for cookie_name in unique_to_higher:
                escalation_values.add(f"{cookie_name}={higher_cookies[cookie_name]}")
            
            if escalation_values:
                with open(test_lower_dir / "wordlist.txt", 'w') as f:
                    for value in sorted(escalation_values):
                        f.write(f"{value}\n")
            
            # Generate Test_Higher wordlist (for downgrade)
            downgrade_values = set()
            
            # Add lower's values for shared cookies
            for cookie_name in shared_cookie_names:
                downgrade_values.add(lower_cookies[cookie_name])
            
            # Add all unique cookies from lower with their names
            for cookie_name in unique_to_lower:
                downgrade_values.add(f"{cookie_name}={lower_cookies[cookie_name]}")
            
            if downgrade_values:
                with open(test_higher_dir / "wordlist.txt", 'w') as f:
                    for value in sorted(downgrade_values):
                        f.write(f"{value}\n")
            
            # Create info file
            with open(match_dir / "match_info.json", 'w') as f:
                info = {
                    "lower_index": lower_idx,
                    "higher_index": higher_idx,
                    "normalized_endpoint": normalized,
                    "lower_url": self.requests_lower[lower_idx]["url"],
                    "higher_url": self.requests_higher[higher_idx]["url"],
                    "shared_cookies": list(shared_cookie_names),
                    "unique_to_lower": list(unique_to_lower),
                    "unique_to_higher": list(unique_to_higher)
                }
                json.dump(info, f, indent=2)
            
            # Update repository data
            self.repository_data["shared"]["indexes"].append({
                "folder": f"H{higher_idx}_L{lower_idx}",
                "lower_index": lower_idx,
                "higher_index": higher_idx,
                "endpoint": normalized
            })
    
    def generate_unique_higher_wordlists(self, base_dir):
        """Generate wordlists for unique higher privilege endpoints"""
        u_higher_dir = base_dir / "U_Higher"
        u_higher_dir.mkdir(parents=True, exist_ok=True)
        
        # Collect all lower privilege cookie values
        all_lower_values = set()
        
        # From unique lower endpoints
        for idx in self.unique_lower_indexes:
            for cookie_name, cookie_value in self.requests_lower[idx]["cookies"].items():
                all_lower_values.add(cookie_value)
                # Add with name if it's unique to lower
                if cookie_name not in self.all_cookies_higher:
                    all_lower_values.add(f"{cookie_name}={cookie_value}")
        
        # From shared endpoints (lower's values)
        for lower_idx, _, _ in self.shared_matches:
            for cookie_value in self.requests_lower[lower_idx]["cookies"].values():
                all_lower_values.add(cookie_value)
        
        # Create wordlist for each unique higher endpoint
        for higher_idx in self.unique_higher_indexes:
            idx_dir = u_higher_dir / f"H{higher_idx}"
            test_lower_dir = idx_dir / "Test_Lower"
            test_lower_dir.mkdir(parents=True, exist_ok=True)
            
            # Write the wordlist
            if all_lower_values:
                with open(test_lower_dir / "wordlist.txt", 'w') as f:
                    for value in sorted(all_lower_values):
                        f.write(f"{value}\n")
            
            # Create info file
            with open(idx_dir / "endpoint_info.json", 'w') as f:
                info = {
                    "index": higher_idx,
                    "url": self.requests_higher[higher_idx]["url"],
                    "method": self.requests_higher[higher_idx]["method"],
                    "cookies_present": list(self.requests_higher[higher_idx]["cookies"].keys()),
                    "test_purpose": "Test if lower privilege cookies can access this admin-only endpoint"
                }
                json.dump(info, f, indent=2)
            
            # Update repository data
            self.repository_data["u_higher"]["indexes"].append({
                "folder": f"H{higher_idx}",
                "index": higher_idx,
                "url": self.requests_higher[higher_idx]["url"]
            })
    
    def generate_unique_lower_wordlists(self, base_dir):
        """Generate wordlists for unique lower privilege endpoints"""
        u_lower_dir = base_dir / "U_Lower"
        u_lower_dir.mkdir(parents=True, exist_ok=True)
        
        # Collect all higher privilege cookie values
        all_higher_values = set()
        
        # From unique higher endpoints
        for idx in self.unique_higher_indexes:
            for cookie_name, cookie_value in self.requests_higher[idx]["cookies"].items():
                all_higher_values.add(cookie_value)
                # Add with name if it's unique to higher
                if cookie_name not in self.all_cookies_lower:
                    all_higher_values.add(f"{cookie_name}={cookie_value}")
        
        # From shared endpoints (higher's values for shared cookies)
        for _, higher_idx, _ in self.shared_matches:
            higher_cookies = self.requests_higher[higher_idx]["cookies"]
            for cookie_name, cookie_value in higher_cookies.items():
                # Only add if it's a shared cookie type
                if cookie_name in self.all_cookies_lower:
                    all_higher_values.add(cookie_value)
        
        # Create wordlist for each unique lower endpoint
        for lower_idx in self.unique_lower_indexes:
            idx_dir = u_lower_dir / f"L{lower_idx}"
            test_higher_dir = idx_dir / "Test_Higher"
            test_higher_dir.mkdir(parents=True, exist_ok=True)
            
            # Write the wordlist
            if all_higher_values:
                with open(test_higher_dir / "wordlist.txt", 'w') as f:
                    for value in sorted(all_higher_values):
                        f.write(f"{value}\n")
            
            # Create info file
            with open(idx_dir / "endpoint_info.json", 'w') as f:
                info = {
                    "index": lower_idx,
                    "url": self.requests_lower[lower_idx]["url"],
                    "method": self.requests_lower[lower_idx]["method"],
                    "cookies_present": list(self.requests_lower[lower_idx]["cookies"].keys()),
                    "test_purpose": "Test if higher privilege cookies work on this user-only endpoint"
                }
                json.dump(info, f, indent=2)
            
            # Update repository data
            self.repository_data["u_lower"]["indexes"].append({
                "folder": f"L{lower_idx}",
                "index": lower_idx,
                "url": self.requests_lower[lower_idx]["url"]
            })
    
    def generate_repository_json(self, base_dir):
        """Generate the main repository JSON file"""
        # Count empty intersections
        empty_intersection_count = len(self.repository_data.get("empty_intersection", {}).get("indexes", []))
        
        # Add statistics
        self.repository_data["statistics"] = {
            "total_lower_requests": len(self.requests_lower),
            "total_higher_requests": len(self.requests_higher),
            "shared_matches": len(self.shared_matches),
            "empty_intersection_matches": empty_intersection_count,
            "unique_lower": len(self.unique_lower_indexes),
            "unique_higher": len(self.unique_higher_indexes),
            "total_cookie_types_lower": len(self.all_cookies_lower),
            "total_cookie_types_higher": len(self.all_cookies_higher),
            "shared_cookie_types": len(set(self.all_cookies_lower.keys()) & set(self.all_cookies_higher.keys()))
        }
        
        with open(base_dir / "repository.json", 'w') as f:
            json.dump(self.repository_data, f, indent=2)
    
    def generate_main_readme(self, base_dir):
        """Generate main README file"""
        empty_intersection_count = len(self.repository_data.get("empty_intersection", {}).get("indexes", []))
        
        with open(base_dir / "README.md", 'w') as f:
            f.write("# Authorization Testing Repository\n\n")
            f.write(f"Analysis of {self.lower_name} (lower privilege) vs {self.higher_name} (higher privilege)\n\n")
            
            if empty_intersection_count > 0:
                f.write("## ⚠️ CRITICAL FINDINGS\n")
                f.write(f"Found {empty_intersection_count} endpoints with EMPTY COOKIE INTERSECTION!\n")
                f.write("These endpoints are accessed by both privilege levels but share NO common cookies.\n")
                f.write("Check the `EmptyIntersection/` directory for critical security issues.\n\n")
            
            f.write("## Directory Structure\n\n")
            f.write("### Shared/\n")
            f.write("Contains matches between lower and higher privilege requests.\n")
            f.write("- Folders named `H{higher_index}_L{lower_index}`\n")
            f.write("- Each contains `Test_Lower/` and `Test_Higher/` subdirectories\n\n")
            
            if empty_intersection_count > 0:
                f.write("### EmptyIntersection/ ⚠️ CRITICAL\n")
                f.write("Contains endpoints with NO shared cookies between privilege levels.\n")
                f.write("- Folders named `H{higher_index}_L{lower_index}_EMPTY`\n")
                f.write("- Contains comprehensive wordlists for testing authorization bypass\n\n")
            
            f.write("### U_Higher/\n")
            f.write("Contains endpoints unique to higher privilege.\n")
            f.write("- Folders named `H{index}`\n")
            f.write("- Each contains `Test_Lower/` for testing unauthorized access\n\n")
            f.write("### U_Lower/\n")
            f.write("Contains endpoints unique to lower privilege.\n")
            f.write("- Folders named `L{index}`\n")
            f.write("- Each contains `Test_Higher/` for testing improper access\n\n")
            f.write("## Test Cases\n\n")
            f.write("1. **Privilege Escalation** (Shared/*/Test_Lower/)\n")
            f.write("   - Test as lower user with higher privilege cookies\n\n")
            f.write("2. **Downgrade Vulnerabilities** (Shared/*/Test_Higher/)\n")
            f.write("   - Test as higher user with lower privilege cookies\n\n")
            
            if empty_intersection_count > 0:
                f.write("3. **⚠️ CRITICAL: Empty Intersection** (EmptyIntersection/*/)\n")
                f.write("   - Test endpoints that share NO cookies between privilege levels\n")
                f.write("   - High risk of authorization bypass\n")
                f.write("   - Use `wordlist_all_cookies.txt` for comprehensive testing\n\n")
                f.write("4. **Unauthorized Access** (U_Higher/*/Test_Lower/)\n")
                f.write("   - Test admin endpoints as lower user\n\n")
                f.write("5. **Improper Access** (U_Lower/*/Test_Higher/)\n")
                f.write("   - Test user endpoints as admin\n\n")
            else:
                f.write("3. **Unauthorized Access** (U_Higher/*/Test_Lower/)\n")
                f.write("   - Test admin endpoints as lower user\n\n")
                f.write("4. **Improper Access** (U_Lower/*/Test_Higher/)\n")
                f.write("   - Test user endpoints as admin\n\n")
            
            f.write("## Usage\n\n")
            f.write("1. Navigate to the appropriate test directory\n")
            f.write("2. Use `wordlist.txt` with Burp Intruder on cookie positions\n")
            f.write("3. Check `match_info.json` or `endpoint_info.json` for details\n")
            f.write("4. See `repository.json` for complete analysis summary\n")
            
            if empty_intersection_count > 0:
                f.write("\n## Priority Testing\n\n")
                f.write("Start with EmptyIntersection cases - these represent the highest risk!\n")
    
    def run(self):
        """Execute the complete analysis"""
        print(f"Parsing {self.lower_xml_path} (lower privilege)...")
        self.requests_lower = self.parse_burp_xml(self.lower_xml_path)
        
        print(f"Parsing {self.higher_xml_path} (higher privilege)...")
        self.requests_higher = self.parse_burp_xml(self.higher_xml_path)
        
        print("Finding matches and unique requests...")
        self.find_matches_and_uniques()
        
        print("Collecting all cookies...")
        self.collect_all_cookies()
        
        # Create base directory
        base_dir = Path("Authorization-Testing")
        base_dir.mkdir(exist_ok=True)
        
        print("Generating wordlists for shared endpoints...")
        self.generate_shared_wordlists(base_dir)
        
        print("Generating wordlists for unique higher privilege endpoints...")
        self.generate_unique_higher_wordlists(base_dir)
        
        print("Generating wordlists for unique lower privilege endpoints...")
        self.generate_unique_lower_wordlists(base_dir)
        
        print("Generating repository JSON...")
        self.generate_repository_json(base_dir)
        
        print("Generating main README...")
        self.generate_main_readme(base_dir)
        
        # Print summary with empty intersection warning
        print("\nAnalysis complete!")
        print(f"Results saved in ./Authorization-Testing/")
        print(f"\nSummary:")
        print(f"  - Shared matches: {len(self.shared_matches)}")
        
        empty_intersection_count = len(self.repository_data.get("empty_intersection", {}).get("indexes", []))
        if empty_intersection_count > 0:
            print(f"  - ⚠️  CRITICAL: Empty intersection cases: {empty_intersection_count}")
            print(f"     (Same endpoint, NO shared cookies - high risk!)")
        
        print(f"  - Unique to higher: {len(self.unique_higher_indexes)}")
        print(f"  - Unique to lower: {len(self.unique_lower_indexes)}")
        print("\nCheck repository.json for detailed analysis")
        
        if empty_intersection_count > 0:
            print("\n⚠️  SECURITY ALERT: Found endpoints with empty cookie intersection!")
            print("Check ./Authorization-Testing/EmptyIntersection/ for critical findings")


def main():
    parser = argparse.ArgumentParser(
        description="Advanced authorization testing using Burp Suite XML files with index-based organization"
    )
    parser.add_argument(
        "lower_xml",
        help="Path to the LOWER privilege Burp Suite XML file"
    )
    parser.add_argument(
        "higher_xml", 
        help="Path to the HIGHER privilege Burp Suite XML file"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output"
    )
    parser.add_argument(
        "--path-tolerance",
        type=int,
        default=2,
        help="Number of path segments that can differ for endpoint matching (default: 2)"
    )
    
    args = parser.parse_args()
    
    # Validate input files
    if not os.path.exists(args.lower_xml):
        print(f"Error: File {args.lower_xml} not found")
        return 1
    
    if not os.path.exists(args.higher_xml):
        print(f"Error: File {args.higher_xml} not found")
        return 1
    
    # Run analysis
    tester = AdvancedAuthTester(
        args.lower_xml, 
        args.higher_xml, 
        debug=args.debug,
        path_tolerance=args.path_tolerance
    )
    tester.run()
    
    return 0


if __name__ == "__main__":
    exit(main())
