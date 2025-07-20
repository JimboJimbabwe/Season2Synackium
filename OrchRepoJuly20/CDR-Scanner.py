#!/usr/bin/env python3
"""
Burp Suite XML Parameter Analyzer

Analyzes Burp Suite XML files for:
- POST requests with body parameters
- GET requests with URL parameters
"""

import xml.etree.ElementTree as ET
import argparse
import urllib.parse
import re
import json
import base64
from collections import defaultdict
import sys
import hashlib

def parse_burp_xml(file_path):
    """
    Parse a Burp Suite XML file
    
    Args:
        file_path (str): Path to the XML file
        
    Returns:
        list: List of dictionaries with request data
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        items = []
        for idx, item in enumerate(root.findall('./item')):
            url_elem = item.find('url')
            request_elem = item.find('request')
            response_elem = item.find('response')
            
            if url_elem is None or request_elem is None:
                continue
                
            url = url_elem.text or ""
            
            # Get request data
            request_data = {
                "raw": request_elem.text or "",
                "base64": request_elem.get('base64', 'false') == 'true'
            }
            
            # Parse the request
            parsed_request = parse_http_request(request_data["raw"], request_data["base64"])
            
            items.append({
                "index": idx,  # Store original index
                "url": url,
                "method": parsed_request["method"],
                "headers": parsed_request["headers"],
                "body": parsed_request["body"],
                "path": parsed_request["path"]
            })
        
        return items
    except Exception as e:
        print(f"Error parsing XML file: {str(e)}")
        return []

def parse_http_request(raw_request, is_base64=False):
    """
    Parse raw HTTP request
    
    Args:
        raw_request (str): Raw HTTP request
        is_base64 (bool): Whether the request is base64 encoded
        
    Returns:
        dict: Parsed request data
    """
    if is_base64:
        try:
            raw_request = base64.b64decode(raw_request).decode('utf-8', errors='ignore')
        except:
            return {"method": "", "headers": {}, "body": "", "path": ""}
    
    lines = raw_request.split('\n')
    
    # Parse first line
    if lines:
        parts = lines[0].strip().split(' ')
        method = parts[0] if len(parts) > 0 else ""
        path = parts[1] if len(parts) > 1 else ""
    else:
        method = ""
        path = ""
    
    # Parse headers
    headers = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ':' in lines[i]:
            key, value = lines[i].split(':', 1)
            headers[key.strip()] = value.strip()
        i += 1
    
    # Get body (everything after empty line)
    body = ""
    if i < len(lines):
        body = '\n'.join(lines[i+1:]).strip()
    
    return {
        "method": method,
        "headers": headers,
        "body": body,
        "path": path
    }

def normalize_url(url):
    """
    Normalize URL by removing query parameters and fragments
    
    Args:
        url (str): URL to normalize
        
    Returns:
        str: Normalized URL
    """
    try:
        parsed = urllib.parse.urlparse(url)
        # Reconstruct URL without query and fragment
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    except:
        return url

def get_request_signature(item, dedup_mode):
    """
    Generate a signature for a request based on deduplication mode
    
    Args:
        item (dict): Request item
        dedup_mode (str): Deduplication mode
        
    Returns:
        str: Request signature
    """
    if dedup_mode == "exact":
        # Exact URL match (including parameters)
        return item["url"]
    
    elif dedup_mode == "endpoint":
        # Same endpoint (URL without parameters)
        return f"{item['method']}:{normalize_url(item['url'])}"
    
    elif dedup_mode == "params":
        # Same endpoint and parameter names (ignoring values)
        normalized_url = normalize_url(item["url"])
        url_params = extract_url_parameters(item["url"])
        param_names = sorted(url_params.keys())
        
        if item["method"] == "POST" and item["body"]:
            content_type = item["headers"].get("Content-Type", "")
            body_params = extract_body_parameters(item["body"], content_type)
            param_names.extend(sorted(body_params.keys()))
        
        return f"{item['method']}:{normalized_url}:{','.join(param_names)}"
    
    elif dedup_mode == "full":
        # Full request signature (method, endpoint, params, and body hash)
        normalized_url = normalize_url(item["url"])
        url_params = extract_url_parameters(item["url"])
        
        # Create a consistent representation of URL parameters
        url_param_str = "&".join([f"{k}={','.join(sorted(v))}" for k, v in sorted(url_params.items())])
        
        # Hash the body for comparison
        body_hash = hashlib.md5(item["body"].encode()).hexdigest() if item["body"] else ""
        
        return f"{item['method']}:{normalized_url}:{url_param_str}:{body_hash}"
    
    else:  # "none"
        return None

def deduplicate_requests(items, dedup_mode):
    """
    Remove duplicate requests based on the specified mode
    
    Args:
        items (list): List of request items
        dedup_mode (str): Deduplication mode
        
    Returns:
        tuple: (deduplicated_items, duplicate_count, duplicate_groups)
    """
    if dedup_mode == "none":
        return items, 0, {}
    
    seen_signatures = {}
    deduplicated = []
    duplicate_groups = defaultdict(list)
    
    for item in items:
        signature = get_request_signature(item, dedup_mode)
        
        if signature not in seen_signatures:
            seen_signatures[signature] = len(deduplicated)
            deduplicated.append(item)
        else:
            # Track which items are duplicates of which
            original_index = seen_signatures[signature]
            # Store both URL and original index
            duplicate_groups[original_index].append({
                "url": item["url"],
                "index": item["index"]
            })
    
    duplicate_count = len(items) - len(deduplicated)
    
    return deduplicated, duplicate_count, dict(duplicate_groups)

def extract_url_parameters(url):
    """
    Extract parameters from URL query string
    
    Args:
        url (str): URL to analyze
        
    Returns:
        dict: Dictionary of parameters
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.query:
            return urllib.parse.parse_qs(parsed.query)
        return {}
    except:
        return {}

def extract_body_parameters(body, content_type=""):
    """
    Extract parameters from request body
    
    Args:
        body (str): Request body
        content_type (str): Content-Type header value
        
    Returns:
        dict: Dictionary of parameters
    """
    parameters = {}
    
    # URL-encoded form data
    if 'application/x-www-form-urlencoded' in content_type.lower() or (not content_type and '=' in body and '&' in body):
        try:
            parameters = urllib.parse.parse_qs(body)
        except:
            pass
    
    # Multipart form data
    elif 'multipart/form-data' in content_type.lower():
        boundary_match = re.search(r'boundary=([^;]+)', content_type)
        if boundary_match:
            boundary = boundary_match.group(1).strip()
            parameters = extract_multipart_parameters(body, boundary)
    
    # JSON data
    elif 'application/json' in content_type.lower() or body.strip().startswith('{'):
        try:
            import json
            data = json.loads(body)
            if isinstance(data, dict):
                parameters = {k: [str(v)] for k, v in data.items()}
        except:
            pass
    
    # XML data
    elif 'xml' in content_type.lower() or body.strip().startswith('<?xml'):
        parameters = extract_xml_parameters(body)
    
    return parameters

def extract_multipart_parameters(body, boundary):
    """
    Extract parameters from multipart form data
    
    Args:
        body (str): Request body
        boundary (str): Multipart boundary
        
    Returns:
        dict: Dictionary of parameters
    """
    parameters = {}
    parts = re.split(f'--{re.escape(boundary)}', body)
    
    for part in parts:
        if not part.strip():
            continue
            
        name_match = re.search(r'Content-Disposition:[^\n]*name="([^"]+)"', part, re.IGNORECASE)
        if name_match:
            name = name_match.group(1)
            value_match = re.search(r'\r?\n\r?\n(.*)', part, re.DOTALL)
            if value_match:
                value = value_match.group(1).strip()
                if name in parameters:
                    parameters[name].append(value)
                else:
                    parameters[name] = [value]
    
    return parameters

def extract_xml_parameters(body):
    """
    Extract parameters from XML data
    
    Args:
        body (str): XML body
        
    Returns:
        dict: Dictionary of parameters
    """
    parameters = {}
    
    # Simple attribute extraction
    attr_pattern = r'<[^>]+\s+([a-zA-Z0-9_:-]+)="([^"]*)"'
    matches = re.finditer(attr_pattern, body)
    
    for match in matches:
        name, value = match.groups()
        if name in parameters:
            parameters[name].append(value)
        else:
            parameters[name] = [value]
    
    return parameters

def format_index_ranges(indices):
    """
    Format a list of indices into ranges for display
    
    Args:
        indices (list): List of index numbers
        
    Returns:
        str: Formatted string with ranges (e.g., "1-5, 7, 9-12")
    """
    if not indices:
        return ""
    
    indices = sorted(indices)
    ranges = []
    start = indices[0]
    end = indices[0]
    
    for i in range(1, len(indices)):
        if indices[i] == end + 1:
            end = indices[i]
        else:
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = indices[i]
            end = indices[i]
    
    # Add the last range
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")
    
    return ", ".join(ranges)

def export_indices_only(results, filename, indices_type="all"):
    """
    Export only the indices of requests with parameters to a file
    
    Args:
        results (dict): Analysis results
        filename (str): Output filename
        indices_type (str): Type of indices to export ("all", "url", "body")
    """
    indices = set()
    
    # Debug: Check what's in results
    if not results.get('requests_with_url_params') and not results.get('requests_with_body_params'):
        print(f"\nWarning: No requests with parameters found in results")
        print(f"  GET requests with params: {results.get('get_with_params', 0)}")
        print(f"  POST requests with params: {results.get('post_with_params', 0)}")
    
    # Collect indices based on type
    if indices_type in ["all", "url"] and results.get('requests_with_url_params'):
        for req in results['requests_with_url_params']:
            indices.add(req['index'])
        print(f"  Found {len(results['requests_with_url_params'])} requests with URL parameters")
    
    if indices_type in ["all", "body"] and results.get('requests_with_body_params'):
        for req in results['requests_with_body_params']:
            indices.add(req['index'])
        print(f"  Found {len(results['requests_with_body_params'])} requests with body parameters")
    
    # If no indices found, try alternative approach using parameter data
    if not indices:
        print("\nUsing alternative approach to extract indices from parameter data...")
        
        if indices_type in ["all", "url"]:
            for param_name, param_info in results.get('url_parameters', {}).items():
                if 'indices' in param_info:
                    indices.update(param_info['indices'])
        
        if indices_type in ["all", "body"]:
            for param_name, param_info in results.get('body_parameters', {}).items():
                if 'indices' in param_info:
                    indices.update(param_info['indices'])
    
    # Sort indices and write to file
    sorted_indices = sorted(indices)
    
    if not sorted_indices:
        print(f"\nWarning: No indices found to export!")
        return
    
    with open(filename, 'w') as f:
        for index in sorted_indices:
            f.write(f"{index}\n")
    
    print(f"\nExported {len(sorted_indices)} indices to: {filename}")
    
    # Print summary of what was exported
    if indices_type == "all":
        print(f"  Includes requests with URL and body parameters")
    elif indices_type == "url":
        print(f"  Includes only requests with URL parameters")
    elif indices_type == "body":
        print(f"  Includes only requests with body parameters")

def create_work_targets_file(results, duplicate_info=None):
    """
    Create a Work_Targets.txt file with focused penetration test targets
    
    Args:
        results (dict): Analysis results
        duplicate_info (dict): Information about duplicates removed
    """
    with open("Work_Targets.txt", 'w') as f:
        # Header with immersive message
        f.write("="*80 + "\n")
        f.write("PENETRATION TEST WORK TARGETS\n")
        f.write("="*80 + "\n\n")
        
        f.write("CRITICAL NOTICE:\n")
        f.write("-"*80 + "\n")
        f.write("The following requests extracted from the dataset are the only requests to\n")
        f.write("target in the upcoming Penetration Test. These endpoints are to be targeted\n")
        f.write("and analyzed for evidence of Client Side Redirection first. Even if no\n")
        f.write("evidence is found, thereafter you will test for injection based vulnerabilities\n")
        f.write("on those endpoints only.\n")
        f.write("-"*80 + "\n\n")
        
        # 1. Requests with URL parameters
        f.write("1. REQUESTS WITH URL PARAMETERS\n")
        f.write("="*80 + "\n")
        
        if results.get('requests_with_url_params'):
            # Group by endpoint
            endpoint_groups = defaultdict(list)
            for req in results['requests_with_url_params']:
                endpoint = normalize_url(req['url'])
                endpoint_groups[endpoint].append(req['index'])
            
            for endpoint, indices in sorted(endpoint_groups.items()):
                index_ranges = format_index_ranges(indices)
                f.write(f"\n{endpoint}\n")
                f.write(f"  Indices: {index_ranges}\n")
                f.write(f"  Count: {len(indices)}\n")
        else:
            f.write("\nNo requests with URL parameters found.\n")
        
        # 2. Requests with body parameters
        f.write("\n\n2. REQUESTS WITH BODY PARAMETERS\n")
        f.write("="*80 + "\n")
        
        if results.get('requests_with_body_params'):
            # Group by endpoint
            endpoint_groups = defaultdict(list)
            for req in results['requests_with_body_params']:
                endpoint = normalize_url(req['url'])
                endpoint_groups[endpoint].append(req['index'])
            
            for endpoint, indices in sorted(endpoint_groups.items()):
                index_ranges = format_index_ranges(indices)
                f.write(f"\n{endpoint}\n")
                f.write(f"  Indices: {index_ranges}\n")
                f.write(f"  Count: {len(indices)}\n")
        else:
            f.write("\nNo requests with body parameters found.\n")
        
        # 3. Burp Suite XML Analysis Summary
        f.write("\n\n3. BURP SUITE XML ANALYSIS SUMMARY\n")
        f.write("="*80 + "\n\n")
        
        f.write(f"Total Requests Analyzed: {results['total_requests']}\n")
        
        if duplicate_info:
            f.write(f"Duplicates Removed: {duplicate_info['count']}\n")
            f.write(f"Deduplication Mode: {duplicate_info['mode']}\n")
        
        f.write(f"GET Requests: {results['get_requests']}\n")
        f.write(f"POST Requests: {results['post_requests']}\n")
        f.write(f"GET Requests with Parameters: {results['get_with_params']}\n")
        f.write(f"POST Requests with Body Parameters: {results['post_with_params']}\n")
        
        # Total unique endpoints to test
        unique_endpoints = set()
        if results.get('requests_with_url_params'):
            for req in results['requests_with_url_params']:
                unique_endpoints.add(normalize_url(req['url']))
        if results.get('requests_with_body_params'):
            for req in results['requests_with_body_params']:
                unique_endpoints.add(normalize_url(req['url']))
        
        f.write(f"\nTotal Unique Endpoints to Test: {len(unique_endpoints)}\n")
        f.write(f"Total Requests with Parameters: {results['get_with_params'] + results['post_with_params']}\n")
        
        f.write("\n" + "="*80 + "\n")
        f.write("END OF WORK TARGETS\n")
        f.write("="*80 + "\n")
    """
    Format a list of indices into ranges for display
    
    Args:
        indices (list): List of index numbers
        
    Returns:
        str: Formatted string with ranges (e.g., "1-5, 7, 9-12")
    """
    if not indices:
        return ""
    
    indices = sorted(indices)
    ranges = []
    start = indices[0]
    end = indices[0]
    
    for i in range(1, len(indices)):
        if indices[i] == end + 1:
            end = indices[i]
        else:
            if start == end:
                ranges.append(str(start))
            else:
                ranges.append(f"{start}-{end}")
            start = indices[i]
            end = indices[i]
    
    # Add the last range
    if start == end:
        ranges.append(str(start))
    else:
        ranges.append(f"{start}-{end}")
    
    return ", ".join(ranges)

def analyze_requests(items):
    """
    Analyze all requests and extract parameters
    
    Args:
        items (list): List of parsed request items
        
    Returns:
        dict: Analysis results
    """
    results = {
        "total_requests": len(items),
        "get_requests": 0,
        "post_requests": 0,
        "get_with_params": 0,
        "post_with_params": 0,
        "url_parameters": defaultdict(lambda: {"count": 0, "values": set(), "urls": set(), "indices": []}),
        "body_parameters": defaultdict(lambda: {"count": 0, "values": set(), "urls": set(), "indices": []}),
        "detailed_requests": [],
        "requests_with_url_params": [],
        "requests_with_body_params": []
    }
    
    for item in items:
        method = item["method"].upper()
        url = item["url"]
        index = item["index"]
        
        request_detail = {
            "index": index,
            "url": url,
            "method": method,
            "url_params": {},
            "body_params": {}
        }
        
        # Count request types
        if method == "GET":
            results["get_requests"] += 1
        elif method == "POST":
            results["post_requests"] += 1
        
        # Extract URL parameters
        url_params = extract_url_parameters(url)
        if url_params:
            request_detail["url_params"] = url_params
            results["requests_with_url_params"].append({
                "index": index,
                "url": url,
                "method": method,
                "params": list(url_params.keys())
            })
            
            if method == "GET":
                results["get_with_params"] += 1
            
            # Record parameter details
            for param_name, values in url_params.items():
                results["url_parameters"][param_name]["count"] += 1
                results["url_parameters"][param_name]["urls"].add(normalize_url(url))
                results["url_parameters"][param_name]["indices"].append(index)
                for value in values:
                    results["url_parameters"][param_name]["values"].add(value[:50])  # Limit value length
        
        # Extract body parameters for POST requests
        if method == "POST" and item["body"]:
            content_type = item["headers"].get("Content-Type", "")
            body_params = extract_body_parameters(item["body"], content_type)
            
            if body_params:
                request_detail["body_params"] = body_params
                results["post_with_params"] += 1
                results["requests_with_body_params"].append({
                    "index": index,
                    "url": url,
                    "method": method,
                    "params": list(body_params.keys())
                })
                
                # Record parameter details
                for param_name, values in body_params.items():
                    results["body_parameters"][param_name]["count"] += 1
                    results["body_parameters"][param_name]["urls"].add(normalize_url(url))
                    results["body_parameters"][param_name]["indices"].append(index)
                    for value in values:
                        results["body_parameters"][param_name]["values"].add(value[:50])  # Limit value length
        
        # Add to detailed requests if it has parameters
        if request_detail["url_params"] or request_detail["body_params"]:
            results["detailed_requests"].append(request_detail)
    
    # Convert sets to lists and format indices for JSON serialization
    for param_dict in [results["url_parameters"], results["body_parameters"]]:
        for param_name in param_dict:
            param_dict[param_name]["values"] = list(param_dict[param_name]["values"])
            param_dict[param_name]["urls"] = list(param_dict[param_name]["urls"])
            param_dict[param_name]["index_ranges"] = format_index_ranges(param_dict[param_name]["indices"])
    
    return results

def print_summary(results, duplicate_info=None):
    """
    Print a summary of the analysis results
    
    Args:
        results (dict): Analysis results
        duplicate_info (dict): Information about duplicates removed
    """
    print("\n" + "="*60)
    print("BURP SUITE XML ANALYSIS SUMMARY")
    print("="*60)
    
    print(f"\nTotal Requests: {results['total_requests']}")
    
    if duplicate_info:
        print(f"Duplicates Removed: {duplicate_info['count']}")
        print(f"Unique Requests: {results['total_requests']}")
    
    print(f"GET Requests: {results['get_requests']}")
    print(f"POST Requests: {results['post_requests']}")
    print(f"GET Requests with Parameters: {results['get_with_params']}")
    print(f"POST Requests with Body Parameters: {results['post_with_params']}")
    
    # Print requests with URL parameters
    if results.get('requests_with_url_params'):
        print("\n" + "-"*60)
        print("REQUESTS WITH URL PARAMETERS")
        print("-"*60)
        
        # Group by endpoint
        endpoint_groups = defaultdict(list)
        for req in results['requests_with_url_params']:
            endpoint = normalize_url(req['url'])
            endpoint_groups[endpoint].append(req['index'])
        
        for endpoint, indices in sorted(endpoint_groups.items()):
            index_ranges = format_index_ranges(indices)
            print(f"\n{endpoint}")
            print(f"  Indices: {index_ranges}")
            print(f"  Count: {len(indices)}")
    
    # Print requests with body parameters
    if results.get('requests_with_body_params'):
        print("\n" + "-"*60)
        print("REQUESTS WITH BODY PARAMETERS")
        print("-"*60)
        
        # Group by endpoint
        endpoint_groups = defaultdict(list)
        for req in results['requests_with_body_params']:
            endpoint = normalize_url(req['url'])
            endpoint_groups[endpoint].append(req['index'])
        
        for endpoint, indices in sorted(endpoint_groups.items()):
            index_ranges = format_index_ranges(indices)
            print(f"\n{endpoint}")
            print(f"  Indices: {index_ranges}")
            print(f"  Count: {len(indices)}")
    
    print("\n" + "-"*60)
    print("URL PARAMETERS FOUND")
    print("-"*60)
    
    if results['url_parameters']:
        for param_name, details in sorted(results['url_parameters'].items()):
            print(f"\nParameter: {param_name}")
            print(f"  Occurrences: {details['count']}")
            print(f"  Indices: {details['index_ranges']}")
            print(f"  Found on {len(details['urls'])} unique endpoints")
            if details['values']:
                print(f"  Sample Values: {', '.join(list(details['values'])[:3])}")
    else:
        print("No URL parameters found")
    
    print("\n" + "-"*60)
    print("BODY PARAMETERS FOUND")
    print("-"*60)
    
    if results['body_parameters']:
        for param_name, details in sorted(results['body_parameters'].items()):
            print(f"\nParameter: {param_name}")
            print(f"  Occurrences: {details['count']}")
            print(f"  Indices: {details['index_ranges']}")
            print(f"  Found on {len(details['urls'])} unique endpoints")
            if details['values']:
                print(f"  Sample Values: {', '.join(list(details['values'])[:3])}")
    else:
        print("No body parameters found")
    
    print("\n" + "="*60)

def main():
    parser = argparse.ArgumentParser(
        description="Analyze Burp Suite XML files for GET/POST parameters",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Deduplication Modes:
  none     - No deduplication (default)
  exact    - Remove requests with exact same URL
  endpoint - Remove requests to same endpoint (ignores query params)
  params   - Remove requests with same endpoint and parameter names
  full     - Remove requests with same method, endpoint, params, and body

Examples:
  %(prog)s burp_output.xml
  %(prog)s burp_output.xml --dedup endpoint
  %(prog)s burp_output.xml --dedup params -o results.json
  %(prog)s burp_output.xml -o results.txt --format txt
  %(prog)s burp_output.xml --detailed --dedup full
  %(prog)s burp_output.xml --work-targets
  %(prog)s burp_output.xml --indices-only indices.txt
  %(prog)s burp_output.xml --indices-only url_indices.txt --indices-type url
        """
    )
    
    parser.add_argument("xml_file", help="Path to Burp Suite XML file")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-f", "--format", choices=["json", "txt"], default="json",
                       help="Output format (default: json)")
    parser.add_argument("-d", "--detailed", action="store_true",
                       help="Include detailed request information in output")
    parser.add_argument("-s", "--summary", action="store_true", default=True,
                       help="Print summary to console (default: True)")
    parser.add_argument("--no-summary", dest="summary", action="store_false",
                       help="Don't print summary to console")
    parser.add_argument("--dedup", choices=["none", "exact", "endpoint", "params", "full"],
                       default="none", help="Deduplication mode (default: none)")
    parser.add_argument("--show-duplicates", action="store_true",
                       help="Show details about removed duplicates")
    parser.add_argument("-w", "--work-targets", action="store_true",
                       help="Create Work_Targets.txt file with focused penetration test targets")
    parser.add_argument("--indices-only", metavar="FILENAME",
                       help="Export only the indices of requests with parameters to a file (one per line)")
    parser.add_argument("--indices-type", choices=["all", "url", "body"], default="all",
                       help="Type of parameter requests to include in indices export (default: all)")
    
    args = parser.parse_args()
    
    # Parse the XML file
    print(f"Parsing Burp Suite XML file: {args.xml_file}")
    items = parse_burp_xml(args.xml_file)
    
    if not items:
        print("Error: No valid requests found in the XML file")
        sys.exit(1)
    
    original_count = len(items)
    duplicate_info = None
    
    # Deduplicate if requested
    if args.dedup != "none":
        print(f"Deduplicating requests using '{args.dedup}' mode...")
        items, duplicate_count, duplicate_groups = deduplicate_requests(items, args.dedup)
        duplicate_info = {
            "count": duplicate_count,
            "mode": args.dedup,
            "groups": duplicate_groups
        }
        print(f"Removed {duplicate_count} duplicate requests ({original_count} → {len(items)})")
        
        if args.show_duplicates and duplicate_groups:
            print("\nDuplicate Groups:")
            for original_idx, duplicates in duplicate_groups.items():
                original_item = items[original_idx]
                print(f"\n  Original [Index {original_item['index']}]: {original_item['url']}")
                
                # Extract indices and format as ranges
                dup_indices = [dup['index'] for dup in duplicates]
                index_ranges = format_index_ranges(dup_indices)
                
                print(f"  Duplicates [{index_ranges}]: {len(duplicates)} items")
                # Show first few duplicate URLs
                for i, dup in enumerate(duplicates[:3]):
                    print(f"    - [{dup['index']}] {dup['url']}")
                if len(duplicates) > 3:
                    print(f"    ... and {len(duplicates) - 3} more")
    
    # Analyze the requests
    print(f"\nAnalyzing {len(items)} unique requests...")
    results = analyze_requests(items)
    
    # Add duplicate info to results if applicable
    if duplicate_info:
        results["deduplication"] = {
            "original_count": original_count,
            "duplicates_removed": duplicate_info["count"],
            "mode": duplicate_info["mode"]
        }
    
    # Print summary if requested
    if args.summary:
        print_summary(results, duplicate_info)
    
    # Save results if output file specified
    if args.output:
        if not args.detailed:
            # Remove detailed requests for cleaner output
            results.pop("detailed_requests", None)
        
        if args.format == "json":
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
        else:
            # Text format
            with open(args.output, 'w') as f:
                f.write("BURP SUITE XML ANALYSIS RESULTS\n")
                f.write("="*60 + "\n\n")
                
                if duplicate_info:
                    f.write(f"Original Requests: {original_count}\n")
                    f.write(f"Duplicates Removed: {duplicate_info['count']}\n")
                    f.write(f"Deduplication Mode: {duplicate_info['mode']}\n\n")
                
                f.write(f"Total Unique Requests: {results['total_requests']}\n")
                f.write(f"GET Requests: {results['get_requests']}\n")
                f.write(f"POST Requests: {results['post_requests']}\n")
                f.write(f"GET with Parameters: {results['get_with_params']}\n")
                f.write(f"POST with Parameters: {results['post_with_params']}\n\n")
                
                f.write("URL PARAMETERS\n")
                f.write("-"*40 + "\n")
                for param, details in sorted(results['url_parameters'].items()):
                    f.write(f"{param}: {details['count']} occurrences on {len(details['urls'])} endpoints\n")
                
                f.write("\nBODY PARAMETERS\n")
                f.write("-"*40 + "\n")
                for param, details in sorted(results['body_parameters'].items()):
                    f.write(f"{param}: {details['count']} occurrences on {len(details['urls'])} endpoints\n")
        
        print(f"\nResults saved to: {args.output}")
    
    # Create Work_Targets.txt if requested
    if args.work_targets:
        create_work_targets_file(results, duplicate_info)
        print("\nWork_Targets.txt created with focused penetration test targets")
    
    # Export indices only if requested
    if args.indices_only:
        export_indices_only(results, args.indices_only, args.indices_type)

if __name__ == "__main__":
    main()
