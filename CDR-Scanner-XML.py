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
        for item in root.findall('./item'):
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
    if 'application/x-www-form-urlencoded' in content_type.lower() or (not content_type and '=' in body):
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
        "url_parameters": defaultdict(lambda: {"count": 0, "values": set(), "urls": []}),
        "body_parameters": defaultdict(lambda: {"count": 0, "values": set(), "urls": []}),
        "detailed_requests": []
    }
    
    for item in items:
        method = item["method"].upper()
        url = item["url"]
        
        request_detail = {
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
            
            if method == "GET":
                results["get_with_params"] += 1
            
            # Record parameter details
            for param_name, values in url_params.items():
                results["url_parameters"][param_name]["count"] += 1
                results["url_parameters"][param_name]["urls"].append(url)
                for value in values:
                    results["url_parameters"][param_name]["values"].add(value[:50])  # Limit value length
        
        # Extract body parameters for POST requests
        if method == "POST" and item["body"]:
            content_type = item["headers"].get("Content-Type", "")
            body_params = extract_body_parameters(item["body"], content_type)
            
            if body_params:
                request_detail["body_params"] = body_params
                results["post_with_params"] += 1
                
                # Record parameter details
                for param_name, values in body_params.items():
                    results["body_parameters"][param_name]["count"] += 1
                    results["body_parameters"][param_name]["urls"].append(url)
                    for value in values:
                        results["body_parameters"][param_name]["values"].add(value[:50])  # Limit value length
        
        # Add to detailed requests if it has parameters
        if request_detail["url_params"] or request_detail["body_params"]:
            results["detailed_requests"].append(request_detail)
    
    # Convert sets to lists for JSON serialization
    for param_dict in [results["url_parameters"], results["body_parameters"]]:
        for param_name in param_dict:
            param_dict[param_name]["values"] = list(param_dict[param_name]["values"])
    
    return results

def print_summary(results):
    """
    Print a summary of the analysis results
    
    Args:
        results (dict): Analysis results
    """
    print("\n" + "="*60)
    print("BURP SUITE XML ANALYSIS SUMMARY")
    print("="*60)
    
    print(f"\nTotal Requests: {results['total_requests']}")
    print(f"GET Requests: {results['get_requests']}")
    print(f"POST Requests: {results['post_requests']}")
    print(f"GET Requests with Parameters: {results['get_with_params']}")
    print(f"POST Requests with Body Parameters: {results['post_with_params']}")
    
    print("\n" + "-"*60)
    print("URL PARAMETERS (Found in GET requests)")
    print("-"*60)
    
    if results['url_parameters']:
        for param_name, details in sorted(results['url_parameters'].items()):
            print(f"\nParameter: {param_name}")
            print(f"  Occurrences: {details['count']}")
            print(f"  Unique Values: {len(details['values'])}")
            if details['values']:
                print(f"  Sample Values: {', '.join(list(details['values'])[:3])}")
    else:
        print("No URL parameters found")
    
    print("\n" + "-"*60)
    print("BODY PARAMETERS (Found in POST requests)")
    print("-"*60)
    
    if results['body_parameters']:
        for param_name, details in sorted(results['body_parameters'].items()):
            print(f"\nParameter: {param_name}")
            print(f"  Occurrences: {details['count']}")
            print(f"  Unique Values: {len(details['values'])}")
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
Examples:
  %(prog)s burp_output.xml
  %(prog)s burp_output.xml -o results.json
  %(prog)s burp_output.xml -o results.txt --format txt
  %(prog)s burp_output.xml --detailed
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
    
    args = parser.parse_args()
    
    # Parse the XML file
    print(f"Parsing Burp Suite XML file: {args.xml_file}")
    items = parse_burp_xml(args.xml_file)
    
    if not items:
        print("Error: No valid requests found in the XML file")
        sys.exit(1)
    
    # Analyze the requests
    print(f"Analyzing {len(items)} requests...")
    results = analyze_requests(items)
    
    # Print summary if requested
    if args.summary:
        print_summary(results)
    
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
                f.write(f"Total Requests: {results['total_requests']}\n")
                f.write(f"GET Requests: {results['get_requests']}\n")
                f.write(f"POST Requests: {results['post_requests']}\n")
                f.write(f"GET with Parameters: {results['get_with_params']}\n")
                f.write(f"POST with Parameters: {results['post_with_params']}\n\n")
                
                f.write("URL PARAMETERS\n")
                f.write("-"*40 + "\n")
                for param, details in sorted(results['url_parameters'].items()):
                    f.write(f"{param}: {details['count']} occurrences\n")
                
                f.write("\nBODY PARAMETERS\n")
                f.write("-"*40 + "\n")
                for param, details in sorted(results['body_parameters'].items()):
                    f.write(f"{param}: {details['count']} occurrences\n")
        
        print(f"\nResults saved to: {args.output}")

if __name__ == "__main__":
    main()
