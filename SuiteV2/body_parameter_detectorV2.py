"""
Request Body Parameter Detector Module

This module scans through all requests and extracts parameters from
the request body (form data, multipart forms, etc.) for potential testing.
"""

import re
import urllib.parse
import tkinter as tk
from tkinter import ttk
import base64

# Module metadata
MODULE_NAME = "Body Parameter Detector"
MODULE_DESCRIPTION = "Scans all requests for parameters in request bodies"
MODULE_VERSION = "1.0"
MODULE_AUTHOR = "Security Researcher"
# Flag to indicate this module scans all requests
SCAN_ALL_REQUESTS = True

# Configuration
config = {
    "min_param_name_length": 1,
    "min_param_value_length": 1,
    "include_values": True,
    "max_value_preview_length": 30,
    "check_form_urlencoded": True,
    "check_multipart_form": True,
    "check_xml_attributes": True,
    "check_plain_key_value": True
}

def configure(frame):
    """Set up the configuration UI"""
    # Clear the frame
    for widget in frame.winfo_children():
        widget.destroy()
    
    # Create configuration widgets
    ttk.Label(frame, text="Body Parameter Detection Settings", font=("", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
    
    # Minimum parameter name length
    ttk.Label(frame, text="Minimum Parameter Name Length:").grid(row=1, column=0, sticky="w")
    min_name_var = tk.IntVar(value=config["min_param_name_length"])
    min_name_spinbox = ttk.Spinbox(frame, from_=1, to=10, textvariable=min_name_var, width=5)
    min_name_spinbox.grid(row=1, column=1, sticky="w")
    min_name_spinbox.bind("<FocusOut>", lambda e: update_config("min_param_name_length", int(min_name_var.get())))
    
    # Minimum parameter value length
    ttk.Label(frame, text="Minimum Parameter Value Length:").grid(row=2, column=0, sticky="w", pady=(10, 5))
    min_value_var = tk.IntVar(value=config["min_param_value_length"])
    min_value_spinbox = ttk.Spinbox(frame, from_=0, to=10, textvariable=min_value_var, width=5)
    min_value_spinbox.grid(row=2, column=1, sticky="w")
    min_value_spinbox.bind("<FocusOut>", lambda e: update_config("min_param_value_length", int(min_value_var.get())))
    
    # Maximum value preview length
    ttk.Label(frame, text="Maximum Value Preview Length:").grid(row=3, column=0, sticky="w", pady=(10, 5))
    max_preview_var = tk.IntVar(value=config["max_value_preview_length"])
    max_preview_spinbox = ttk.Spinbox(frame, from_=10, to=100, textvariable=max_preview_var, width=5)
    max_preview_spinbox.grid(row=3, column=1, sticky="w")
    max_preview_spinbox.bind("<FocusOut>", lambda e: update_config("max_value_preview_length", int(max_preview_var.get())))
    
    # Checkboxes for options
    include_values_var = tk.BooleanVar(value=config["include_values"])
    ttk.Checkbutton(frame, text="Show Parameter Values", variable=include_values_var,
                  command=lambda: update_config("include_values", include_values_var.get())).grid(row=4, column=0, sticky="w", pady=(10, 5))
    
    check_form_var = tk.BooleanVar(value=config["check_form_urlencoded"])
    ttk.Checkbutton(frame, text="Check URL-encoded Form Data", variable=check_form_var,
                  command=lambda: update_config("check_form_urlencoded", check_form_var.get())).grid(row=5, column=0, sticky="w")
    
    check_multipart_var = tk.BooleanVar(value=config["check_multipart_form"])
    ttk.Checkbutton(frame, text="Check Multipart Form Data", variable=check_multipart_var,
                  command=lambda: update_config("check_multipart_form", check_multipart_var.get())).grid(row=6, column=0, sticky="w")
    
    check_xml_var = tk.BooleanVar(value=config["check_xml_attributes"])
    ttk.Checkbutton(frame, text="Check XML Attributes", variable=check_xml_var,
                  command=lambda: update_config("check_xml_attributes", check_xml_var.get())).grid(row=7, column=0, sticky="w")
    
    check_plain_var = tk.BooleanVar(value=config["check_plain_key_value"])
    ttk.Checkbutton(frame, text="Check Plain Key-Value Pairs", variable=check_plain_var,
                  command=lambda: update_config("check_plain_key_value", check_plain_var.get())).grid(row=8, column=0, sticky="w")

def update_config(key, value):
    """Update a configuration value"""
    config[key] = value

def analyze(request_data, response_data, url, aggregate_results=None):
    """
    Analyze the request for body parameters
    
    Args:
        request_data (dict): The request data
        response_data (dict): The response data (we'll ignore this)
        url (str): The full URL
        aggregate_results (dict, optional): Existing results to merge with
        
    Returns:
        dict: Analysis results with body parameters found
    """
    if aggregate_results:
        results = aggregate_results
        # Update URL only if it's the base analysis (not combining from multiple sources)
        if "aggregate_source_count" not in results:
            results["aggregate_source_count"] = 0
            results["source_urls"] = []
        
        results["aggregate_source_count"] += 1
        if url not in results["source_urls"]:
            results["source_urls"].append(url)
    else:
        results = {
            "title": "Request Body Parameter Detection Results",
            "description": "Parameters found in request bodies",
            "parameters": {},
            "request_count": 1,
            "requests_with_parameters": 0,
            "total_parameters": 0,
            "unique_parameters": 0,
            "requests": [],
            "source_urls": [url],
            "aggregate_source_count": 1
        }
    
    # Get method and content type
    method = request_data.get("method", "")
    content_type = ""
    
    if "headers" in request_data:
        for header_name, header_value in request_data["headers"].items():
            if header_name.lower() == "content-type":
                content_type = header_value
                break
    
    # Skip if no body
    if "body" not in request_data or not request_data["body"]:
        return results
    
    body = request_data["body"]
    
    # Extract parameters based on content type
    body_params = []
    
    # URL-encoded form data
    if config["check_form_urlencoded"] and (
        'application/x-www-form-urlencoded' in content_type.lower() or
        method == 'POST' and not content_type  # Assume form data for POST with no content type
    ):
        form_params = extract_urlencoded_params(body)
        if form_params:
            body_params.extend([{"name": p["name"], "value": p["value"], "type": "form"} for p in form_params])
    
    # Multipart form data
    if config["check_multipart_form"] and 'multipart/form-data' in content_type.lower():
        boundary = extract_multipart_boundary(content_type)
        if boundary:
            multipart_params = extract_multipart_params(body, boundary)
            if multipart_params:
                body_params.extend([{"name": p["name"], "value": p["value"], "type": "multipart"} for p in multipart_params])
    
    # XML attributes
    if config["check_xml_attributes"] and ('xml' in content_type.lower() or body.strip().startswith('<?xml')):
        xml_params = extract_xml_attributes(body)
        if xml_params:
            body_params.extend([{"name": p["name"], "value": p["value"], "type": "xml"} for p in xml_params])
    
    # Plain key-value pairs
    if config["check_plain_key_value"]:
        plain_params = extract_key_value_pairs(body)
        if plain_params:
            body_params.extend([{"name": p["name"], "value": p["value"], "type": "plain"} for p in plain_params])
    
    # If no parameters found, skip processing
    if not body_params:
        return results
    
    results["requests_with_parameters"] += 1
    results["total_parameters"] += len(body_params)
    
    # Assign an index if not present (for single request analysis)
    index = 0
    
    # Store the request information
    request_info = {
        "index": index + 1,  # 1-based index for user display
        "url": url,
        "method": method,
        "content_type": content_type,
        "parameter_count": len(body_params),
        "parameters": body_params
    }
    
    results["requests"].append(request_info)
    
    # Add parameters to the master list
    for param in body_params:
        param_name = param["name"]
        
        if param_name not in results["parameters"]:
            results["parameters"][param_name] = {
                "count": 0,
                "types": set(),
                "values": set(),
                "methods": set(),
                "requests": []
            }
            
            results["unique_parameters"] += 1
            
        results["parameters"][param_name]["count"] += 1
        results["parameters"][param_name]["requests"].append(index + 1)  # 1-based index
        results["parameters"][param_name]["types"].add(param["type"])
        results["parameters"][param_name]["methods"].add(method)
        
        if param.get("value") and config["include_values"]:
            value_preview = get_value_preview(param["value"])
            if value_preview:
                results["parameters"][param_name]["values"].add(value_preview)
    
    # Convert sets to lists for JSON serialization
    for param_name, param_info in results["parameters"].items():
        param_info["types"] = list(param_info["types"])
        param_info["values"] = list(param_info["values"])
        param_info["methods"] = list(param_info["methods"])
    
    return results

def analyze_all(all_items_data):
    """
    Analyze all requests for body parameters
    
    Args:
        all_items_data (list): List of dictionaries containing request and response data
        
    Returns:
        dict: Analysis results with all body parameters found across all requests
    """
    combined_results = None
    
    for item_data in all_items_data:
        url = item_data.get("url", "")
        request_data = item_data.get("request_data", {})
        response_data = item_data.get("response_data", {})
        
        # Skip items without a valid URL
        if not url:
            continue
        
        # Analyze this item
        results = analyze(
            request_data, 
            response_data, 
            url, 
            aggregate_results=combined_results
        )
        
        # For the first item, initialize combined_results
        if combined_results is None:
            combined_results = results
    
    # Update request count
    if combined_results:
        combined_results["request_count"] = len(all_items_data)
    else:
        combined_results = {
            "title": "Request Body Parameter Detection Results",
            "description": "Parameters found in request bodies",
            "parameters": {},
            "request_count": len(all_items_data),
            "requests_with_parameters": 0,
            "total_parameters": 0,
            "unique_parameters": 0,
            "requests": [],
            "source_urls": []
        }
    
    return combined_results

def parse_request(request_content):
    """
    Parse raw HTTP request into method, headers, and body
    
    Args:
        request_content (str): The raw HTTP request
        
    Returns:
        tuple: (method, headers_dict, body)
    """
    # Split into lines
    lines = request_content.splitlines()
    
    # Extract method from first line
    method = lines[0].split(' ', 1)[0] if lines else ""
    
    # Extract headers
    headers = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ':' in lines[i]:
            key, value = lines[i].split(':', 1)
            headers[key.strip()] = value.strip()
        i += 1
    
    # Extract body (everything after the blank line)
    body = ""
    if i < len(lines):
        body = '\n'.join(lines[i+1:])
    
    return method, headers, body

def get_header_value(headers, header_name):
    """
    Get a header value case-insensitively
    
    Args:
        headers (dict): Headers dictionary
        header_name (str): Header name to find
        
    Returns:
        str: Header value or empty string if not found
    """
    header_name_lower = header_name.lower()
    for key, value in headers.items():
        if key.lower() == header_name_lower:
            return value
    return ""

def extract_urlencoded_params(body):
    """
    Extract parameters from URL-encoded form data
    
    Args:
        body (str): Request body
        
    Returns:
        list: List of parameter dictionaries
    """
    parameters = []
    
    try:
        # Parse the body as query string
        param_dict = urllib.parse.parse_qs(body)
        
        for name, values in param_dict.items():
            # Skip parameters with names that are too short
            if len(name) < config["min_param_name_length"]:
                continue
                
            for value in values:
                # Skip parameters with values that are too short
                if len(value) < config["min_param_value_length"]:
                    continue
                    
                param_info = {
                    "name": name,
                    "value": get_value_preview(value) if config["include_values"] else ""
                }
                
                parameters.append(param_info)
    except:
        # Not valid URL-encoded data
        pass
    
    return parameters

def extract_multipart_boundary(content_type):
    """
    Extract boundary string from multipart form content type
    
    Args:
        content_type (str): Content-Type header value
        
    Returns:
        str: Boundary string or empty string if not found
    """
    match = re.search(r'boundary=([^;]+)', content_type)
    if match:
        return match.group(1).strip()
    return ""

def extract_multipart_params(body, boundary):
    """
    Extract parameters from multipart form data
    
    Args:
        body (str): Request body
        boundary (str): Multipart boundary string
        
    Returns:
        list: List of parameter dictionaries
    """
    parameters = []
    
    # Prepare boundary patterns
    boundary_pattern = f'--{re.escape(boundary)}'
    
    # Split body by boundary
    parts = re.split(boundary_pattern, body)
    
    for part in parts:
        if not part.strip():
            continue
            
        # Extract name from Content-Disposition
        name_match = re.search(r'Content-Disposition:[^\n]*name="([^"]+)"', part, re.IGNORECASE)
        if not name_match:
            name_match = re.search(r'Content-Disposition:[^\n]*name=([^\s;]+)', part, re.IGNORECASE)
            
        if name_match:
            name = name_match.group(1)
            
            # Skip parameters with names that are too short
            if len(name) < config["min_param_name_length"]:
                continue
                
            # Extract value (everything after the blank line)
            value_match = re.search(r'\r?\n\r?\n(.*)', part, re.DOTALL)
            value = value_match.group(1).strip() if value_match else ""
            
            # Skip parameters with values that are too short
            if len(value) < config["min_param_value_length"]:
                continue
                
            param_info = {
                "name": name,
                "value": get_value_preview(value) if config["include_values"] else ""
            }
            
            parameters.append(param_info)
    
    return parameters

def extract_xml_attributes(body):
    """
    Extract attributes from XML data
    
    Args:
        body (str): Request body
        
    Returns:
        list: List of parameter dictionaries
    """
    parameters = []
    
    # Find all XML attributes - this is a simple regex approach, not full XML parsing
    attr_pattern = r'<[^>]+\s+([a-zA-Z0-9_:-]+)="([^"]*)"'
    matches = re.finditer(attr_pattern, body)
    
    for match in matches:
        name, value = match.groups()
        
        # Skip parameters with names that are too short
        if len(name) < config["min_param_name_length"]:
            continue
            
        # Skip parameters with values that are too short
        if len(value) < config["min_param_value_length"]:
            continue
            
        param_info = {
            "name": name,
            "value": get_value_preview(value) if config["include_values"] else ""
        }
        
        parameters.append(param_info)
    
    return parameters

def extract_key_value_pairs(body):
    """
    Extract plain key-value pairs from text
    
    Args:
        body (str): Request body
        
    Returns:
        list: List of parameter dictionaries
    """
    parameters = []
    
    # Look for key=value patterns (not part of HTML/XML tags)
    # This is a heuristic approach that might have false positives/negatives
    kv_pattern = r'(?<![<\w])([a-zA-Z0-9_-]+)=([^\s&;]+|"[^"]*"|\'[^\']*\')'
    matches = re.finditer(kv_pattern, body)
    
    for match in matches:
        name, value = match.groups()
        
        # Skip parameters with names that are too short
        if len(name) < config["min_param_name_length"]:
            continue
            
        # Clean up value (remove quotes)
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
            
        # Skip parameters with values that are too short
        if len(value) < config["min_param_value_length"]:
            continue
            
        param_info = {
            "name": name,
            "value": get_value_preview(value) if config["include_values"] else ""
        }
        
        parameters.append(param_info)
    
    return parameters

def get_value_preview(value):
    """
    Get a preview of a value for display
    
    Args:
        value (str): The original value
        
    Returns:
        str: Value preview
    """
    max_length = config["max_value_preview_length"]
    
    if not value:
        return ""
        
    if len(value) > max_length:
        return value[:max_length] + "..."
        
    return value

def process_xml_dataset(xml_data, base_url=None):
    """
    Process all items in the XML dataset and collate results
    
    Args:
        xml_data (list): List of items from the XML file
        base_url (str, optional): Base URL to use if URLs are relative
        
    Returns:
        dict: Combined analysis results
    """
    if not xml_data:
        return None
    
    combined_results = None
    
    for item in xml_data:
        url = item["url"]
        
        # If URL is relative and base_url is provided, join them
        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)
        
        # Skip items without a valid URL
        if not url:
            continue
        
        # Analyze this item
        results = analyze(
            item["request_data"], 
            item["response_data"], 
            url, 
            aggregate_results=combined_results
        )
        
        # For the first item, initialize combined_results
        if combined_results is None:
            combined_results = results
        
    return combined_results or {}

def parse_xml_file(file_path):
    """
    Parse an XML file containing HTTP responses
    
    Args:
        file_path (str): Path to the XML file
        
    Returns:
        list: List of dictionaries with request, response data and URLs
    """
    import xml.etree.ElementTree as ET
    
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        items = []
        for item in root.findall('./item'):
            url_elem = item.find('url')
            request_elem = item.find('request')
            response_elem = item.find('response')
            
            url = url_elem.text if url_elem is not None else ""
            
            request_data = {}
            if request_elem is not None:
                headers_elem = request_elem.find('headers')
                body_elem = request_elem.find('body')
                path_elem = request_elem.find('path')
                method_elem = request_elem.find('method')
                
                headers = {}
                if headers_elem is not None:
                    for header in headers_elem.findall('header'):
                        name = header.get('name')
                        value = header.text
                        if name and value:
                            headers[name] = value
                
                request_data = {
                    "headers": headers,
                    "body": body_elem.text if body_elem is not None else "",
                    "path": path_elem.text if path_elem is not None else "",
                    "method": method_elem.text if method_elem is not None else ""
                }
            
            response_data = {}
            if response_elem is not None:
                headers_elem = response_elem.find('headers')
                body_elem = response_elem.find('body')
                status_code_elem = response_elem.find('status_code')
                
                headers = {}
                if headers_elem is not None:
                    for header in headers_elem.findall('header'):
                        name = header.get('name')
                        value = header.text
                        if name and value:
                            headers[name] = value
                
                response_data = {
                    "headers": headers,
                    "body": body_elem.text if body_elem is not None else "",
                    "status_code": status_code_elem.text if status_code_elem is not None else "200"
                }
            
            items.append({
                "url": url,
                "request_data": request_data,
                "response_data": response_data
            })
        
        return items
    except Exception as e:
        print(f"Error parsing XML file: {str(e)}")
        return []

def add_command_line_arguments(parser):
    """
    Add command line arguments
    
    Args:
        parser: ArgumentParser instance
    """
    # XML processing arguments
    parser.add_argument("--xml", "-x", dest="xml_file",
                      help="Path to XML file containing multiple HTTP responses")
    parser.add_argument("--base-url", "-b", dest="base_url",
                      help="Base URL to use for relative URLs in the XML file")
    
    # Result storage path arguments
    parser.add_argument("--base-path", dest="base_path",
                      help="Base path for storing results")
    parser.add_argument("--target", dest="target",
                      help="Target identifier")
    parser.add_argument("--auth-mode", dest="auth_mode", choices=["Auth", "Raw"],
                      help="Authentication mode (Auth or Raw)")
    parser.add_argument("--category", dest="category",
                      help="Test category")
    parser.add_argument("--test-type", dest="test_type",
                      help="Type of test being performed")
    
    # Output format options
    parser.add_argument("--output", "-o", dest="output_file",
                      help="Output file for the results (default: auto-generated path)")
    parser.add_argument("--format", "-f", dest="output_format", choices=["json", "txt"],
                      default="json", help="Output format (default: json)")

def build_results_path(base_path, target, auth_mode, category, test_type):
    """
    Build the path for saving results based on parameters
    
    Args:
        base_path (str): Base directory path
        target (str): Target name/identifier
        auth_mode (str): Authentication mode ("Auth" or "Raw")
        category (str): Test category
        test_type (str): Type of test
        
    Returns:
        str: Full path for results directory
    """
    # Sanitize path components to handle spaces and special characters safely
    # We'll preserve spaces but replace characters that are problematic in file paths
    
    def sanitize_path_component(component):
        # Replace characters that are problematic in file paths with underscores
        problematic_chars = '<>:"|?*'
        for char in problematic_chars:
            component = component.replace(char, '_')
        return component
    
    # Sanitize each component
    target = sanitize_path_component(target)
    # Auth mode should only be "Auth" or "Raw"
    auth_mode = "Auth" if auth_mode.lower() == "auth" else "Raw"
    category = sanitize_path_component(category)
    test_type = sanitize_path_component(test_type)
    
    # Build the path
    result_path = os.path.join(
        base_path,
        target,
        auth_mode,
        category,
        test_type,
        "Results"
    )
    
    # Ensure the directory exists
    ensure_directory_exists(result_path)
    
    return result_path

def ensure_directory_exists(directory_path):
    """
    Create directory and any parent directories if they don't exist
    
    Args:
        directory_path (str): Path to create
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)

def export_results(results, output_format="json", output_file=None, 
                  base_path=None, target=None, auth_mode=None, category=None, test_type=None):
    """
    Export analysis results to a file or stdout
    
    Args:
        results (dict): Analysis results
        output_format (str): Output format (json or txt)
        output_file (str, optional): Explicit output file path
        base_path (str, optional): Base directory for results
        target (str, optional): Target identifier
        auth_mode (str, optional): Authentication mode
        category (str, optional): Category
        test_type (str, optional): Type of test
    """
    # Format the results
    if output_format == "json":
        output = json.dumps(results, indent=2)
    else:
        # Text format
        output = format_results_as_text(results)
    
    # If we have all the path components, build a structured path
    if base_path and target and auth_mode and category and test_type:
        # Build the path
        results_dir = build_results_path(base_path, target, auth_mode, category, test_type)
        
        # If no explicit output file is provided, use a default name
        if not output_file:
            timestamp = time.strftime("%Y%m%d-%H%M%S")
            output_file = os.path.join(results_dir, f"results-{timestamp}.{output_format}")
    
    # Write to file or stdout
    if output_file:
        # Ensure the parent directory exists
        parent_dir = os.path.dirname(output_file)
        if parent_dir and not os.path.exists(parent_dir):
            os.makedirs(parent_dir)
            
        with open(output_file, "w") as f:
            f.write(output)
        print(f"Results written to {output_file}")
    else:
        print(output)

def format_results_as_text(results):
    """
    Format results as plain text
    
    Args:
        results (dict): Analysis results
        
    Returns:
        str: Formatted text
    """
    text = []
    text.append("BODY PARAMETER DETECTION RESULTS")
    text.append("=" * 40)
    
    if "source_urls" in results and results["source_urls"]:
        text.append(f"Source URLs: {len(results['source_urls'])}")
        for url in results["source_urls"][:5]:
            text.append(f"- {url}")
        if len(results["source_urls"]) > 5:
            text.append(f"... and {len(results['source_urls']) - 5} more")
    text.append("")
    
    text.append("STATISTICS")
    text.append("-" * 40)
    text.append(f"Total Requests: {results.get('request_count', 0)}")
    text.append(f"Requests with Parameters: {results.get('requests_with_parameters', 0)}")
    text.append(f"Total Parameters: {results.get('total_parameters', 0)}")
    text.append(f"Unique Parameters: {results.get('unique_parameters', 0)}")
    text.append("")
    
    text.append("UNIQUE PARAMETERS")
    text.append("-" * 40)
    for param_name, param_info in results.get("parameters", {}).items():
        text.append(f"Parameter: {param_name}")
        text.append(f"Occurrences: {param_info.get('count', 0)}")
        text.append(f"Types: {', '.join(param_info.get('types', []))}")
        text.append(f"HTTP Methods: {', '.join(param_info.get('methods', []))}")
        
        if param_info.get("values"):
            text.append("Example Values:")
            for value in param_info.get("values", [])[:3]:
                text.append(f"- {value}")
            
            if len(param_info.get("values", [])) > 3:
                text.append(f"... and {len(param_info.get('values', [])) - 3} more")
                
        text.append("")
    
    return "\n".join(text)

# If this module is run directly, provide a command-line interface
if __name__ == "__main__":
    import argparse
    import os
    import time
    import json
    from urllib.parse import urljoin
    
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="Body Parameter Detector Module")
    add_command_line_arguments(parser)
    args = parser.parse_args()
    
    # Process the input and generate results
    if args.xml_file:
        # XML processing
        print(f"Processing XML file: {args.xml_file}")
        xml_data = parse_xml_file(args.xml_file)
        if xml_data:
            results = process_xml_dataset(xml_data, args.base_url)
        else:
            print("Error: Failed to parse XML file or file is empty")
            exit(1)
    else:
        # Test data for demonstration when no XML file is provided
        print("No XML file provided. Using default test data.")
        test_request = {
            "method": "POST",
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Mozilla/5.0",
                "Content-Length": "53"
            },
            "body": "username=testuser&password=testpass&action=login&remember=true"
        }
        
        # Test the analyze function with a single request
        results = analyze(test_request, {}, "https://example.com/login.php")
    
    # Export the results
    if args.base_path and args.target and args.auth_mode and args.category and args.test_type:
        # Use structured path
        print(f"Saving results using structured path: {args.base_path}/{args.target}/{args.auth_mode}/{args.category}/{args.test_type}/Results/")
        export_results(
            results=results,
            output_format=args.output_format,
            output_file=args.output_file,
            base_path=args.base_path,
            target=args.target,
            auth_mode=args.auth_mode,
            category=args.category,
            test_type=args.test_type
        )
    else:
        # Use simple output
        print("Using simple output (no structured path provided)")
        export_results(
            results=results,
            output_format=args.output_format,
            output_file=args.output_file
        )
