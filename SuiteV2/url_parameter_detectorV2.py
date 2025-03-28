"""
URL Parameter Detector Module

This module scans through all requests and extracts URL parameters
from query strings for potential testing.
"""

import re
import urllib.parse
from collections import defaultdict
import tkinter as tk
from tkinter import ttk

# Module metadata
MODULE_NAME = "URL Parameter Detector"
MODULE_DESCRIPTION = "Scans all requests for URL parameters"
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
    "group_by_parameter": True,
    "include_hash_parameters": True  # Parameters after # in URLs
}

def configure(frame):
    """Set up the configuration UI"""
    # Clear the frame
    for widget in frame.winfo_children():
        widget.destroy()
    
    # Create configuration widgets
    ttk.Label(frame, text="URL Parameter Detection Settings", font=("", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
    
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
    
    group_by_param_var = tk.BooleanVar(value=config["group_by_parameter"])
    ttk.Checkbutton(frame, text="Group Results by Parameter", variable=group_by_param_var,
                  command=lambda: update_config("group_by_parameter", group_by_param_var.get())).grid(row=5, column=0, sticky="w")
    
    include_hash_var = tk.BooleanVar(value=config["include_hash_parameters"])
    ttk.Checkbutton(frame, text="Include URL Fragment Parameters", variable=include_hash_var,
                  command=lambda: update_config("include_hash_parameters", include_hash_var.get())).grid(row=6, column=0, sticky="w")

def update_config(key, value):
    """Update a configuration value"""
    config[key] = value

def analyze(request_data, response_data, url):
    """
    Analyze ALL requests for URL parameters
    
    Args:
        request_data (dict): The request data (we'll ignore this)
        response_data (dict): The response data (we'll ignore this)
        url (str): The full URL (we'll ignore this)
        
    Returns:
        dict: Analysis results with all URL parameters found across all requests
    """
    results = {
        "title": "URL Parameter Detection Results",
        "description": "Parameters found in URL query strings",
        "parameters": {},
        "request_count": 0,
        "requests_with_parameters": 0,
        "total_parameters": 0,
        "unique_parameters": 0,
        "requests": []
    }
    
    # Access the CoreXMLParser instance via the global reference
    import __main__
    if not hasattr(__main__, 'app'):
        return {"error": "Cannot access application instance"}
    
    app = __main__.app
    items = app.items
    
    # Process all items
    for index, item in enumerate(items):
        # Get URL
        url_elem = item.find('url')
        if url_elem is None or not url_elem.text:
            continue
            
        item_url = url_elem.text
        
        # Extract request method
        request = item.find('request')
        method = "GET"  # Default to GET
        if request is not None:
            request_content = request.text or ""
            if request.get('base64') == 'true':
                try:
                    request_content = app.decode_base64(request_content)
                    first_line = request_content.split('\n', 1)[0]
                    method = first_line.split(' ', 1)[0] if first_line else "GET"
                except:
                    pass
        
        # Extract parameters from URL
        url_params = extract_url_parameters(item_url)
        
        if not url_params:
            continue
            
        results["requests_with_parameters"] += 1
        results["total_parameters"] += len(url_params)
        
        # Store the request information
        request_info = {
            "index": index + 1,  # 1-based index for user display
            "url": item_url,
            "method": method,
            "parameter_count": len(url_params),
            "parameters": url_params
        }
        
        results["requests"].append(request_info)
        
        # Add parameters to the master list
        for param in url_params:
            param_name = param["name"]
            
            if param_name not in results["parameters"]:
                results["parameters"][param_name] = {
                    "count": 0,
                    "values": set(),
                    "methods": set(),
                    "requests": []
                }
                
                results["unique_parameters"] += 1
                
            results["parameters"][param_name]["count"] += 1
            results["parameters"][param_name]["requests"].append(index + 1)  # 1-based index
            
            if param.get("value"):
                results["parameters"][param_name]["values"].add(param["value"])
                
            results["parameters"][param_name]["methods"].add(method)
    
    # Convert sets to lists for JSON serialization
    for param_name, param_info in results["parameters"].items():
        param_info["values"] = list(param_info["values"])
        param_info["methods"] = list(param_info["methods"])
    
    results["request_count"] = len(items)
    
    return results

def analyze_all(all_items_data):
    """
    Analyze all requests for URL parameters
    
    Args:
        all_items_data (list): List of dictionaries containing request and response data
        
    Returns:
        dict: Analysis results with all URL parameters found across all requests
    """
    results = {
        "title": "URL Parameter Detection Results",
        "description": "Parameters found in URL query strings",
        "parameters": {},
        "request_count": len(all_items_data),
        "requests_with_parameters": 0,
        "total_parameters": 0,
        "unique_parameters": 0,
        "requests": []
    }
    
    # Process all items
    for item_data in all_items_data:
        index = item_data["index"]
        url = item_data["url"]
        request_data = item_data["request_data"]
        
        # Skip if no URL
        if not url:
            continue
            
        # Get method
        method = request_data.get("method", "GET")
        
        # Extract parameters from URL
        url_params = extract_url_parameters(url)
        
        if not url_params:
            continue
            
        results["requests_with_parameters"] += 1
        results["total_parameters"] += len(url_params)
        
        # Store the request information
        request_info = {
            "index": index + 1,  # 1-based index for user display
            "url": url,
            "method": method,
            "parameter_count": len(url_params),
            "parameters": url_params
        }
        
        results["requests"].append(request_info)
        
        # Add parameters to the master list
        for param in url_params:
            param_name = param["name"]
            
            if param_name not in results["parameters"]:
                results["parameters"][param_name] = {
                    "count": 0,
                    "values": set(),
                    "methods": set(),
                    "requests": []
                }
                
                results["unique_parameters"] += 1
                
            results["parameters"][param_name]["count"] += 1
            results["parameters"][param_name]["requests"].append(index + 1)  # 1-based index
            
            if param.get("value"):
                results["parameters"][param_name]["values"].add(param["value"])
                
            results["parameters"][param_name]["methods"].add(method)
    
    # Convert sets to lists for JSON serialization
    for param_name, param_info in results["parameters"].items():
        param_info["values"] = list(param_info["values"])
        param_info["methods"] = list(param_info["methods"])
    
    return results

def extract_url_parameters(url):
    """
    Extract parameters from a URL
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        list: List of parameter dictionaries
    """
    parameters = []
    
    # Parse the URL
    try:
        parsed = urllib.parse.urlparse(url)
        
        # Extract query parameters (after ?)
        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query)
            for name, values in query_params.items():
                # Skip parameters with names that are too short
                if len(name) < config["min_param_name_length"]:
                    continue
                    
                for value in values:
                    # Skip parameters with values that are too short
                    if len(value) < config["min_param_value_length"]:
                        continue
                        
                    param_info = {
                        "name": name,
                        "location": "query"
                    }
                    
                    # Add value preview if enabled
                    if config["include_values"]:
                        param_info["value"] = get_value_preview(value)
                        
                    parameters.append(param_info)
        
        # Extract hash parameters (after #) if enabled
        if config["include_hash_parameters"] and parsed.fragment:
            # Check if the fragment contains parameters
            if '=' in parsed.fragment:
                # Try to parse as query string
                try:
                    fragment_params = urllib.parse.parse_qs(parsed.fragment)
                    for name, values in fragment_params.items():
                        # Skip parameters with names that are too short
                        if len(name) < config["min_param_name_length"]:
                            continue
                            
                        for value in values:
                            # Skip parameters with values that are too short
                            if len(value) < config["min_param_value_length"]:
                                continue
                                
                            param_info = {
                                "name": name,
                                "location": "fragment"
                            }
                            
                            # Add value preview if enabled
                            if config["include_values"]:
                                param_info["value"] = get_value_preview(value)
                                
                            parameters.append(param_info)
                except:
                    # Not valid query string in fragment
                    pass
    except:
        # Invalid URL
        return []
    
    return parameters

def get_value_preview(value):
    """Get a preview of a value for display"""
    max_length = config["max_value_preview_length"]
    
    if not value:
        return ""
        
    if len(value) > max_length:
        return value[:max_length] + "..."
        
    return value

# Function to analyze a URL directly (for testing)
def analyze_url(url):
    """Analyze a URL directly (for testing)"""
    parameters = extract_url_parameters(url)
    return {
        "url": url,
        "parameters": parameters
    }

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
    
    # Convert the XML data into the format expected by analyze_all
    all_items_data = []
    
    for i, item in enumerate(xml_data):
        url = item["url"]
        
        # If URL is relative and base_url is provided, join them
        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)
        
        # Skip items without a valid URL
        if not url:
            continue
            
        # Add to the items data
        all_items_data.append({
            "index": i,
            "url": url,
            "request_data": item["request_data"],
            "response_data": item["response_data"]
        })
    
    # Process all items
    if all_items_data:
        return analyze_all(all_items_data)
    
    return {
        "title": "URL Parameter Detection Results",
        "description": "Parameters found in URL query strings",
        "parameters": {},
        "request_count": 0,
        "requests_with_parameters": 0,
        "total_parameters": 0,
        "unique_parameters": 0,
        "requests": []
    }

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
    text.append("URL PARAMETER DETECTION RESULTS")
    text.append("=" * 50)
    
    # Basic stats
    text.append("STATISTICS")
    text.append("-" * 40)
    text.append(f"Total Requests: {results.get('request_count', 0)}")
    text.append(f"Requests with Parameters: {results.get('requests_with_parameters', 0)}")
    text.append(f"Total Parameters Detected: {results.get('total_parameters', 0)}")
    text.append(f"Unique Parameters: {results.get('unique_parameters', 0)}")
    text.append("")
    
    # Parameters section
    text.append("PARAMETERS")
    text.append("-" * 40)
    for param_name, param_info in sorted(results.get("parameters", {}).items()):
        text.append(f"Parameter: {param_name}")
        text.append(f"Occurrences: {param_info.get('count', 0)}")
        text.append(f"HTTP Methods: {', '.join(param_info.get('methods', []))}")
        
        # Show example values if available
        if param_info.get("values"):
            text.append("Example Values:")
            for i, value in enumerate(param_info["values"][:5]):
                text.append(f"  - {value}")
            
            if len(param_info["values"]) > 5:
                text.append(f"  ... and {len(param_info['values']) - 5} more values")
        
        text.append("")
    
    # Requests section (limited to keep output manageable)
    if results.get("requests"):
        text.append("REQUESTS WITH PARAMETERS")
        text.append("-" * 40)
        
        for i, request in enumerate(results["requests"][:20]):  # Limit to 20 requests
            text.append(f"Request #{request.get('index', '?')}: {request.get('url', 'Unknown URL')}")
            text.append(f"Method: {request.get('method', 'GET')}")
            text.append(f"Parameters: {request.get('parameter_count', 0)}")
            
            # List parameters for this request
            if request.get("parameters"):
                for param in request["parameters"][:5]:  # Limit to 5 parameters per request
                    if "value" in param:
                        text.append(f"  - {param['name']} = {param['value']} ({param.get('location', 'query')})")
                    else:
                        text.append(f"  - {param['name']} ({param.get('location', 'query')})")
                        
                if len(request.get("parameters", [])) > 5:
                    text.append(f"  ... and {len(request['parameters']) - 5} more parameters")
            
            text.append("")
            
        if len(results["requests"]) > 20:
            text.append(f"... and {len(results['requests']) - 20} more requests with parameters")
    
    return "\n".join(text)

# If this module is run directly, provide a command-line interface
if __name__ == "__main__":
    import argparse
    import os
    import time
    import json
    from urllib.parse import urljoin
    
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="URL Parameter Detector Module")
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
        
        # Test URLs
        test_urls = [
            "https://example.com/search?q=test&page=1&limit=10",
            "https://example.com/profile#user=123&tab=settings",
            "https://example.com/api/data?id=5&format=json"
        ]
        
        # Create test items
        test_items = []
        for i, url in enumerate(test_urls):
            test_items.append({
                "index": i,
                "url": url,
                "request_data": {"method": "GET", "headers": {}, "body": ""},
                "response_data": {}
            })
        
        # Analyze test data
        results = analyze_all(test_items)
    
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
