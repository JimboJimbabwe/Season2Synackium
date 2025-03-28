"""
JSON Parameter Detector Module

This module scans through all requests with JSON content type
and extracts all JSON parameters/objects for potential testing.
"""

import json
import re
import tkinter as tk
from tkinter import ttk

# Module metadata
MODULE_NAME = "JSON Parameter Detector"
MODULE_DESCRIPTION = "Scans all requests for JSON parameters"
MODULE_VERSION = "1.0"
MODULE_AUTHOR = "Security Researcher"
# Flag to indicate this module scans all requests
SCAN_ALL_REQUESTS = True

# Configuration
config = {
    "include_arrays": True,
    "include_values": True,
    "include_nested": True,
    "min_key_length": 1,
    "max_depth": 10,
    "max_value_preview_length": 30
}

def configure(frame):
    """Set up the configuration UI"""
    # Clear the frame
    for widget in frame.winfo_children():
        widget.destroy()
    
    # Create configuration widgets
    ttk.Label(frame, text="JSON Detection Settings", font=("", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
    
    # Checkboxes for options
    include_arrays_var = tk.BooleanVar(value=config["include_arrays"])
    ttk.Checkbutton(frame, text="Include Array Indices", variable=include_arrays_var,
                  command=lambda: update_config("include_arrays", include_arrays_var.get())).grid(row=1, column=0, sticky="w")
    
    include_values_var = tk.BooleanVar(value=config["include_values"])
    ttk.Checkbutton(frame, text="Show Parameter Values", variable=include_values_var,
                  command=lambda: update_config("include_values", include_values_var.get())).grid(row=2, column=0, sticky="w")
    
    include_nested_var = tk.BooleanVar(value=config["include_nested"])
    ttk.Checkbutton(frame, text="Include Nested Parameters", variable=include_nested_var,
                  command=lambda: update_config("include_nested", include_nested_var.get())).grid(row=3, column=0, sticky="w")
    
    # Minimum key length
    ttk.Label(frame, text="Minimum Parameter Name Length:").grid(row=4, column=0, sticky="w", pady=(10, 5))
    min_length_var = tk.IntVar(value=config["min_key_length"])
    min_length_spinbox = ttk.Spinbox(frame, from_=1, to=10, textvariable=min_length_var, width=5)
    min_length_spinbox.grid(row=4, column=1, sticky="w")
    min_length_spinbox.bind("<FocusOut>", lambda e: update_config("min_key_length", int(min_length_var.get())))
    
    # Maximum recursion depth
    ttk.Label(frame, text="Maximum Nested Object Depth:").grid(row=5, column=0, sticky="w", pady=(10, 5))
    max_depth_var = tk.IntVar(value=config["max_depth"])
    max_depth_spinbox = ttk.Spinbox(frame, from_=1, to=20, textvariable=max_depth_var, width=5)
    max_depth_spinbox.grid(row=5, column=1, sticky="w")
    max_depth_spinbox.bind("<FocusOut>", lambda e: update_config("max_depth", int(max_depth_var.get())))
    
    # Maximum value preview length
    ttk.Label(frame, text="Maximum Value Preview Length:").grid(row=6, column=0, sticky="w", pady=(10, 5))
    max_preview_var = tk.IntVar(value=config["max_value_preview_length"])
    max_preview_spinbox = ttk.Spinbox(frame, from_=10, to=100, textvariable=max_preview_var, width=5)
    max_preview_spinbox.grid(row=6, column=1, sticky="w")
    max_preview_spinbox.bind("<FocusOut>", lambda e: update_config("max_value_preview_length", int(max_preview_var.get())))

def update_config(key, value):
    """Update a configuration value"""
    config[key] = value

def analyze(request_data, response_data, url):
    """
    Analyze the current request/response for JSON parameters.
    This function will be called by the main application for the CURRENT request.
    However, we'll analyze ALL requests in the XML file.
    
    Args:
        request_data (dict): The request data (we'll ignore this)
        response_data (dict): The response data (we'll ignore this)
        url (str): The full URL (we'll ignore this)
        
    Returns:
        dict: Analysis results with all JSON parameters found across all requests
    """
    results = {
        "title": "JSON Parameter Detection Results",
        "description": "Parameters found in JSON request bodies",
        "parameters": {},
        "request_count": 0,
        "json_request_count": 0,
        "total_parameters": 0,
        "requests_with_parameters": []
    }
    
    # Access the CoreXMLParser instance via the global reference
    # This is a bit of a hack, but it allows us to access all items
    import __main__
    if not hasattr(__main__, 'app'):
        return {"error": "Cannot access application instance"}
    
    app = __main__.app
    items = app.items
    
    # Process all items
    for index, item in enumerate(items):
        request = item.find('request')
        if request is None:
            continue
            
        # Get URL
        url_elem = item.find('url')
        item_url = url_elem.text if url_elem is not None else "Unknown URL"
            
        # Get request content
        request_content = request.text or ""
        if request.get('base64') == 'true':
            try:
                request_content = app.decode_base64(request_content)
            except:
                continue
        
        # Check if this is a JSON request
        is_json = False
        content_type = ""
        
        # Extract headers to check content type
        headers_match = re.search(r'^(.*?)\r?\n\r?\n', request_content, re.DOTALL)
        if headers_match:
            headers_text = headers_match.group(1)
            content_type_match = re.search(r'Content-Type:\s*(.*?)(\r?\n|$)', headers_text, re.IGNORECASE)
            if content_type_match:
                content_type = content_type_match.group(1).strip()
                is_json = 'json' in content_type.lower() or 'application/json' in content_type.lower()
        
        # Skip if not JSON
        if not is_json:
            continue
            
        results["json_request_count"] += 1
            
        # Extract body
        body_match = re.search(r'\r?\n\r?\n(.*)', request_content, re.DOTALL)
        if not body_match:
            continue
            
        body = body_match.group(1).strip()
        if not body:
            continue
        
        # Try to parse JSON
        try:
            json_data = json.loads(body)
            
            # Extract parameters
            parameters = extract_json_parameters(json_data)
            
            if parameters:
                request_info = {
                    "index": index + 1,  # 1-based index for user display
                    "url": item_url,
                    "method": get_request_method(request_content),
                    "content_type": content_type,
                    "parameters": parameters
                }
                
                results["requests_with_parameters"].append(request_info)
                results["total_parameters"] += len(parameters)
                
                # Add parameters to the overall collection
                for param in parameters:
                    param_name = param["name"]
                    if param_name not in results["parameters"]:
                        results["parameters"][param_name] = {
                            "count": 0,
                            "type": param["type"],
                            "example_value": param["value"] if "value" in param else None,
                            "requests": []
                        }
                    
                    results["parameters"][param_name]["count"] += 1
                    results["parameters"][param_name]["requests"].append(index + 1)  # 1-based index
        except json.JSONDecodeError:
            # Not valid JSON, skip
            continue
    
    results["request_count"] = len(items)
    
    return results

def analyze_all(all_items_data):
    """
    Analyze all requests for JSON parameters
    
    Args:
        all_items_data (list): List of dictionaries containing request and response data
        
    Returns:
        dict: Analysis results with all JSON parameters found across all requests
    """
    results = {
        "title": "JSON Parameter Detection Results",
        "description": "Parameters found in JSON request bodies",
        "parameters": {},
        "request_count": len(all_items_data),
        "json_request_count": 0,
        "total_parameters": 0,
        "requests_with_parameters": [],
        "debug_info": []  # Add debug info to help troubleshoot issues
    }
    
    # Process all items
    for item_data in all_items_data:
        index = item_data["index"]
        url = item_data.get("url", "Unknown URL")
        request_data = item_data.get("request_data", {})
        
        # Debug info for this request
        request_debug = {
            "index": index,
            "url": url,
            "has_content_type": False,
            "content_type": None,
            "is_json": False,
            "has_body": False,
            "body_length": 0,
            "parse_attempt": False,
            "parse_error": None
        }
        
        # Check if this is a JSON request (more lenient check)
        is_json = False
        content_type = ""
        
        # Extract Content-Type in a case-insensitive way
        if "headers" in request_data and request_data["headers"]:
            for header_name, header_value in request_data["headers"].items():
                if header_name.lower() == "content-type":
                    content_type = header_value
                    request_debug["has_content_type"] = True
                    request_debug["content_type"] = content_type
                    # More lenient check for JSON content types
                    is_json = 'json' in content_type.lower() or '+json' in content_type.lower()
                    request_debug["is_json"] = is_json
                    break
        
        # Check for body presence and non-emptiness
        has_body = "body" in request_data and request_data["body"] and request_data["body"].strip()
        request_debug["has_body"] = has_body
        if has_body:
            request_debug["body_length"] = len(request_data["body"])
        
        # Skip if not JSON or no body
        if not is_json or not has_body:
            results["debug_info"].append(request_debug)
            continue
            
        results["json_request_count"] += 1
        
        # Try to parse JSON with better error handling
        try:
            request_debug["parse_attempt"] = True
            json_data = json.loads(request_data["body"])
            
            # Extract parameters
            parameters = extract_json_parameters(json_data)
            
            if parameters:
                request_info = {
                    "index": index + 1,  # 1-based index for user display
                    "url": url,
                    "method": request_data.get("method", ""),
                    "content_type": content_type,
                    "parameters": parameters
                }
                
                results["requests_with_parameters"].append(request_info)
                results["total_parameters"] += len(parameters)
                
                # Add parameters to the overall collection
                for param in parameters:
                    param_name = param["name"]
                    if param_name not in results["parameters"]:
                        results["parameters"][param_name] = {
                            "count": 0,
                            "type": param["type"],
                            "example_value": param.get("value"),
                            "requests": []
                        }
                    
                    results["parameters"][param_name]["count"] += 1
                    results["parameters"][param_name]["requests"].append(index + 1)  # 1-based index
        except json.JSONDecodeError as e:
            # Capture JSON parse errors for debugging
            request_debug["parse_error"] = str(e)
        except Exception as e:
            # Capture other unexpected errors
            request_debug["parse_error"] = f"Unexpected error: {str(e)}"
        
        results["debug_info"].append(request_debug)
    
    return results

def extract_json_parameters(json_data, prefix="", depth=0):
    """
    Recursively extract parameters from JSON data
    
    Args:
        json_data: The JSON data to process
        prefix (str): Current key prefix for nested objects
        depth (int): Current recursion depth
        
    Returns:
        list: List of parameter info dictionaries
    """
    if depth > config["max_depth"]:
        return []
        
    parameters = []
    
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            # Skip keys that are too short
            if len(key) < config["min_key_length"]:
                continue
                
            full_key = f"{prefix}.{key}" if prefix else key
            param_type = get_type_name(value)
            
            param_info = {
                "name": full_key,
                "type": param_type
            }
            
            # Add value preview if enabled
            if config["include_values"]:
                param_info["value"] = get_value_preview(value)
            
            parameters.append(param_info)
            
            # Recursively process nested objects and arrays if enabled
            if config["include_nested"]:
                if isinstance(value, dict):
                    parameters.extend(extract_json_parameters(value, full_key, depth + 1))
                elif isinstance(value, list) and config["include_arrays"]:
                    for i, item in enumerate(value):
                        if isinstance(item, (dict, list)):
                            parameters.extend(extract_json_parameters(item, f"{full_key}[{i}]", depth + 1))
    
    elif isinstance(json_data, list) and config["include_arrays"]:
        for i, item in enumerate(json_data):
            array_key = f"{prefix}[{i}]"
            
            if isinstance(item, (dict, list)):
                parameters.extend(extract_json_parameters(item, array_key, depth + 1))
    
    return parameters

def get_type_name(value):
    """Get a user-friendly type name for a value"""
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "boolean"
    elif isinstance(value, int):
        return "integer"
    elif isinstance(value, float):
        return "float"
    elif isinstance(value, str):
        return "string"
    elif isinstance(value, list):
        return "array"
    elif isinstance(value, dict):
        return "object"
    else:
        return type(value).__name__

def get_value_preview(value):
    """Get a preview of a value for display"""
    max_length = config["max_value_preview_length"]
    
    if value is None:
        return "null"
    elif isinstance(value, (bool, int, float)):
        return str(value)
    elif isinstance(value, str):
        if len(value) > max_length:
            return value[:max_length] + "..."
        return value
    elif isinstance(value, list):
        return f"Array[{len(value)}]"
    elif isinstance(value, dict):
        return f"Object({len(value)} keys)"
    else:
        return str(type(value).__name__)

def get_request_method(request_content):
    """Extract HTTP method from request content"""
    first_line = request_content.split('\n', 1)[0] if request_content else ""
    method = first_line.split(' ', 1)[0] if first_line else "Unknown"
    return method

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
        "title": "JSON Parameter Detection Results",
        "description": "Parameters found in JSON request bodies",
        "parameters": {},
        "request_count": 0,
        "json_request_count": 0,
        "total_parameters": 0,
        "requests_with_parameters": []
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
    text.append("JSON PARAMETER DETECTION RESULTS")
    text.append("=" * 50)
    
    # Basic stats
    text.append("STATISTICS")
    text.append("-" * 40)
    text.append(f"Total Requests: {results.get('request_count', 0)}")
    text.append(f"JSON Requests: {results.get('json_request_count', 0)}")
    text.append(f"Total Parameters Found: {results.get('total_parameters', 0)}")
    text.append(f"Unique Parameters: {len(results.get('parameters', {}))}")
    text.append("")
    
    # Parameters section with detailed information
    if results.get("parameters"):
        text.append("PARAMETERS DETAILS")
        text.append("-" * 40)
        
        for param_name, param_info in sorted(results.get("parameters", {}).items()):
            text.append(f"Parameter: {param_name}")
            text.append(f"Type: {param_info.get('type', 'unknown')}")
            text.append(f"Occurrences: {param_info.get('count', 0)}")
            
            # Show requests where this parameter appears
            if param_info.get("requests"):
                request_list = ", ".join(map(str, param_info.get("requests", [])))
                text.append(f"Found in Requests: {request_list}")
            
            # Show example value if available
            if param_info.get("example_value") is not None:
                text.append(f"Example Value: {param_info.get('example_value')}")
                
            text.append("")
    
    # Detailed Request Information
    if results.get("requests_with_parameters"):
        text.append("REQUESTS WITH JSON PARAMETERS")
        text.append("-" * 40)
        
        for req_info in results["requests_with_parameters"]:
            text.append(f"Request #{req_info.get('index', '?')}")
            text.append(f"URL: {req_info.get('url', 'Unknown URL')}")
            text.append(f"Method: {req_info.get('method', 'GET')}")
            text.append(f"Content-Type: {req_info.get('content_type', 'Unknown')}")
            text.append(f"Parameters: {len(req_info.get('parameters', []))}")
            
            # List all parameters in this request with full details
            if req_info.get("parameters"):
                text.append("Parameter Details:")
                for param in req_info["parameters"]:
                    param_text = f"  - {param.get('name', 'Unknown')} ({param.get('type', 'unknown')})"
                    if "value" in param:
                        param_text += f" = {param['value']}"
                    text.append(param_text)
            
            text.append("")
    else:
        text.append("NO JSON PARAMETERS FOUND")
        text.append("-" * 40)
        text.append("No JSON parameters were detected in any of the requests.")
    
    return "\n".join(text)


# If this module is run directly, provide a command-line interface
if __name__ == "__main__":
    import argparse
    import os
    import time
    from urllib.parse import urljoin
    
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="JSON Parameter Detector Module")
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
        
        # Test JSON data
        test_json = {
            "user": {
                "id": 123,
                "name": "Test User",
                "email": "test@example.com",
                "preferences": {
                    "theme": "dark",
                    "notifications": True
                },
                "roles": ["user", "editor"]
            },
            "action": "login",
            "timestamp": 1620000000
        }
        
        test_request = {
            "method": "POST",
            "headers": {
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0"
            },
            "body": json.dumps(test_json)
        }
        
        # Analyze a single request and convert to the expected format
        single_item = [{
            "index": 0,
            "url": "https://example.com/api/login",
            "request_data": test_request,
            "response_data": {}
        }]
        
        results = analyze_all(single_item)
    
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
