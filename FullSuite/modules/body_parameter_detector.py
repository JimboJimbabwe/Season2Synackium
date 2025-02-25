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

def analyze(request_data, response_data, url):
    """
    Analyze ALL requests for body parameters
    
    Args:
        request_data (dict): The request data (we'll ignore this)
        response_data (dict): The response data (we'll ignore this)
        url (str): The full URL (we'll ignore this)
        
    Returns:
        dict: Analysis results with all body parameters found across all requests
    """
    results = {
        "title": "Request Body Parameter Detection Results",
        "description": "Parameters found in request bodies",
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
        # Get request
        request = item.find('request')
        if request is None:
            continue
        
        # Get URL
        url_elem = item.find('url')
        item_url = url_elem.text if url_elem is not None else "Unknown URL"
        
        # Extract request content
        request_content = request.text or ""
        if request.get('base64') == 'true':
            try:
                request_content = app.decode_base64(request_content)
            except:
                continue
        
        # Parse the request
        method, headers, body = parse_request(request_content)
        
        # Skip if no body
        if not body:
            continue
        
        # Determine content type
        content_type = get_header_value(headers, 'Content-Type')
        
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
        
        # If no parameters found, skip this request
        if not body_params:
            continue
        
        results["requests_with_parameters"] += 1
        results["total_parameters"] += len(body_params)
        
        # Store the request information
        request_info = {
            "index": index + 1,  # 1-based index for user display
            "url": item_url,
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
    
    results["request_count"] = len(items)
    
    return results

def analyze_all(all_items_data):
    """
    Analyze all requests for body parameters
    
    Args:
        all_items_data (list): List of dictionaries containing request and response data
        
    Returns:
        dict: Analysis results with all body parameters found across all requests
    """
    results = {
        "title": "Request Body Parameter Detection Results",
        "description": "Parameters found in request bodies",
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
            continue
        
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
        
        # If no parameters found, skip this request
        if not body_params:
            continue
        
        results["requests_with_parameters"] += 1
        results["total_parameters"] += len(body_params)
        
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

# If this module is run directly, provide a test
if __name__ == "__main__":
    print("This module is designed to be run from the main application.")
    print("It will scan all requests in the loaded XML file for body parameters.")
