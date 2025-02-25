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
        "requests_with_parameters": []
    }
    
    # Process all items
    for item_data in all_items_data:
        index = item_data["index"]
        url = item_data["url"]
        request_data = item_data["request_data"]
        
        # Check if this is a JSON request
        is_json = False
        content_type = ""
        
        if "headers" in request_data:
            content_type = request_data["headers"].get("Content-Type", "")
            is_json = 'json' in content_type.lower() or 'application/json' in content_type.lower()
        
        # Skip if not JSON
        if not is_json or "body" not in request_data or not request_data["body"]:
            continue
            
        results["json_request_count"] += 1
        
        # Try to parse JSON
        try:
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
        except json.JSONDecodeError:
            # Not valid JSON, skip
            continue
    
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

# If this module is run directly, provide a test
if __name__ == "__main__":
    # This is just for testing; when the module is loaded by the main application,
    # the analyze function will be called with the current request data
    print("This module is designed to be run from the main application.")
    print("It will scan all requests in the loaded XML file for JSON parameters.")
