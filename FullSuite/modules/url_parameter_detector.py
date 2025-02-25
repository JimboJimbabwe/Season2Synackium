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

# If this module is run directly, provide a test
if __name__ == "__main__":
    # Test URLs
    test_urls = [
        "https://example.com/search?q=test&page=1&limit=10",
        "https://example.com/profile#user=123&tab=settings",
        "https://example.com/api/data?id=5&format=json"
    ]
    
    for test_url in test_urls:
        result = analyze_url(test_url)
        print(f"URL: {result['url']}")
        print("Parameters:")
        for param in result["parameters"]:
            if "value" in param:
                print(f"  {param['name']} = {param['value']} ({param['location']})")
            else:
                print(f"  {param['name']} ({param['location']})")
        print()
