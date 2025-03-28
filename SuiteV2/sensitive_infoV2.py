"""
Sensitive Information Detector Module

This module scans for potentially sensitive information in HTTP responses
such as API keys, tokens, passwords, and personally identifiable information.
"""

import re
import tkinter as tk
from tkinter import ttk

# Module metadata
MODULE_NAME = "Sensitive Information Detector"
MODULE_DESCRIPTION = "Detects sensitive information in HTTP responses"
MODULE_VERSION = "1.0"
MODULE_AUTHOR = "Security Researcher"

# Configuration
config = {
    "scan_request": True,
    "scan_response": True,
    "scan_headers": True,
    "scan_body": True,
    "highlight_matches": True,
    # Pattern categories to scan for
    "patterns": {
        "api_keys": True,
        "tokens": True,
        "passwords": True,
        "personal_info": True,
        "credit_cards": True,
        "custom_patterns": []
    }
}

# Regular expression patterns for sensitive information
PATTERNS = {
    "api_keys": [
        # Generic API key format
        r'(?i)(api[_-]?key|apikey|api[_-]?token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,})["\'&]?',
        # AWS keys
        r'(?i)AKIA[0-9A-Z]{16}',
        # Stripe API keys
        r'(?i)sk_live_[0-9a-zA-Z]{24}',
        # Google API keys
        r'(?i)AIza[0-9A-Za-z-_]{35}',
    ],
    "tokens": [
        # JWT tokens
        r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        # OAuth tokens
        r'(?i)(access_token|auth_token|token)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{10,})["\'&]?',
        # Session IDs
        r'(?i)(sessionid|session[_-]?id)["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{10,})["\'&]?',
    ],
    "passwords": [
        # Password fields
        r'(?i)(password|passwd|pwd)["\']?\s*[:=]\s*["\']?([^"\'\s&]{3,})["\'&]?',
        # Secret fields
        r'(?i)(secret|private_key)["\']?\s*[:=]\s*["\']?([^"\'\s&]{3,})["\'&]?',
    ],
    "personal_info": [
        # Email addresses
        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        # Phone numbers (various formats)
        r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
        # Social Security Numbers
        r'\b\d{3}[-]?\d{2}[-]?\d{4}\b',
    ],
    "credit_cards": [
        # Credit card numbers (major brands)
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b',
    ]
}

def configure(frame):
    """Set up the configuration UI"""
    # Clear the frame
    for widget in frame.winfo_children():
        widget.destroy()
    
    # Create configuration widgets
    ttk.Label(frame, text="Scan Settings", font=("", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
    
    # Checkboxes for scan targets
    scan_request_var = tk.BooleanVar(value=config["scan_request"])
    ttk.Checkbutton(frame, text="Scan Request", variable=scan_request_var,
                  command=lambda: update_config("scan_request", scan_request_var.get())).grid(row=1, column=0, sticky="w")
    
    scan_response_var = tk.BooleanVar(value=config["scan_response"])
    ttk.Checkbutton(frame, text="Scan Response", variable=scan_response_var,
                   command=lambda: update_config("scan_response", scan_response_var.get())).grid(row=2, column=0, sticky="w")
    
    scan_headers_var = tk.BooleanVar(value=config["scan_headers"])
    ttk.Checkbutton(frame, text="Scan Headers", variable=scan_headers_var,
                   command=lambda: update_config("scan_headers", scan_headers_var.get())).grid(row=3, column=0, sticky="w")
    
    scan_body_var = tk.BooleanVar(value=config["scan_body"])
    ttk.Checkbutton(frame, text="Scan Body", variable=scan_body_var,
                   command=lambda: update_config("scan_body", scan_body_var.get())).grid(row=4, column=0, sticky="w")
    
    # Checkboxes for pattern categories
    ttk.Label(frame, text="Pattern Categories", font=("", 12, "bold")).grid(row=5, column=0, sticky="w", pady=(10, 5))
    
    row = 6
    for category in PATTERNS.keys():
        if category in config["patterns"]:
            var = tk.BooleanVar(value=config["patterns"][category])
            ttk.Checkbutton(frame, text=category.replace("_", " ").title(), variable=var,
                           command=lambda cat=category, v=var: update_pattern_config(cat, v.get())).grid(row=row, column=0, sticky="w")
            row += 1
    
    # Custom pattern entry
    ttk.Label(frame, text="Custom Patterns", font=("", 12, "bold")).grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    ttk.Label(frame, text="Add new regex pattern:").grid(row=row, column=0, sticky="w")
    row += 1
    
    pattern_entry = ttk.Entry(frame, width=50)
    pattern_entry.grid(row=row, column=0, sticky="we", padx=(0, 5))
    
    def add_custom_pattern():
        pattern = pattern_entry.get().strip()
        if pattern:
            config["patterns"]["custom_patterns"].append(pattern)
            update_custom_patterns_list()
            pattern_entry.delete(0, tk.END)
    
    ttk.Button(frame, text="Add", command=add_custom_pattern).grid(row=row, column=1, sticky="w")
    row += 1
    
    # List of custom patterns
    ttk.Label(frame, text="Current custom patterns:").grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    custom_patterns_frame = ttk.Frame(frame)
    custom_patterns_frame.grid(row=row, column=0, columnspan=2, sticky="we")
    
    custom_listbox = tk.Listbox(custom_patterns_frame, width=50, height=5)
    custom_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    scrollbar = ttk.Scrollbar(custom_patterns_frame, orient=tk.VERTICAL, command=custom_listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    custom_listbox['yscrollcommand'] = scrollbar.set
    
    def update_custom_patterns_list():
        custom_listbox.delete(0, tk.END)
        for pattern in config["patterns"]["custom_patterns"]:
            custom_listbox.insert(tk.END, pattern)
    
    update_custom_patterns_list()
    
    # Remove button for custom patterns
    def remove_selected_pattern():
        selection = custom_listbox.curselection()
        if selection:
            index = selection[0]
            del config["patterns"]["custom_patterns"][index]
            update_custom_patterns_list()
    
    ttk.Button(frame, text="Remove Selected", command=remove_selected_pattern).grid(row=row+1, column=0, sticky="w", pady=5)

def update_config(key, value):
    """Update a configuration value"""
    config[key] = value

def update_pattern_config(category, value):
    """Update a pattern category configuration"""
    config["patterns"][category] = value

def analyze(request_data, response_data, url):
    """
    Analyze the request and response for sensitive information
    
    Args:
        request_data (dict): The request data
        response_data (dict): The response data
        url (str): The full URL
        
    Returns:
        dict: Analysis results
    """
    results = {
        "url": url,
        "findings": [],
        "summary": {
            "total_findings": 0,
            "categories": {}
        }
    }
    
    # Check if we should scan the request
    if config["scan_request"]:
        scan_data(request_data, "request", results)
    
    # Check if we should scan the response
    if config["scan_response"]:
        scan_data(response_data, "response", results)
    
    # Update summary
    results["summary"]["total_findings"] = len(results["findings"])
    
    # Count findings by category
    for finding in results["findings"]:
        category = finding["category"]
        if category not in results["summary"]["categories"]:
            results["summary"]["categories"][category] = 0
        results["summary"]["categories"][category] += 1
    
    return results

def scan_data(data, source_type, results):
    """
    Scan data for sensitive information
    
    Args:
        data (dict): The data to scan
        source_type (str): 'request' or 'response'
        results (dict): Results dictionary to update
    """
    # Check if we should scan headers
    if config["scan_headers"] and "headers" in data:
        for header_name, header_value in data["headers"].items():
            scan_text(header_value, source_type, f"header:{header_name}", results)
    
    # Check if we should scan body
    if config["scan_body"] and "body" in data and data["body"]:
        scan_text(data["body"], source_type, "body", results)

def scan_text(text, source_type, location, results):
    """
    Scan text for sensitive information
    
    Args:
        text (str): The text to scan
        source_type (str): 'request' or 'response'
        location (str): Where in the request/response this text is from
        results (dict): Results dictionary to update
    """
    # Go through each enabled pattern category
    for category, enabled in config["patterns"].items():
        if not enabled or category == "custom_patterns":
            continue
            
        # Scan with each pattern in the category
        for pattern in PATTERNS[category]:
            for match in re.finditer(pattern, text):
                results["findings"].append({
                    "category": category,
                    "pattern": pattern,
                    "match": match.group(0),
                    "source": source_type,
                    "location": location,
                    "start": match.start(),
                    "end": match.end()
                })
    
    # Scan with custom patterns
    if "custom_patterns" in config["patterns"]:
        for pattern in config["patterns"]["custom_patterns"]:
            try:
                for match in re.finditer(pattern, text):
                    results["findings"].append({
                        "category": "custom",
                        "pattern": pattern,
                        "match": match.group(0),
                        "source": source_type,
                        "location": location,
                        "start": match.group().start(),
                        "end": match.group().end()
                    })
            except re.error:
                # Skip invalid regex patterns
                pass

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
    
    combined_results = {
        "title": "Sensitive Information Detection Results",
        "description": "Potentially sensitive information found in HTTP requests and responses",
        "total_scanned": len(xml_data),
        "total_findings": 0,
        "findings_by_category": {},
        "findings_by_url": {},
        "items_with_findings": 0,
        "all_findings": []
    }
    
    for i, item in enumerate(xml_data):
        url = item["url"]
        
        # If URL is relative and base_url is provided, join them
        if base_url and not url.startswith(("http://", "https://")):
            url = urljoin(base_url, url)
        
        # Skip items without a valid URL
        if not url:
            continue
        
        # Analyze this item
        item_results = analyze(item["request_data"], item["response_data"], url)
        
        # If findings were found, add to combined results
        if item_results["findings"]:
            combined_results["items_with_findings"] += 1
            combined_results["total_findings"] += len(item_results["findings"])
            
            # Add to findings by URL
            combined_results["findings_by_url"][url] = {
                "count": len(item_results["findings"]),
                "categories": item_results["summary"]["categories"]
            }
            
            # Add to findings by category
            for category, count in item_results["summary"]["categories"].items():
                if category not in combined_results["findings_by_category"]:
                    combined_results["findings_by_category"][category] = {
                        "count": 0,
                        "urls": []
                    }
                combined_results["findings_by_category"][category]["count"] += count
                combined_results["findings_by_category"][category]["urls"].append(url)
            
            # Add to all findings with URL
            for finding in item_results["findings"]:
                finding["url"] = url
                finding["item_index"] = i + 1  # 1-based index
                combined_results["all_findings"].append(finding)
    
    return combined_results

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
    text.append("SENSITIVE INFORMATION DETECTION RESULTS")
    text.append("=" * 50)
    
    # Basic stats
    text.append("SUMMARY")
    text.append("-" * 40)
    text.append(f"Total Items Scanned: {results.get('total_scanned', 0)}")
    text.append(f"Items with Findings: {results.get('items_with_findings', 0)}")
    text.append(f"Total Findings: {results.get('total_findings', 0)}")
    text.append("")
    
    # Findings by category
    text.append("FINDINGS BY CATEGORY")
    text.append("-" * 40)
    for category, data in results.get("findings_by_category", {}).items():
        text.append(f"{category.replace('_', ' ').title()}: {data['count']} findings")
        text.append(f"Found in {len(data['urls'])} URLs")
        text.append("")
    
    # Detailed findings (limit to keep output manageable)
    text.append("DETAILED FINDINGS")
    text.append("-" * 40)
    
    max_findings = 50  # Limit number of detailed findings shown
    for i, finding in enumerate(results.get("all_findings", [])[:max_findings]):
        text.append(f"Finding #{i+1}")
        text.append(f"Category: {finding.get('category', 'unknown').replace('_', ' ').title()}")
        text.append(f"URL: {finding.get('url', 'unknown')}")
        text.append(f"Location: {finding.get('source', 'unknown')} {finding.get('location', '')}")
        
        # Mask sensitive data in output
        match_text = finding.get('match', '')
        if len(match_text) > 10:
            # Show first few and last few characters
            masked_match = match_text[:4] + "****" + match_text[-4:]
        else:
            masked_match = "****" 
        
        text.append(f"Sensitive Data: {masked_match}")
        text.append("")
    
    if len(results.get("all_findings", [])) > max_findings:
        text.append(f"... and {len(results.get('all_findings', [])) - max_findings} more findings (truncated for readability)")
    
    return "\n".join(text)

# If this module is run directly, provide a command-line interface
if __name__ == "__main__":
    import argparse
    import os
    import time
    import json
    from urllib.parse import urljoin
    
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="Sensitive Information Detector Module")
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
        
        # Test data
        test_request = {
            "method": "POST",
            "headers": {
                "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTYzOTUwNTk4MCwiZXhwIjoxNjM5NTA5NTgwfQ.6YAqPb0N6PKJtj7E9SpEddJ3MCQPbKOGvxH8kbN2qjk",
                "Content-Type": "application/json"
            },
            "body": '{"username": "user123", "password": "Secret123!", "email": "john@example.com"}'
        }
        
        test_response = {
            "status_code": "200",
            "headers": {
                "Content-Type": "application/json",
                "Set-Cookie": "session_id=abcdef123456; Path=/; HttpOnly"
            },
            "body": '{"status": "success", "data": {"api_key": "a1b2c3d4e5f6g7h8", "user_id": 12345}}'
        }
        
        # Get individual results first
        single_result = analyze(test_request, test_response, "https://api.example.com/login")
        
        # Convert to combined results format for consistency
        results = {
            "title": "Sensitive Information Detection Results",
            "description": "Potentially sensitive information found in HTTP requests and responses",
            "total_scanned": 1,
            "total_findings": len(single_result["findings"]),
            "findings_by_category": {},
            "findings_by_url": {},
            "items_with_findings": 1 if single_result["findings"] else 0,
            "all_findings": []
        }
        
        # Add URL to each finding
        for finding in single_result["findings"]:
            finding["url"] = single_result["url"]
            finding["item_index"] = 1  # 1-based index
            results["all_findings"].append(finding)
        
        # Add to findings by URL
        if single_result["findings"]:
            results["findings_by_url"][single_result["url"]] = {
                "count": len(single_result["findings"]),
                "categories": single_result["summary"]["categories"]
            }
            
            # Add to findings by category
            for category, count in single_result["summary"]["categories"].items():
                results["findings_by_category"][category] = {
                    "count": count,
                    "urls": [single_result["url"]]
                }
    
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
