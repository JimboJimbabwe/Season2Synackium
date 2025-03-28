"""
LDAP Injection Parameter Detector Module

This module scans all requests for parameters that are commonly targeted
for LDAP injection attacks, based on parameter names and patterns.
"""

import re
import urllib.parse
import tkinter as tk
from tkinter import ttk
import json

# Module metadata
MODULE_NAME = "LDAP Parameter Detector"
MODULE_DESCRIPTION = "Scans all requests for potential LDAP injection parameters"
MODULE_VERSION = "1.0"
MODULE_AUTHOR = "Security Researcher"

# Flag to indicate this module scans all requests
SCAN_ALL_REQUESTS = True

# Configuration
config = {
    "min_risk_score": 1,  # Minimum risk score to report (1-10)
    "include_values": True,
    "max_value_preview_length": 30,
    "highlight_special_chars": True,
    "highlight_ldap_keywords": True
}

# LDAP injection parameter patterns
LDAP_PARAMETER_PATTERNS = [
    # Directory service identifiers (high risk)
    r'^(?:username|user|uid|login|cn|dn|sAMAccountName|userPrincipal|distinguishedName)$',
    
    # Authentication params (high risk)
    r'^(?:password|passwd|auth|authentication|bind_dn|binddn|securityPrincipal)$',
    
    # Directory structure (high risk)
    r'^(?:directory|group|memberOf|ou|domain|basedn|base_dn|dc)$',
    
    # LDAP filters and queries (high risk)
    r'^(?:filter|ldap_query|query|search|attributes|scope)$',
    
    # Authentication methods (medium risk)
    r'^(?:auth_method|directory|domain|account|role)$',
    
    # Common LDAP attributes (medium risk)
    r'^(?:mail|email|telephonenumber|sn|givenName|role|account)$'
]

# LDAP keywords that might appear in injection attempts
LDAP_KEYWORDS = [
    "objectClass", "sAMAccountName", "cn=", "ou=", "dc=", "uid=", "(&", "(|", 
    "(!)", "*)", "memberOf", "groupMembership", "userPassword", "distinguishedName",
    "subtree", "onelevel", "base", "NTLM", "Kerberos", "Simple", "DIGEST-MD5"
]

def configure(frame):
    """Set up the configuration UI"""
    # Clear the frame
    for widget in frame.winfo_children():
        widget.destroy()
    
    # Create configuration widgets
    ttk.Label(frame, text="LDAP Parameter Detection Settings", font=("", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
    
    # Minimum risk score slider
    ttk.Label(frame, text="Minimum Risk Score (1-10):").grid(row=1, column=0, sticky="w")
    risk_score_var = tk.IntVar(value=config["min_risk_score"])
    risk_score_slider = ttk.Scale(frame, from_=1, to=10, variable=risk_score_var, orient="horizontal",
                                 length=200, command=lambda v: update_risk_score_label(risk_score_label, float(v)))
    risk_score_slider.grid(row=1, column=1, sticky="w", padx=(5, 0))
    risk_score_slider.bind("<ButtonRelease-1>", lambda e: update_config("min_risk_score", int(risk_score_var.get())))
    
    risk_score_label = ttk.Label(frame, text=str(config["min_risk_score"]))
    risk_score_label.grid(row=1, column=2, padx=(5, 0))
    
    # Maximum value preview length
    ttk.Label(frame, text="Maximum Value Preview Length:").grid(row=2, column=0, sticky="w", pady=(10, 5))
    max_preview_var = tk.IntVar(value=config["max_value_preview_length"])
    max_preview_spinbox = ttk.Spinbox(frame, from_=10, to=100, textvariable=max_preview_var, width=5)
    max_preview_spinbox.grid(row=2, column=1, sticky="w", padx=(5, 0))
    max_preview_spinbox.bind("<FocusOut>", lambda e: update_config("max_value_preview_length", int(max_preview_var.get())))
    
    # Checkboxes for options
    include_values_var = tk.BooleanVar(value=config["include_values"])
    ttk.Checkbutton(frame, text="Show Parameter Values", variable=include_values_var,
                  command=lambda: update_config("include_values", include_values_var.get())).grid(row=3, column=0, sticky="w", pady=(10, 5))
    
    highlight_special_var = tk.BooleanVar(value=config["highlight_special_chars"])
    ttk.Checkbutton(frame, text="Highlight Special Characters", variable=highlight_special_var,
                   command=lambda: update_config("highlight_special_chars", highlight_special_var.get())).grid(row=4, column=0, sticky="w")
    
    highlight_ldap_var = tk.BooleanVar(value=config["highlight_ldap_keywords"])
    ttk.Checkbutton(frame, text="Highlight LDAP Keywords in Values", variable=highlight_ldap_var,
                   command=lambda: update_config("highlight_ldap_keywords", highlight_ldap_var.get())).grid(row=5, column=0, sticky="w")
    
    # LDAP parameter patterns section
    ttk.Label(frame, text="LDAP Parameter Patterns", font=("", 12, "bold")).grid(row=6, column=0, sticky="w", pady=(15, 5))
    
    patterns_text = tk.Text(frame, wrap=tk.WORD, width=60, height=10)
    patterns_text.grid(row=7, column=0, columnspan=3, sticky="we")
    
    # Add a scrollbar
    patterns_scroll = ttk.Scrollbar(frame, orient="vertical", command=patterns_text.yview)
    patterns_scroll.grid(row=7, column=3, sticky="ns")
    patterns_text["yscrollcommand"] = patterns_scroll.set
    
    # Show current patterns
    for pattern in LDAP_PARAMETER_PATTERNS:
        patterns_text.insert(tk.END, pattern + "\n")
    
    # Make it read-only for now (could be made editable in the future)
    patterns_text.config(state=tk.DISABLED)

def update_risk_score_label(label, value):
    """Update the risk score label when the slider is moved"""
    label.config(text=str(int(value)))

def update_config(key, value):
    """Update a configuration value"""
    config[key] = value

def analyze_all(all_items_data):
    """
    Analyze all requests for potential LDAP injection parameters
    
    Args:
        all_items_data (list): List of dictionaries containing request and response data
        
    Returns:
        dict: Analysis results with all potentially vulnerable parameters found
    """
    results = {
        "title": "LDAP Injection Parameter Detection Results",
        "description": "Parameters that may be vulnerable to LDAP injection attacks",
        "vulnerable_parameters": {},
        "request_count": len(all_items_data),
        "requests_with_vulnerable_params": 0,
        "total_vulnerable_params": 0,
        "high_risk_count": 0,
        "medium_risk_count": 0,
        "low_risk_count": 0,
        "requests": []
    }
    
    # Process all items
    for item_data in all_items_data:
        index = item_data["index"]
        url = item_data["url"]
        request_data = item_data["request_data"]
        
        # Collect all parameters from different sources
        all_params = []
        
        # 1. URL parameters
        url_params = extract_url_parameters(url)
        for param in url_params:
            param["source"] = "url"
            all_params.append(param)
        
        # 2. Form parameters (if it's a POST request with form data)
        if request_data.get("method") == "POST" and "body" in request_data:
            # Check content type
            content_type = ""
            if "headers" in request_data:
                for header_name, header_value in request_data["headers"].items():
                    if header_name.lower() == "content-type":
                        content_type = header_value.lower()
                        break
            
            # Process form data
            if "application/x-www-form-urlencoded" in content_type:
                try:
                    form_params = urllib.parse.parse_qs(request_data["body"])
                    for name, values in form_params.items():
                        for value in values:
                            all_params.append({
                                "name": name,
                                "value": value,
                                "source": "form"
                            })
                except:
                    pass
            # Process JSON data
            elif "application/json" in content_type:
                try:
                    json_data = json.loads(request_data["body"])
                    json_params = extract_json_params(json_data)
                    for param in json_params:
                        param["source"] = "json"
                        all_params.append(param)
                except:
                    pass
        
        # Check each parameter for LDAP injection vulnerability
        vulnerable_params = []
        
        for param in all_params:
            risk_score, risk_factors = assess_ldap_injection_risk(param)
            
            # Skip parameters with risk scores below threshold
            if risk_score < config["min_risk_score"]:
                continue
            
            # Add risk information
            param["risk_score"] = risk_score
            param["risk_factors"] = risk_factors
            param["risk_level"] = get_risk_level(risk_score)
            
            # Add to vulnerable parameters list
            vulnerable_params.append(param)
            
            # Add to global vulnerable parameters dictionary
            param_name = param["name"]
            if param_name not in results["vulnerable_parameters"]:
                results["vulnerable_parameters"][param_name] = {
                    "count": 0,
                    "risk_score": risk_score,
                    "risk_level": get_risk_level(risk_score),
                    "risk_factors": risk_factors,
                    "sources": set(),
                    "requests": [],
                    "values": set() if config["include_values"] else None
                }
            
            # Update parameter info
            param_info = results["vulnerable_parameters"][param_name]
            param_info["count"] += 1
            param_info["sources"].add(param["source"])
            param_info["requests"].append(index + 1)  # 1-based index
            
            if config["include_values"] and "value" in param:
                value_preview = get_value_preview(param["value"])
                if value_preview:
                    param_info["values"].add(value_preview)
        
        # If vulnerable parameters found in this request
        if vulnerable_params:
            results["requests_with_vulnerable_params"] += 1
            results["total_vulnerable_params"] += len(vulnerable_params)
            
            # Update risk counts
            for param in vulnerable_params:
                risk_level = param["risk_level"]
                if risk_level == "high":
                    results["high_risk_count"] += 1
                elif risk_level == "medium":
                    results["medium_risk_count"] += 1
                else:
                    results["low_risk_count"] += 1
            
            # Add request info
            request_info = {
                "index": index + 1,  # 1-based index for user display
                "url": url,
                "method": request_data.get("method", ""),
                "vulnerable_param_count": len(vulnerable_params),
                "parameters": vulnerable_params
            }
            
            results["requests"].append(request_info)
    
    # Convert sets to lists for JSON serialization
    for param_name, param_info in results["vulnerable_parameters"].items():
        param_info["sources"] = list(param_info["sources"])
        if param_info["values"] is not None:
            param_info["values"] = list(param_info["values"])
    
    return results

def extract_url_parameters(url):
    """Extract parameters from a URL"""
    parameters = []
    
    try:
        # Parse the URL
        parsed = urllib.parse.urlparse(url)
        
        # Extract query parameters
        if parsed.query:
            query_params = urllib.parse.parse_qs(parsed.query)
            for name, values in query_params.items():
                for value in values:
                    parameters.append({
                        "name": name,
                        "value": value
                    })
    except:
        pass
    
    return parameters

def extract_json_params(json_data, prefix=""):
    """Recursively extract parameters from JSON data"""
    parameters = []
    
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            param_name = f"{prefix}.{key}" if prefix else key
            
            if isinstance(value, (dict, list)):
                # Recursively process nested objects
                parameters.extend(extract_json_params(value, param_name))
            else:
                # Add leaf node as parameter
                parameters.append({
                    "name": param_name,
                    "value": str(value) if value is not None else ""
                })
    
    elif isinstance(json_data, list):
        for i, item in enumerate(json_data):
            param_name = f"{prefix}[{i}]" if prefix else f"[{i}]"
            
            if isinstance(item, (dict, list)):
                # Recursively process nested objects
                parameters.extend(extract_json_params(item, param_name))
            else:
                # Add leaf node as parameter
                parameters.append({
                    "name": param_name,
                    "value": str(item) if item is not None else ""
                })
    
    return parameters

def assess_ldap_injection_risk(param):
    """
    Assess the risk of LDAP injection for a parameter
    
    Args:
        param (dict): Parameter information
        
    Returns:
        tuple: (risk_score, risk_factors)
    """
    risk_score = 0
    risk_factors = []
    
    # Check parameter name against patterns
    param_name = param["name"]
    
    # Check patterns
    for i, pattern in enumerate(LDAP_PARAMETER_PATTERNS):
        if re.search(pattern, param_name, re.IGNORECASE):
            # Different patterns have different risk weights
            if i < 4:  # High risk patterns (directory service, auth, structure, filters)
                risk_score += 5
                risk_factors.append(f"Parameter name matches high-risk LDAP pattern: {pattern}")
            else:  # Medium/Low risk patterns
                risk_score += 3
                risk_factors.append(f"Parameter name matches potential LDAP pattern: {pattern}")
            break  # Only count the highest risk pattern
    
    # If value is available, check it too
    if "value" in param and param["value"]:
        value = param["value"]
        
        # Check for special characters used in LDAP injection
        if config["highlight_special_chars"]:
            special_chars = ["*", "(", ")", "\\", "/", "&", "|", "!", "=", "~"]
            for char in special_chars:
                if char in value:
                    risk_score += 1
                    risk_factors.append(f"Parameter value contains special character used in LDAP: {char}")
                    break  # Only count once
        
        # Check for LDAP keywords in value
        if config["highlight_ldap_keywords"]:
            for keyword in LDAP_KEYWORDS:
                if keyword.lower() in value.lower():
                    risk_score += 2
                    risk_factors.append(f"Parameter value contains LDAP keyword: {keyword}")
                    break  # Only count once
        
        # Check for common LDAP injection patterns
        ldap_injection_patterns = [
            r"[*]",  # Wildcard
            r"\([&|!]",  # LDAP boolean operators
            r"cn=|uid=|ou=|dc=",  # LDAP attribute patterns
            r"objectClass=",  # Common LDAP attribute
            r"\)\(|\)\z",  # Closing/opening parentheses patterns
        ]
        
        for pattern in ldap_injection_patterns:
            if re.search(pattern, value):
                risk_score += 3
                risk_factors.append(f"Parameter value contains potential LDAP injection pattern")
                break  # Only count once
    
    # Cap the risk score at 10
    risk_score = min(risk_score, 10)
    
    return risk_score, risk_factors

def get_risk_level(risk_score):
    """Convert a risk score to a risk level"""
    if risk_score >= 7:
        return "high"
    elif risk_score >= 4:
        return "medium"
    else:
        return "low"

def get_value_preview(value):
    """Get a preview of a value for display"""
    max_length = config["max_value_preview_length"]
    
    if not value:
        return ""
        
    if len(value) > max_length:
        return value[:max_length] + "..."
        
    return value

# For backward compatibility
def analyze(request_data, response_data, url):
    """Legacy analyze function - processes only the current request"""
    results = {
        "title": "LDAP Injection Parameter Detection Results",
        "description": "Parameters that may be vulnerable to LDAP injection attacks",
        "note": "This module is designed to scan all requests. Please use the 'Scan All' feature for comprehensive results.",
        "parameters": []
    }
    
    # Extract URL parameters
    url_params = extract_url_parameters(url)
    
    # Check each parameter
    for param in url_params:
        risk_score, risk_factors = assess_ldap_injection_risk(param)
        
        # Skip parameters with risk scores below threshold
        if risk_score < config["min_risk_score"]:
            continue
        
        # Add risk information
        param["risk_score"] = risk_score
        param["risk_factors"] = risk_factors
        param["risk_level"] = get_risk_level(risk_score)
        param["source"] = "url"
        
        # Add to results
        results["parameters"].append(param)
    
    # Process form data if present
    if request_data.get("method") == "POST" and "body" in request_data:
        # Check if it's form data
        content_type = ""
        if "headers" in request_data:
            content_type = request_data["headers"].get("Content-Type", "").lower()
        
        if "application/x-www-form-urlencoded" in content_type:
            try:
                form_params = urllib.parse.parse_qs(request_data["body"])
                for name, values in form_params.items():
                    for value in values:
                        param = {"name": name, "value": value, "source": "form"}
                        risk_score, risk_factors = assess_ldap_injection_risk(param)
                        
                        if risk_score >= config["min_risk_score"]:
                            param["risk_score"] = risk_score
                            param["risk_factors"] = risk_factors
                            param["risk_level"] = get_risk_level(risk_score)
                            results["parameters"].append(param)
            except:
                pass
    
    return results

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
        "title": "LDAP Injection Parameter Detection Results",
        "description": "Parameters that may be vulnerable to LDAP injection attacks",
        "vulnerable_parameters": {},
        "request_count": 0,
        "requests_with_vulnerable_params": 0,
        "total_vulnerable_params": 0,
        "high_risk_count": 0,
        "medium_risk_count": 0,
        "low_risk_count": 0,
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
    text.append("LDAP INJECTION PARAMETER DETECTION RESULTS")
    text.append("=" * 50)
    
    # Basic stats
    text.append("STATISTICS")
    text.append("-" * 40)
    text.append(f"Total Requests: {results.get('request_count', 0)}")
    text.append(f"Requests with Vulnerable Parameters: {results.get('requests_with_vulnerable_params', 0)}")
    text.append(f"Total Vulnerable Parameters: {results.get('total_vulnerable_params', 0)}")
    text.append(f"High Risk Parameters: {results.get('high_risk_count', 0)}")
    text.append(f"Medium Risk Parameters: {results.get('medium_risk_count', 0)}")
    text.append(f"Low Risk Parameters: {results.get('low_risk_count', 0)}")
    text.append("")
    
    # Vulnerable parameters
    text.append("VULNERABLE PARAMETERS")
    text.append("-" * 40)
    for param_name, param_info in results.get("vulnerable_parameters", {}).items():
        risk_level = param_info.get("risk_level", "unknown").upper()
        text.append(f"Parameter: {param_name} (Risk: {risk_level}, Score: {param_info.get('risk_score', 0)})")
        text.append(f"Occurrences: {param_info.get('count', 0)}")
        text.append(f"Sources: {', '.join(param_info.get('sources', []))}")
        
        # Risk factors
        if "risk_factors" in param_info:
            text.append("Risk Factors:")
            for factor in param_info["risk_factors"]:
                text.append(f"- {factor}")
        
        # Values
        if param_info.get("values"):
            text.append("Example Values:")
            for value in list(param_info["values"])[:3]:
                text.append(f"- {value}")
                
            if len(param_info["values"]) > 3:
                text.append(f"... and {len(param_info['values']) - 3} more")
                
        text.append("")
    
    # Requests with vulnerable parameters
    if results.get("requests"):
        text.append("AFFECTED REQUESTS")
        text.append("-" * 40)
        for i, request in enumerate(results["requests"]):
            if i >= 10:  # Limit to 10 examples
                text.append(f"... and {len(results['requests']) - 10} more requests")
                break
                
            text.append(f"Request #{request.get('index', '?')} - {request.get('url', 'Unknown URL')}")
            text.append(f"Method: {request.get('method', 'GET')}")
            text.append(f"Vulnerable Parameters: {request.get('vulnerable_param_count', 0)}")
            text.append("")
    
    return "\n".join(text)


# If this module is run directly, provide a command-line interface
if __name__ == "__main__":
    import argparse
    import os
    import time
    from urllib.parse import urljoin
    
    # Set up command line arguments
    parser = argparse.ArgumentParser(description="LDAP Injection Parameter Detector Module")
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
        
        # Test URL with LDAP parameters
        test_url = "https://example.com/login?username=admin&password=test&domain=example.com"
        
        test_request = {
            "method": "GET",
            "headers": {
                "User-Agent": "Mozilla/5.0"
            },
            "body": ""
        }
        
        # Analyze a single request and convert to the expected format
        single_item = [{
            "index": 0,
            "url": test_url,
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
