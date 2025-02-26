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

# If this module is run directly, provide a test
if __name__ == "__main__":
    print("This module is designed to be run from the main application.")
    print("It will scan all requests for parameters that might be vulnerable to LDAP injection.")
