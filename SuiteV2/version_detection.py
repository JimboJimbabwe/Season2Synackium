"""
Version and Server Information Detector Module

This module scans for version numbers, server information, and technology fingerprints
in HTTP responses that could be used for fingerprinting and potential vulnerability targeting.
"""

import re
import tkinter as tk
from tkinter import ttk
import json

# Module metadata
MODULE_NAME = "Version Detector"
MODULE_DESCRIPTION = "Detects version information and technology fingerprints in HTTP responses"
MODULE_VERSION = "1.0"
MODULE_AUTHOR = "Security Researcher"

# Configuration
config = {
    "scan_headers": True,
    "scan_body": True,
    "version_patterns": True,
    "server_info": True,
    "technology_fingerprints": True,
    "known_vulnerabilities_check": True,
    "custom_patterns": []
}

# Common version patterns
VERSION_PATTERNS = [
    # Generic version numbers: X.Y.Z or X.Y
    r'[vV]ersion["\': ]+(\d+\.\d+(?:\.\d+)?)',
    r'[vV]er["\': ]+(\d+\.\d+(?:\.\d+)?)',
    r'[vV](\d+\.\d+(?:\.\d+)?)',
    r'(?:^|[^a-zA-Z0-9.])(\d+\.\d+\.\d+)(?:[^a-zA-Z0-9]|$)',
    r'(?:^|[^a-zA-Z0-9.])(\d+\.\d+)(?:[^a-zA-Z0-9]|$)',
    
    # Build/release numbers
    r'[bB]uild["\': ]+([0-9a-zA-Z._-]+)',
    r'[rR]elease["\': ]+([0-9a-zA-Z._-]+)',
]

# Server information patterns
SERVER_INFO_PATTERNS = [
    # Common server headers
    r'(?i)Server: (.+)',
    r'(?i)X-Powered-By: (.+)',
    r'(?i)X-AspNet-Version: (.+)',
    r'(?i)X-Runtime: (.+)',
    r'(?i)X-Version: (.+)',
    r'(?i)X-Generator: (.+)',
    r'(?i)X-UA-Compatible: (.+)',
    r'(?i)X-AMZN-',
    r'(?i)X-Drupal-',
    r'(?i)X-Varnish:',
    r'(?i)Liferay-Portal:',
    r'(?i)owa/',
    r'(?i)Phusion Passenger',
]

# Technology fingerprints (HTML comments, meta tags, etc.)
TECH_FINGERPRINT_PATTERNS = [
    # Common JS frameworks
    r'(?i)<script[^>]*src=["\'][^"\']*(?:jquery|react|angular|vue|backbone|ember|bootstrap)[^"\']*\.js["\']',
    r'(?i)<script[^>]*src=["\'][^"\']*cloudflare[^"\']*\.js["\']',
    r'(?i)<script[^>]*src=["\'][^"\']*akamai[^"\']*\.js["\']',
    
    # Meta generator tags
    r'(?i)<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)["\']',
    r'(?i)<meta[^>]*content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']',
    
    # WordPress, Drupal, Joomla
    r'(?i)wp-content',
    r'(?i)wp-includes',
    r'(?i)Drupal\.settings',
    r'(?i)Joomla!',
    
    # Common HTML comments
    r'(?i)<!--[^>]*wordpress[^>]*-->',
    r'(?i)<!--[^>]*drupal[^>]*-->',
    r'(?i)<!--[^>]*joomla[^>]*-->',
    r'(?i)<!--[^>]*sitecore[^>]*-->',
    
    # Server-side technologies
    r'(?i)\.asp(?:x)?',
    r'(?i)\.jsp',
    r'(?i)\.php',
    r'(?i)\.cgi',
    r'(?i)Laravel',
    r'(?i)Django',
    r'(?i)Rails',
    r'(?i)Express',
    r'(?i)Symfony',
]

# Known vulnerable software versions (example, would need regular updates)
KNOWN_VULNERABILITIES = {
    "Apache": {
        "2.4.49": ["CVE-2021-41773", "Path Traversal Vulnerability"],
        "2.4.50": ["CVE-2021-42013", "Path Traversal Vulnerability"],
    },
    "Nginx": {
        "1.20.0": ["CVE-2021-23017", "Heap Buffer Overflow"],
    },
    "PHP": {
        "7.4.11": ["CVE-2020-7069", "Type Confusion Vulnerability"],
    },
    "WordPress": {
        "5.7.0": ["CVE-2021-29447", "XXE Vulnerability"],
    },
    "Drupal": {
        "8.9.0": ["CVE-2020-13666", "CSRF Vulnerability"],
    },
    "OpenSSL": {
        "1.0.1": ["CVE-2014-0160", "Heartbleed Vulnerability"],
        "1.0.2": ["CVE-2016-0800", "DROWN Vulnerability"],
    },
    "Apache Struts": {
        "2.5.12": ["CVE-2017-5638", "Remote Code Execution"],
    }
}


def configure(frame):
    """Set up the configuration UI"""
    # Clear the frame
    for widget in frame.winfo_children():
        widget.destroy()
    
    # Create configuration widgets
    ttk.Label(frame, text="Scan Settings", font=("", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
    
    # Checkboxes for scan targets
    scan_headers_var = tk.BooleanVar(value=config["scan_headers"])
    ttk.Checkbutton(frame, text="Scan Headers", variable=scan_headers_var,
                   command=lambda: update_config("scan_headers", scan_headers_var.get())).grid(row=1, column=0, sticky="w")
    
    scan_body_var = tk.BooleanVar(value=config["scan_body"])
    ttk.Checkbutton(frame, text="Scan Body", variable=scan_body_var,
                   command=lambda: update_config("scan_body", scan_body_var.get())).grid(row=2, column=0, sticky="w")
    
    # Checkboxes for detection types
    ttk.Label(frame, text="Detection Types", font=("", 12, "bold")).grid(row=3, column=0, sticky="w", pady=(10, 5))
    
    version_patterns_var = tk.BooleanVar(value=config["version_patterns"])
    ttk.Checkbutton(frame, text="Version Patterns", variable=version_patterns_var,
                   command=lambda: update_config("version_patterns", version_patterns_var.get())).grid(row=4, column=0, sticky="w")
    
    server_info_var = tk.BooleanVar(value=config["server_info"])
    ttk.Checkbutton(frame, text="Server Information", variable=server_info_var,
                   command=lambda: update_config("server_info", server_info_var.get())).grid(row=5, column=0, sticky="w")
    
    tech_fp_var = tk.BooleanVar(value=config["technology_fingerprints"])
    ttk.Checkbutton(frame, text="Technology Fingerprints", variable=tech_fp_var,
                   command=lambda: update_config("technology_fingerprints", tech_fp_var.get())).grid(row=6, column=0, sticky="w")
    
    vuln_check_var = tk.BooleanVar(value=config["known_vulnerabilities_check"])
    ttk.Checkbutton(frame, text="Check Known Vulnerabilities", variable=vuln_check_var,
                   command=lambda: update_config("known_vulnerabilities_check", vuln_check_var.get())).grid(row=7, column=0, sticky="w")
    
    # Custom pattern entry
    ttk.Label(frame, text="Custom Patterns", font=("", 12, "bold")).grid(row=8, column=0, sticky="w", pady=(10, 5))
    
    ttk.Label(frame, text="Add new regex pattern:").grid(row=9, column=0, sticky="w")
    
    pattern_entry = ttk.Entry(frame, width=50)
    pattern_entry.grid(row=10, column=0, sticky="we", padx=(0, 5))
    
    def add_custom_pattern():
        pattern = pattern_entry.get().strip()
        if pattern:
            config["custom_patterns"].append(pattern)
            update_custom_patterns_list()
            pattern_entry.delete(0, tk.END)
    
    ttk.Button(frame, text="Add", command=add_custom_pattern).grid(row=10, column=1, sticky="w")
    
    # List of custom patterns
    ttk.Label(frame, text="Current custom patterns:").grid(row=11, column=0, sticky="w", pady=(10, 5))
    
    custom_patterns_frame = ttk.Frame(frame)
    custom_patterns_frame.grid(row=12, column=0, columnspan=2, sticky="we")
    
    custom_listbox = tk.Listbox(custom_patterns_frame, width=50, height=5)
    custom_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    
    scrollbar = ttk.Scrollbar(custom_patterns_frame, orient=tk.VERTICAL, command=custom_listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    custom_listbox['yscrollcommand'] = scrollbar.set
    
    def update_custom_patterns_list():
        custom_listbox.delete(0, tk.END)
        for pattern in config["custom_patterns"]:
            custom_listbox.insert(tk.END, pattern)
    
    update_custom_patterns_list()
    
    # Remove button for custom patterns
    def remove_selected_pattern():
        selection = custom_listbox.curselection()
        if selection:
            index = selection[0]
            del config["custom_patterns"][index]
            update_custom_patterns_list()
    
    ttk.Button(frame, text="Remove Selected", command=remove_selected_pattern).grid(row=13, column=0, sticky="w", pady=5)


def update_config(key, value):
    """Update a configuration value"""
    config[key] = value


def analyze(request_data, response_data, url):
    """
    Analyze the request and response for version information and technology fingerprints
    
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
        "technologies": {},
        "potential_vulnerabilities": [],
        "summary": {
            "total_findings": 0,
            "categories": {}
        }
    }
    
    # Mainly focus on the response
    scan_response(response_data, results)
    
    # Update summary
    results["summary"]["total_findings"] = len(results["findings"])
    
    # Count findings by category
    for finding in results["findings"]:
        category = finding["category"]
        if category not in results["summary"]["categories"]:
            results["summary"]["categories"][category] = 0
        results["summary"]["categories"][category] += 1
    
    # Check for known vulnerabilities if enabled
    if config["known_vulnerabilities_check"]:
        check_known_vulnerabilities(results)
    
    return results


def scan_response(response_data, results):
    """
    Scan response data for version information and technology fingerprints
    
    Args:
        response_data (dict): The response data
        results (dict): Results dictionary to update
    """
    # Check headers if enabled
    if config["scan_headers"] and "headers" in response_data:
        scan_headers(response_data["headers"], results)
    
    # Check body if enabled
    if config["scan_body"] and "body" in response_data and response_data["body"]:
        scan_body(response_data["body"], results)


def scan_headers(headers, results):
    """
    Scan headers for version information and server details
    
    Args:
        headers (dict): The headers dictionary
        results (dict): Results dictionary to update
    """
    # Check for server headers
    if config["server_info"]:
        for header_name, header_value in headers.items():
            # Common informative headers
            if header_name.lower() == "server":
                add_finding(results, "server_info", header_name, header_value, "header")
                detect_technology(results, "server", header_value)
            
            elif header_name.lower() == "x-powered-by":
                add_finding(results, "server_info", header_name, header_value, "header")
                detect_technology(results, "platform", header_value)
            
            # Other informative headers
            elif any(header_name.lower().startswith(x.lower()) for x in ["X-", "Powered-By", "Engine"]):
                add_finding(results, "server_info", header_name, header_value, "header")
    
    # Look for version patterns in all headers
    if config["version_patterns"]:
        for header_name, header_value in headers.items():
            for pattern in VERSION_PATTERNS:
                matches = re.findall(pattern, header_value)
                for match in matches:
                    add_finding(results, "version", pattern, match, f"header:{header_name}")
                    detect_technology_version(results, header_name, match)


def scan_body(body, results):
    """
    Scan response body for version information and technology fingerprints
    
    Args:
        body (str): The response body
        results (dict): Results dictionary to update
    """
    # Look for version patterns
    if config["version_patterns"]:
        for pattern in VERSION_PATTERNS:
            matches = re.findall(pattern, body)
            for match in matches:
                add_finding(results, "version", pattern, match, "body")
                
                # Try to associate with a technology based on surrounding text
                context = get_context(body, match, 50)
                detect_technology_from_context(results, context, match)
    
    # Look for technology fingerprints
    if config["technology_fingerprints"]:
        for pattern in TECH_FINGERPRINT_PATTERNS:
            matches = re.findall(pattern, body)
            if matches:
                # Some patterns return the actual match, others just confirm presence
                if isinstance(matches[0], tuple) and matches[0]:
                    match_text = matches[0][0]
                elif isinstance(matches[0], str):
                    match_text = matches[0]
                else:
                    match_text = re.search(pattern, body).group(0)
                
                add_finding(results, "technology", pattern, match_text, "body")
                detect_technology_from_pattern(results, pattern, match_text)
    
    # Check custom patterns
    for pattern in config["custom_patterns"]:
        try:
            matches = re.findall(pattern, body)
            for match in matches:
                if isinstance(match, tuple) and match:
                    match_text = match[0]
                else:
                    match_text = match
                
                add_finding(results, "custom", pattern, match_text, "body")
        except re.error:
            # Skip invalid regex patterns
            pass


def add_finding(results, category, pattern, match, location):
    """
    Add a finding to the results
    
    Args:
        results (dict): Results dictionary to update
        category (str): The finding category
        pattern (str): The pattern that matched
        match (str): The matched text
        location (str): Where the match was found
    """
    # Check if this is a duplicate
    for finding in results["findings"]:
        if finding["match"] == match and finding["location"] == location:
            return
    
    results["findings"].append({
        "category": category,
        "pattern": pattern,
        "match": match,
        "location": location
    })


def detect_technology(results, type_key, value):
    """
    Detect and record a technology
    
    Args:
        results (dict): Results dictionary to update
        type_key (str): The type of technology
        value (str): The technology value
    """
    # Extract the technology name (remove version numbers if present)
    parts = value.split()
    tech_name = parts[0] if parts else value
    
    # Clean up
    tech_name = tech_name.strip()
    
    # Record the technology
    if tech_name:
        if type_key not in results["technologies"]:
            results["technologies"][type_key] = []
        
        if tech_name not in results["technologies"][type_key]:
            results["technologies"][type_key].append(tech_name)


def detect_technology_version(results, header_name, version):
    """
    Associate a version with a technology based on header name
    
    Args:
        results (dict): Results dictionary to update
        header_name (str): The header name
        version (str): The version string
    """
    # Map common headers to technologies
    header_to_tech = {
        "server": "server",
        "x-powered-by": "platform",
        "x-aspnet-version": "ASP.NET",
        "x-drupal-cache": "Drupal",
        "x-generator": "generator",
        "x-wordpress": "WordPress",
        "x-joomla": "Joomla",
    }
    
    header_lower = header_name.lower()
    
    # Find the appropriate technology
    for header_prefix, tech_name in header_to_tech.items():
        if header_lower.startswith(header_prefix):
            # Add to technologies with version
            if tech_name not in results["technologies"]:
                results["technologies"][tech_name] = []
            
            version_info = {"name": header_name, "version": version}
            
            # Check if already exists
            exists = False
            for item in results["technologies"][tech_name]:
                if isinstance(item, dict) and item.get("version") == version:
                    exists = True
                    break
            
            if not exists:
                results["technologies"][tech_name].append(version_info)
            
            break


def detect_technology_from_context(results, context, version):
    """
    Try to determine the technology associated with a version based on surrounding text
    
    Args:
        results (dict): Results dictionary to update
        context (str): The text surrounding the version
        version (str): The version string
    """
    # List of common technology names to look for
    common_techs = [
        "Apache", "Nginx", "IIS", "Tomcat", "PHP", "MySQL", "MariaDB", 
        "WordPress", "Drupal", "Joomla", "jQuery", "React", "Angular", 
        "Vue", "Bootstrap", "Laravel", "Symfony", "Django", "Flask", 
        "Express", "Node.js", "ASP.NET", "Ruby", "Rails", "Python"
    ]
    
    context_lower = context.lower()
    
    # Check for each technology name in the context
    for tech in common_techs:
        if tech.lower() in context_lower:
            # Add to technologies with version
            if "detected" not in results["technologies"]:
                results["technologies"]["detected"] = []
            
            version_info = {"name": tech, "version": version, "confidence": "medium"}
            
            # Check if already exists
            exists = False
            for item in results["technologies"]["detected"]:
                if isinstance(item, dict) and item.get("name") == tech and item.get("version") == version:
                    exists = True
                    break
            
            if not exists:
                results["technologies"]["detected"].append(version_info)


def detect_technology_from_pattern(results, pattern, match):
    """
    Detect technology based on the matched fingerprint pattern
    
    Args:
        results (dict): Results dictionary to update
        pattern (str): The pattern that matched
        match (str): The matched text
    """
    # Map patterns to technologies
    if "jquery" in pattern.lower():
        add_tech_to_results(results, "jQuery", match)
    elif "react" in pattern.lower():
        add_tech_to_results(results, "React", match)
    elif "angular" in pattern.lower():
        add_tech_to_results(results, "Angular", match)
    elif "vue" in pattern.lower():
        add_tech_to_results(results, "Vue.js", match)
    elif "bootstrap" in pattern.lower():
        add_tech_to_results(results, "Bootstrap", match)
    elif "wordpress" in pattern.lower() or "wp-" in pattern.lower():
        add_tech_to_results(results, "WordPress", match)
    elif "drupal" in pattern.lower():
        add_tech_to_results(results, "Drupal", match)
    elif "joomla" in pattern.lower():
        add_tech_to_results(results, "Joomla", match)
    elif "asp" in pattern.lower():
        add_tech_to_results(results, "ASP.NET", match)
    elif "jsp" in pattern.lower():
        add_tech_to_results(results, "JSP", match)
    elif "php" in pattern.lower():
        add_tech_to_results(results, "PHP", match)
    elif "cloudflare" in pattern.lower():
        add_tech_to_results(results, "Cloudflare", match)
    elif "akamai" in pattern.lower():
        add_tech_to_results(results, "Akamai", match)
    elif "laravel" in pattern.lower():
        add_tech_to_results(results, "Laravel", match)
    elif "django" in pattern.lower():
        add_tech_to_results(results, "Django", match)
    elif "rails" in pattern.lower():
        add_tech_to_results(results, "Ruby on Rails", match)
    elif "express" in pattern.lower():
        add_tech_to_results(results, "Express.js", match)
    elif "symfony" in pattern.lower():
        add_tech_to_results(results, "Symfony", match)


def add_tech_to_results(results, tech_name, match):
    """
    Add a technology to the results
    
    Args:
        results (dict): Results dictionary to update
        tech_name (str): The technology name
        match (str): The matched text
    """
    if "fingerprinted" not in results["technologies"]:
        results["technologies"]["fingerprinted"] = []
    
    # Extract version if present
    version = None
    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', match)
    if version_match:
        version = version_match.group(1)
    
    # Create the tech info object
    tech_info = {"name": tech_name}
    if version:
        tech_info["version"] = version
    
    # Check if already exists
    exists = False
    for item in results["technologies"]["fingerprinted"]:
        if isinstance(item, dict) and item.get("name") == tech_name:
            if version and not item.get("version"):
                item["version"] = version
            exists = True
            break
    
    if not exists:
        results["technologies"]["fingerprinted"].append(tech_info)


def get_context(text, match_text, context_size):
    """
    Get text surrounding a match for context
    
    Args:
        text (str): The full text
        match_text (str): The matched text
        context_size (int): Number of characters to include before and after
        
    Returns:
        str: The context string
    """
    match_pos = text.find(match_text)
    if match_pos == -1:
        return ""
    
    start_pos = max(0, match_pos - context_size)
    end_pos = min(len(text), match_pos + len(match_text) + context_size)
    
    return text[start_pos:end_pos]


def check_known_vulnerabilities(results):
    """
    Check if any detected technologies have known vulnerabilities
    
    Args:
        results (dict): Results dictionary to update
    """
    for category, techs in results["technologies"].items():
        for tech in techs:
            tech_name = tech["name"] if isinstance(tech, dict) else tech
            tech_version = tech.get("version") if isinstance(tech, dict) else None
            
            if tech_name in KNOWN_VULNERABILITIES and tech_version:
                # Check if this exact version is in our database
                if tech_version in KNOWN_VULNERABILITIES[tech_name]:
                    vuln_info = KNOWN_VULNERABILITIES[tech_name][tech_version]
                    results["potential_vulnerabilities"].append({
                        "technology": tech_name,
                        "version": tech_version,
                        "cve_id": vuln_info[0],
                        "description": vuln_info[1],
                        "confidence": "high"
                    })
                else:
                    # Check if this version might be vulnerable based on version comparison
                    for vuln_version, vuln_info in KNOWN_VULNERABILITIES[tech_name].items():
                        if is_version_vulnerable(tech_version, vuln_version):
                            results["potential_vulnerabilities"].append({
                                "technology": tech_name,
                                "version": tech_version,
                                "vulnerable_version": vuln_version,
                                "cve_id": vuln_info[0],
                                "description": vuln_info[1],
                                "confidence": "medium"
                            })


def is_version_vulnerable(detected_version, vulnerable_version):
    """
    Check if a detected version is vulnerable based on version comparison
    
    Args:
        detected_version (str): The detected version
        vulnerable_version (str): The known vulnerable version
        
    Returns:
        bool: True if the detected version is likely vulnerable
    """
    try:
        # Simple version comparison - could be enhanced with proper version parsing
        detected_parts = [int(p) for p in detected_version.split('.')]
        vulnerable_parts = [int(p) for p in vulnerable_version.split('.')]
        
        # Pad with zeros if the lengths don't match
        while len(detected_parts) < len(vulnerable_parts):
            detected_parts.append(0)
        while len(vulnerable_parts) < len(detected_parts):
            vulnerable_parts.append(0)
        
        # Compare version parts
        for d, v in zip(detected_parts, vulnerable_parts):
            if d < v:
                return False
            if d > v:
                return True
        
        # If all parts are equal, the versions are the same
        return True
    except:
        # If version comparison fails, be conservative
        return False


# If this module is run directly, provide a simple test
if __name__ == "__main__":
    # Test data
    test_response = {
        "status_code": "200",
        "headers": {
            "Server": "Apache/2.4.49 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.11",
            "X-Generator": "Drupal 8.9.0 (https://www.drupal.org)",
            "Content-Type": "text/html; charset=UTF-8"
        },
        "body": """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Page</title>
            <meta name="generator" content="WordPress 5.7.0" />
            <script src="/js/jquery-3.5.1.min.js"></script>
            <script src="/js/bootstrap-4.5.2.min.js"></script>
        </head>
        <body>
            <div class="container">
                <h1>Welcome to My Website</h1>
                <p>Running on Apache version 2.4.49</p>
                <!-- Built with WordPress version 5.7.0 -->
                <p class="version">Version 1.2.3</p>
            </div>
        </body>
        </html>
        """
    }
    
    # Test the analyze function
    results = analyze({}, test_response, "https://example.com/")
    
    # Print results
    import json
    print(json.dumps(results, indent=2))
