"""
XSS Vulnerability Detector Module

This module analyzes HTTP requests and responses to identify potential XSS vulnerabilities.
It looks for reflections of parameters, lack of proper escaping, and vulnerable contexts.
"""

import re
import html
import tkinter as tk
from tkinter import ttk
from urllib.parse import parse_qs, urlparse, unquote
import json

# Module metadata
MODULE_NAME = "XSS Detector"
MODULE_DESCRIPTION = "Detects potential Cross-Site Scripting (XSS) vulnerabilities"
MODULE_VERSION = "1.0"
MODULE_AUTHOR = "Security Researcher"

# Configuration
config = {
    "check_url_parameters": True,
    "check_form_fields": True,
    "check_headers": True,
    "check_cookies": True,
    "check_json_responses": True,
    "check_reflected_parameters": True,
    "check_sinks": True,
    "check_dom_xss": True,
    "min_param_length": 3,
    "xss_test_strings": [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>",
        "'><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "<img src=1 onerror=alert(1)>",
        "<body onload=alert(1)>",
    ],
    "dangerous_sinks": [
        "eval", "setTimeout", "setInterval", "Function", "innerHTML", 
        "outerHTML", "document.write", "document.writeln", "location",
        "location.href", "location.replace", "location.assign", "execScript",
        "document.domain", "document.URL", "document.documentURI", "document.URLUnencoded",
        "document.baseURI", "document.referrer"
    ],
    "dangerous_js_patterns": [
        r'document\.(?:location|URL|documentURI|URLUnencoded|baseURI|referrer)',
        r'location(?:\.(?:href|search|hash|pathname))?',
        r'(?:window|self|parent|top)\.location',
        r'(?:window|self|parent|top)\.name',
        r'(?:localStorage|sessionStorage)\.getItem',
        r'performance\.getEntries\(\)',
        r'document\.cookie',
    ],
    "custom_test_strings": []
}

# Regular expressions for detecting potential XSS
FORM_FIELD_PATTERN = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
JSON_KEY_PATTERN = r'"([^"]+)"\s*:\s*'
REFLECTED_PATTERN_TEMPLATE = r'{}' # Will be formatted with the parameter value

# DOM XSS source patterns
DOM_XSS_SOURCE_PATTERNS = [
    r'document\.URL',
    r'document\.documentURI',
    r'document\.URLUnencoded',
    r'document\.baseURI',
    r'document\.referrer',
    r'location(?:\.(?:href|search|hash|pathname))?',
    r'window\.name',
    r'(?:localStorage|sessionStorage)\.getItem\([^\)]+\)',
]

# DOM XSS sink patterns
DOM_XSS_SINK_PATTERNS = [
    r'document\.write\s*\(',
    r'(?:\w+)\.innerHTML\s*=',
    r'(?:\w+)\.outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\(',
    r'setInterval\s*\(',
    r'new\s+Function\s*\(',
]


def configure(frame):
    """Set up the configuration UI"""
    # Clear the frame
    for widget in frame.winfo_children():
        widget.destroy()
        
    # Create scrollable canvas for all the options
    canvas = tk.Canvas(frame)
    scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)
    
    scrollable_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )
    
    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)
    
    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    # Create configuration widgets
    ttk.Label(scrollable_frame, text="Detection Settings", font=("", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
    
    row = 1
    
    # Checkboxes for scan targets
    for option, label in [
        ("check_url_parameters", "Check URL Parameters"),
        ("check_form_fields", "Check Form Fields"),
        ("check_headers", "Check Headers"),
        ("check_cookies", "Check Cookies"),
        ("check_json_responses", "Check JSON Responses"),
        ("check_reflected_parameters", "Check Parameter Reflection"),
        ("check_sinks", "Check JavaScript Sinks"),
        ("check_dom_xss", "Check DOM-based XSS")
    ]:
        var = tk.BooleanVar(value=config[option])
        ttk.Checkbutton(scrollable_frame, text=label, variable=var,
                      command=lambda opt=option, v=var: update_config(opt, v.get())).grid(row=row, column=0, sticky="w")
        row += 1
    
    # Minimum parameter length
    ttk.Label(scrollable_frame, text="Minimum Parameter Length:").grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    min_length_var = tk.IntVar(value=config["min_param_length"])
    min_length_spinbox = ttk.Spinbox(scrollable_frame, from_=1, to=20, textvariable=min_length_var, width=5)
    min_length_spinbox.grid(row=row, column=0, sticky="w", padx=(20, 0))
    min_length_spinbox.bind("<FocusOut>", lambda e: update_config("min_param_length", int(min_length_var.get())))
    row += 1
    
    # XSS test strings section
    ttk.Label(scrollable_frame, text="XSS Test Strings", font=("", 12, "bold")).grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    test_frame = ttk.Frame(scrollable_frame)
    test_frame.grid(row=row, column=0, columnspan=2, sticky="we")
    
    test_listbox = tk.Listbox(test_frame, width=50, height=10)
    test_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    test_scrollbar = ttk.Scrollbar(test_frame, orient=tk.VERTICAL, command=test_listbox.yview)
    test_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    test_listbox['yscrollcommand'] = test_scrollbar.set
    
    # Populate listbox with built-in test strings
    for test in config["xss_test_strings"]:
        test_listbox.insert(tk.END, test)
        
    row += 1
    
    # Add custom test string
    ttk.Label(scrollable_frame, text="Add Custom Test String:").grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    test_entry = ttk.Entry(scrollable_frame, width=50)
    test_entry.grid(row=row, column=0, sticky="we", padx=(0, 5))
    
    def add_custom_test():
        test = test_entry.get().strip()
        if test and test not in config["custom_test_strings"]:
            config["custom_test_strings"].append(test)
            test_listbox.insert(tk.END, f"(custom) {test}")
            test_entry.delete(0, tk.END)
    
    ttk.Button(scrollable_frame, text="Add Test String", command=add_custom_test).grid(row=row, column=1, sticky="w")
    row += 1
    
    # Remove test string
    def remove_test_string():
        selection = test_listbox.curselection()
        if selection:
            index = selection[0]
            test = test_listbox.get(index)
            test_listbox.delete(index)
            
            # Check if it's a custom test string
            if test.startswith("(custom) "):
                test = test[9:]  # Remove the "(custom) " prefix
                if test in config["custom_test_strings"]:
                    config["custom_test_strings"].remove(test)
    
    ttk.Button(scrollable_frame, text="Remove Selected Test", 
              command=remove_test_string).grid(row=row, column=0, sticky="w", pady=5)
    
    # Dangerous sinks section
    row += 1
    ttk.Label(scrollable_frame, text="Dangerous JavaScript Sinks", font=("", 12, "bold")).grid(row=row, column=0, sticky="w", pady=(10, 5))
    row += 1
    
    sink_frame = ttk.Frame(scrollable_frame)
    sink_frame.grid(row=row, column=0, columnspan=2, sticky="we")
    
    sink_listbox = tk.Listbox(sink_frame, width=50, height=10)
    sink_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    sink_scrollbar = ttk.Scrollbar(sink_frame, orient=tk.VERTICAL, command=sink_listbox.yview)
    sink_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    sink_listbox['yscrollcommand'] = sink_scrollbar.set
    
    # Populate listbox
    for sink in config["dangerous_sinks"]:
        sink_listbox.insert(tk.END, sink)
        
    row += 1


def update_config(key, value):
    """Update a configuration value"""
    config[key] = value


def analyze(request_data, response_data, url):
    """
    Analyze the request and response for potential XSS vulnerabilities
    
    Args:
        request_data (dict): The request data
        response_data (dict): The response data
        url (str): The full URL
        
    Returns:
        dict: Analysis results
    """
    results = {
        "url": url,
        "potential_vulnerabilities": [],
        "params_to_test": [],
        "reflected_params": [],
        "dangerous_sinks": [],
        "summary": {
            "total_findings": 0,
            "categories": {
                "url_parameter": 0,
                "form_field": 0,
                "header": 0,
                "cookie": 0,
                "reflected": 0,
                "dom": 0,
                "sink": 0
            }
        }
    }
    
    # Check URL parameters if enabled
    if config["check_url_parameters"]:
        check_url_parameters(url, response_data, results)
    
    # Check form fields if enabled
    if config["check_form_fields"] and "body" in response_data and response_data["body"]:
        check_form_fields(response_data["body"], results)
    
    # Check headers if enabled
    if config["check_headers"]:
        check_headers(request_data, response_data, results)
    
    # Check cookies if enabled
    if config["check_cookies"]:
        check_cookies(request_data, response_data, results)
    
    # Check for reflected parameters if enabled
    if config["check_reflected_parameters"] and results["params_to_test"]:
        check_reflected_parameters(response_data, results)
    
    # Check for dangerous JavaScript sinks if enabled
    if config["check_sinks"] and "body" in response_data and response_data["body"]:
        check_dangerous_sinks(response_data["body"], results)
    
    # Check for DOM-based XSS if enabled
    if config["check_dom_xss"] and "body" in response_data and response_data["body"]:
        check_dom_xss(response_data["body"], results)
    
    # Update summary
    results["summary"]["total_findings"] = len(results["potential_vulnerabilities"])
    
    # Count findings by category
    for vuln in results["potential_vulnerabilities"]:
        category = vuln["category"]
        if category in results["summary"]["categories"]:
            results["summary"]["categories"][category] += 1
    
    return results


def check_url_parameters(url, response_data, results):
    """
    Check URL parameters for potential XSS
    
    Args:
        url (str): The URL to check
        response_data (dict): The response data
        results (dict): Results to update
    """
    parsed_url = urlparse(url)
    
    # Parse query parameters
    if parsed_url.query:
        query_params = parse_qs(parsed_url.query)
        
        for param_name, param_values in query_params.items():
            for param_value in param_values:
                # Skip parameters that are too short
                if len(param_value) < config["min_param_length"]:
                    continue
                    
                # Add to params to test
                results["params_to_test"].append({
                    "name": param_name,
                    "value": param_value,
                    "source": "url_parameter"
                })
                
                # Quick check if the parameter might be injectable
                if contains_injectable_char(param_value):
                    add_potential_vulnerability(results, "url_parameter", param_name, 
                                              "URL parameter contains potentially injectable characters", 
                                              "low", param_value)


def check_form_fields(body, results):
    """
    Check form fields for potential XSS
    
    Args:
        body (str): The response body
        results (dict): Results to update
    """
    # Extract form fields
    form_fields = re.findall(FORM_FIELD_PATTERN, body)
    
    for field_name in form_fields:
        # Add to params to test
        results["params_to_test"].append({
            "name": field_name,
            "value": field_name,  # Just use the name as a placeholder
            "source": "form_field"
        })
        
        # Check for dangerous field names
        if is_dangerous_name(field_name):
            add_potential_vulnerability(results, "form_field", field_name,
                                      "Form field has a potentially dangerous name that might be injectable",
                                      "low")


def check_headers(request_data, response_data, results):
    """
    Check headers for potential XSS
    
    Args:
        request_data (dict): The request data
        response_data (dict): The response data
        results (dict): Results to update
    """
    # Check request headers
    if "headers" in request_data:
        for header_name, header_value in request_data["headers"].items():
            # Skip standard headers that are unlikely to be reflected
            if header_name.lower() in ["host", "connection", "content-length", "cache-control"]:
                continue
                
            # Skip headers with values that are too short
            if len(header_value) < config["min_param_length"]:
                continue
                
            # Add to params to test
            results["params_to_test"].append({
                "name": header_name,
                "value": header_value,
                "source": "header"
            })
            
            # Particularly check Referer and User-Agent headers
            if header_name.lower() in ["referer", "user-agent"] and contains_injectable_char(header_value):
                add_potential_vulnerability(results, "header", header_name,
                                          f"{header_name} header contains potentially injectable characters",
                                          "medium", header_value)


def check_cookies(request_data, response_data, results):
    """
    Check cookies for potential XSS
    
    Args:
        request_data (dict): The request data
        response_data (dict): The response data
        results (dict): Results to update
    """
    # Check request cookies
    if "headers" in request_data and "Cookie" in request_data["headers"]:
        cookie_header = request_data["headers"]["Cookie"]
        cookie_pairs = cookie_header.split(';')
        
        for pair in cookie_pairs:
            if '=' in pair:
                cookie_name, cookie_value = pair.split('=', 1)
                cookie_name = cookie_name.strip()
                cookie_value = cookie_value.strip()
                
                # Skip cookies with values that are too short
                if len(cookie_value) < config["min_param_length"]:
                    continue
                    
                # Add to params to test
                results["params_to_test"].append({
                    "name": cookie_name,
                    "value": cookie_value,
                    "source": "cookie"
                })
                
                # Check for potentially injectable cookies
                if contains_injectable_char(cookie_value):
                    add_potential_vulnerability(results, "cookie", cookie_name,
                                              "Cookie value contains potentially injectable characters",
                                              "medium", cookie_value)
    
    # Also check for Set-Cookie headers in the response
    if "headers" in response_data and "Set-Cookie" in response_data["headers"]:
        set_cookie_header = response_data["headers"]["Set-Cookie"]
        
        # Check if the HttpOnly flag is missing
        if "httponly" not in set_cookie_header.lower():
            add_potential_vulnerability(results, "cookie", "Set-Cookie",
                                      "Cookie is set without the HttpOnly flag",
                                      "medium")


def check_reflected_parameters(response_data, results):
    """
    Check for parameters reflected in the response
    
    Args:
        response_data (dict): The response data
        results (dict): Results to update
    """
    if "body" not in response_data or not response_data["body"]:
        return
        
    body = response_data["body"]
    
    for param in results["params_to_test"]:
        param_name = param["name"]
        param_value = param["value"]
        param_source = param["source"]
        
        # Skip values that are too short
        if len(param_value) < config["min_param_length"]:
            continue
            
        # Look for reflections
        pattern = REFLECTED_PATTERN_TEMPLATE.format(re.escape(param_value))
        matches = re.findall(pattern, body)
        
        if matches:
            # Parameter is reflected
            results["reflected_params"].append({
                "name": param_name,
                "value": param_value,
                "source": param_source,
                "count": len(matches)
            })
            
            # Check if value is reflected without proper encoding
            encoded_value = html.escape(param_value)
            if param_value != encoded_value and param_value in body:
                # Potential XSS if special characters are not encoded
                add_potential_vulnerability(results, "reflected", param_name,
                                          f"Parameter from {param_source} is reflected without proper HTML encoding",
                                          "high", param_value)
            else:
                # Parameter is reflected but seems to be encoded properly
                add_potential_vulnerability(results, "reflected", param_name,
                                          f"Parameter from {param_source} is reflected (appears to be properly encoded)",
                                          "info", param_value)
            
            # Further check for context - is it reflected inside a script tag?
            script_pattern = r'<script[^>]*>([^<]*{}[^<]*)</script>'.format(re.escape(param_value))
            script_matches = re.findall(script_pattern, body)
            
            if script_matches:
                add_potential_vulnerability(results, "reflected", param_name,
                                          f"Parameter from {param_source} is reflected inside a script tag",
                                          "high", param_value)
            
            # Is it reflected inside an attribute?
            attr_pattern = r'<[^>]+\s+(?:[a-zA-Z0-9_-]+\s*=\s*["\'][^"\']*{}[^"\']*["\'])[^>]*>'.format(re.escape(param_value))
            attr_matches = re.findall(attr_pattern, body)
            
            if attr_matches:
                add_potential_vulnerability(results, "reflected", param_name,
                                          f"Parameter from {param_source} is reflected inside an HTML attribute",
                                          "medium", param_value)


def check_dangerous_sinks(body, results):
    """
    Check for dangerous JavaScript sinks
    
    Args:
        body (str): The response body
        results (dict): Results to update
    """
    # Look for script tags
    script_tags = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
    
    for script in script_tags:
        # Check for dangerous sinks
        for sink in config["dangerous_sinks"]:
            pattern = r'[^\w]{}[^\w]'.format(re.escape(sink))
            matches = re.findall(pattern, script)
            
            if matches:
                results["dangerous_sinks"].append({
                    "sink": sink,
                    "context": get_context(script, sink, 50)
                })
                
                add_potential_vulnerability(results, "sink", sink,
                                          "Dangerous JavaScript sink detected",
                                          "medium")


def check_dom_xss(body, results):
    """
    Check for potential DOM-based XSS
    
    Args:
        body (str): The response body
        results (dict): Results to update
    """
    # Look for script tags
    script_tags = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL)
    
    for script in script_tags:
        # Check for DOM XSS sources
        for source_pattern in DOM_XSS_SOURCE_PATTERNS:
            source_matches = re.findall(source_pattern, script)
            
            if source_matches:
                # Found a potential source, now check if it's used in a sink
                for sink_pattern in DOM_XSS_SINK_PATTERNS:
                    sink_matches = re.findall(sink_pattern, script)
                    
                    if sink_matches:
                        # Both source and sink found in the same script
                        add_potential_vulnerability(results, "dom", "DOM XSS",
                                                  f"Potential DOM-based XSS: {source_pattern} used with {sink_pattern}",
                                                  "high")
                        
                        # Don't need to check other sinks for this source
                        break


def add_potential_vulnerability(results, category, name, description, severity, value=None):
    """
    Add a potential vulnerability to the results
    
    Args:
        results (dict): Results to update
        category (str): The vulnerability category
        name (str): The vulnerability name
        description (str): The vulnerability description
        severity (str): The vulnerability severity (low, medium, high, info)
        value (str, optional): The value associated with the vulnerability
    """
    vulnerability = {
        "category": category,
        "name": name,
        "description": description,
        "severity": severity
    }
    
    if value:
        vulnerability["value"] = value
        
    # Check if this exact vulnerability has already been added
    for existing in results["potential_vulnerabilities"]:
        if (existing["category"] == category and 
            existing["name"] == name and 
            existing["description"] == description):
            
            # Already exists, don't add a duplicate
            return
    
    results["potential_vulnerabilities"].append(vulnerability)


def is_dangerous_name(name):
    """
    Check if a parameter name looks potentially dangerous
    
    Args:
        name (str): The parameter name
        
    Returns:
        bool: True if the name looks dangerous
    """
    dangerous_names = [
        "q", "s", "search", "id", "action", "keyword", "query", "page", "keywords",
        "url", "view", "cat", "p", "path", "pg", "style", "template", "theme",
        "lang", "language", "callback", "cb", "jsonp", "api", "token", "user",
        "file", "filename", "fileext", "type", "version", "redirect", "redir",
        "load", "include", "next", "prev", "html", "javascript", "js", "css",
    ]
    
    return name.lower() in dangerous_names


def contains_injectable_char(value):
    """
    Check if a value contains characters that might be used for XSS
    
    Args:
        value (str): The value to check
        
    Returns:
        bool: True if the value contains potentially injectable characters
    """
    injectable_chars = ['<', '>', '"', "'", '(', ')', '{', '}', ';', '=', '`']
    
    for char in injectable_chars:
        if char in value:
            return True
            
    return False


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


def check_json_responses(response_data, results):
    """
    Check JSON responses for potential XSS vulnerabilities
    
    Args:
        response_data (dict): The response data
        results (dict): Results to update
    """
    if "body" not in response_data or not response_data["body"]:
        return
        
    body = response_data["body"]
    
    # Check if it's a JSON response
    if "headers" in response_data and "Content-Type" in response_data["headers"]:
        content_type = response_data["headers"]["Content-Type"].lower()
        if "application/json" not in content_type:
            return
    
    # Try to parse the body as JSON
    try:
        json_data = json.loads(body)
        
        # Recursively check JSON values for potential XSS
        check_json_object(json_data, "json_response", results)
    except json.JSONDecodeError:
        # Not valid JSON
        pass


def check_json_object(obj, path, results, depth=0):
    """
    Recursively check JSON objects for potential XSS
    
    Args:
        obj: The JSON object or value
        path (str): The current path in the JSON structure
        results (dict): Results to update
        depth (int): Current recursion depth
    """
    # Prevent too deep recursion
    if depth > 5:
        return
    
    if isinstance(obj, dict):
        # It's a dictionary, check each key/value pair
        for key, value in obj.items():
            new_path = f"{path}.{key}" if path else key
            
            # Check if the key itself looks dangerous
            if is_dangerous_name(key):
                add_potential_vulnerability(results, "json", key,
                                          f"JSON key with dangerous name: {new_path}",
                                          "low")
            
            # Check the value
            if isinstance(value, (str, int, float, bool)):
                check_json_value(value, new_path, results)
            else:
                # Recurse into nested objects/arrays
                check_json_object(value, new_path, results, depth + 1)
    
    elif isinstance(obj, list):
        # It's a list, check each element
        for i, value in enumerate(obj):
            new_path = f"{path}[{i}]"
            
            if isinstance(value, (str, int, float, bool)):
                check_json_value(value, new_path, results)
            else:
                # Recurse into nested objects/arrays
                check_json_object(value, new_path, results, depth + 1)


def check_json_value(value, path, results):
    """
    Check a single JSON value for potential XSS
    
    Args:
        value: The value to check
        path (str): The current path in the JSON structure
        results (dict): Results to update
    """
    # Convert to string for checking
    value_str = str(value)
    
    # Skip values that are too short
    if len(value_str) < config["min_param_length"]:
        return
    
    # Check if the value contains injectable characters
    if contains_injectable_char(value_str):
        add_potential_vulnerability(results, "json", path,
                                  "JSON value contains potentially injectable characters",
                                  "medium", value_str)
    
    # Add to params to test for reflection
    results["params_to_test"].append({
        "name": path,
        "value": value_str,
        "source": "json_value"
    })


# If this module is run directly, provide a simple test
if __name__ == "__main__":
    # Test data
    test_url = "https://example.com/search.php?q=test<script>&page=1"
    
    test_request = {
        "method": "GET",
        "headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Referer": "https://example.com/",
            "Cookie": "session=abc123; user=test<img>"
        }
    }
    
    test_response = {
        "status_code": "200",
        "headers": {
            "Content-Type": "text/html; charset=UTF-8",
            "Set-Cookie": "tracking=test123; path=/; expires=Fri, 31 Dec 2021 23:59:59 GMT"
        },
        "body": """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Search Results for: test<script></title>
        </head>
        <body>
            <h1>Search Results</h1>
            <p>You searched for: test<script></p>
            <div id="results">
                <p>No results found.</p>
            </div>
            
            <form action="/search.php" method="get">
                <input type="text" name="q" value="test<script>">
                <input type="hidden" name="page" value="1">
                <button type="submit">Search</button>
            </form>
            
            <script>
            // Get the search query from the URL
            const urlParams = new URLSearchParams(window.location.search);
            const query = urlParams.get('q');
            
            // Update the page
            document.getElementById('results').innerHTML = 'Searching for: ' + query;
            </script>
        </body>
        </html>
        """
    }
    
    # Test the analyze function
    results = analyze(test_request, test_response, test_url)
    
    #Print results
    import json
    print(json.dumps(results, indent=2))
