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

# If this module is run directly, provide a simple test
if __name__ == "__main__":
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
    
    # Test the analyze function
    results = analyze(test_request, test_response, "https://api.example.com/login")
    
    # Print results
    import json
    print(json.dumps(results, indent=2))
