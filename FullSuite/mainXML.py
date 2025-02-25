import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import xml.etree.ElementTree as ET
import base64
from pathlib import Path
import re
from datetime import datetime
import os
import sys
import argparse
import importlib
import importlib.util
import json
import shlex

class CoreXMLParser:
    def __init__(self, root):
        self.root = root
        self.root.title("Pentesting XML Parser")
        self.root.geometry("1400x900")
        
        # Data
        self.current_index = 0
        self.items = []
        self.current_item = None
        self.output_dir = Path.home() / "pentest_output"  # Default output directory
        self.modules = {}  # Will store loaded analysis modules
        
        # Setup the main GUI structure
        self.setup_gui()
        self.setup_bindings()
        
        # Load available modules
        self.load_modules()
        
    def setup_gui(self):
        """Setup all GUI elements"""
        # Create a notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Main viewer tab
        self.viewer_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.viewer_frame, text="HTTP Viewer")
        
        # Module tab
        self.module_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.module_frame, text="Analysis Modules")
        
        # Setup the main viewer
        self.setup_viewer_tab()
        
        # Setup the module tab
        self.setup_module_tab()
    
    def setup_viewer_tab(self):
        """Setup the main viewer tab with request/response display"""
        # Main frame
        self.main_frame = ttk.Frame(self.viewer_frame, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Setup all sub-frames
        self.setup_navigation_frame()
        self.setup_output_frame()
        self.setup_url_frame()
        
        # Paned window for request/response
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        self.paned_window.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Setup request and response frames
        self.setup_request_frame()
        self.setup_response_frame()
    
    def setup_module_tab(self):
        """Setup the module configuration tab"""
        # Module selection frame
        module_select_frame = ttk.LabelFrame(self.module_frame, text="Available Modules", padding="10")
        module_select_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=10)
        
        # Module listbox
        self.module_listbox = tk.Listbox(module_select_frame, height=10)
        self.module_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        module_scrollbar = ttk.Scrollbar(module_select_frame, command=self.module_listbox.yview)
        module_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.module_listbox['yscrollcommand'] = module_scrollbar.set
        
        # Module buttons frame
        module_buttons_frame = ttk.Frame(module_select_frame)
        module_buttons_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
        
        ttk.Button(module_buttons_frame, text="Run Module", 
                  command=self.run_selected_module).pack(fill=tk.X, pady=5)
        ttk.Button(module_buttons_frame, text="Configure", 
                  command=self.configure_selected_module).pack(fill=tk.X, pady=5)
        ttk.Button(module_buttons_frame, text="Reload Modules", 
                  command=self.load_modules).pack(fill=tk.X, pady=5)
        
        # Module configuration frame
        self.module_config_frame = ttk.LabelFrame(self.module_frame, text="Module Configuration", padding="10")
        self.module_config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Module output frame
        self.module_output_frame = ttk.LabelFrame(self.module_frame, text="Module Output", padding="10")
        self.module_output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Module output text area
        self.module_output_text = tk.Text(self.module_output_frame, wrap=tk.WORD)
        self.module_output_text.pack(fill=tk.BOTH, expand=True)
        module_output_scroll = ttk.Scrollbar(self.module_output_frame, orient=tk.VERTICAL, 
                                           command=self.module_output_text.yview)
        module_output_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.module_output_text['yscrollcommand'] = module_output_scroll.set
    
    def setup_navigation_frame(self):
        """Setup navigation buttons and counter"""
        nav_frame = ttk.Frame(self.main_frame)
        nav_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.prev_button = ttk.Button(nav_frame, text="← Previous", command=self.previous_item)
        self.prev_button.pack(side=tk.LEFT)
        
        self.next_button = ttk.Button(nav_frame, text="Next →", command=self.next_item)
        self.next_button.pack(side=tk.LEFT, padx=5)
        
        self.counter_label = ttk.Label(nav_frame, text="")
        self.counter_label.pack(side=tk.LEFT, padx=10)
        
        self.save_button = ttk.Button(nav_frame, text="Export Current", command=self.export_current)
        self.save_button.pack(side=tk.RIGHT)
        
        self.search_entry = ttk.Entry(nav_frame, width=30)
        self.search_entry.pack(side=tk.RIGHT, padx=5)
        self.search_entry.insert(0, "Search...")
        self.search_entry.bind("<FocusIn>", lambda e: self.search_entry.delete(0, tk.END) 
                              if self.search_entry.get() == "Search..." else None)
        self.search_entry.bind("<FocusOut>", lambda e: self.search_entry.insert(0, "Search...") 
                              if not self.search_entry.get() else None)
        self.search_entry.bind("<Return>", self.search_items)
        
        search_button = ttk.Button(nav_frame, text="Search", command=self.search_items)
        search_button.pack(side=tk.RIGHT)
    
    def setup_output_frame(self):
        """Setup output directory configuration"""
        output_frame = ttk.Frame(self.main_frame)
        output_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(output_frame, text="Output Directory:").pack(side=tk.LEFT)
        self.output_path_entry = ttk.Entry(output_frame, width=50)
        self.output_path_entry.pack(side=tk.LEFT, padx=5)
        self.output_path_entry.insert(0, str(self.output_dir))
        
        browse_button = ttk.Button(output_frame, text="Browse...", command=self.browse_output_dir)
        browse_button.pack(side=tk.LEFT)
    
    def setup_url_frame(self):
        """Setup URL and endpoint input fields"""
        url_frame = ttk.Frame(self.main_frame)
        url_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Base URL
        ttk.Label(url_frame, text="Base URL:").pack(side=tk.LEFT)
        self.base_url_entry = ttk.Entry(url_frame, width=50)
        self.base_url_entry.pack(side=tk.LEFT, padx=(5, 20))
        
        # Endpoint
        ttk.Label(url_frame, text="Endpoint:").pack(side=tk.LEFT)
        self.endpoint_entry = ttk.Entry(url_frame, width=30)
        self.endpoint_entry.pack(side=tk.LEFT, padx=5)
    
    def setup_request_frame(self):
        """Setup request display area"""
        req_frame = ttk.LabelFrame(self.paned_window, text="Request", padding="5")
        self.paned_window.add(req_frame, weight=1)
        
        # Request method and path
        req_header_frame = ttk.Frame(req_frame)
        req_header_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.req_method_label = ttk.Label(req_header_frame, text="Method: ")
        self.req_method_label.pack(side=tk.LEFT)
        
        self.req_path_label = ttk.Label(req_header_frame, text="Path: ")
        self.req_path_label.pack(side=tk.LEFT, padx=10)
        
        # Text area with syntax highlighting
        self.req_text = tk.Text(req_frame, wrap=tk.WORD, width=60, height=30)
        self.req_text.pack(fill=tk.BOTH, expand=True)
        req_scroll = ttk.Scrollbar(req_frame, orient=tk.VERTICAL, command=self.req_text.yview)
        req_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.req_text['yscrollcommand'] = req_scroll.set
        
        # Headers/body toggle
        req_toggle_frame = ttk.Frame(req_frame)
        req_toggle_frame.pack(fill=tk.X, pady=5)
        
        self.req_view_var = tk.StringVar(value="all")
        ttk.Radiobutton(req_toggle_frame, text="All", variable=self.req_view_var, 
                       value="all", command=self.update_request_view).pack(side=tk.LEFT)
        ttk.Radiobutton(req_toggle_frame, text="Headers Only", variable=self.req_view_var,
                       value="headers", command=self.update_request_view).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(req_toggle_frame, text="Body Only", variable=self.req_view_var,
                       value="body", command=self.update_request_view).pack(side=tk.LEFT)
    
    def setup_response_frame(self):
        """Setup response display area"""
        resp_frame = ttk.LabelFrame(self.paned_window, text="Response", padding="5")
        self.paned_window.add(resp_frame, weight=1)
        
        # Response status
        resp_header_frame = ttk.Frame(resp_frame)
        resp_header_frame.pack(fill=tk.X, pady=(0, 5))
        
        self.status_label = ttk.Label(resp_header_frame, text="Status: ")
        self.status_label.pack(side=tk.LEFT)
        
        self.resp_length_label = ttk.Label(resp_header_frame, text="Length: ")
        self.resp_length_label.pack(side=tk.LEFT, padx=10)
        
        # Text area with syntax highlighting
        self.resp_text = tk.Text(resp_frame, wrap=tk.WORD, width=60, height=30)
        self.resp_text.pack(fill=tk.BOTH, expand=True)
        resp_scroll = ttk.Scrollbar(resp_frame, orient=tk.VERTICAL, command=self.resp_text.yview)
        resp_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.resp_text['yscrollcommand'] = resp_scroll.set
        
        # Headers/body toggle
        resp_toggle_frame = ttk.Frame(resp_frame)
        resp_toggle_frame.pack(fill=tk.X, pady=5)
        
        self.resp_view_var = tk.StringVar(value="all")
        ttk.Radiobutton(resp_toggle_frame, text="All", variable=self.resp_view_var, 
                       value="all", command=self.update_response_view).pack(side=tk.LEFT)
        ttk.Radiobutton(resp_toggle_frame, text="Headers Only", variable=self.resp_view_var,
                       value="headers", command=self.update_response_view).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(resp_toggle_frame, text="Body Only", variable=self.resp_view_var,
                       value="body", command=self.update_response_view).pack(side=tk.LEFT)
        
        # Display format options
        format_frame = ttk.Frame(resp_frame)
        format_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(format_frame, text="Format:").pack(side=tk.LEFT)
        
        self.format_var = tk.StringVar(value="auto")
        ttk.Radiobutton(format_frame, text="Auto", variable=self.format_var, 
                       value="auto", command=self.update_response_format).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="JSON", variable=self.format_var,
                       value="json", command=self.update_response_format).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="XML", variable=self.format_var,
                       value="xml", command=self.update_response_format).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="HTML", variable=self.format_var,
                       value="html", command=self.update_response_format).pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(format_frame, text="Plain", variable=self.format_var,
                       value="plain", command=self.update_response_format).pack(side=tk.LEFT, padx=5)
    
    def setup_bindings(self):
        """Setup all event bindings"""
        self.root.bind('<Left>', lambda e: self.previous_item())
        self.root.bind('<Right>', lambda e: self.next_item())
        self.base_url_entry.bind('<KeyRelease>', self.on_url_change)
        self.endpoint_entry.bind('<KeyRelease>', self.on_url_change)
        
        # Module listbox bindings
        self.module_listbox.bind('<Double-Button-1>', lambda e: self.run_selected_module())
    
    def load_modules(self):
        """Load all available analysis modules"""
        # Clear existing module list
        self.module_listbox.delete(0, tk.END)
        self.modules = {}
        
        # Look for modules in the 'modules' directory
        module_dir = Path(__file__).parent / "modules"
        
        if not module_dir.exists():
            messagebox.showinfo("Modules", "No modules directory found. Creating one...")
            module_dir.mkdir(parents=True, exist_ok=True)
        
        # Create an __init__.py file if it doesn't exist
        init_file = module_dir / "__init__.py"
        if not init_file.exists():
            with open(init_file, 'w') as f:
                f.write("# Pentest module initialization\n")
        
        # Look for Python files in the modules directory
        for module_file in module_dir.glob("*.py"):
            if module_file.name == "__init__.py":
                continue
                
            module_name = module_file.stem
            
            try:
                # Import the module dynamically
                spec = importlib.util.spec_from_file_location(
                    f"modules.{module_name}", module_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Check if the module has the required attributes
                if hasattr(module, "MODULE_NAME") and hasattr(module, "analyze"):
                    self.modules[module_name] = module
                    self.module_listbox.insert(tk.END, module.MODULE_NAME)
            except Exception as e:
                print(f"Error loading module {module_name}: {str(e)}")
    
    def run_selected_module(self):
        """Run the selected analysis module on the current item"""
        if not self.modules:
            messagebox.showinfo("Module", "Please load an XML file first")
            return
            
        selected_indices = self.module_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("Module", "Please select a module to run")
            return
            
        module_name = self.module_listbox.get(selected_indices[0])
        
        # Find the module object
        module_obj = None
        for name, module in self.modules.items():
            if module.MODULE_NAME == module_name:
                module_obj = module
                break
                
        if not module_obj:
            messagebox.showerror("Module Error", f"Module '{module_name}' not found")
            return
        
        try:
            result = None
            
            # Check if this module supports scanning all requests
            if hasattr(module_obj, "SCAN_ALL_REQUESTS") and module_obj.SCAN_ALL_REQUESTS:
                # Show a progress dialog
                progress = tk.Toplevel(self.root)
                progress.title("Processing")
                progress.geometry("300x100")
                progress.transient(self.root)
                progress.grab_set()
                
                ttk.Label(progress, text=f"Scanning all requests with {module_name}...").pack(pady=10)
                progress_bar = ttk.Progressbar(progress, mode='indeterminate')
                progress_bar.pack(fill=tk.X, padx=20)
                progress_bar.start()
                
                # Force UI update
                self.root.update_idletasks()
                
                # Get all items
                all_items_data = []
                for i, item in enumerate(self.items):
                    url_elem = item.find('url')
                    url = url_elem.text if url_elem is not None else ""
                    
                    request = item.find('request')
                    if request is not None:
                        request_content = request.text or ""
                        if request.get('base64') == 'true':
                            try:
                                request_content = self.decode_base64(request_content)
                            except:
                                request_content = ""
                        
                        # Parse request data
                        request_data = self.parse_request_content(request_content)
                    else:
                        request_data = {}
                    
                    response = item.find('response')
                    if response is not None:
                        response_content = response.text or ""
                        if response.get('base64') == 'true':
                            try:
                                response_content = self.decode_base64(response_content)
                            except:
                                response_content = ""
                        
                        # Parse response data
                        response_data = self.parse_response_content(response_content)
                    else:
                        response_data = {}
                    
                    all_items_data.append({
                        "index": i,
                        "url": url,
                        "request_data": request_data,
                        "response_data": response_data,
                    })
                
                # Call the module's analyze_all function
                result = module_obj.analyze_all(all_items_data)
                
                # Close progress dialog
                progress.destroy()
            else:
                # Just analyze the current item as before
                if not self.current_item:
                    messagebox.showinfo("Module", "Please select a request to analyze")
                    return
                    
                # Prepare the data for the module
                request_data = self.get_current_request_data()
                response_data = self.get_current_response_data()
                url = self.get_full_url()
                
                # Run the module's analyze function
                result = module_obj.analyze(request_data, response_data, url)
            
            # Display the result
            self.module_output_text.delete('1.0', tk.END)
            
            if isinstance(result, dict) or isinstance(result, list):
                # Format JSON output
                result_str = json.dumps(result, indent=2)
            else:
                result_str = str(result)
                
            self.module_output_text.insert('1.0', result_str)
            
            # Switch to the module tab
            self.notebook.select(self.module_frame)
            
        except Exception as e:
            messagebox.showerror("Module Error", f"Error running module: {str(e)}")
            import traceback
            traceback.print_exc()

    def parse_request_content(self, request_content):
        """Parse raw HTTP request into structured data"""
        lines = request_content.splitlines()
        
        # Extract method, path, protocol
        first_line = lines[0] if lines else ""
        first_line_parts = first_line.split()
        method = first_line_parts[0] if len(first_line_parts) > 0 else ""
        path = first_line_parts[1] if len(first_line_parts) > 1 else ""
        protocol = first_line_parts[2] if len(first_line_parts) > 2 else ""
        
        # Extract headers
        headers = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                key, value = lines[i].split(":", 1)
                headers[key.strip()] = value.strip()
            i += 1
            
        # Extract body
        body = ""
        if i < len(lines):
            body = "\n".join(lines[i+1:])
            
        return {
            "method": method,
            "path": path,
            "protocol": protocol,
            "headers": headers,
            "body": body,
            "raw": request_content
        }

    def parse_response_content(self, response_content):
        """Parse raw HTTP response into structured data"""
        lines = response_content.splitlines()
        
        # Extract status line
        first_line = lines[0] if lines else ""
        first_line_parts = first_line.split()
        protocol = first_line_parts[0] if len(first_line_parts) > 0 else ""
        status_code = first_line_parts[1] if len(first_line_parts) > 1 else ""
        status_text = " ".join(first_line_parts[2:]) if len(first_line_parts) > 2 else ""
        
        # Extract headers
        headers = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                key, value = lines[i].split(":", 1)
                headers[key.strip()] = value.strip()
            i += 1
            
        # Extract body
        body = ""
        if i < len(lines):
            body = "\n".join(lines[i+1:])
            
        return {
            "protocol": protocol,
            "status_code": status_code,
            "status_text": status_text,
            "headers": headers,
            "body": body,
            "length": len(response_content),
            "raw": response_content
        }

    def configure_selected_module(self):
        """Configure the selected module"""
        selected_indices = self.module_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("Module", "Please select a module to configure")
            return
            
        module_name = self.module_listbox.get(selected_indices[0])
        
        # Find the module object
        module_obj = None
        for name, module in self.modules.items():
            if module.MODULE_NAME == module_name:
                module_obj = module
                break
                
        if not module_obj:
            messagebox.showerror("Module Error", f"Module '{module_name}' not found")
            return
            
        # Check if the module has a configure function
        if hasattr(module_obj, "configure"):
            # Clear the configuration frame
            for widget in self.module_config_frame.winfo_children():
                widget.destroy()
                
            # Run the module's configure function with the frame
            module_obj.configure(self.module_config_frame)
        else:
            messagebox.showinfo("Module", f"Module '{module_name}' has no configuration options")
    
    def browse_output_dir(self):
        """Open directory browser dialog"""
        dir_path = filedialog.askdirectory(initialdir=self.output_dir)
        if dir_path:
            self.output_dir = Path(dir_path)
            self.output_path_entry.delete(0, tk.END)
            self.output_path_entry.insert(0, str(self.output_dir))
    
    def on_url_change(self, event=None):
        """Handle URL or endpoint changes"""
        if self.current_item is not None:
            full_url = self.get_full_url()
            url_elem = self.current_item.find('url')
            if url_elem is not None:
                url_elem.text = full_url
    
    def get_full_url(self):
        """Combine base URL and endpoint"""
        base_url = self.base_url_entry.get().rstrip('/')
        endpoint = self.endpoint_entry.get()
        if endpoint and not endpoint.startswith('/'):
            endpoint = '/' + endpoint
        return base_url + endpoint
    
    def split_url(self, url):
        """Split URL into base and endpoint"""
        if not url:
            return '', ''
        
        # Find the last occurrence of / before any query parameters
        base_end = url.find('?')
        if base_end == -1:
            base_end = len(url)
            
        last_slash = url.rfind('/', 0, base_end)
        
        if last_slash == -1:
            return url, ''
        else:
            base_url = url[:last_slash]
            endpoint = url[last_slash:]
            return base_url, endpoint
    
    def load_xml_file(self, filename):
        """Load and parse XML file"""
        try:
            tree = ET.parse(filename)
            root = tree.getroot()
            self.items = root.findall('.//item')
            self.current_index = 0
            
            if self.items:
                self.update_display()
                # Switch to the viewer tab
                self.notebook.select(self.viewer_frame)
            else:
                messagebox.showerror("Error", "No items found in XML file")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load XML file: {str(e)}")
    
    def decode_base64(self, content):
        """Decode base64 content"""
        try:
            return base64.b64decode(content).decode('utf-8')
        except:
            return "Unable to decode base64 content"
    
    def update_display(self):
        """Update all display elements with current item data"""
        if not self.items:
            return
            
        self.current_item = self.items[self.current_index]
        
        # Update counter
        self.counter_label.config(text=f"Request {self.current_index + 1} of {len(self.items)}")
        
        # Update URL fields
        url_elem = self.current_item.find('url')
        if url_elem is not None and url_elem.text:
            url = url_elem.text
            base_url, endpoint = self.split_url(url)
            self.base_url_entry.delete(0, tk.END)
            self.base_url_entry.insert(0, base_url)
            self.endpoint_entry.delete(0, tk.END)
            self.endpoint_entry.insert(0, endpoint)
        
        # Update status
        status_elem = self.current_item.find('status')
        if status_elem is not None:
            self.status_label.config(text=f"Status: {status_elem.text}")
        
        # Update request
        request = self.current_item.find('request')
        if request is not None:
            request_content = request.text or ""
            if request.get('base64') == 'true':
                request_content = self.decode_base64(request_content)
            
            # Try to extract method and path
            first_line_match = re.match(r'^(\w+)\s+([^\s]+)', request_content)
            if first_line_match:
                method, path = first_line_match.groups()
                self.req_method_label.config(text=f"Method: {method}")
                self.req_path_label.config(text=f"Path: {path}")
            
            self.req_text.delete('1.0', tk.END)
            self.req_text.insert('1.0', request_content)
            
            # Apply the current view filter
            self.update_request_view()
        
        # Update response
        response = self.current_item.find('response')
        if response is not None:
            response_content = response.text or ""
            if response.get('base64') == 'true':
                response_content = self.decode_base64(response_content)
            
            self.resp_length_label.config(text=f"Length: {len(response_content)}")
            
            self.resp_text.delete('1.0', tk.END)
            self.resp_text.insert('1.0', response_content)
            
            # Apply the current view filter and format
            self.update_response_view()
            self.update_response_format()
        
        # Update button states
        self.prev_button.state(['!disabled'] if self.current_index > 0 else ['disabled'])
        self.next_button.state(['!disabled'] if self.current_index < len(self.items) - 1 else ['disabled'])
    
    def update_request_view(self):
        """Update the request view based on the selected filter"""
        if not self.current_item:
            return
            
        request = self.current_item.find('request')
        if request is None:
            return
            
        request_content = request.text or ""
        if request.get('base64') == 'true':
            request_content = self.decode_base64(request_content)
            
        view_mode = self.req_view_var.get()
        
        self.req_text.delete('1.0', tk.END)
        
        if view_mode == "all":
            self.req_text.insert('1.0', request_content)
        elif view_mode == "headers":
            # Extract headers (everything before the first double newline)
            headers_match = re.match(r'(.*?\r?\n\r?\n)', request_content, re.DOTALL)
            if headers_match:
                self.req_text.insert('1.0', headers_match.group(1))
            else:
                self.req_text.insert('1.0', request_content)
        elif view_mode == "body":
            # Extract body (everything after the first double newline)
            body_match = re.search(r'\r?\n\r?\n(.*)', request_content, re.DOTALL)
            if body_match:
                self.req_text.insert('1.0', body_match.group(1))
    
    def update_response_view(self):
        """Update the response view based on the selected filter"""
        if not self.current_item:
            return
            
        response = self.current_item.find('response')
        if response is None:
            return
            
        response_content = response.text or ""
        if response.get('base64') == 'true':
            response_content = self.decode_base64(response_content)
            
        view_mode = self.resp_view_var.get()
        
        self.resp_text.delete('1.0', tk.END)
        
        if view_mode == "all":
            self.resp_text.insert('1.0', response_content)
        elif view_mode == "headers":
            # Extract headers (everything before the first double newline)
            headers_match = re.match(r'(.*?\r?\n\r?\n)', response_content, re.DOTALL)
            if headers_match:
                self.resp_text.insert('1.0', headers_match.group(1))
            else:
                self.resp_text.insert('1.0', response_content)
        elif view_mode == "body":
            # Extract body (everything after the first double newline)
            body_match = re.search(r'\r?\n\r?\n(.*)', response_content, re.DOTALL)
            if body_match:
                self.resp_text.insert('1.0', body_match.group(1))
                
        # Apply the current format
        self.update_response_format()
    
    def update_response_format(self):
        """Format the response content based on the selected format"""
        if not self.current_item:
            return
            
        # Get the current content
        content = self.resp_text.get('1.0', tk.END).strip()
        if not content:
            return
            
        format_mode = self.format_var.get()
        
        # Only format if we're in body view or the response starts with {, <, or [
        is_formattable = (self.resp_view_var.get() == "body" or 
                         content.lstrip().startswith(("{", "<", "[")))
        
        if not is_formattable:
            return
            
        # Auto-detect format if needed
        if format_mode == "auto":
            if content.lstrip().startswith("{") or content.lstrip().startswith("["):
                format_mode = "json"
            elif content.lstrip().startswith("<"):
                if "<html" in content.lower() or "<body" in content.lower():
                    format_mode = "html"
                else:
                    format_mode = "xml"
            else:
                format_mode = "plain"
        
        # Apply formatting
        if format_mode == "json":
            try:
                parsed = json.loads(content)
                formatted = json.dumps(parsed, indent=2)
                self.resp_text.delete('1.0', tk.END)
                self.resp_text.insert('1.0', formatted)
            except:
                # Not valid JSON, leave as is
                pass
        elif format_mode == "xml":
            try:
                from xml.dom import minidom
                parsed = minidom.parseString(content)
                formatted = parsed.toprettyxml(indent="  ")
                self.resp_text.delete('1.0', tk.END)
                self.resp_text.insert('1.0', formatted)
            except:
                # Not valid XML, leave as is
                pass
    
    def get_current_request_data(self):
        """Get the current request data as a dictionary"""
        if not self.current_item:
            return {}
            
        request = self.current_item.find('request')
        if request is None:
            return {}
            
        request_content = request.text or ""
        if request.get('base64') == 'true':
            request_content = self.decode_base64(request_content)
            
        # Parse the request
        lines = request_content.splitlines()
        
        # Extract method, path, protocol
        first_line = lines[0] if lines else ""
        first_line_parts = first_line.split()
        method = first_line_parts[0] if len(first_line_parts) > 0 else ""
        path = first_line_parts[1] if len(first_line_parts) > 1 else ""
        protocol = first_line_parts[2] if len(first_line_parts) > 2 else ""
        
        # Extract headers
        headers = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                key, value = lines[i].split(":", 1)
                headers[key.strip()] = value.strip()
            i += 1
            
        # Extract body
        body = ""
        if i < len(lines):
            body = "\n".join(lines[i+1:])
            
        return {
            "method": method,
            "path": path,
            "protocol": protocol,
            "headers": headers,
            "body": body,
            "raw": request_content
        }
    
    def get_current_response_data(self):
        """Get the current response data as a dictionary"""
        if not self.current_item:
            return {}
            
        response = self.current_item.find('response')
        if response is None:
            return {}
            
        response_content = response.text or ""
        if response.get('base64') == 'true':
            response_content = self.decode_base64(response_content)
            
        # Parse the response
        lines = response_content.splitlines()
        
        # Extract status line
        first_line = lines[0] if lines else ""
        first_line_parts = first_line.split()
        protocol = first_line_parts[0] if len(first_line_parts) > 0 else ""
        status_code = first_line_parts[1] if len(first_line_parts) > 1 else ""
        status_text = " ".join(first_line_parts[2:]) if len(first_line_parts) > 2 else ""
        
        # Extract headers
        headers = {}
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                key, value = lines[i].split(":", 1)
                headers[key.strip()] = value.strip()
            i += 1
            
        # Extract body
        body = ""
        if i < len(lines):
            body = "\n".join(lines[i+1:])
            
        return {
            "protocol": protocol,
            "status_code": status_code,
            "status_text": status_text,
            "headers": headers,
            "body": body,
            "length": len(response_content),
            "raw": response_content
        }
    
    def export_current(self):
        """Export the current request/response in various formats"""
        if not self.current_item:
            return
            
        # Create a popup menu for export options
        popup = tk.Menu(self.root, tearoff=0)
        popup.add_command(label="Export as Curl", command=self.export_as_curl)
        popup.add_command(label="Export as Python requests", command=self.export_as_python)
        popup.add_command(label="Export Raw Request/Response", command=self.export_raw)
        popup.add_command(label="Export as JSON", command=self.export_as_json)
        
        # Display the popup menu
        try:
            popup.tk_popup(self.root.winfo_pointerx(), self.root.winfo_pointery())
        finally:
            popup.grab_release()
    
    def export_as_curl(self):
        """Export current request as curl command"""
        request_data = self.get_current_request_data()
        url = self.get_full_url()
        
        # Build curl command
        curl_parts = [f"curl --path-as-is -i -s -k -X '{request_data['method']}'"]
        
        # Add headers
        for key, value in request_data["headers"].items():
            if key.lower() not in ['connection', 'content-length']:
                curl_parts.append(f"    -H '{key}: {value}'")
        
        # Add cookies
        if 'Cookie' in request_data["headers"]:
            curl_parts.append(f"    -b '{request_data['headers']['Cookie']}'")
        
        # Add body if present
        if request_data["body"]:
            body_quoted = shlex.quote(request_data["body"])
            curl_parts.append(f"    -d {body_quoted}")
        
        curl_parts.append(f"    '{url}'")
        
        # Create the output directory if it doesn't exist
        output_dir = Path(self.output_path_entry.get())
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate a filename
        filename = self.generate_filename("curl", ".sh")
        output_file = output_dir / filename
        
        # Write the curl command to the file
        with open(output_file, "w") as f:
            f.write("#!/bin/bash\n\n")
            f.write(" \\\n".join(curl_parts))
        
        messagebox.showinfo("Export", f"Curl command exported to {output_file}")
    
    def export_as_python(self):
        """Export current request as Python requests code"""
        request_data = self.get_current_request_data()
        url = self.get_full_url()
        
        python_code = [
            "import requests",
            "",
            "# Request URL",
            f"url = '{url}'",
            "",
            "# Request headers",
            "headers = {"
        ]
        
        # Add headers
        for key, value in request_data["headers"].items():
            if key.lower() not in ['connection', 'content-length']:
                python_code.append(f"    '{key}': '{value}',")
        
        python_code.append("}")
        python_code.append("")
        
        # Add cookies if present
        if 'Cookie' in request_data["headers"]:
            cookies_line = request_data["headers"]["Cookie"]
            python_code.append("# Cookies")
            python_code.append("cookies = {")
            for cookie in cookies_line.split(';'):
                if '=' in cookie:
                    name, value = cookie.strip().split('=', 1)
                    python_code.append(f"    '{name}': '{value}',")
            python_code.append("}")
            python_code.append("")
        
        # Add body if present
        if request_data["body"]:
            python_code.append("# Request data")
            if request_data["body"].strip().startswith('{'):
                # Looks like JSON
                python_code.append("import json")
                python_code.append("")
                python_code.append("data = json.loads('''")
                python_code.append(request_data["body"])
                python_code.append("''')")
                python_code.append("")
                python_code.append(f"response = requests.{request_data['method'].lower()}(url, headers=headers, json=data)")
            else:
                # Plain data
                python_code.append("data = '''")
                python_code.append(request_data["body"])
                python_code.append("'''")
                python_code.append("")
                python_code.append(f"response = requests.{request_data['method'].lower()}(url, headers=headers, data=data)")
        else:
            python_code.append(f"response = requests.{request_data['method'].lower()}(url, headers=headers)")
        
        python_code.append("")
        python_code.append("# Print response status and content")
        python_code.append("print(f'Status: {response.status_code}')")
        python_code.append("print('Headers:', response.headers)")
        python_code.append("print('Response:')")
        python_code.append("print(response.text)")
        
        # Create the output directory if it doesn't exist
        output_dir = Path(self.output_path_entry.get())
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate a filename
        filename = self.generate_filename("python_request", ".py")
        output_file = output_dir / filename
        
        # Write the Python code to the file
        with open(output_file, "w") as f:
            f.write("\n".join(python_code))
        
        messagebox.showinfo("Export", f"Python code exported to {output_file}")
    
    def export_raw(self):
        """Export raw request and response to a file"""
        if not self.current_item:
            return
        
        request = self.current_item.find('request')
        response = self.current_item.find('response')
        
        if request is None or response is None:
            messagebox.showerror("Export", "Missing request or response data")
            return
            
        request_content = request.text or ""
        if request.get('base64') == 'true':
            request_content = self.decode_base64(request_content)
            
        response_content = response.text or ""
        if response.get('base64') == 'true':
            response_content = self.decode_base64(response_content)
        
        # Create the output directory if it doesn't exist
        output_dir = Path(self.output_path_entry.get())
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate a filename
        filename = self.generate_filename("raw", ".txt")
        output_file = output_dir / filename
        
        # Write the raw data to the file
        with open(output_file, "w") as f:
            f.write("===== REQUEST =====\n")
            f.write(request_content)
            f.write("\n\n===== RESPONSE =====\n")
            f.write(response_content)
        
        messagebox.showinfo("Export", f"Raw data exported to {output_file}")
    
    def export_as_json(self):
        """Export the current request/response as a JSON file"""
        request_data = self.get_current_request_data()
        response_data = self.get_current_response_data()
        url = self.get_full_url()
        
        export_data = {
            "url": url,
            "request": request_data,
            "response": response_data
        }
        
        # Create the output directory if it doesn't exist
        output_dir = Path(self.output_path_entry.get())
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate a filename
        filename = self.generate_filename("export", ".json")
        output_file = output_dir / filename
        
        # Write the JSON data to the file
        with open(output_file, "w") as f:
            json.dump(export_data, f, indent=2)
        
        messagebox.showinfo("Export", f"JSON data exported to {output_file}")
    
    def generate_filename(self, prefix="export", extension=".txt"):
        """Generate a unique filename for output"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        method = "unknown"
        endpoint = "unknown"
        
        # Try to extract method and endpoint
        if self.current_item:
            request_data = self.get_current_request_data()
            method = request_data.get("method", "unknown").lower()
            
            endpoint = self.endpoint_entry.get().strip('/')
            if endpoint:
                # Replace special characters with underscores
                endpoint = re.sub(r'[^\w-]', '_', endpoint)
                endpoint = re.sub(r'_+', '_', endpoint)  # Replace multiple underscores with single
                endpoint = endpoint[:30]  # Limit length
        
        return f"{prefix}_{method}_{endpoint}_{timestamp}{extension}"
    
    def search_items(self, event=None):
        """Search through items based on search criteria"""
        search_term = self.search_entry.get()
        if search_term == "Search..." or not search_term:
            return
            
        # Create a list to store matching indices
        matching_indices = []
        
        # Search in all items
        for i, item in enumerate(self.items):
            # Check URL
            url_elem = item.find('url')
            if url_elem is not None and url_elem.text and search_term.lower() in url_elem.text.lower():
                matching_indices.append(i)
                continue
                
            # Check request
            request = item.find('request')
            if request is not None:
                request_content = request.text or ""
                if request.get('base64') == 'true':
                    request_content = self.decode_base64(request_content)
                    
                if search_term.lower() in request_content.lower():
                    matching_indices.append(i)
                    continue
            
            # Check response
            response = item.find('response')
            if response is not None:
                response_content = response.text or ""
                if response.get('base64') == 'true':
                    response_content = self.decode_base64(response_content)
                    
                if search_term.lower() in response_content.lower():
                    matching_indices.append(i)
                    continue
        
        # Display search results
        if matching_indices:
            # Create a popup dialog
            search_dialog = tk.Toplevel(self.root)
            search_dialog.title("Search Results")
            search_dialog.geometry("600x400")
            
            # Results label
            ttk.Label(search_dialog, 
                    text=f"Found {len(matching_indices)} matches for '{search_term}'").pack(pady=10)
            
            # Results listbox
            results_frame = ttk.Frame(search_dialog)
            results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            results_listbox = tk.Listbox(results_frame, width=80, height=20)
            results_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            
            results_scrollbar = ttk.Scrollbar(results_frame, command=results_listbox.yview)
            results_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            results_listbox['yscrollcommand'] = results_scrollbar.set
            
            # Populate listbox
            for i in matching_indices:
                item = self.items[i]
                url_elem = item.find('url')
                url = url_elem.text if url_elem is not None else ""
                
                # Get method if available
                method = "?"
                request = item.find('request')
                if request is not None:
                    request_content = request.text or ""
                    if request.get('base64') == 'true':
                        request_content = self.decode_base64(request_content)
                        
                    first_line = request_content.splitlines()[0] if request_content.splitlines() else ""
                    first_part = first_line.split()[0] if first_line.split() else "?"
                    method = first_part
                
                # Get status if available
                status = "?"
                status_elem = item.find('status')
                if status_elem is not None:
                    status = status_elem.text
                
                results_listbox.insert(tk.END, f"{i + 1}. [{method}] {url} - Status: {status}")
            
            # Button function to go to selected item
            def go_to_selected():
                selection = results_listbox.curselection()
                if selection:
                    selected_index = matching_indices[selection[0]]
                    self.current_index = selected_index
                    self.update_display()
                    search_dialog.destroy()
            
            # Buttons
            button_frame = ttk.Frame(search_dialog)
            button_frame.pack(pady=10)
            
            ttk.Button(button_frame, text="Go to Selected", command=go_to_selected).pack(side=tk.LEFT, padx=5)
            ttk.Button(button_frame, text="Close", command=search_dialog.destroy).pack(side=tk.LEFT)
            
            # Double-click binding
            results_listbox.bind('<Double-Button-1>', lambda e: go_to_selected())
            
        else:
            messagebox.showinfo("Search", f"No matches found for '{search_term}'")
    
    def previous_item(self):
        """Navigate to previous item"""
        if self.current_index > 0:
            self.current_index -= 1
            self.update_display()
    
    def next_item(self):
        """Navigate to next item"""
        if self.current_index < len(self.items) - 1:
            self.current_index += 1
            self.update_display()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Pentesting XML Parser')
    parser.add_argument('xml_file', nargs='?', default=None,
                       help='Path to the XML file containing HTTP requests/responses')
    parser.add_argument('--module', '-m', default=None,
                       help='Name of the module to run automatically')
    return parser.parse_args()


def main():
    """Main entry point of the application"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Initialize GUI
    root = tk.Tk()
    app = CoreXMLParser(root)
    
    # Load the XML file if specified
    if args.xml_file:
        if not os.path.exists(args.xml_file):
            print(f"Error: File '{args.xml_file}' does not exist", file=sys.stderr)
            sys.exit(1)
        
        app.load_xml_file(args.xml_file)
        
        # Run a specific module if requested
        if args.module:
            # Find the module in the listbox
            for i in range(app.module_listbox.size()):
                if app.module_listbox.get(i).lower() == args.module.lower():
                    app.module_listbox.selection_set(i)
                    app.run_selected_module()
                    break
    
    # Start the main event loop
    root.mainloop()


if __name__ == "__main__":
    main()
