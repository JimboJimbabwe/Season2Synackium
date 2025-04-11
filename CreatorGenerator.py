import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import json
import os
import re
from typing import Dict, List, Any, Tuple
import ttkthemes

class DynamicField:
    def __init__(self, parent, label_text, container, callback=None):
        self.parent = parent
        self.container = container
        self.label_text = label_text
        self.entries = []
        self.callback = callback
        self.add_entry()
    
    def add_entry(self):
        frame = ttk.Frame(self.container)
        frame.pack(fill='x', padx=5, pady=2)
        
        # Only show label for first entry in containerized layout
        if len(self.entries) == 0:
            ttk.Label(frame, text=self.label_text).pack(side='left', padx=(0, 10))
        
        entry = ttk.Entry(frame, width=50)
        entry.pack(side='left', padx=5, fill='x', expand=True)
        
        btn_remove = ttk.Button(frame, text="−", width=2, 
                               command=lambda: self.remove_entry(frame, entry))
        if len(self.entries) > 0:  # Only show remove button if there's more than one entry
            btn_remove.pack(side='left', padx=2)
        
        btn_add = ttk.Button(frame, text="+", width=2, 
                            command=self.add_entry)
        btn_add.pack(side='left', padx=2)
        
        self.entries.append((frame, entry, btn_remove))
        
        # Update parameters if this is an endpoint field
        if self.callback and self.label_text == "Endpoint":
            entry.bind('<KeyRelease>', lambda e: self.callback())
    
    def remove_entry(self, frame, entry):
        if len(self.entries) > 1:  # Ensure at least one entry remains
            idx = next(i for i, (f, e, _) in enumerate(self.entries) if f == frame)
            frame.destroy()
            self.entries.pop(idx)
            
            # Update parameters if this is an endpoint field
            if self.callback and self.label_text == "Endpoint":
                self.callback()
    
    def get_values(self):
        return [entry.get().strip() for _, entry, _ in self.entries if entry.get().strip()]
        
    def get_endpoints_with_methods(self):
        """Parse endpoints and extract HTTP methods"""
        endpoints_with_methods = []
        http_method_pattern = r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(.+)$'
        
        for _, entry, _ in self.entries:
            value = entry.get().strip()
            if value:
                match = re.match(http_method_pattern, value, re.IGNORECASE)
                if match:
                    method = match.group(1).upper()
                    endpoint = match.group(2).strip()
                    endpoints_with_methods.append((endpoint, method))
                else:
                    # No method specified, default to GET
                    endpoints_with_methods.append((value, "GET"))
        
        return endpoints_with_methods


class ParameterSection:
    def __init__(self, parent, container):
        self.parent = parent
        self.container = container
        self.endpoint_params: Dict[str, List[str]] = {}
        self.param_frames: Dict[str, Any] = {}
        self.endpoint_methods: Dict[str, str] = {}
        
    def update_endpoints(self, endpoints_with_methods):
        # Clear existing endpoints that are no longer in the list
        current_endpoints = list(self.endpoint_params.keys())
        endpoints = [endpoint for endpoint, _ in endpoints_with_methods]
        
        for endpoint in current_endpoints:
            if endpoint not in endpoints:
                if endpoint in self.param_frames:
                    self.param_frames[endpoint].destroy()
                    del self.param_frames[endpoint]
                if endpoint in self.endpoint_params:
                    del self.endpoint_params[endpoint]
                if endpoint in self.endpoint_methods:
                    del self.endpoint_methods[endpoint]
        
        # Add new endpoints
        for endpoint, method in endpoints_with_methods:
            if endpoint and endpoint not in self.endpoint_params:
                self.endpoint_params[endpoint] = []
                self.endpoint_methods[endpoint] = method
                self.create_endpoint_section(endpoint, method)
            elif endpoint and endpoint in self.endpoint_params:
                # Update the method if endpoint already exists
                self.endpoint_methods[endpoint] = method
                # Update the frame title to include the method
                if endpoint in self.param_frames:
                    self.param_frames[endpoint].configure(text=f"{endpoint} ({method})")
    
    def create_endpoint_section(self, endpoint, method):
        frame = ttk.LabelFrame(self.container, text=f"{endpoint} ({method})")
        frame.pack(fill='x', padx=5, pady=5, expand=True)
        
        self.param_frames[endpoint] = frame
        self.add_param_entry(endpoint, frame)
    
    def add_param_entry(self, endpoint, frame, param_value=""):
        param_frame = ttk.Frame(frame)
        param_frame.pack(fill='x', padx=5, pady=2)
        
        ttk.Label(param_frame, text="* Param:").pack(side='left', padx=(0, 10))
        
        entry = ttk.Entry(param_frame, width=50)
        if param_value:
            entry.insert(0, param_value)
        entry.pack(side='left', padx=5, fill='x', expand=True)
        
        btn_remove = ttk.Button(param_frame, text="−", width=2, 
                               command=lambda: self.remove_param_entry(endpoint, param_frame))
        if len([f for f in frame.winfo_children() if isinstance(f, ttk.Frame)]) > 1:
            btn_remove.pack(side='left', padx=2)
        
        btn_add = ttk.Button(param_frame, text="+", width=2, 
                            command=lambda: self.add_param_entry(endpoint, frame))
        btn_add.pack(side='left', padx=2)
    
    def remove_param_entry(self, endpoint, param_frame):
        if len([f for f in self.param_frames[endpoint].winfo_children() if isinstance(f, ttk.Frame)]) > 1:
            param_frame.destroy()
    
    def get_params(self):
        result = {}
        for endpoint, frame in self.param_frames.items():
            params = []
            for param_frame in frame.winfo_children():
                if isinstance(param_frame, ttk.Frame):
                    for widget in param_frame.winfo_children():
                        if isinstance(widget, ttk.Entry):
                            param_value = widget.get().strip()
                            if param_value:
                                params.append(param_value)
            result[endpoint] = params
        return result
        
    def get_methods(self):
        return self.endpoint_methods


class SynackMissionAutomator:
    def __init__(self, root):
        self.root = root
        self.root.title("Synack Mission Automator")
        self.root.geometry("800x700")
        
        # Apply theme
        try:
            self.style = ttkthemes.ThemedStyle(root)
            self.style.set_theme("arc")  # Modern theme
        except:
            self.style = ttk.Style()
            print("ttkthemes not found, using standard ttk theme")
        
        self.create_ui()
    
    def create_ui(self):
        # Create a main canvas with scrollbar for the entire app
        main_canvas = tk.Canvas(self.root)
        main_scrollbar = ttk.Scrollbar(self.root, orient="vertical", command=main_canvas.yview)
        main_canvas.configure(yscrollcommand=main_scrollbar.set)
        
        main_scrollbar.pack(side="right", fill="y")
        main_canvas.pack(side="left", fill="both", expand=True)
        
        # Main frame
        main_frame = ttk.Frame(main_canvas)
        main_canvas.create_window((0, 0), window=main_frame, anchor="nw")
        
        # Configure the scrolling behavior
        def configure_scroll_region(event):
            main_canvas.configure(scrollregion=main_canvas.bbox("all"))
            main_canvas.bind_all("<MouseWheel>", lambda e: main_canvas.yview_scroll(int(-1*(e.delta/120)), "units"))
        
        main_frame.bind("<Configure>", configure_scroll_region)
        
        # Title
        title_label = ttk.Label(main_frame, text="Synack Mission Automator", font=("Helvetica", 16))
        title_label.pack(pady=10)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Mission Information")
        input_frame.pack(fill='x', padx=5, pady=5)
        
        # Create containerized frames for each dynamic field type
        url_container = ttk.LabelFrame(input_frame, text="URLs")
        url_container.pack(fill='x', padx=5, pady=5)
        
        endpoint_container = ttk.LabelFrame(input_frame, text="Endpoints")
        endpoint_container.pack(fill='x', padx=5, pady=5)
        
        tool_container = ttk.LabelFrame(input_frame, text="Tools")
        tool_container.pack(fill='x', padx=5, pady=5)
        
        # Dynamic fields in their containers
        self.url_field = DynamicField(self, "URL", url_container)
        self.endpoint_field = DynamicField(self, "Endpoint", endpoint_container, self.update_parameters)
        self.tool_field = DynamicField(self, "Tool", tool_container)
        
        # Topic field
        topic_frame = ttk.Frame(input_frame)
        topic_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(topic_frame, text="Topic").pack(side='left', padx=(0, 10))
        self.topic_entry = ttk.Entry(topic_frame, width=50)
        self.topic_entry.pack(side='left', padx=5, fill='x', expand=True)
        
        # Parameters section
        params_frame = ttk.LabelFrame(main_frame, text="Parameters")
        params_frame.pack(fill='x', padx=5, pady=5)
        
        # Create scrollable frame for parameters
        self.params_canvas = tk.Canvas(params_frame, height=200)
        params_scrollbar = ttk.Scrollbar(params_frame, orient="vertical", command=self.params_canvas.yview)
        self.params_canvas.configure(yscrollcommand=params_scrollbar.set)
        
        params_scrollbar.pack(side="right", fill="y")
        self.params_canvas.pack(side="left", fill="both", expand=True)
        
        self.scrollable_params_frame = ttk.Frame(self.params_canvas)
        self.params_canvas.create_window((0, 0), window=self.scrollable_params_frame, anchor="nw")
        
        self.scrollable_params_frame.bind(
            "<Configure>",
            lambda e: self.params_canvas.configure(scrollregion=self.params_canvas.bbox("all"))
        )
        
        self.parameter_section = ParameterSection(self, self.scrollable_params_frame)
        
        # Output section
        output_frame = ttk.LabelFrame(main_frame, text="Output Configuration")
        output_frame.pack(fill='x', padx=5, pady=5)
        
        # Folder path
        folder_frame = ttk.Frame(output_frame)
        folder_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(folder_frame, text="Folder Path").pack(side='left', padx=(0, 10))
        self.folder_path_var = tk.StringVar()
        ttk.Entry(folder_frame, textvariable=self.folder_path_var, width=50).pack(side='left', padx=5, fill='x', expand=True)
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).pack(side='left', padx=5)
        
        # Text input for pass/fail conclusions
        self.create_conclusion_section(main_frame)
        
        # Push button
        self.push_button = ttk.Button(main_frame, text="Push to Folder", command=self.push_to_folder, style="Accent.TButton")
        self.push_button.pack(pady=10)
        
        # Status
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, font=("Helvetica", 10))
        status_label.pack(pady=5)
        
        # Custom button style
        self.style.configure("Accent.TButton", font=("Helvetica", 11, "bold"))
    
    def create_conclusion_section(self, parent):
        conclusion_frame = ttk.LabelFrame(parent, text="Conclusion Templates")
        conclusion_frame.pack(fill='x', padx=5, pady=5)
        
        # Pass conclusion
        pass_frame = ttk.LabelFrame(conclusion_frame, text="Pass Conclusion Response")
        pass_frame.pack(fill='x', padx=5, pady=5)
        self.pass_conclusion_text = scrolledtext.ScrolledText(pass_frame, height=3, wrap=tk.WORD)
        self.pass_conclusion_text.insert("1.0", "(ENTER TEXT HERE)")
        self.pass_conclusion_text.pack(fill='x', padx=5, pady=5)
        
        # Fail conclusion
        fail_frame = ttk.LabelFrame(conclusion_frame, text="Fail Conclusion Response")
        fail_frame.pack(fill='x', padx=5, pady=5)
        self.fail_conclusion_text = scrolledtext.ScrolledText(fail_frame, height=3, wrap=tk.WORD)
        self.fail_conclusion_text.insert("1.0", "(ENTER TEXT HERE)")
        self.fail_conclusion_text.pack(fill='x', padx=5, pady=5)
        
        # Implications
        implications_frame = ttk.Frame(conclusion_frame)
        implications_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(implications_frame, text="Implications").pack(side='left', padx=(0, 10))
        self.implications_entry = ttk.Entry(implications_frame, width=50)
        self.implications_entry.pack(side='left', padx=5, fill='x', expand=True)
        
        # Explanation (for fail)
        explanation_frame = ttk.Frame(conclusion_frame)
        explanation_frame.pack(fill='x', padx=5, pady=5)
        ttk.Label(explanation_frame, text="Explanation (Fail)").pack(side='left', padx=(0, 10))
        self.explanation_entry = ttk.Entry(explanation_frame, width=50)
        self.explanation_entry.pack(side='left', padx=5, fill='x', expand=True)
    
    def browse_folder(self):
        folder_path = filedialog.askdirectory(title="Select Output Folder")
        if folder_path:
            self.folder_path_var.set(folder_path)
    
    def update_parameters(self):
        endpoints_with_methods = self.endpoint_field.get_endpoints_with_methods()
        self.parameter_section.update_endpoints(endpoints_with_methods)
    
    def generate_steps_content(self, urls, endpoints_with_methods, params):
        content = "##### Steps Taken:\n\n"
        
        # Step 1: Go to Main URL
        if urls:
            content += f"1. Go to Main URL at: {urls[0]}\n"
        else:
            content += "1. Go to Main URL at: [URL NOT PROVIDED]\n"
        
        # Step 2: Navigate
        content += "2. Go to [Target Page/Functionality]\n"
        
        # Step 3-9: Endpoint steps
        step_num = 3
        endpoints = [endpoint for endpoint, _ in endpoints_with_methods]
        methods = {endpoint: method for endpoint, method in endpoints_with_methods}
        
        for endpoint in endpoints:
            method = methods.get(endpoint, "GET")
            content += f"{step_num}. On {endpoint} using {method} method do [Action]\n"
            step_num += 1
        
        content += f"{step_num}. Find in Burp Proxy\n"
        step_num += 1
        content += f"{step_num}. Send to Intruder\n"
        step_num += 1
        
        # Add steps for each endpoint's parameters
        for endpoint in endpoints:
            if endpoint in params and params[endpoint]:
                param_list = ", ".join(params[endpoint])
                method = methods.get(endpoint, "GET")
                content += f"{step_num}. For {endpoint} ({method}) add payload position to {param_list}\n"
                step_num += 1
        
        content += f"{step_num}. Load payloads from payloads.txt\n"
        step_num += 1
        content += f"{step_num}. Launch Attack\n"
        step_num += 1
        content += f"{step_num}. See results\n"
        
        return content
    
    def generate_methodology_content(self, urls, tools, steps_content):
        content = "##### Assets Tested:\n"
        for i, url in enumerate(urls, 1):
            content += f"{i}. {url}\n"
        
        content += "\n##### Tools Used:\n"
        for i, tool in enumerate(tools, 1):
            content += f"{i}. {tool}\n"
        
        content += "\n##### Steps Taken:\n"
        # Remove the header from steps content since we just added it
        steps_without_header = steps_content.replace("##### Steps Taken:\n\n", "")
        content += steps_without_header
        
        return content
    
    def generate_conclusion_content(self, conclusion_type, url, endpoints_with_methods, topic, response_text, implications, explanation=""):
        # Create a formatted string with endpoints and their methods
        endpoint_method_pairs = []
        for endpoint, method in endpoints_with_methods:
            endpoint_method_pairs.append(f"{endpoint} ({method})")
        
        endpoints_str = ", ".join(endpoint_method_pairs)
        
        implications_text = implications if implications.strip() else "<IMPLICATIONS>"
        explanation_text = explanation if explanation.strip() else "<EXPLANATIONS>"
        response = response_text if response_text.strip() != "(ENTER TEXT HERE)" and response_text.strip() else "(ENTER TEXT HERE)"
        
        if conclusion_type == "pass":
            content = (f"When testing the asset {url} at Endpoints: {endpoints_str} for {topic} "
                      f"vulnerabilities and/or flaws, the application infrastructure did not yield "
                      f"responses indicative of compromise. When tested across a variety of payloads, "
                      f"for the given attack, the target responded with '{response}'. "
                      f"{implications_text}. At the given moment in time there is no need for remediation "
                      f"of the asset at hand at the Endpoints tested.")
        else:  # fail
            content = (f"When testing the asset {url} at Endpoints: {endpoints_str} for {topic} "
                      f"vulnerabilities and/or flaws, the application infrastructure yielded "
                      f"responses indicative of compromise. When tested across a variety of payloads, "
                      f"for the given attack, the target responded with '{response}'. "
                      f"{implications_text}. At the given moment in time it is advised that the client "
                      f"remediate the asset at hand for the Endpoints tested. {explanation_text}.")
        
        return content
    
    def push_to_folder(self):
        # Get values
        urls = self.url_field.get_values()
        endpoints_with_methods = self.endpoint_field.get_endpoints_with_methods()
        tools = self.tool_field.get_values()
        topic = self.topic_entry.get().strip()
        folder_path = self.folder_path_var.get().strip()
        params = self.parameter_section.get_params()
        
        pass_response = self.pass_conclusion_text.get("1.0", "end-1c").strip()
        fail_response = self.fail_conclusion_text.get("1.0", "end-1c").strip()
        implications = self.implications_entry.get().strip()
        explanation = self.explanation_entry.get().strip()
        
        # Validate
        if not folder_path:
            self.status_var.set("Error: Please select a folder path")
            return
        
        if not os.path.exists(folder_path):
            try:
                os.makedirs(folder_path)
            except Exception as e:
                self.status_var.set(f"Error creating folder: {e}")
                return
        
        try:
            # Create files
            # 1. topics.txt
            with open(os.path.join(folder_path, "topics.txt"), "w") as f:
                f.write(topic)
            
            # 2. steps.txt
            steps_content = self.generate_steps_content(urls, endpoints_with_methods, params)
            with open(os.path.join(folder_path, "steps.txt"), "w") as f:
                f.write(steps_content)
            
            # 3. Methodology.txt
            methodology_content = self.generate_methodology_content(urls, tools, steps_content)
            with open(os.path.join(folder_path, "Methodology.txt"), "w") as f:
                f.write(methodology_content)
            
            # 4. PassConclusion.txt
            if urls:
                main_url = urls[0]
            else:
                main_url = "[URL NOT PROVIDED]"
                
            pass_conclusion = self.generate_conclusion_content(
                "pass", main_url, endpoints_with_methods, topic, pass_response, implications
            )
            with open(os.path.join(folder_path, "PassConclusion.txt"), "w") as f:
                f.write(pass_conclusion)
            
            # 5. FailConclusion.txt
            fail_conclusion = self.generate_conclusion_content(
                "fail", main_url, endpoints_with_methods, topic, fail_response, implications, explanation
            )
            with open(os.path.join(folder_path, "FailConclusion.txt"), "w") as f:
                f.write(fail_conclusion)
            
            self.status_var.set(f"Success! Files created in {folder_path}")
        
        except Exception as e:
            self.status_var.set(f"Error: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = SynackMissionAutomator(root)
    root.mainloop()
