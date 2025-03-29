"""
Renderer for XPath/XQuery injection test results
"""
import tkinter as tk
import customtkinter as ctk
from gui.renderers.base_renderer import BaseRenderer
from config import THEME_COLORS

class XPathRenderer(BaseRenderer):
    """Renderer for XPath/XQuery injection test results"""
    
    def render_content(self):
        """Render XPath/XQuery injection results"""
        # Create header
        self.create_header("XPath/XQuery Injection Results")
        
        # Display title and description if available
        if self.processed_data.get("title") or self.processed_data.get("description"):
            self.render_title_and_description()
        
        # Display statistics
        self.render_statistics()
        
        # Display vulnerable parameters
        if self.processed_data.get("vulnerable_parameters"):
            self.render_vulnerable_parameters()
        
        # Display affected requests
        if self.processed_data.get("requests"):
            self.render_requests()
    
    def render_title_and_description(self):
        """Render title and description section"""
        info_frame = self.create_section_frame()
        
        if self.processed_data.get("title"):
            title_label = ctk.CTkLabel(
                info_frame, 
                text=f"Title: {self.processed_data.get('title')}", 
                font=("Arial", 14, "bold")
            )
            title_label.pack(anchor="w", pady=5, padx=10)
        
        if self.processed_data.get("description"):
            desc_label = ctk.CTkLabel(
                info_frame, 
                text=f"Description: {self.processed_data.get('description')}", 
                font=("Arial", 12),
                wraplength=800
            )
            desc_label.pack(anchor="w", pady=5, padx=10)
    
    def render_statistics(self):
        """Render statistics section"""
        stats_frame = self.create_section_frame()
        
        stats_label = ctk.CTkLabel(stats_frame, text="Statistics", font=("Arial", 14, "bold"))
        stats_label.pack(anchor="w", pady=5, padx=10)
        
        stats_grid = ctk.CTkFrame(stats_frame)
        stats_grid.pack(fill="x", pady=5, padx=10)
        
        # Create a grid for stats (2x3)
        req_count_label = ctk.CTkLabel(
            stats_grid, 
            text=f"Total Requests: {self.processed_data.get('request_count', 0)}", 
            font=("Arial", 12)
        )
        req_count_label.grid(row=0, column=0, sticky="w", padx=10, pady=2)
        
        vuln_req_label = ctk.CTkLabel(
            stats_grid, 
            text=f"Requests with Vulnerable Params: {self.processed_data.get('requests_with_vulnerable_params', 0)}", 
            font=("Arial", 12)
        )
        vuln_req_label.grid(row=0, column=1, sticky="w", padx=10, pady=2)
        
        total_vuln_label = ctk.CTkLabel(
            stats_grid, 
            text=f"Total Vulnerable Params: {self.processed_data.get('total_vulnerable_params', 0)}", 
            font=("Arial", 12)
        )
        total_vuln_label.grid(row=0, column=2, sticky="w", padx=10, pady=2)
        
        high_risk_label = ctk.CTkLabel(
            stats_grid, 
            text=f"High Risk: {self.processed_data.get('high_risk_count', 0)}", 
            font=("Arial", 12), 
            text_color=self.get_risk_color("high")
        )
        high_risk_label.grid(row=1, column=0, sticky="w", padx=10, pady=2)
        
        medium_risk_label = ctk.CTkLabel(
            stats_grid, 
            text=f"Medium Risk: {self.processed_data.get('medium_risk_count', 0)}", 
            font=("Arial", 12), 
            text_color=self.get_risk_color("medium")
        )
        medium_risk_label.grid(row=1, column=1, sticky="w", padx=10, pady=2)
        
        low_risk_label = ctk.CTkLabel(
            stats_grid, 
            text=f"Low Risk: {self.processed_data.get('low_risk_count', 0)}", 
            font=("Arial", 12), 
            text_color=self.get_risk_color("low")
        )
        low_risk_label.grid(row=1, column=2, sticky="w", padx=10, pady=2)
    
    def render_vulnerable_parameters(self):
        """Render vulnerable parameters section"""
        vuln_params_frame = self.create_section_frame()
        
        vuln_params_label = ctk.CTkLabel(
            vuln_params_frame, 
            text="Vulnerable Parameters", 
            font=("Arial", 14, "bold")
        )
        vuln_params_label.pack(anchor="w", pady=5, padx=10)
        
        # Create a scrollable frame for vulnerable parameters
        params_scroll = ctk.CTkScrollableFrame(vuln_params_frame, height=200)
        params_scroll.pack(fill="x", expand=True, pady=5, padx=10)
        
        # Display each vulnerable parameter
        for param_name, param_data in self.processed_data["vulnerable_parameters"].items():
            self.render_parameter(params_scroll, param_name, param_data)
    
    def render_parameter(self, parent, param_name, param_data):
        """Render a single parameter"""
        # Create a frame for this parameter
        param_frame = ctk.CTkFrame(parent)
        param_frame.pack(fill="x", pady=5)
        
        # Risk level color
        risk_color = self.get_risk_color(param_data.get("risk_level"))
        
        # Parameter header
        header_frame = ctk.CTkFrame(param_frame, fg_color=THEME_COLORS["header_bg"])
        header_frame.pack(fill="x", pady=0)
        
        param_name_label = ctk.CTkLabel(header_frame, text=param_name, font=("Arial", 12, "bold"))
        param_name_label.pack(side="left", padx=10, pady=5)
        
        risk_level = param_data.get("risk_level", "unknown").capitalize()
        risk_label = ctk.CTkLabel(
            header_frame, 
            text=f"Risk: {risk_level}", 
            font=("Arial", 12, "bold"), 
            text_color=risk_color
        )
        risk_label.pack(side="right", padx=10, pady=5)
        
        # Create details frame that starts collapsed
        details_frame = ctk.CTkFrame(param_frame)
        details_frame.pack(fill="x", pady=5, padx=10)
        details_frame.pack_forget()  # Initially hidden
        
        # Toggle button
        toggle_button = ctk.CTkButton(
            param_frame, 
            text="Show Details", 
            command=lambda: self.toggle_details(details_frame, toggle_button)
        )
        toggle_button.pack(anchor="w", pady=5, padx=10)
        
        # Parameter details
        details_text = f"Occurrences: {param_data.get('count', 0)}"
        details_label = ctk.CTkLabel(details_frame, text=details_text, font=("Arial", 12))
        details_label.pack(anchor="w", pady=2)
        
        # Risk factors
        if param_data.get("risk_factors"):
            risk_factors_label = ctk.CTkLabel(details_frame, text="Risk Factors:", font=("Arial", 12, "bold"))
            risk_factors_label.pack(anchor="w", pady=5)
            
            for factor in param_data.get("risk_factors", []):
                factor_label = ctk.CTkLabel(details_frame, text=f"• {factor}", font=("Arial", 12))
                factor_label.pack(anchor="w", padx=10)
    
    def render_requests(self):
        """Render requests section"""
        requests_frame = self.create_section_frame()
        requests_frame.pack(fill="both", expand=True)
        
        requests_label = ctk.CTkLabel(
            requests_frame, 
            text="Affected Requests", 
            font=("Arial", 14, "bold")
        )
        requests_label.pack(anchor="w", pady=5, padx=10)
        
        # Create a scrollable frame for the requests
        requests_scroll = ctk.CTkScrollableFrame(requests_frame, height=200)
        requests_scroll.pack(fill="both", expand=True, pady=5, padx=10)
        
        # Create list header
        header_frame = ctk.CTkFrame(requests_scroll, fg_color=THEME_COLORS["list_header_bg"])
        header_frame.pack(fill="x", pady=(0, 5))
        
        index_header = ctk.CTkLabel(header_frame, text="Index", font=("Arial", 12, "bold"), width=60)
        index_header.pack(side="left", padx=5, pady=5)
        
        method_header = ctk.CTkLabel(header_frame, text="Method", font=("Arial", 12, "bold"), width=80)
        method_header.pack(side="left", padx=5, pady=5)
        
        url_header = ctk.CTkLabel(header_frame, text="URL", font=("Arial", 12, "bold"), width=400)
        url_header.pack(side="left", padx=5, pady=5)
        
        params_header = ctk.CTkLabel(header_frame, text="Vulnerable Params", font=("Arial", 12, "bold"), width=100)
        params_header.pack(side="left", padx=5, pady=5)
        
        # Add items to the list
        for req in self.processed_data.get("requests", []):
            self.render_request_row(requests_scroll, req)
    
    def render_request_row(self, parent, req):
        """Render a single request row"""
        row_frame = ctk.CTkFrame(parent)
        row_frame.pack(fill="x", pady=1)
        
        index_label = ctk.CTkLabel(row_frame, text=str(req.get("index", "")), width=60)
        index_label.pack(side="left", padx=5, pady=5)
        
        method_label = ctk.CTkLabel(row_frame, text=req.get("method", "GET"), width=80)
        method_label.pack(side="left", padx=5, pady=5)
        
        url_label = ctk.CTkLabel(row_frame, text=req.get("url", ""), width=400, 
                               anchor="w", wraplength=390)
        url_label.pack(side="left", padx=5, pady=5)
        
        params_label = ctk.CTkLabel(row_frame, text=str(req.get("vulnerable_param_count", 0)), width=100)
        params_label.pack(side="left", padx=5, pady=5)
        
        # Create details frame that starts collapsed
        details_frame = ctk.CTkFrame(parent)
        details_frame.pack(fill="x", pady=2, padx=20)
        details_frame.pack_forget()  # Initially hidden
        
        # Toggle button
        details_button = ctk.CTkButton(row_frame, text="➕", width=30, height=20,
                                    command=lambda: self.toggle_request_details(details_frame, row_frame, details_button))
        details_button.pack(side="right", padx=5)
        
        # Only add parameter details if there are parameters
        if req.get("parameters") and len(req.get("parameters", [])) > 0:
            self.render_request_parameters(details_frame, req.get("parameters", []))
    
    def render_request_parameters(self, parent, parameters):
        """Render parameters for a request"""
        # Create a table for the parameters
        param_table_frame = ctk.CTkFrame(parent)
        param_table_frame.pack(fill="x", pady=5)
        
        # Add parameter headers
        param_header_frame = ctk.CTkFrame(param_table_frame, fg_color=THEME_COLORS["list_header_bg"])
        param_header_frame.pack(fill="x", pady=0)
        
        param_name_header = ctk.CTkLabel(param_header_frame, text="Name", font=("Arial", 12, "bold"), width=120)
        param_name_header.pack(side="left", padx=5, pady=2)
        
        param_source_header = ctk.CTkLabel(param_header_frame, text="Source", font=("Arial", 12, "bold"), width=80)
        param_source_header.pack(side="left", padx=5, pady=2)
        
        param_value_header = ctk.CTkLabel(param_header_frame, text="Value", font=("Arial", 12, "bold"), width=200)
        param_value_header.pack(side="left", padx=5, pady=2)
        
        param_risk_header = ctk.CTkLabel(param_header_frame, text="Risk", font=("Arial", 12, "bold"), width=80)
        param_risk_header.pack(side="left", padx=5, pady=2)
        
        # Add parameter rows
        for param in parameters:
            param_row_frame = ctk.CTkFrame(param_table_frame)
            param_row_frame.pack(fill="x", pady=1)
            
            # Risk level colors
            risk_color = self.get_risk_color(param.get("risk_level"))
            
            param_name_label = ctk.CTkLabel(param_row_frame, text=param.get("name", ""), 
                                         width=120, anchor="w", wraplength=110)
            param_name_label.pack(side="left", padx=5, pady=2)
            
            param_source_label = ctk.CTkLabel(param_row_frame, text=param.get("source", ""), 
                                           width=80, anchor="w")
            param_source_label.pack(side="left", padx=5, pady=2)
            
            param_value_label = ctk.CTkLabel(param_row_frame, text=param.get("value", ""), 
                                          width=200, anchor="w", wraplength=190)
            param_value_label.pack(side="left", padx=5, pady=2)
            
            risk_level = param.get("risk_level", "unknown").capitalize()
            param_risk_label = ctk.CTkLabel(param_row_frame, text=risk_level, 
                                         width=80, text_color=risk_color)
            param_risk_label.pack(side="left", padx=5, pady=2)
    
    def toggle_details(self, frame, button):
        """Toggle visibility of details frame"""
        if frame.winfo_ismapped():
            frame.pack_forget()
            button.configure(text="Show Details")
        else:
            frame.pack(fill="x", pady=5, padx=10)
            button.configure(text="Hide Details")
    
    def toggle_request_details(self, frame, row_frame, button):
        """Toggle visibility of request details frame"""
        if frame.winfo_ismapped():
            frame.pack_forget()
            button.configure(text="➕")
            row_frame.configure(fg_color=("gray90", "gray10"))
        else:
            frame.pack(fill="x", pady=2, padx=20, after=row_frame)
            button.configure(text="➖")
            row_frame.configure(fg_color=("gray80", "gray20"))