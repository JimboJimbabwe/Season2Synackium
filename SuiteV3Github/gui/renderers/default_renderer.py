"""
Default renderer for test types without specific renderers
"""
import json
import tkinter as tk
import customtkinter as ctk
from gui.renderers.base_renderer import BaseRenderer

class DefaultRenderer(BaseRenderer):
    """Default renderer for test types without specific renderers"""
    
    def render_content(self):
        """Render content in a generic way"""
        # Create header based on test type if available
        if "test_type" in self.processed_data:
            self.create_header(f"Results for {self.processed_data['test_type']}")
        else:
            self.create_header("Test Results")
        
        # Create a text widget to show the JSON data
        data_frame = self.create_section_frame()
        
        # Display the data in a simple format
        data_text = ctk.CTkTextbox(data_frame, height=400, width=800)
        data_text.pack(fill="both", expand=True, pady=10, padx=10)
        data_text.insert("1.0", json.dumps(self.processed_data, indent=2))
        data_text.configure(state="disabled")  # Make read-only
