"""
Content view component for the application
"""
import json
import tkinter as tk
from tkinter import scrolledtext
import customtkinter as ctk
import threading
from core.data_loader import load_json_data
from core.file_utils import sanitize_directory_name
from processors import ProcessorFactory
from gui.renderers import RendererFactory

class ContentView:
    """Content view component"""
    
    def __init__(self, parent, base_dir):
        """
        Initialize the content view.
        
        Args:
            parent: Parent widget
            base_dir (Path): Base directory path
        """
        self.parent = parent
        self.base_dir = base_dir
        
        # State variables
        self.current_target = None
        self.current_section = None
        self.current_category = None
        self.current_test_type = None
        self.current_result_file = None
        self.raw_data = None
        self.processed_data = None
        
        # Create main content frame
        self.frame = ctk.CTkFrame(parent)
        self.frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # Create breadcrumb
        self.create_breadcrumb()
        
        # Create separator
        separator = ttk.Separator(self.frame, orient="horizontal")
        separator.pack(fill="x", padx=10, pady=5)
        
        # Create tab view for processed and raw views
        self.create_tabview()
        
        # Display welcome message
        self.display_welcome()
    
    def create_breadcrumb(self):
        """Create breadcrumb navigation bar"""
        self.breadcrumb_frame = ctk.CTkFrame(self.frame)
        self.breadcrumb_frame.pack(fill="x", padx=10, pady=10)
        
        self.breadcrumb_label = ctk.CTkLabel(self.breadcrumb_frame, text="Home", font=("Arial", 12))
        self.breadcrumb_label.pack(side="left", padx=5)
    
    def create_tabview(self):
        """Create tabbed view for different content views"""
        self.tab_view = ctk.CTkTabview(self.frame)
        self.tab_view.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs
        self.processed_tab = self.tab_view.add("Processed View")
        self.raw_tab = self.tab_view.add("Raw JSON")
        
        # Create frames for each tab
        self.processed_frame = ctk.CTkFrame(self.processed_tab)
        self.processed_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.raw_frame = ctk.CTkFrame(self.raw_tab)
        self.raw_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add text area for raw JSON
        self.raw_text = scrolledtext.ScrolledText(
            self.raw_frame, 
            wrap=tk.WORD, 
            bg="#2b2b2b", 
            fg="white", 
            font=("Courier", 10)
        )
        self.raw_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Initialize processed view with scrollable frame
        self.processed_scroll = ctk.CTkScrollableFrame(self.processed_frame)
        self.processed_scroll.pack(fill="both", expand=True, padx=5, pady=5)
    
    def update_breadcrumb(self):
        """Update breadcrumb text based on current selection"""
        breadcrumb_text = "Home"
        
        if self.current_target:
            breadcrumb_text += f" > {self.current_target}"
            
        if self.current_section:
            breadcrumb_text += f" > {self.current_section}"
            
        if self.current_category:
            breadcrumb_text += f" > {sanitize_directory_name(self.current_category)}"
            
        if self.current_test_type:
            breadcrumb_text += f" > {sanitize_directory_name(self.current_test_type)}"
            
        if self.current_result_file:
            breadcrumb_text += f" > {self.current_result_file}"
        
        self.breadcrumb_label.configure(text=breadcrumb_text)
    
    def clear_content(self):
        """Clear all content from the view"""
        # Clear processed view
        for widget in self.processed_scroll.winfo_children():
            widget.destroy()
        
        # Clear raw JSON view
        self.raw_text.delete(1.0, tk.END)
    
    def update_selection(self, target=None, section=None, category=None, test_type=None, result_file=None):
        """
        Update the current selection and display appropriate content.
        
        Args:
            target (str, optional): Target name
            section (str, optional): Section name
            category (str, optional): Category name
            test_type (str, optional): Test type name
            result_file (str, optional): Result file name
        """
        # Update state
        self.current_target = target
        self.current_section = section
        self.current_category = category
        self.current_test_type = test_type
        self.current_result_file = result_file
        
        # Update breadcrumb
        self.update_breadcrumb()
        
        # Clear content
        self.clear_content()
        
        # Display appropriate content based on selection level
        if result_file:
            self.load_result_data()
        elif test_type:
            self.display_test_type_info()
        elif category:
            self.display_category_info()
        elif section:
            self.display_section_info()
        elif target:
            self.display_target_info()
        else:
            self.display_welcome()
    
    def display_welcome(self):
        """Display welcome message"""
        welcome_label = ctk.CTkLabel(
            self.processed_scroll, 
            text="Select a target to get started", 
            font=("Arial", 14, "bold")
        )
        welcome_label.pack(pady=20)
    
    def display_target_info(self):
        """Display information about the selected target"""
        label = ctk.CTkLabel(
            self.processed_scroll, 
            text=f"Selected Target: {self.current_target}\nPlease select a section (Auth or raw)", 
            font=("Arial", 14)
        )
        label.pack(pady=20)
    
    def display_section_info(self):
        """Display information about the selected section"""
        label = ctk.CTkLabel(
            self.processed_scroll, 
            text=f"Selected Section: {self.current_section}\nPlease select a category", 
            font=("Arial", 14)
        )
        label.pack(pady=20)
    
    def display_category_info(self):
        """Display information about the selected category"""
        label = ctk.CTkLabel(
            self.processed_scroll, 
            text=f"Selected Category: {sanitize_directory_name(self.current_category)}\nPlease select a test type", 
            font=("Arial", 14)
        )
        label.pack(pady=20)
    
    def display_test_type_info(self):
        """Display information about the selected test type"""
        label = ctk.CTkLabel(
            self.processed_scroll, 
            text=f"Selected Test Type: {sanitize_directory_name(self.current_test_type)}\nPlease select a result file", 
            font=("Arial", 14)
        )
        label.pack(pady=20)
    
    def load_result_data(self):
        """Load and display result data for the selected file"""
        # Display loading message
        loading_label = ctk.CTkLabel(
            self.processed_scroll, 
            text="Loading result data...", 
            font=("Arial", 14)
        )
        loading_label.pack(pady=20)
        
        # Use threading to prevent UI freeze during loading
        threading.Thread(target=self.load_and_process_data).start()
    
    def load_and_process_data(self):
        """Load and process result data in a background thread"""
        try:
            # Load the JSON data
            self.raw_data = load_json_data(
                self.base_dir, 
                self.current_target, 
                self.current_section, 
                self.current_category, 
                self.current_test_type, 
                self.current_result_file
            )
            
            # Process the data
            processor = ProcessorFactory.get_processor(self.current_test_type)
            self.processed_data = processor.process(self.raw_data)
            
            # Update UI on the main thread
            self.parent.after(0, self.update_result_display)
        except Exception as e:
            # Update UI on the main thread
            self.parent.after(0, lambda: self.display_error(str(e)))
    
    def display_error(self, error_message):
        """
        Display an error message.
        
        Args:
            error_message (str): Error message to display
        """
        self.clear_content()
        error_label = ctk.CTkLabel(
            self.processed_scroll, 
            text=f"Error: {error_message}", 
            font=("Arial", 14), 
            text_color="red"
        )
        error_label.pack(pady=20)
    
    def update_result_display(self):
        """Update the display with processed result data"""
        # Clear the content
        self.clear_content()
        
        # Update raw JSON view
        self.raw_text.insert(tk.END, json.dumps(self.raw_data, indent=2))
        
        # If error in raw data
        if "error" in self.raw_data:
            error_label = ctk.CTkLabel(
                self.processed_scroll, 
                text=f"Error: {self.raw_data['error']}", 
                font=("Arial", 14), 
                text_color="red"
            )
            error_label.pack(pady=20)
            return
        
        # Create and use the appropriate renderer
        renderer = RendererFactory.get_renderer(self.current_test_type, self.processed_scroll)
        renderer.render(self.processed_data)
