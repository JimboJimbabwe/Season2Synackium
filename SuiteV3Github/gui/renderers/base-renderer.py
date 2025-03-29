"""
Base renderer for displaying processed test results
"""
import tkinter as tk
import customtkinter as ctk
from abc import ABC, abstractmethod
from config import RISK_COLORS, THEME_COLORS

class BaseRenderer(ABC):
    """Base class for all renderers"""
    
    def __init__(self, parent_frame):
        """
        Initialize the renderer.
        
        Args:
            parent_frame: Parent frame where the content will be rendered
        """
        self.parent_frame = parent_frame
        self.content_frame = None
        self.processed_data = None
    
    def clear(self):
        """Clear all content from the renderer"""
        if self.content_frame:
            self.content_frame.destroy()
        
        self.content_frame = ctk.CTkScrollableFrame(self.parent_frame)
        self.content_frame.pack(fill="both", expand=True, padx=5, pady=5)
    
    def render(self, processed_data):
        """
        Render the processed data.
        
        Args:
            processed_data (dict): Processed data to render
        """
        self.processed_data = processed_data
        self.clear()
        
        # Check for errors
        if "error" in processed_data:
            self.render_error(processed_data["error"])
            return
        
        # Call the specific render implementation
        self.render_content()
    
    def render_error(self, error_message):
        """
        Render an error message.
        
        Args:
            error_message (str): Error message to display
        """
        error_label = ctk.CTkLabel(
            self.content_frame, 
            text=f"Error: {error_message}", 
            font=("Arial", 14), 
            text_color="red"
        )
        error_label.pack(pady=20)
    
    @abstractmethod
    def render_content(self):
        """Render the specific content for this test type. Must be implemented by subclasses."""
        pass
    
    def create_header(self, text, font_size=16):
        """
        Create a header label.
        
        Args:
            text (str): Header text
            font_size (int): Font size
            
        Returns:
            ctk.CTkLabel: Header label
        """
        header = ctk.CTkLabel(
            self.content_frame, 
            text=text, 
            font=("Arial", font_size, "bold")
        )
        header.pack(pady=10)
        return header
    
    def create_section_frame(self):
        """
        Create a section frame.
        
        Returns:
            ctk.CTkFrame: Section frame
        """
        frame = ctk.CTkFrame(self.content_frame)
        frame.pack(fill="x", pady=5, padx=10)
        return frame
    
    def get_risk_color(self, risk_level):
        """
        Get the color for a risk level.
        
        Args:
            risk_level (str): Risk level string (high, medium, low)
            
        Returns:
            str: Hex color code
        """
        if isinstance(risk_level, str):
            return RISK_COLORS.get(risk_level.lower(), RISK_COLORS["unknown"])
        return RISK_COLORS["unknown"]
