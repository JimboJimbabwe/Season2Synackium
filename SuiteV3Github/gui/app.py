"""
Main application class for the Security Testing Directory Navigator
"""
import customtkinter as ctk
from config import APP_TITLE, APP_GEOMETRY, APP_MIN_SIZE
from gui.navigation import NavigationTree
from gui.content_view import ContentView

class NavigatorApp:
    """Main application class"""
    
    def __init__(self, root, base_dir):
        """
        Initialize the application.
        
        Args:
            root: Root window
            base_dir (Path): Base directory path
        """
        self.root = root
        self.base_dir = base_dir
        
        # Configure root window
        self.root.title(APP_TITLE)
        self.root.geometry(APP_GEOMETRY)
        self.root.minsize(*APP_MIN_SIZE)
        
        # Create main frame
        self.main_frame = ctk.CTkFrame(self.root)
        self.main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create components
        self.navigation = NavigationTree(self.main_frame, self.base_dir, self.on_selection_change)
        self.content_view = ContentView(self.main_frame, self.base_dir)
    
    def on_selection_change(self, target, section, category, test_type, result_file):
        """
        Handle selection changes from the navigation tree.
        
        Args:
            target (str, optional): Target name
            section (str, optional): Section name
            category (str, optional): Category name
            test_type (str, optional): Test type name
            result_file (str, optional): Result file name
        """
        # Update content view
        self.content_view.update_selection(target, section, category, test_type, result_file)