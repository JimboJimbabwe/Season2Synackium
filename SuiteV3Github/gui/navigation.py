"""
Navigation component for the application
"""
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from core.file_utils import (
    sanitize_directory_name,
    get_targets,
    get_categories,
    get_test_types,
    get_results_files
)

class NavigationTree:
    """Tree navigation component"""
    
    def __init__(self, parent, base_dir, on_selection_change):
        """
        Initialize the navigation tree.
        
        Args:
            parent: Parent widget
            base_dir (Path): Base directory path
            on_selection_change: Callback function for selection changes
        """
        self.parent = parent
        self.base_dir = base_dir
        self.on_selection_change = on_selection_change
        
        # Create frame for the tree
        self.frame = ctk.CTkFrame(parent, width=250)
        self.frame.pack(side="left", fill="y", padx=5, pady=5)
        
        # Create label
        sidebar_label = ctk.CTkLabel(self.frame, text="Navigation", font=("Arial", 14, "bold"))
        sidebar_label.pack(pady=10)
        
        # Create a frame for the treeview
        tree_frame = ctk.CTkFrame(self.frame)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create Treeview for navigation
        self.tree = ttk.Treeview(tree_frame, selectmode="browse")
        self.tree.pack(fill="both", expand=True)
        
        # Configure Treeview style for better visibility in dark mode
        style = ttk.Style()
        style.configure("Treeview", background="#2b2b2b", foreground="white", fieldbackground="#2b2b2b")
        style.configure("Treeview.Heading", background="#2b2b2b", foreground="white")
        style.map('Treeview', background=[('selected', '#347ab3')])
        
        # Add a scrollbar to the treeview
        tree_scrollbar = ctk.CTkScrollbar(tree_frame, command=self.tree.yview)
        tree_scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tree_scrollbar.set)
        
        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self.on_tree_select)
        
        # Initialize the tree
        self.initialize_tree()
    
    def initialize_tree(self):
        """Initialize the tree with targets"""
        # Clear the treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add targets
        targets = get_targets(self.base_dir)
        for target in targets:
            target_id = self.tree.insert("", "end", text=target, values=("target", target))
            
            # Add sections
            for section in ["Auth", "raw"]:
                self.tree.insert(target_id, "end", text=section, values=("section", section))
    
    def on_tree_select(self, event):
        """
        Handle tree selection events.
        
        Args:
            event: Event object
        """
        # Get selected item
        selected_item = self.tree.focus()
        if not selected_item:
            return
        
        item_type, item_value = self.tree.item(selected_item, "values")
        parent_item = self.tree.parent(selected_item)
        
        if item_type == "target":
            # Clear children and add sections
            self.clear_children(selected_item)
            for section in ["Auth", "raw"]:
                self.tree.insert(selected_item, "end", text=section, values=("section", section))
            
            # Notify parent
            self.on_selection_change(
                target=item_value,
                section=None,
                category=None,
                test_type=None,
                result_file=None
            )
        
        elif item_type == "section":
            # Get parent (target)
            parent_type, parent_value = self.tree.item(parent_item, "values")
            
            # Load categories
            categories = get_categories(self.base_dir, parent_value, item_value)
            self.clear_children(selected_item)
            for category in categories:
                self.tree.insert(
                    selected_item, 
                    "end", 
                    text=sanitize_directory_name(category), 
                    values=("category", category)
                )
            
            # Notify parent
            self.on_selection_change(
                target=parent_value,
                section=item_value,
                category=None,
                test_type=None,
                result_file=None
            )
        
        elif item_type == "category":
            # Get parent (section)
            parent_type, parent_value = self.tree.item(parent_item, "values")
            
            # Get grandparent (target)
            grandparent = self.tree.parent(parent_item)
            grandparent_type, grandparent_value = self.tree.item(grandparent, "values")
            
            # Load test types
            test_types = get_test_types(self.base_dir, grandparent_value, parent_value, item_value)
            self.clear_children(selected_item)
            for test_type in test_types:
                self.tree.insert(
                    selected_item, 
                    "end", 
                    text=sanitize_directory_name(test_type), 
                    values=("test_type", test_type)
                )
            
            # Notify parent
            self.on_selection_change(
                target=grandparent_value,
                section=parent_value,
                category=item_value,
                test_type=None,
                result_file=None
            )
        
        elif item_type == "test_type":
            # Get parent chain
            parent_type, parent_value = self.tree.item(parent_item, "values")
            grandparent = self.tree.parent(parent_item)
            grandparent_type, grandparent_value = self.tree.item(grandparent, "values")
            great_grandparent = self.tree.parent(grandparent)
            great_grandparent_type, great_grandparent_value = self.tree.item(great_grandparent, "values")
            
            # Load result files
            result_files = get_results_files(
                self.base_dir, 
                great_grandparent_value, 
                grandparent_value, 
                parent_value, 
                item_value
            )
            self.clear_children(selected_item)
            for result_file in result_files:
                self.tree.insert(
                    selected_item, 
                    "end", 
                    text=result_file, 
                    values=("result_file", result_file)
                )
            
            # Notify parent
            self.on_selection_change(
                target=great_grandparent_value,
                section=grandparent_value,
                category=parent_value,
                test_type=item_value,
                result_file=None
            )
        
        elif item_type == "result_file":
            # Get parent chain
            parent_type, parent_value = self.tree.item(parent_item, "values")
            grandparent = self.tree.parent(parent_item)
            grandparent_type, grandparent_value = self.tree.item(grandparent, "values")
            great_grandparent = self.tree.parent(grandparent)
            great_grandparent_type, great_grandparent_value = self.tree.item(great_grandparent, "values")
            great_great_grandparent = self.tree.parent(great_grandparent)
            great_great_grandparent_type, great_great_grandparent_value = self.tree.item(great_great_grandparent, "values")
            
            # Notify parent
            self.on_selection_change(
                target=great_great_grandparent_value,
                section=great_grandparent_value,
                category=grandparent_value,
                test_type=parent_value,
                result_file=item_value
            )
    
    def clear_children(self, item):
        """
        Clear all children of an item.
        
        Args:
            item: Item ID
        """
        for child in self.tree.get_children(item):
            self.tree.delete(child)
