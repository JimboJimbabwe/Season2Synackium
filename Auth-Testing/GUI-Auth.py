#!/usr/bin/env python3
"""
Authorization Test Case Visualizer
Modern GUI for visualizing and streamlining auth testing workflow
"""
""" 
ENSURE TO DO pip install customtkinter pyperclip
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox
import json
from pathlib import Path
import pyperclip
from typing import Dict, List, Tuple
import os

# Set theme
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class TestCase:
    """Represents a single test case with its wordlists and directives"""
    def __init__(self, case_type: str, folder: str, data: dict):
        self.case_type = case_type
        self.folder = folder
        self.data = data
        self.wordlists = self._find_wordlists()
        
    def _find_wordlists(self) -> Dict[str, List[str]]:
        """Find all wordlists in the test case folder"""
        wordlists = {}
        base_path = Path("Authorization-Testing") / self.folder
        
        # Look for wordlist files
        for wl_path in base_path.rglob("wordlist*.txt"):
            rel_path = wl_path.relative_to(base_path)
            wordlist_name = str(rel_path)
            
            try:
                with open(wl_path, 'r') as f:
                    wordlists[wordlist_name] = [line.strip() for line in f if line.strip()]
            except:
                wordlists[wordlist_name] = []
                
        return wordlists
    
    def get_directive(self, wordlist_name: str) -> str:
        """Get testing directive for a specific wordlist"""
        if self.case_type == "empty_intersection":
            if "all_cookies" in wordlist_name:
                return (f"⚠️ CRITICAL: Empty Cookie Intersection on endpoints "
                       f"L{self.data.get('lower_index', '?')} and H{self.data.get('higher_index', '?')}\n\n"
                       f"Test with ALL cookies from both privilege levels.\n"
                       f"This endpoint shares NO cookies between users - high risk of auth bypass!\n"
                       f"Replace cookie values with payloads from this wordlist.")
            else:
                return (f"Empty Intersection - Unique Values Test\n\n"
                       f"Test with unique cookie values only.\n"
                       f"Focus on cookies that exist in only one privilege level.")
                       
        elif self.case_type == "shared":
            if "Test_Lower" in wordlist_name:
                return (f"Privilege Escalation Test - L{self.data.get('lower_index', '?')} → H{self.data.get('higher_index', '?')}\n\n"
                       f"You are testing AS the LOWER privilege user.\n"
                       f"Replace cookie values with payloads from this wordlist.\n"
                       f"Goal: Check if lower user can access higher privilege functionality.")
            else:
                return (f"Privilege Downgrade Test - H{self.data.get('higher_index', '?')} → L{self.data.get('lower_index', '?')}\n\n"
                       f"You are testing AS the HIGHER privilege user.\n"
                       f"Replace cookie values with payloads from this wordlist.\n"
                       f"Goal: Check if higher user is restricted to lower privilege cookies.")
                       
        elif self.case_type == "u_higher":
            return (f"Unauthorized Access Test - Admin Endpoint H{self.data.get('index', '?')}\n\n"
                   f"This is a HIGHER privilege only endpoint.\n"
                   f"Test AS the LOWER privilege user with these cookie values.\n"
                   f"Goal: Check if lower user can access admin-only functionality.")
                   
        elif self.case_type == "u_lower":
            return (f"Improper Access Test - User Endpoint L{self.data.get('index', '?')}\n\n"
                   f"This is a LOWER privilege only endpoint.\n"
                   f"Test AS the HIGHER privilege user with these cookie values.\n"
                   f"Goal: Check if admin access is properly restricted on user endpoints.")
                   
        return "No specific directive available for this test case."


class AuthTestVisualizer(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Authorization Test Visualizer")
        self.geometry("1400x800")
        
        # Data storage
        self.test_cases = {
            "empty_intersection": [],
            "shared": [],
            "u_higher": [],
            "u_lower": []
        }
        self.current_case_type = None
        self.current_case_index = 0
        self.current_test_case = None
        
        # Load data
        self.load_test_cases()
        
        # Setup UI
        self.setup_ui()
        
        # Keyboard bindings
        self.bind("<Left>", lambda e: self.navigate_case(-1))
        self.bind("<Right>", lambda e: self.navigate_case(1))
        self.bind("<Up>", lambda e: self.navigate_case(-1))
        self.bind("<Down>", lambda e: self.navigate_case(1))
        
        # Show first case type
        if any(self.test_cases.values()):
            first_type = next(k for k, v in self.test_cases.items() if v)
            self.show_case_type(first_type)
    
    def load_test_cases(self):
        """Load test cases from repository.json and file structure"""
        base_path = Path("Authorization-Testing")
        
        if not base_path.exists():
            messagebox.showerror("Error", "Authorization-Testing folder not found!")
            return
            
        # Try to load repository.json
        repo_path = base_path / "repository.json"
        if repo_path.exists():
            try:
                with open(repo_path, 'r') as f:
                    repo_data = json.load(f)
                    
                # Load empty intersection cases
                if "empty_intersection" in repo_data:
                    for case in repo_data["empty_intersection"]["indexes"]:
                        tc = TestCase("empty_intersection", case["folder"], case)
                        self.test_cases["empty_intersection"].append(tc)
                
                # Load shared cases
                for case in repo_data.get("shared", {}).get("indexes", []):
                    tc = TestCase("shared", case["folder"], case)
                    self.test_cases["shared"].append(tc)
                
                # Load unique higher cases
                for case in repo_data.get("u_higher", {}).get("indexes", []):
                    tc = TestCase("u_higher", case["folder"], case)
                    self.test_cases["u_higher"].append(tc)
                
                # Load unique lower cases
                for case in repo_data.get("u_lower", {}).get("indexes", []):
                    tc = TestCase("u_lower", case["folder"], case)
                    self.test_cases["u_lower"].append(tc)
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load repository.json: {str(e)}")
        else:
            # Fallback: scan directories
            self._scan_directories(base_path)
    
    def _scan_directories(self, base_path: Path):
        """Fallback method to scan directories if repository.json is missing"""
        # Scan EmptyIntersection
        empty_path = base_path / "EmptyIntersection"
        if empty_path.exists():
            for folder in empty_path.iterdir():
                if folder.is_dir() and "_EMPTY" in folder.name:
                    tc = TestCase("empty_intersection", f"EmptyIntersection/{folder.name}", 
                                {"folder": folder.name})
                    self.test_cases["empty_intersection"].append(tc)
        
        # Scan Shared
        shared_path = base_path / "Shared"
        if shared_path.exists():
            for folder in shared_path.iterdir():
                if folder.is_dir() and folder.name.startswith("H") and "_L" in folder.name:
                    tc = TestCase("shared", f"Shared/{folder.name}", 
                                {"folder": folder.name})
                    self.test_cases["shared"].append(tc)
        
        # Scan U_Higher
        u_higher_path = base_path / "U_Higher"
        if u_higher_path.exists():
            for folder in u_higher_path.iterdir():
                if folder.is_dir() and folder.name.startswith("H"):
                    tc = TestCase("u_higher", f"U_Higher/{folder.name}", 
                                {"folder": folder.name})
                    self.test_cases["u_higher"].append(tc)
        
        # Scan U_Lower
        u_lower_path = base_path / "U_Lower"
        if u_lower_path.exists():
            for folder in u_lower_path.iterdir():
                if folder.is_dir() and folder.name.startswith("L"):
                    tc = TestCase("u_lower", f"U_Lower/{folder.name}", 
                                {"folder": folder.name})
                    self.test_cases["u_lower"].append(tc)
    
    def setup_ui(self):
        """Setup the main UI components"""
        # Main container
        main_container = ctk.CTkFrame(self)
        main_container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Top section - Tabs
        self.tab_frame = ctk.CTkFrame(main_container)
        self.tab_frame.pack(fill="x", padx=5, pady=(5, 10))
        
        # Create tab buttons
        self.tab_buttons = {}
        tab_configs = [
            ("empty_intersection", "⚠️ Empty Intersection", "#FF6B6B"),
            ("shared", "🔄 Shared Endpoints", "#4ECDC4"),
            ("u_higher", "🔒 Unique Higher", "#45B7D1"),
            ("u_lower", "🔓 Unique Lower", "#96CEB4")
        ]
        
        for case_type, label, color in tab_configs:
            count = len(self.test_cases[case_type])
            btn_text = f"{label} ({count})"
            btn = ctk.CTkButton(
                self.tab_frame,
                text=btn_text,
                command=lambda ct=case_type: self.show_case_type(ct),
                fg_color=color if count > 0 else "gray30",
                hover_color=color if count > 0 else "gray40",
                state="normal" if count > 0 else "disabled"
            )
            btn.pack(side="left", padx=5, expand=True, fill="x")
            self.tab_buttons[case_type] = btn
        
        # Middle section - Split view
        content_frame = ctk.CTkFrame(main_container)
        content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Left panel - Case list
        left_panel = ctk.CTkFrame(content_frame)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        # Case type title
        self.case_title = ctk.CTkLabel(
            left_panel, 
            text="Select a test case type",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.case_title.pack(pady=10)
        
        # Navigation info
        self.nav_info = ctk.CTkLabel(
            left_panel,
            text="Use ← → or ↑ ↓ to navigate",
            font=ctk.CTkFont(size=12),
            text_color="gray60"
        )
        self.nav_info.pack()
        
        # Case list frame
        self.case_list_frame = ctk.CTkScrollableFrame(left_panel, width=400)
        self.case_list_frame.pack(fill="both", expand=True, pady=10)
        
        # Right panel - Wordlists
        right_panel = ctk.CTkFrame(content_frame)
        right_panel.pack(side="right", fill="both", expand=True)
        
        # Wordlist title
        self.wordlist_title = ctk.CTkLabel(
            right_panel,
            text="Wordlists",
            font=ctk.CTkFont(size=18, weight="bold")
        )
        self.wordlist_title.pack(pady=10)
        
        # Wordlist container
        self.wordlist_container = ctk.CTkScrollableFrame(right_panel)
        self.wordlist_container.pack(fill="both", expand=True, padx=10, pady=5)
    
    def show_case_type(self, case_type: str):
        """Display cases for a specific type"""
        self.current_case_type = case_type
        self.current_case_index = 0
        
        # Update tab highlighting
        for ct, btn in self.tab_buttons.items():
            if ct == case_type:
                btn.configure(state="disabled")
            else:
                count = len(self.test_cases[ct])
                if count > 0:
                    btn.configure(state="normal")
        
        # Update title
        titles = {
            "empty_intersection": "⚠️ Empty Intersection Cases - CRITICAL",
            "shared": "🔄 Shared Endpoint Cases",
            "u_higher": "🔒 Unique Higher Privilege Endpoints",
            "u_lower": "🔓 Unique Lower Privilege Endpoints"
        }
        self.case_title.configure(text=titles.get(case_type, "Test Cases"))
        
        # Clear and populate case list
        for widget in self.case_list_frame.winfo_children():
            widget.destroy()
        
        cases = self.test_cases[case_type]
        if not cases:
            ctk.CTkLabel(
                self.case_list_frame,
                text="No cases found for this type",
                text_color="gray50"
            ).pack(pady=20)
            return
        
        # Create case buttons
        self.case_buttons = []
        for i, test_case in enumerate(cases):
            # Extract index info for display
            folder = test_case.folder
            if case_type == "empty_intersection":
                display_text = f"🚨 {folder.split('/')[-1]}"
            elif case_type == "shared":
                display_text = f"📁 {folder.split('/')[-1]}"
            elif case_type in ["u_higher", "u_lower"]:
                display_text = f"📄 {folder.split('/')[-1]}"
            else:
                display_text = folder
            
            # Add endpoint info if available
            if "endpoint" in test_case.data:
                display_text += f"\n{test_case.data['endpoint'][:50]}..."
            elif "url" in test_case.data:
                display_text += f"\n{test_case.data['url'][:50]}..."
            
            btn = ctk.CTkButton(
                self.case_list_frame,
                text=display_text,
                command=lambda idx=i: self.select_case(idx),
                height=60,
                anchor="w",
                font=ctk.CTkFont(size=12)
            )
            btn.pack(fill="x", pady=2)
            self.case_buttons.append(btn)
        
        # Select first case
        if cases:
            self.select_case(0)
    
    def select_case(self, index: int):
        """Select a specific test case"""
        cases = self.test_cases[self.current_case_type]
        if 0 <= index < len(cases):
            self.current_case_index = index
            self.current_test_case = cases[index]
            
            # Update button highlighting
            for i, btn in enumerate(self.case_buttons):
                if i == index:
                    btn.configure(fg_color=["#3B8ED0", "#1F6AA5"])
                else:
                    btn.configure(fg_color=["#3B3B3B", "#2B2B2B"])
            
            # Display wordlists
            self.display_wordlists()
    
    def display_wordlists(self):
        """Display wordlists for the selected test case"""
        # Clear previous wordlists
        for widget in self.wordlist_container.winfo_children():
            widget.destroy()
        
        if not self.current_test_case:
            return
        
        wordlists = self.current_test_case.wordlists
        if not wordlists:
            ctk.CTkLabel(
                self.wordlist_container,
                text="No wordlists found for this test case",
                text_color="gray50"
            ).pack(pady=20)
            return
        
        # Display each wordlist
        for wl_name, wl_values in wordlists.items():
            # Wordlist frame
            wl_frame = ctk.CTkFrame(self.wordlist_container)
            wl_frame.pack(fill="x", pady=10, padx=5)
            
            # Header with name and copy button
            header_frame = ctk.CTkFrame(wl_frame)
            header_frame.pack(fill="x", padx=10, pady=(10, 5))
            
            # Wordlist name
            name_label = ctk.CTkLabel(
                header_frame,
                text=f"📋 {wl_name}",
                font=ctk.CTkFont(size=14, weight="bold")
            )
            name_label.pack(side="left")
            
            # Value count
            count_label = ctk.CTkLabel(
                header_frame,
                text=f"({len(wl_values)} values)",
                font=ctk.CTkFont(size=12),
                text_color="gray60"
            )
            count_label.pack(side="left", padx=10)
            
            # Copy button
            copy_btn = ctk.CTkButton(
                header_frame,
                text="📋 Copy All",
                command=lambda vals=wl_values: self.copy_to_clipboard(vals),
                width=100,
                height=28
            )
            copy_btn.pack(side="right")
            
            # Directive
            directive_frame = ctk.CTkFrame(wl_frame, fg_color="gray20")
            directive_frame.pack(fill="x", padx=10, pady=5)
            
            directive_text = self.current_test_case.get_directive(wl_name)
            directive_label = ctk.CTkLabel(
                directive_frame,
                text=directive_text,
                font=ctk.CTkFont(size=12),
                justify="left",
                anchor="w",
                wraplength=600
            )
            directive_label.pack(fill="x", padx=10, pady=10)
            
            # Values preview
            preview_frame = ctk.CTkFrame(wl_frame)
            preview_frame.pack(fill="x", padx=10, pady=(5, 10))
            
            preview_label = ctk.CTkLabel(
                preview_frame,
                text="Preview (first 10 values):",
                font=ctk.CTkFont(size=12),
                anchor="w"
            )
            preview_label.pack(fill="x")
            
            # Value list
            value_text = ctk.CTkTextbox(
                preview_frame,
                height=150,
                font=ctk.CTkFont(family="Consolas", size=11)
            )
            value_text.pack(fill="x", pady=5)
            
            # Insert values
            preview_values = wl_values[:10]
            if len(wl_values) > 10:
                preview_values.append(f"... and {len(wl_values) - 10} more values")
            
            value_text.insert("1.0", "\n".join(preview_values))
            value_text.configure(state="disabled")
    
    def navigate_case(self, direction: int):
        """Navigate between cases with arrow keys"""
        if not self.current_case_type:
            return
        
        cases = self.test_cases[self.current_case_type]
        if not cases:
            return
        
        new_index = self.current_case_index + direction
        if 0 <= new_index < len(cases):
            self.select_case(new_index)
        elif new_index < 0:
            # Wrap to last
            self.select_case(len(cases) - 1)
        else:
            # Wrap to first
            self.select_case(0)
    
    def copy_to_clipboard(self, values: List[str]):
        """Copy wordlist values to clipboard"""
        try:
            text = "\n".join(values)
            pyperclip.copy(text)
            
            # Show success message (temporary popup)
            popup = ctk.CTkToplevel(self)
            popup.geometry("250x80")
            popup.title("Success")
            popup.attributes('-topmost', True)
            
            msg = ctk.CTkLabel(
                popup,
                text="✅ Copied to clipboard!",
                font=ctk.CTkFont(size=14)
            )
            msg.pack(expand=True)
            
            # Auto close after 1.5 seconds
            popup.after(1500, popup.destroy)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy: {str(e)}")


def main():
    # Check if Authorization-Testing directory exists
    if not Path("Authorization-Testing").exists():
        print("Error: Authorization-Testing directory not found!")
        print("Please run the auth testing script first to generate test cases.")
        return
    
    # Create and run the app
    app = AuthTestVisualizer()
    app.mainloop()


if __name__ == "__main__":
    main()
