#!/usr/bin/env python3
"""
Security Testing Directory Navigator
Main entry point for the application
"""
import os
import argparse
from pathlib import Path
import customtkinter as ctk
from gui.app import NavigatorApp

def main():
    """Main entry point for the application"""
    parser = argparse.ArgumentParser(description='Security Testing Directory Navigator (GUI)')
    parser.add_argument('--dir', type=str, required=True, help='Base directory containing test results')
    
    args = parser.parse_args()
    
    if not os.path.isdir(args.dir):
        print(f"Error: Directory '{args.dir}' does not exist or is not a directory.")
        return
    
    # Set appearance mode and default color theme
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    
    root = ctk.CTk()
    app = NavigatorApp(root, Path(args.dir))
    root.mainloop()

if __name__ == "__main__":
    main()
