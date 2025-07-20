#!/usr/bin/env python3
"""
Injection Scanner Orchestrator GUI
A comprehensive GUI tool to orchestrate multiple security scanning scripts
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import sys
import subprocess
import threading
import time
from pathlib import Path
import json
from datetime import datetime

class InjectionScannerOrchestrator:
    def __init__(self, root):
        self.root = root
        self.root.title("Injection Scanner Orchestrator")
        self.root.geometry("900x700")
        
        # Variables
        self.target_path = tk.StringVar()
        self.raw_xml_path = tk.StringVar()
        self.results_json_path = tk.StringVar()
        self.dom_analysis_json_path = tk.StringVar()
        
        # Script states
        self.script_states = {
            1: False,  # CDR-Scanner
            2: False,  # Cache-Scan
            3: False,  # P2G
            4: False,  # DOM_Scanner
            5: False   # DOM_Contextualize
        }
        
        # Create GUI
        self.create_widgets()
        
        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
    def create_widgets(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Injection Scanner Orchestrator", 
                               font=('Helvetica', 16, 'bold'))
        title_label.grid(row=0, column=0, pady=10)
        
        # Target folder selection
        folder_frame = ttk.LabelFrame(main_frame, text="Target Folder Selection", padding="10")
        folder_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=10)
        folder_frame.columnconfigure(1, weight=1)
        
        ttk.Label(folder_frame, text="Target Path:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(folder_frame, textvariable=self.target_path, state='readonly').grid(
            row=0, column=1, sticky=(tk.W, tk.E), padx=5)
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).grid(
            row=0, column=2)
        
        # File drop zones
        files_frame = ttk.LabelFrame(main_frame, text="Input Files", padding="10")
        files_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=10)
        files_frame.columnconfigure(0, weight=1)
        files_frame.columnconfigure(1, weight=1)
        
        # Raw XML drop zone
        self.create_drop_zone(files_frame, "raw.xml", self.raw_xml_path, 0, 0, 
                             self.handle_raw_xml_drop)
        
        # Results JSON drop zone (initially disabled)
        self.results_drop_frame = self.create_drop_zone(
            files_frame, "results.json", self.results_json_path, 0, 1, 
            self.handle_results_json_drop, enabled=False)
        
        # DOM Analysis JSON drop zone
        dom_frame = ttk.LabelFrame(main_frame, text="DOM Analysis File", padding="10")
        dom_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=10)
        dom_frame.columnconfigure(0, weight=1)
        
        self.create_drop_zone(dom_frame, "DOM_Analysis_File.json", 
                             self.dom_analysis_json_path, 0, 0, 
                             self.handle_dom_json_drop)
        
        # Script execution status
        status_frame = ttk.LabelFrame(main_frame, text="Execution Status", padding="10")
        status_frame.grid(row=4, column=0, sticky=(tk.W, tk.E), pady=10)
        status_frame.columnconfigure(0, weight=1)
        
        self.status_labels = {}
        scripts = [
            "1. CDR-Scanner",
            "2. Cache-Scan", 
            "3. P2G",
            "4. DOM_Scanner",
            "5. DOM_Contextualize"
        ]
        
        for i, script in enumerate(scripts):
            frame = ttk.Frame(status_frame)
            frame.grid(row=i, column=0, sticky=(tk.W, tk.E), pady=2)
            frame.columnconfigure(1, weight=1)
            
            ttk.Label(frame, text=script, width=25).grid(row=0, column=0, sticky=tk.W)
            status_label = ttk.Label(frame, text="Not Started", foreground="gray")
            status_label.grid(row=0, column=1, sticky=tk.W, padx=10)
            self.status_labels[i+1] = status_label
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, pady=10)
        
        self.run_button = ttk.Button(button_frame, text="Run Script 1 (CDR-Scanner)", 
                                    command=self.run_next_script, state='disabled')
        self.run_button.grid(row=0, column=0, padx=5)
        
        ttk.Button(button_frame, text="View Log", command=self.show_log).grid(
            row=0, column=1, padx=5)
        
        # Track current script
        self.current_script = 1
        
        # Log output (hidden by default)
        self.log_frame = ttk.LabelFrame(main_frame, text="Execution Log", padding="10")
        self.log_text = scrolledtext.ScrolledText(self.log_frame, height=10, width=80)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
    def create_drop_zone(self, parent, label_text, text_var, row, col, handler, enabled=True):
        frame = ttk.LabelFrame(parent, text=label_text, padding="10")
        frame.grid(row=row, column=col, sticky=(tk.W, tk.E), padx=5, pady=5)
        
        drop_label = ttk.Label(frame, text="Click to browse and select file", 
                              relief="solid", anchor="center", padding=20,
                              background="#f0f0f0" if enabled else "#e0e0e0")
        drop_label.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        path_label = ttk.Label(frame, textvariable=text_var, wraplength=300)
        path_label.grid(row=1, column=0, pady=5)
        
        if enabled:
            drop_label.bind("<Button-1>", lambda e: self.browse_file(text_var, handler))
            drop_label.bind("<Enter>", lambda e: drop_label.configure(background="#e8e8e8"))
            drop_label.bind("<Leave>", lambda e: drop_label.configure(background="#f0f0f0"))
            drop_label.configure(cursor="hand2")
        else:
            drop_label.configure(foreground="gray")
            
        return frame
    
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Target Folder")
        if folder:
            # Normalize path for Windows
            normalized_folder = os.path.normpath(folder)
            self.target_path.set(normalized_folder)
            self.create_subdirectories()
            self.check_enable_run()
    
    def browse_file(self, text_var, handler):
        file_path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("XML files", "*.xml"), ("JSON files", "*.json"), 
                      ("All files", "*.*")]
        )
        if file_path:
            handler(file_path)
    
    def create_subdirectories(self):
        """Create Inj and Auth subdirectories if they don't exist"""
        if self.target_path.get():
            inj_path = os.path.normpath(os.path.join(self.target_path.get(), "Inj"))
            auth_path = os.path.normpath(os.path.join(self.target_path.get(), "Auth"))
            
            os.makedirs(inj_path, exist_ok=True)
            os.makedirs(auth_path, exist_ok=True)
            
            self.log(f"Created/verified subdirectories: {inj_path}, {auth_path}")
    
    def handle_raw_xml_drop(self, file_path):
        file_path = file_path.strip('{}')  # Remove curly braces if present
        if file_path.endswith('.xml'):
            # Normalize path for Windows
            normalized_path = os.path.normpath(file_path)
            self.raw_xml_path.set(normalized_path)
            self.log(f"Raw XML file loaded: {normalized_path}")
            self.check_enable_run()
        else:
            messagebox.showerror("Error", "Please select a valid XML file")
    
    def handle_results_json_drop(self, file_path):
        file_path = file_path.strip('{}')
        if file_path.endswith('.json'):
            # Normalize path for Windows
            normalized_path = os.path.normpath(file_path)
            self.results_json_path.set(normalized_path)
            self.log(f"Results JSON file loaded: {normalized_path}")
            self.check_enable_script_2()
        else:
            messagebox.showerror("Error", "Please select a valid JSON file")
    
    def handle_dom_json_drop(self, file_path):
        file_path = file_path.strip('{}')
        if file_path.endswith('.json'):
            # Normalize path for Windows
            normalized_path = os.path.normpath(file_path)
            self.dom_analysis_json_path.set(normalized_path)
            self.log(f"DOM Analysis JSON file loaded: {normalized_path}")
            self.update_run_button()
        else:
            messagebox.showerror("Error", "Please select a valid JSON file")
    
    def check_enable_run(self):
        """Enable run button if target path and raw XML are set"""
        if self.target_path.get() and self.raw_xml_path.get():
            self.run_button.configure(state='normal')
            self.update_run_button()
    
    def check_enable_script_2(self):
        """Enable script 2 execution if results.json is loaded"""
        if self.results_json_path.get() and self.script_states[1]:
            self.update_run_button()
            # Show message about continuing
            messagebox.showinfo(
                "Ready to Continue",
                "Results.json loaded successfully!\n\n" +
                "Click the run button to continue with Cache-Scan."
            )
    
    def log(self, message):
        """Add message to log"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)
    
    def show_log(self):
        """Toggle log visibility"""
        if self.log_frame.winfo_ismapped():
            self.log_frame.grid_forget()
        else:
            self.log_frame.grid(row=6, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
    
    def update_status(self, script_num, status, color="black"):
        """Update script execution status"""
        self.status_labels[script_num].configure(text=status, foreground=color)
        # Update button after status change
        if status == "Completed":
            self.update_run_button()
    
    def update_run_button(self):
        """Update the run button text and state based on current progress"""
        script_names = {
            1: "CDR-Scanner",
            2: "Cache-Scan",
            3: "P2G",
            4: "DOM_Scanner",
            5: "DOM_Contextualize"
        }
        
        # Find next script to run
        next_script = None
        for i in range(1, 6):
            if not self.script_states[i]:
                next_script = i
                break
        
        if next_script:
            self.current_script = next_script
            button_text = f"Run Script {next_script} ({script_names[next_script]})"
            
            # Check if prerequisites are met
            can_run = False
            if next_script == 1:
                can_run = bool(self.target_path.get() and self.raw_xml_path.get())
            elif next_script in [2, 3]:
                can_run = bool(self.results_json_path.get())
            elif next_script in [4, 5]:
                can_run = bool(self.results_json_path.get() and self.dom_analysis_json_path.get())
            
            self.run_button.configure(text=button_text, state='normal' if can_run else 'disabled')
        else:
            self.run_button.configure(text="All Scripts Completed", state='disabled')
    
    def run_next_script(self):
        """Run the next script in sequence"""
        if self.current_script == 1:
            self.run_script_1()
        elif self.current_script == 2:
            self.run_script_2()
        elif self.current_script == 3:
            self.run_script_3()
        elif self.current_script == 4:
            self.run_script_4()
        elif self.current_script == 5:
            self.run_script_5()
    
    def run_command(self, command, script_num, script_name):
        """Execute a command with user approval"""
        # Show command approval dialog
        result = messagebox.askyesno(
            f"Run {script_name}?",
            f"Execute the following command?\n\n{command}\n\nClick Yes to proceed."
        )
        
        if not result:
            self.log(f"User cancelled execution of {script_name}")
            return False
        
        self.update_status(script_num, "Running...", "blue")
        self.log(f"Executing: {command}")
        
        try:
            # Set environment for UTF-8 encoding on Windows
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            
            # Run the command with UTF-8 encoding
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                errors='replace',
                env=env
            )
            
            # Wait for completion
            stdout, stderr = process.communicate()
            
            # Log full output
            if stdout:
                self.log(f"STDOUT from {script_name}:\n{stdout}")
            if stderr:
                self.log(f"STDERR from {script_name}:\n{stderr}")
            
            if process.returncode == 0:
                self.update_status(script_num, "Completed", "green")
                self.log(f"{script_name} completed successfully")
                self.script_states[script_num] = True
                
                # Show completion message
                messagebox.showinfo(
                    f"{script_name} Complete",
                    f"{script_name} has completed successfully!"
                )
                return True
            else:
                self.update_status(script_num, "Failed", "red")
                self.log(f"{script_name} failed with return code: {process.returncode}")
                
                # Create a dialog with full error details
                error_window = tk.Toplevel(self.root)
                error_window.title(f"{script_name} Error Details")
                error_window.geometry("800x600")
                
                # Create scrolled text widget for full error
                error_frame = ttk.Frame(error_window, padding="10")
                error_frame.pack(fill=tk.BOTH, expand=True)
                
                ttk.Label(error_frame, text=f"Full error from {script_name}:", 
                         font=('Helvetica', 10, 'bold')).pack(anchor=tk.W)
                
                error_text = scrolledtext.ScrolledText(error_frame, height=20, width=80)
                error_text.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
                
                # Add full error details
                error_text.insert(tk.END, f"Command: {command}\n")
                error_text.insert(tk.END, f"Return Code: {process.returncode}\n")
                error_text.insert(tk.END, "-" * 80 + "\n")
                error_text.insert(tk.END, "STDOUT:\n")
                error_text.insert(tk.END, stdout if stdout else "(No output)\n")
                error_text.insert(tk.END, "-" * 80 + "\n")
                error_text.insert(tk.END, "STDERR:\n")
                error_text.insert(tk.END, stderr if stderr else "(No error output)\n")
                
                error_text.configure(state='disabled')
                
                # Add copy button
                def copy_error():
                    self.root.clipboard_clear()
                    self.root.clipboard_append(error_text.get(1.0, tk.END))
                    messagebox.showinfo("Copied", "Error details copied to clipboard!")
                
                ttk.Button(error_frame, text="Copy Error to Clipboard", 
                          command=copy_error).pack(pady=10)
                
                return False
                
        except Exception as e:
            self.update_status(script_num, "Error", "red")
            self.log(f"Error running {script_name}: {str(e)}")
            
            # Show full exception details
            import traceback
            full_error = traceback.format_exc()
            self.log(f"Full exception:\n{full_error}")
            
            messagebox.showerror("Execution Error", 
                               f"Error: {str(e)}\n\nCheck the log for full details.")
            return False
    
    def run_script_1(self):
        """Run CDR-Scanner.py"""
        target_path = os.path.normpath(self.target_path.get())
        xml_path = os.path.normpath(self.raw_xml_path.get())
        
        # Use os.path.join and normalize for Windows
        results_path = os.path.normpath(os.path.join(target_path, "Inj", "results.json"))
        command = f'python CDR-Scanner.py "{xml_path}" -o "{results_path}" --dedup endpoint --work-targets'
        
        def run():
            time.sleep(5)  # Initial delay
            if self.run_command(command, 1, "CDR-Scanner"):
                time.sleep(10)  # Post-execution delay
                
                # Enable results.json drop zone
                self.results_drop_frame.destroy()
                self.results_drop_frame = self.create_drop_zone(
                    self.results_drop_frame.master, "results.json", 
                    self.results_json_path, 0, 1, 
                    self.handle_results_json_drop, enabled=True)
                
                messagebox.showinfo(
                    "Next Step",
                    "CDR-Scanner complete!\n\n" +
                    "Please click on the results.json zone and select the file from:\n" +
                    os.path.normpath(os.path.join(target_path, "Inj")) + "\n\n" +
                    "to continue with the next scripts."
                )
        
        threading.Thread(target=run, daemon=True).start()
    
    def run_script_2(self):
        """Run Cache-Scan.py"""
        target_path = os.path.normpath(self.target_path.get())
        xml_path = os.path.normpath(self.raw_xml_path.get())
        results_path = os.path.normpath(self.results_json_path.get())
        
        # Use os.path.join and normalize for Windows
        output_path = os.path.normpath(os.path.join(target_path, "Inj", "cache-repo"))
        command = f'python Cache-Scan.py -j "{results_path}" -x "{xml_path}" -o "{output_path}"'
        
        def run():
            time.sleep(5)
            if self.run_command(command, 2, "Cache-Scan"):
                time.sleep(10)
                # Update button for next script
                self.update_run_button()
                messagebox.showinfo(
                    "Cache-Scan Complete",
                    "Cache-Scan completed successfully!\n\n" +
                    "Click the run button to continue with P2G."
                )
        
        threading.Thread(target=run, daemon=True).start()
    
    def run_script_3(self):
        """Run P2G.py"""
        target_path = os.path.normpath(self.target_path.get())
        
        # Use os.path.join and normalize for Windows
        cache_repo_path = os.path.normpath(os.path.join(target_path, "Inj", "cache-repo"))
        command = f'python P2G.py -c "{cache_repo_path}" -o "{cache_repo_path}"'
        
        def run():
            time.sleep(5)
            if self.run_command(command, 3, "P2G"):
                time.sleep(10)
                # Update button for next script
                self.update_run_button()
                
                # Check if DOM analysis JSON is loaded
                if self.dom_analysis_json_path.get():
                    messagebox.showinfo(
                        "P2G Complete",
                        "P2G completed successfully!\n\n" +
                        "Click the run button to continue with DOM_Scanner."
                    )
                else:
                    messagebox.showinfo(
                        "DOM Analysis Required",
                        "P2G complete!\n\n" +
                        "Please click on the DOM_Analysis_File.json zone and select your file " +
                        "to continue with DOM Scanner."
                    )
        
        threading.Thread(target=run, daemon=True).start()
    
    def run_script_4(self):
        """Run DOM_Scanner.py"""
        target_path = os.path.normpath(self.target_path.get())
        dom_json_path = os.path.normpath(self.dom_analysis_json_path.get())
        results_path = os.path.normpath(self.results_json_path.get())
        
        # Use os.path.join and normalize for Windows
        output_path = os.path.normpath(os.path.join(target_path, "Inj", "Dom_Analysis"))
        command = f'python DOM_Scanner.py "{dom_json_path}" "{results_path}" "{output_path}"'
        
        def run():
            time.sleep(5)
            if self.run_command(command, 4, "DOM_Scanner"):
                time.sleep(10)
                # Update button for next script
                self.update_run_button()
                messagebox.showinfo(
                    "DOM_Scanner Complete",
                    "DOM_Scanner completed successfully!\n\n" +
                    "Click the run button to continue with DOM_Contextualize."
                )
        
        threading.Thread(target=run, daemon=True).start()
    
    def run_script_5(self):
        """Run DOM_Contextualize.py"""
        target_path = os.path.normpath(self.target_path.get())
        xml_path = os.path.normpath(self.raw_xml_path.get())
        
        # Check if contexts.json exists in current directory
        contexts_path = "contexts.json"
        if not os.path.exists(contexts_path):
            messagebox.showerror(
                "Missing File",
                "contexts.json not found in current directory!\n" +
                "Please ensure contexts.json is present."
            )
            return
        
        # Use os.path.join and normalize for Windows
        dom_analysis_path = os.path.normpath(os.path.join(target_path, "Inj", "DOM_Analysis"))
        command = f'python DOM_Contextualize.py -x "{xml_path}" "{dom_analysis_path}" "{contexts_path}"'
        
        def run():
            time.sleep(5)
            if self.run_command(command, 5, "DOM_Contextualize"):
                time.sleep(10)
                messagebox.showinfo(
                    "All Scripts Complete!",
                    "All scripts have been executed successfully!\n\n" +
                    f"Results are available in:\n{os.path.normpath(os.path.join(target_path, 'Inj'))}"
                )
        
        threading.Thread(target=run, daemon=True).start()

def main():
    root = tk.Tk()
    app = InjectionScannerOrchestrator(root)
    root.mainloop()

if __name__ == "__main__":
    main()
