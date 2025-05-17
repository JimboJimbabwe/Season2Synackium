#!/usr/bin/env python3
import os
import sys
import subprocess
import argparse
import time
import glob
import tkinter as tk
from tkinter import messagebox, ttk
from threading import Thread, Event

class CountdownDialog(tk.Toplevel):
    """Dialog window that shows a countdown timer"""
    def __init__(self, parent, target, seconds=10, callback=None):
        super().__init__(parent)
        self.title("Countdown")
        self.geometry("400x200")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        self.target = target
        self.seconds_left = seconds
        self.callback = callback
        
        # Create widgets
        frame = ttk.Frame(self, padding="20")
        frame.pack(fill=tk.BOTH, expand=True)
        
        message = f"Target: {self.target}\n\nStarting assessment in:"
        ttk.Label(frame, text=message, font=("Arial", 12)).pack(pady=10)
        
        self.countdown_label = ttk.Label(frame, text=str(self.seconds_left), font=("Arial", 24, "bold"))
        self.countdown_label.pack(pady=10)
        
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        
        # Start countdown
        self.start_countdown()
    
    def start_countdown(self):
        """Start the countdown timer"""
        if self.seconds_left > 0:
            self.countdown_label.config(text=str(self.seconds_left))
            self.seconds_left -= 1
            self.after(1000, self.start_countdown)
        else:
            self.destroy()
            if self.callback:
                self.callback()
    
    def on_cancel(self):
        """Handle the user closing the dialog"""
        if messagebox.askyesno("Cancel", "Cancel the operation?"):
            self.destroy()


class VulnAssessmentGUI:
    """GUI for vulnerability assessment orchestration"""
    
    def __init__(self, root, base_path, xml2json_path, birchtool_path):
        self.root = root
        self.base_path = base_path
        self.xml2json_path = xml2json_path
        self.birchtool_path = birchtool_path
        
        self.console_output = None
        self.target_buttons = []
        
        # Add a stop event for controlling assessment threads
        self.stop_event = Event()
        self.current_process = None
        self.assessment_thread = None
        
        self.setup_ui()
    
    def setup_ui(self):
        """Set up the user interface"""
        self.root.title("Vulnerability Assessment Orchestration")
        self.root.geometry("900x600")
        self.root.resizable(True, True)
        
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        ttk.Label(main_frame, text="Vulnerability Assessment Orchestration", 
                 font=("Arial", 16, "bold")).pack(pady=(0, 20))
        
        # Instructions
        instructions = (
            "Select a target to begin vulnerability assessment.\n"
            "Ensure you are connected to LP+ before starting."
        )
        ttk.Label(main_frame, text=instructions, font=("Arial", 10)).pack(pady=(0, 20))
        
        # Split into left and right frames
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Target selection frame (left)
        target_frame = ttk.LabelFrame(content_frame, text="Available Targets", padding="10")
        target_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Target buttons frame with scrollbar
        target_buttons_canvas = tk.Canvas(target_frame)
        scrollbar = ttk.Scrollbar(target_frame, orient="vertical", command=target_buttons_canvas.yview)
        target_buttons_canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        target_buttons_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.target_buttons_frame = ttk.Frame(target_buttons_canvas)
        target_buttons_canvas.create_window((0, 0), window=self.target_buttons_frame, anchor="nw")
        
        # Configure scrolling
        self.target_buttons_frame.bind("<Configure>", 
            lambda e: target_buttons_canvas.configure(scrollregion=target_buttons_canvas.bbox("all")))
        
        # Console output frame (right)
        console_frame = ttk.LabelFrame(content_frame, text="Console Output", padding="10")
        console_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Console output text widget with scrollbar
        self.console_output = tk.Text(console_frame, wrap=tk.WORD, bg="#282c34", fg="#abb2bf", 
                                     font=("Consolas", 10))
        console_scrollbar = ttk.Scrollbar(console_frame, orient="vertical", 
                                         command=self.console_output.yview)
        self.console_output.configure(yscrollcommand=console_scrollbar.set)
        
        console_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.console_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Set up text tags for colored output
        self.console_output.tag_configure("info", foreground="#98c379")
        self.console_output.tag_configure("warning", foreground="#e5c07b")
        self.console_output.tag_configure("error", foreground="#e06c75")
        self.console_output.tag_configure("bold", font=("Consolas", 10, "bold"))
        
        # Make text widget read-only
        self.console_output.config(state=tk.DISABLED)
        
        # Control buttons frame
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, pady=(10, 10))
        
        # Stop button
        self.stop_button = ttk.Button(
            control_frame, 
            text="Stop Assessment",
            command=self.stop_assessment,
            state=tk.DISABLED
        )
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        # Shutdown button
        self.shutdown_button = ttk.Button(
            control_frame, 
            text="Shutdown Application",
            command=self.shutdown_application
        )
        self.shutdown_button.pack(side=tk.RIGHT, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        
        # Load targets
        self.load_targets()
    
    def load_targets(self):
        """Load and display target buttons"""
        # Clear existing buttons
        for widget in self.target_buttons_frame.winfo_children():
            widget.destroy()
        
        # Get target list
        targets = list_targets(self.base_path)
        
        if not targets:
            self.log_message("No target directories found.", "error")
            return
        
        # Add a button for each target
        for i, target in enumerate(targets):
            btn = ttk.Button(
                self.target_buttons_frame, 
                text=target,
                command=lambda t=target: self.confirm_target_selection(t),
                width=30
            )
            btn.grid(row=i, column=0, padx=5, pady=5, sticky="w")
            self.target_buttons.append(btn)
        
        self.log_message(f"Loaded {len(targets)} targets.", "info")
    
    def confirm_target_selection(self, target):
        """Show confirmation dialog when a target is selected"""
        result = messagebox.askquestion(
            "Confirm Target Selection",
            f"THE TARGET SELECTED IS {target}\n\nARE YOU CONNECTED TO LP+ AND READY TO TEST THE TARGET?",
            icon="warning"
        )
        
        if result == "yes":
            # Start countdown dialog
            CountdownDialog(
                self.root, 
                target, 
                seconds=10, 
                callback=lambda: self.start_assessment(target)
            )
    
    def start_assessment(self, target):
        """Start the assessment process for the selected target"""
        self.log_message(f"Starting assessment for target: {target}", "info", bold=True)
        self.status_var.set(f"Processing target: {target}")
        
        # Reset stop event
        self.stop_event.clear()
        
        # Disable all target buttons during assessment
        for btn in self.target_buttons:
            btn.config(state=tk.DISABLED)
        
        # Enable stop button
        self.stop_button.config(state=tk.NORMAL)
        
        # Start assessment in a separate thread to avoid blocking the UI
        self.assessment_thread = Thread(
            target=self.run_assessment_thread,
            args=(target,)
        )
        self.assessment_thread.daemon = True
        self.assessment_thread.start()
    
    def stop_assessment(self):
        """Stop the current assessment process"""
        if self.assessment_thread and self.assessment_thread.is_alive():
            self.log_message("Stopping assessment...", "warning", bold=True)
            # Set the stop event to signal the assessment thread to stop
            self.stop_event.set()
            
            # If there's a current process, terminate it
            if self.current_process:
                try:
                    self.log_message("Terminating the current process...", "warning")
                    # On Windows, we need to use taskkill to kill the process tree
                    if sys.platform == 'win32':
                        subprocess.run(['taskkill', '/F', '/T', '/PID', str(self.current_process.pid)])
                    else:
                        self.current_process.terminate()
                except Exception as e:
                    self.log_message(f"Error terminating process: {str(e)}", "error")
            
            self.log_message("Assessment stopped by user.", "warning", bold=True)
            
            # Disable stop button
            self.stop_button.config(state=tk.DISABLED)
            
            # Re-enable target buttons
            self.enable_buttons()
    
    def shutdown_application(self):
        """Shutdown the application"""
        if self.assessment_thread and self.assessment_thread.is_alive():
            if messagebox.askyesno("Shutdown", "An assessment is currently running. Are you sure you want to shutdown?"):
                self.stop_assessment()
                self.root.after(1000, self.root.destroy)  # Give it a second to clean up
            return
        
        # If no assessment is running, just close
        self.root.destroy()
    
    def run_assessment_thread(self, target):
        """Run the assessment in a background thread"""
        try:
            success = run_assessment(
                self.base_path, 
                target, 
                self.xml2json_path, 
                self.birchtool_path,
                logger=self,
                stop_event=self.stop_event,
                process_setter=self.set_current_process
            )
            
            if self.stop_event.is_set():
                self.log_message("Assessment was stopped by user.", "warning", bold=True)
            elif success:
                self.log_message(f"Assessment completed for target: {target}", "info", bold=True)
            else:
                self.log_message(f"Assessment failed for target: {target}", "error", bold=True)
            
            # Re-enable the target buttons
            self.root.after(0, self.enable_buttons)
            
        except Exception as e:
            self.log_message(f"Error during assessment: {str(e)}", "error")
            self.root.after(0, self.enable_buttons)
    
    def set_current_process(self, process):
        """Set the current subprocess for potential termination"""
        self.current_process = process
    
    def enable_buttons(self):
        """Re-enable all target buttons"""
        for btn in self.target_buttons:
            btn.config(state=tk.NORMAL)
        
        # Disable stop button
        self.stop_button.config(state=tk.DISABLED)
        
        self.status_var.set("Ready")
    
    def log_message(self, message, level="info", bold=False):
        """Log a message to the console output area"""
        self.console_output.config(state=tk.NORMAL)
        
        # Add timestamp
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.console_output.insert(tk.END, f"[{timestamp}] ", "bold")
        
        # Add the message with appropriate tag
        if bold:
            self.console_output.insert(tk.END, message + "\n", (level, "bold"))
        else:
            self.console_output.insert(tk.END, message + "\n", level)
        
        # Autoscroll to the end
        self.console_output.see(tk.END)
        self.console_output.config(state=tk.DISABLED)
    
    def info(self, message):
        """Log an info message (compatible with logger interface)"""
        self.root.after(0, lambda: self.log_message(message, "info"))
    
    def warning(self, message):
        """Log a warning message (compatible with logger interface)"""
        self.root.after(0, lambda: self.log_message(message, "warning"))
    
    def error(self, message):
        """Log an error message (compatible with logger interface)"""
        self.root.after(0, lambda: self.log_message(message, "error"))


def ensure_directory_exists(directory):
    """Create directory if it doesn't exist"""
    if not os.path.exists(directory):
        os.makedirs(directory)


def list_targets(base_path):
    """List all target directories in the base path"""
    targets = []
    try:
        for entry in os.listdir(base_path):
            full_path = os.path.join(base_path, entry)
            if os.path.isdir(full_path):
                targets.append(entry)
        return sorted(targets)
    except Exception as e:
        print(f"Error listing targets: {str(e)}")
        return []


def run_command(command, description=None, logger=None, stop_event=None, process_setter=None):
    """Run a command and display its output"""
    if description:
        if logger:
            logger.info(f"[+] {description}")
            logger.info(f"    Command: {command}")
        else:
            print(f"\n[+] {description}")
            print(f"    Command: {command}")
    
    try:
        process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            shell=True,
            universal_newlines=True
        )
        
        # Register the process with the process_setter if provided
        if process_setter:
            process_setter(process)
        
        # Print output in real-time
        while True:
            # Check if stop requested
            if stop_event and stop_event.is_set():
                process.terminate()
                if logger:
                    logger.warning(f"    Command interrupted by user")
                else:
                    print(f"    Command interrupted by user")
                return False
            
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                if logger:
                    logger.info(f"    {output.strip()}")
                else:
                    print(f"    {output.strip()}")
        
        # Get the return code
        return_code = process.poll()
        
        # Print any errors
        if return_code != 0:
            stderr = process.stderr.read()
            if stderr:
                if logger:
                    logger.warning(f"    Error output: {stderr}")
                else:
                    print(f"    Error output: {stderr}")
            
            if logger:
                logger.error(f"    Command failed with return code {return_code}")
            else:
                print(f"    Command failed with return code {return_code}")
            return False
            
        return True
    except Exception as e:
        error_msg = f"    Error executing command: {str(e)}"
        if logger:
            logger.error(error_msg)
        else:
            print(error_msg)
        return False
    finally:
        # Clear the process reference when done
        if process_setter:
            process_setter(None)


def is_ip_address(s):
    """Simple check to see if a string looks like an IP address"""
    parts = s.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) < 256 for p in parts)
    except ValueError:
        return False


def find_ips_in_directory(directory):
    """Search for IP addresses in files within the directory"""
    import re
    
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    found_ips = []
    
    # Search through all text files
    for ext in ['*.txt', '*.json', '*.xml', '*.log']:
        for file_path in glob.glob(os.path.join(directory, '**', ext), recursive=True):
            try:
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    ips = ip_pattern.findall(content)
                    if ips:
                        found_ips.extend(ips)
            except Exception:
                pass
    
    # Return unique IPs
    return list(set(found_ips))


def create_scope_file(target_file, target_directory, base_path, logger=None):
    """Create a scope.txt file with the target IP(s)"""
    # Check if the file already exists and has content
    existing_ips = []
    if os.path.exists(target_file):
        try:
            with open(target_file, 'r') as f:
                existing_ips = [line.strip() for line in f if line.strip()]
            
            if existing_ips:
                info_msg = f"[*] Scope file already exists with {len(existing_ips)} IP(s)"
                if logger:
                    logger.info(info_msg)
                else:
                    print(info_msg)
                return True
        except Exception as e:
            warn_msg = f"[!] Warning: Could not read existing scope file: {str(e)}"
            if logger:
                logger.warning(warn_msg)
            else:
                print(warn_msg)
    
    # If no existing IPs or file doesn't exist, create new scope file
    target_ip = target_directory
    
    # If it's not an IP address format, try to find an IP from files in the directory
    if not is_ip_address(target_ip):
        info_msg = f"[*] Target directory name '{target_ip}' doesn't appear to be an IP address."
        if logger:
            logger.info(info_msg)
            logger.info("[*] Searching for IP addresses in existing files...")
        else:
            print(info_msg)
            print("[*] Searching for IP addresses in existing files...")
        
        # Look for IPs in existing files
        target_path = os.path.join(base_path, target_directory)
        ip_addresses = find_ips_in_directory(target_path)
        
        if ip_addresses:
            target_ip = ip_addresses[0]
            found_msg = f"[+] Found IP address: {target_ip}"
            if logger:
                logger.info(found_msg)
            else:
                print(found_msg)
        else:
            no_ip_msg = "[!] No IP address found. Using the directory name as a placeholder."
            if logger:
                logger.warning(no_ip_msg)
            else:
                print(no_ip_msg)
    
    # Add the target IP if it's not already in the list
    if target_ip not in existing_ips:
        existing_ips.append(target_ip)
    
    # Write all IPs to the scope file - APPEND mode, not WRITE mode
    with open(target_file, 'w') as f:
        for ip in existing_ips:
            f.write(f"{ip}\n")
    
    success_msg = f"[+] Created/updated scope file with {len(existing_ips)} IP(s): {target_file}"
    if logger:
        logger.info(success_msg)
    else:
        print(success_msg)
    
    return True


def run_assessment(base_path, target_directory, xml2json_path, birchtool_path, logger=None, stop_event=None, process_setter=None):
    """Run the full vulnerability assessment process for a target"""
    header = f"{'='*80}\nStarting vulnerability assessment for target: {target_directory}\n{'='*80}"
    
    if logger:
        logger.info(header)
    else:
        print(header)
    
    # Check if stop was requested
    if stop_event and stop_event.is_set():
        return False
    
    # Create the necessary directories
    target_path = os.path.join(base_path, target_directory)
    infra_path = os.path.join(target_path, "V-Infra")
    ensure_directory_exists(infra_path)
    
    # File paths
    scope_file = os.path.join(infra_path, "scope.txt")
    xml_output = os.path.join(infra_path, "service_scan.xml")
    json_output = os.path.join(infra_path, "vuln_infrastructure.json")
    vuln_output_dir = os.path.join(infra_path, "Vuln_Output")
    
    # Step 1: Create scope file
    if not create_scope_file(scope_file, target_directory, base_path, logger):
        error_msg = "[!] Failed to create scope file. Aborting."
        if logger:
            logger.error(error_msg)
        else:
            print(error_msg)
        return False
    
    # Check if stop was requested
    if stop_event and stop_event.is_set():
        return False
    
    # Step 2: Run Nmap scan
    nmap_command = f"nmap -Pn -sV -T4 --min-rate 300 --min-hostgroup 40 --max-hostgroup 50 " \
                   f"--top-ports 10000 -vvv --version-intensity 4 --unprivileged -iL {scope_file} " \
                   f"-oX {xml_output}"
    
    scan_msg = "\n[*] Starting Nmap scan (this may take a while)..."
    if logger:
        logger.info(scan_msg)
    else:
        print(scan_msg)
        
    if not run_command(nmap_command, "Running Nmap service scan", logger, stop_event, process_setter):
        # If stopping was requested, don't show error
        if not (stop_event and stop_event.is_set()):
            error_msg = "[!] Nmap scan failed. Aborting."
            if logger:
                logger.error(error_msg)
            else:
                print(error_msg)
        return False
    
    # Check if stop was requested
    if stop_event and stop_event.is_set():
        return False
    
    # Step 3: Convert XML to JSON
    xml2json_command = f"python {xml2json_path} {xml_output} -o {json_output}"
    
    if not run_command(xml2json_command, "Converting Nmap XML output to JSON", logger, stop_event, process_setter):
        # If stopping was requested, don't show error
        if not (stop_event and stop_event.is_set()):
            error_msg = "[!] XML to JSON conversion failed. Aborting."
            if logger:
                logger.error(error_msg)
            else:
                print(error_msg)
        return False
    
    # Check if stop was requested
    if stop_event and stop_event.is_set():
        return False
    
    # Step 4: Run vulnerability analysis
    birch_command = f"python {birchtool_path} -t nmap {json_output} -o {vuln_output_dir} -l 50"
    
    if not run_command(birch_command, "Running vulnerability analysis", logger, stop_event, process_setter):
        # If stopping was requested, don't show error
        if not (stop_event and stop_event.is_set()):
            error_msg = "[!] Vulnerability analysis failed. Aborting."
            if logger:
                logger.error(error_msg)
            else:
                print(error_msg)
        return False
    
    # Check if stop was requested
    if stop_event and stop_event.is_set():
        return False
    
    success_msg = f"\n{'='*80}\nVulnerability assessment for {target_directory} completed successfully.\n" \
                 f"Results saved to: {vuln_output_dir}\n{'='*80}"
    
    if logger:
        logger.info(success_msg)
    else:
        print(success_msg)
    
    return True


def main():
    parser = argparse.ArgumentParser(description='Orchestrate vulnerability assessment workflow')
    parser.add_argument('--base-path', default='C:\\Users\\REDACTED\\Desktop\\HOSTENV1\\HostTargets',
                      help='Base path containing target directories')
    parser.add_argument('--xml2json', default='XML2JSON.py',
                      help='Path to the XML2JSON.py script')
    parser.add_argument('--birchtool', default='BirchMultiTool.py',
                      help='Path to the BirchMultiTool.py script')
    
    args = parser.parse_args()
    
    # Check paths
    for script in [args.xml2json, args.birchtool]:
        if not os.path.exists(script):
            print(f"[!] Warning: Script not found: {script}")
            if input("Continue anyway? (y/n): ").lower() != 'y':
                print("Exiting.")
                sys.exit(1)
    
    # Ensure the base directory exists
    if not os.path.exists(args.base_path):
        print(f"[!] Error: Base path not found: {args.base_path}")
        sys.exit(1)
    
    # Create and start the GUI
    root = tk.Tk()
    app = VulnAssessmentGUI(root, args.base_path, args.xml2json, args.birchtool)
    root.mainloop()


if __name__ == "__main__":
    main()
