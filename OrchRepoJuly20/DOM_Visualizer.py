#!/usr/bin/env python3
"""
DOM Visualizer - A modern GUI for viewing and beautifying DOM structure from text files
with dangerous sink detection and visual indicators
"""

import tkinter as tk
from tkinter import ttk, font, messagebox
import argparse
import sys
import re
from html.parser import HTMLParser
import json
from collections import defaultdict
import os

class DOMParser(HTMLParser):
    """Parse DOM-like text and build a tree structure"""
    
    def __init__(self):
        super().__init__()
        self.tree = {"tag": "root", "attrs": {}, "children": [], "text": "", "raw_html": ""}
        self.stack = [self.tree]
        self.current_data = []
        self.position_map = {}  # Maps elements to their position in source
        self.current_pos = 0
        
    def handle_starttag(self, tag, attrs):
        node = {
            "tag": tag,
            "attrs": dict(attrs),
            "children": [],
            "text": "",
            "start_pos": self.getpos(),
            "raw_html": self.get_starttag_text() or f"<{tag}>"
        }
        self.stack[-1]["children"].append(node)
        self.stack.append(node)
        
    def handle_endtag(self, tag):
        if len(self.stack) > 1 and self.stack[-1]["tag"] == tag:
            self.stack[-1]["end_pos"] = self.getpos()
            self.stack.pop()
            
    def handle_data(self, data):
        cleaned = data.strip()
        if cleaned and len(self.stack) > 0:
            self.stack[-1]["text"] += cleaned
            
    def get_tree(self):
        return self.tree

class SinkDetector:
    """Detect dangerous sinks in DOM content based on regex patterns"""
    
    def __init__(self, sinks_file=None):
        self.sinks_data = None
        self.sink_patterns = {}
        self.sink_categories = {
            'Initialization': {'color': '#ff6b6b', 'icon': '⚡'},
            'Manipulation': {'color': '#ff9f43', 'icon': '⚠️'},
            'Processing': {'color': '#ffd93d', 'icon': '⚙️'},
            'Execution': {'color': '#ff4757', 'icon': '🔥'},
            'SpecialCases': {'color': '#ee5a6f', 'icon': '🎯'}
        }
        
        if sinks_file and os.path.exists(sinks_file):
            self.load_sinks(sinks_file)
            
    def load_sinks(self, filepath):
        """Load sink patterns from JSON file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Try to parse as JSON first
            try:
                data = json.loads(content)
                self.sinks_data = data.get('GeneralOrder', {})
                print("Successfully loaded sinks.json")
            except json.JSONDecodeError as e:
                print(f"JSON decode error: {e}")
                # If JSON parsing fails due to escape issues, use the manual patterns
                print("Using built-in sink patterns due to JSON parsing error")
                self.parse_sinks_manually(content)
                    
            self.compile_patterns()
        except Exception as e:
            print(f"Error loading sinks file: {e}")
            
    def parse_sinks_manually(self, content):
        """Manually parse sinks data when JSON parsing fails"""
        self.sinks_data = {
            "Initialization": {
                "Construction": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\bnew\s+(WebSocket|Function|RegExp)\b\s*\("
                },
                "ObjectPropertyDefinition": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(innerHTML|outerHTML|document\.(?:cookie|write|writeln|domain|title|evaluate)|location(?:\.(?:href|host|hostname|pathname|search|protocol))?|script\.(?:src|text|textContent|innerText)|element\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search))\s*[:=]\s*[^;]*|Object\.defineProperty\s*\(\s*[^\)]+\s*,\s*['\"](innerHTML|outerHTML|document\.(?:cookie|write|writeln|domain|title|evaluate)|location(?:\.(?:href|host|hostname|pathname|search|protocol))?|script\.(?:src|text|textContent|innerText)|element\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search))['\"]"
                },
                "DataStorage": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(sessionStorage|localStorage)\.setItem\s*\("
                }
            },
            "Manipulation": {
                "Assignment": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(innerHTML|outerHTML|document\.(?:cookie|write|writeln|domain|title)|location(?:\.(?:href|host|hostname|pathname|search|protocol))?|script\.(?:src|text|textContent|innerText)|element\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search))\s*="
                },
                "DOMMutation": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(document\.(?:write|writeln)|element\.setAttribute|history\.(?:pushState|replaceState)|range\.createContextualFragment|document\.implementation\.createHTMLDocument)\s*\("
                },
                "DynamicPropertyAccess": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\[\s*['\"](innerHTML|outerHTML|document\.(?:cookie|write|writeln|domain|title)|location(?:\.(?:href|host|hostname|pathname|search|protocol))?|script\.(?:src|text|textContent|innerText)|element\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search))['\"]\s*\]"
                }
            },
            "Processing": {
                "Read": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(let|const|var)\s+\w+\s*=\s*(innerHTML|outerHTML|document\.(?:cookie|title)|location(?:\.(?:href|host|hostname|pathname|search|protocol))?|script\.(?:src|text|textContent|innerText)|element\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search)|sessionStorage\.getItem|localStorage\.getItem)\b"
                },
                "ConditionalUse": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\bif\s*\([^)]*(innerHTML|outerHTML|document\.(?:cookie|title)|location(?:\.(?:href|host|hostname|pathname|search|protocol))?|script\.(?:src|text|textContent|innerText)|element\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search)|sessionStorage\.getItem|localStorage\.getItem)\b[^)]*\)"
                },
                "FunctionArgument": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b\w+\s*\([^)]*(innerHTML|outerHTML|document\.(?:cookie|title)|location(?:\.(?:href|host|hostname|pathname|search|protocol))?|script\.(?:src|text|textContent|innerText)|element\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search)|sessionStorage\.getItem|localStorage\.getItem)\b[^)]*\)"
                },
                "TemplateLiteralInterpolation": {
                    "Regex": r"`[^`]*\b(innerHTML|document\.(?:write|writeln)|eval)\b[^`]*`"
                }
            },
            "Execution": {
                "MethodInvocation": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(eval|set(?:Timeout|Interval|Immediate)|msSetImmediate|exec(?:Command|Script)|document\.(?:write|writeln)|location\.(?:assign|replace)|open|postMessage|XMLHttpRequest\.(?:open|send|setRequestHeader)|jQuery\.(?:ajax|globalEval)|[$]\.(?:ajax|globalEval|parseJSON)|range\.createContextualFragment|crypto\.generateCRMFRequest|FileReader\.readAs(?:ArrayBuffer|BinaryString|DataURL|Text|File)|FileReader\.root\.getFile|document\.evaluate|element\.evaluate|executeSql|history\.(?:pushState|replaceState)|requestFileSystem)\s*\("
                },
                "PatternBasedExecution": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(RegExp|document\.evaluate)\s*\("
                },
                "EventHandlerBinding": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(on(?:click|error|load|submit)|addEventListener)\s*(?:=|\()"
                }
            },
            "SpecialCases": {
                "AsynchronousFlow": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(Promise|async\s+function)\b.*?(innerHTML|outerHTML|document\.(?:cookie|write|writeln|domain|title|evaluate)|location(?:\.(?:href|host|hostname|pathname|search|protocol|assign|replace))?|open|set(?:Timeout|Interval|Immediate)|msSetImmediate|eval|Function|exec(?:Command|Script)|range\.createContextualFragment|crypto\.generateCRMFRequest|WebSocket|(?:element|script)\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search)|postMessage|XMLHttpRequest\.(?:open|send|setRequestHeader)|jQuery\.(?:ajax|globalEval)|[$]\.(?:ajax|globalEval|parseJSON)|FileReader\.readAs(?:ArrayBuffer|BinaryString|DataURL|Text|File)|FileReader\.root\.getFile|sessionStorage\.setItem|localStorage\.setItem|history\.(?:pushState|replaceState)|RegExp|requestFileSystem|executeSql|element\.evaluate)\b"
                },
                "ErrorHandling": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\btry\b.*?(innerHTML|outerHTML|document\.(?:cookie|write|writeln|domain|title|evaluate)|location(?:\.(?:href|host|hostname|pathname|search|protocol|assign|replace))?|open|set(?:Timeout|Interval|Immediate)|msSetImmediate|eval|Function|exec(?:Command|Script)|range\.createContextualFragment|crypto\.generateCRMFRequest|WebSocket|(?:element|script)\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search)|postMessage|XMLHttpRequest\.(?:open|send|setRequestHeader)|jQuery\.(?:ajax|globalEval)|[$]\.(?:ajax|globalEval|parseJSON)|FileReader\.readAs(?:ArrayBuffer|BinaryString|DataURL|Text|File)|FileReader\.root\.getFile|sessionStorage\.setItem|localStorage\.setItem|history\.(?:pushState|replaceState)|RegExp|requestFileSystem|executeSql|element\.evaluate)\b.*?(catch\b)?"
                },
                "ProxyObjectUsage": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\bnew\s+Proxy\b.*?(innerHTML|outerHTML|document\.(?:cookie|write|writeln|domain|title|evaluate)|location(?:\.(?:href|host|hostname|pathname|search|protocol|assign|replace))?|open|set(?:Timeout|Interval|Immediate)|msSetImmediate|eval|Function|exec(?:Command|Script)|range\.createContextualFragment|crypto\.generateCRMFRequest|WebSocket|(?:element|script)\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search)|postMessage|XMLHttpRequest\.(?:open|send|setRequestHeader)|jQuery\.(?:ajax|globalEval)|[$]\.(?:ajax|globalEval|parseJSON)|FileReader\.readAs(?:ArrayBuffer|BinaryString|DataURL|Text|File)|FileReader\.root\.getFile|sessionStorage\.setItem|localStorage\.setItem|history\.(?:pushState|replaceState)|RegExp|requestFileSystem|executeSql|element\.evaluate)\b"
                },
                "ModuleImportsExports": {
                    "Regex": r"(?<!['\"`][^'`\"]*)\b(export|import)\b.*?(innerHTML|outerHTML|document\.(?:cookie|write|writeln|domain|title|evaluate)|location(?:\.(?:href|host|hostname|pathname|search|protocol|assign|replace))?|open|set(?:Timeout|Interval|Immediate)|msSetImmediate|eval|Function|exec(?:Command|Script)|range\.createContextualFragment|crypto\.generateCRMFRequest|WebSocket|(?:element|script)\.(?:href|src|action|text|textContent|innerText|outerText|value|name|target|method|type|backgroundImage|cssText|codebase|srcdoc|search)|postMessage|XMLHttpRequest\.(?:open|send|setRequestHeader)|jQuery\.(?:ajax|globalEval)|[$]\.(?:ajax|globalEval|parseJSON)|FileReader\.readAs(?:ArrayBuffer|BinaryString|DataURL|Text|File)|FileReader\.root\.getFile|sessionStorage\.setItem|localStorage\.setItem|history\.(?:pushState|replaceState)|RegExp|requestFileSystem|executeSql|element\.evaluate)\b"
                }
            }
        }
            
    def compile_patterns(self):
        """Compile regex patterns from sinks data"""
        for category, subcategories in self.sinks_data.items():
            self.sink_patterns[category] = {}
            for subcat, details in subcategories.items():
                if details.get('Regex'):
                    try:
                        # First try the regex as-is
                        self.sink_patterns[category][subcat] = re.compile(details['Regex'], re.IGNORECASE | re.MULTILINE)
                    except re.error as e:
                        # If it fails, try to fix common issues
                        try:
                            # Attempt to fix by properly escaping backslashes
                            fixed_regex = details['Regex'].replace('\\', '\\\\')
                            self.sink_patterns[category][subcat] = re.compile(fixed_regex, re.IGNORECASE | re.MULTILINE)
                            print(f"Fixed regex in {category}/{subcat}")
                        except re.error as e2:
                            print(f"Invalid regex in {category}/{subcat}: {e}")
                            print(f"Original pattern: {details['Regex'][:100]}...")
                            # Use a simplified version as fallback
                            if subcat == "Construction":
                                self.sink_patterns[category][subcat] = re.compile(r'\bnew\s+(WebSocket|Function|RegExp)\b', re.IGNORECASE)
                            elif subcat == "Assignment":
                                self.sink_patterns[category][subcat] = re.compile(r'\b(innerHTML|outerHTML|document\.(cookie|write|writeln))\s*=', re.IGNORECASE)
                        
    def detect_sinks(self, content):
        """Detect all sinks in the content"""
        detections = defaultdict(list)
        
        for category, subcategories in self.sink_patterns.items():
            for subcat, pattern in subcategories.items():
                matches = pattern.finditer(content)
                for match in matches:
                    detections[category].append({
                        'subcategory': subcat,
                        'match': match.group(),
                        'start': match.start(),
                        'end': match.end(),
                        'line': content[:match.start()].count('\n') + 1
                    })
                    
        return detections

class DOMVisualizer:
    def __init__(self, root, dom_content, sinks_file=None):
        self.root = root
        self.root.title("DOM Visualizer with Sink Detection")
        self.root.geometry("1400x900")
        
        # Modern color scheme with glass morphism effect
        self.colors = {
            'bg': '#0f0f0f',
            'fg': '#e0e0e0',
            'select': '#2a4d69',
            'tag': '#64b5f6',
            'attr_name': '#81c784',
            'attr_value': '#ffb74d',
            'text': '#fff176',
            'tree_bg': '#1a1a1a',
            'detail_bg': '#212121',
            'button': '#2c2c2c',
            'button_hover': '#3c3c3c',
            'sink_highlight': '#ff4757',
            'glass_bg': 'rgba(30, 30, 30, 0.8)'
        }
        
        # Initialize sink detector
        self.sink_detector = SinkDetector(sinks_file)
        self.detected_sinks = {}
        self.sink_items = defaultdict(list)  # Maps tree items to their sinks
        
        self.setup_styles()
        self.create_widgets()
        self.parse_and_display(dom_content)
        
        # Detect sinks if detector is loaded
        if self.sink_detector.sinks_data:
            self.detect_and_highlight_sinks(dom_content)
        
    def setup_styles(self):
        """Configure ttk styles for modern look with animations"""
        self.style = ttk.Style()
        
        # Configure dark theme
        self.root.configure(bg=self.colors['bg'])
        
        # Custom fonts
        self.title_font = font.Font(family='Segoe UI', size=14, weight='bold')
        self.normal_font = font.Font(family='Consolas', size=11)
        self.icon_font = font.Font(family='Segoe UI Emoji', size=12)
        
        # Treeview style with better aesthetics
        self.style.theme_use('clam')
        self.style.configure('Treeview',
            background=self.colors['tree_bg'],
            foreground=self.colors['fg'],
            fieldbackground=self.colors['tree_bg'],
            borderwidth=0,
            relief='flat',
            rowheight=25
        )
        self.style.configure('Treeview.Heading',
            background=self.colors['button'],
            foreground=self.colors['fg'],
            borderwidth=1,
            relief='flat'
        )
        self.style.map('Treeview',
            background=[('selected', self.colors['select'])],
            foreground=[('selected', 'white')]
        )
        
        # Frame styles
        self.style.configure('Dark.TFrame', background=self.colors['bg'])
        self.style.configure('Detail.TFrame', background=self.colors['detail_bg'], relief='flat', borderwidth=1)
        self.style.configure('Glass.TFrame', background=self.colors['bg'])
        
    def create_widgets(self):
        """Create the GUI layout with modern design"""
        # Main container with padding
        main_frame = ttk.Frame(self.root, style='Dark.TFrame')
        main_frame.pack(fill='both', expand=True, padx=15, pady=15)
        
        # Header with title and sink legend
        header_frame = ttk.Frame(main_frame, style='Dark.TFrame')
        header_frame.pack(fill='x', pady=(0, 15))
        
        # Title
        title_label = tk.Label(header_frame, text="DOM Structure Analyzer", 
                              bg=self.colors['bg'], fg=self.colors['fg'],
                              font=self.title_font)
        title_label.pack(side='left')
        
        # Sink legend (initially hidden)
        self.legend_frame = ttk.Frame(header_frame, style='Glass.TFrame')
        self.legend_frame.pack(side='right', padx=10)
        self.create_sink_legend()
        
        # Toolbar with glass morphism effect
        toolbar = tk.Frame(main_frame, bg=self.colors['button'], height=50)
        toolbar.pack(fill='x', pady=(0, 15))
        toolbar.pack_propagate(False)
        
        # Search section
        search_frame = ttk.Frame(toolbar, style='Dark.TFrame')
        search_frame.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        
        search_label = tk.Label(search_frame, text="🔍", bg=self.colors['button'], 
                               fg=self.colors['fg'], font=self.icon_font)
        search_label.pack(side='left', padx=(0, 5))
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var, 
                                    bg=self.colors['tree_bg'], fg=self.colors['fg'],
                                    insertbackground=self.colors['fg'], relief='flat',
                                    font=self.normal_font, bd=5)
        self.search_entry.pack(side='left', fill='x', expand=True)
        self.search_entry.bind('<Return>', self.search_dom)
        self.search_entry.bind('<KeyRelease>', self.live_search)
        
        # Buttons with hover effects
        button_frame = ttk.Frame(toolbar, style='Dark.TFrame')
        button_frame.pack(side='right', padx=10, pady=10)
        
        self.create_modern_button(button_frame, "Expand All", self.expand_all, "📂")
        self.create_modern_button(button_frame, "Collapse All", self.collapse_all, "📁")
        self.create_modern_button(button_frame, "Export JSON", self.export_json, "💾")
        self.create_modern_button(button_frame, "Sink Report", self.show_sink_report, "📊")
        
        # Paned window for tree and detail view
        paned = ttk.PanedWindow(main_frame, orient='horizontal')
        paned.pack(fill='both', expand=True)
        
        # Left panel - Tree view with better frame
        left_frame = tk.Frame(paned, bg=self.colors['tree_bg'], relief='flat', bd=1)
        paned.add(left_frame, weight=3)
        
        tree_header = tk.Frame(left_frame, bg=self.colors['tree_bg'], height=40)
        tree_header.pack(fill='x')
        tree_header.pack_propagate(False)
        
        tree_label = tk.Label(tree_header, text="DOM Structure", 
                             bg=self.colors['tree_bg'], fg=self.colors['fg'],
                             font=self.title_font)
        tree_label.pack(pady=10)
        
        # Tree container with both scrollbars
        tree_container = tk.Frame(left_frame, bg=self.colors['tree_bg'])
        tree_container.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Create tree with horizontal scrolling enabled
        self.tree = ttk.Treeview(tree_container, show='tree', selectmode='browse')
        
        # Scrollbars
        v_scroll = ttk.Scrollbar(tree_container, orient='vertical', command=self.tree.yview)
        h_scroll = ttk.Scrollbar(tree_container, orient='horizontal', command=self.tree.xview)
        
        # Grid layout for tree and scrollbars
        self.tree.grid(row=0, column=0, sticky='nsew')
        v_scroll.grid(row=0, column=1, sticky='ns')
        h_scroll.grid(row=1, column=0, sticky='ew')
        
        # Configure grid weights
        tree_container.grid_rowconfigure(0, weight=1)
        tree_container.grid_columnconfigure(0, weight=1)
        
        # Configure tree scrolling
        self.tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)
        
        # Configure tree tags for sink highlighting
        self.tree.tag_configure('sink', background='#3d1414', foreground='#ff6b6b')
        self.tree.tag_configure('search_match', background='#1a3d5c', foreground='#64b5f6')
        
        # Right panel - Detail view with modern design
        right_frame = tk.Frame(paned, bg=self.colors['detail_bg'], relief='flat', bd=1)
        paned.add(right_frame, weight=2)
        
        detail_header = tk.Frame(right_frame, bg=self.colors['detail_bg'], height=40)
        detail_header.pack(fill='x')
        detail_header.pack_propagate(False)
        
        detail_label = tk.Label(detail_header, text="Element Details", 
                               bg=self.colors['detail_bg'], fg=self.colors['fg'],
                               font=self.title_font)
        detail_label.pack(pady=10)
        
        # Detail text widget with syntax highlighting
        detail_container = tk.Frame(right_frame, bg=self.colors['detail_bg'])
        detail_container.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.detail_text = tk.Text(detail_container, wrap='word',
                                  bg=self.colors['tree_bg'], fg=self.colors['fg'],
                                  insertbackground=self.colors['fg'], relief='flat',
                                  padx=15, pady=15, font=self.normal_font)
        self.detail_text.pack(side='left', fill='both', expand=True)
        
        # Detail scrollbar
        detail_scroll = ttk.Scrollbar(detail_container, orient='vertical', command=self.detail_text.yview)
        detail_scroll.pack(side='right', fill='y')
        self.detail_text.configure(yscrollcommand=detail_scroll.set)
        
        # Configure text tags
        self.detail_text.tag_configure('tag', foreground=self.colors['tag'], font=(self.normal_font.actual()['family'], 12, 'bold'))
        self.detail_text.tag_configure('attr_name', foreground=self.colors['attr_name'])
        self.detail_text.tag_configure('attr_value', foreground=self.colors['attr_value'])
        self.detail_text.tag_configure('text', foreground=self.colors['text'])
        self.detail_text.tag_configure('sink_warning', background='#3d1414', foreground='#ff6b6b', font=(self.normal_font.actual()['family'], 11, 'bold'))
        
        # Bind events
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        self.tree.bind('<Double-Button-1>', self.toggle_item)
        
    def create_modern_button(self, parent, text, command, icon=""):
        """Create a modern button with icon and hover effects"""
        btn_frame = tk.Frame(parent, bg=self.colors['button'], relief='flat', bd=0)
        btn_frame.pack(side='left', padx=3)
        
        btn = tk.Label(btn_frame, text=f"{icon} {text}", 
                      bg=self.colors['button'], fg=self.colors['fg'],
                      padx=15, pady=8, cursor='hand2',
                      font=('Segoe UI', 10))
        btn.pack()
        
        # Bind events
        btn.bind('<Button-1>', lambda e: command())
        btn.bind('<Enter>', lambda e: btn.configure(bg=self.colors['button_hover']))
        btn.bind('<Leave>', lambda e: btn.configure(bg=self.colors['button']))
        btn_frame.bind('<Enter>', lambda e: btn.configure(bg=self.colors['button_hover']))
        btn_frame.bind('<Leave>', lambda e: btn.configure(bg=self.colors['button']))
        
        return btn
        
    def create_sink_legend(self):
        """Create sink category legend"""
        if not self.sink_detector.sinks_data:
            return
            
        legend_label = tk.Label(self.legend_frame, text="Detected Sinks: ", 
                               bg=self.colors['bg'], fg=self.colors['fg'],
                               font=('Segoe UI', 10, 'bold'))
        legend_label.pack(side='left', padx=(0, 10))
        
        self.sink_counters = {}
        for category, info in self.sink_detector.sink_categories.items():
            cat_frame = tk.Frame(self.legend_frame, bg=self.colors['bg'])
            cat_frame.pack(side='left', padx=5)
            
            icon_label = tk.Label(cat_frame, text=info['icon'], 
                                 bg=self.colors['bg'], fg=info['color'],
                                 font=self.icon_font)
            icon_label.pack(side='left')
            
            count_label = tk.Label(cat_frame, text="0", 
                                  bg=self.colors['bg'], fg=info['color'],
                                  font=('Segoe UI', 10, 'bold'))
            count_label.pack(side='left', padx=(2, 0))
            
            self.sink_counters[category] = count_label
            
    def parse_and_display(self, content):
        """Parse DOM content and display in tree"""
        self.dom_data = {}
        self.raw_content = content
        
        try:
            parser = DOMParser()
            parser.feed(content)
            dom_tree = parser.get_tree()
            
            # Build tree view
            self.build_tree(dom_tree, '')
            
        except Exception as e:
            messagebox.showwarning("Parse Warning", 
                                 f"Could not parse as HTML. Displaying raw content.\nError: {str(e)}")
            self.display_raw(content)
            
    def build_tree(self, node, parent_id, level=0):
        """Recursively build tree from DOM structure"""
        if node['tag'] == 'root':
            for child in node['children']:
                self.build_tree(child, '', 0)
        else:
            # Create display text with proper indentation indicator
            indent = "  " * level
            display_text = f"{node['tag']}"
            
            if node['attrs']:
                attrs_str = ' '.join([f'{k}="{v}"' for k, v in node['attrs'].items()])
                display_text += f" {attrs_str}"
                
            # Add sink indicator if detected
            item_tags = ()
            if hasattr(self, 'sink_items') and any(node.get('raw_html', '') in str(sink) for sink in self.sink_items.values()):
                display_text = f"⚠️ {display_text}"
                item_tags = ('sink',)
            
            item_id = self.tree.insert(parent_id, 'end', text=display_text, tags=item_tags)
            
            # Store node data
            self.dom_data[item_id] = node
            
            # Add text content if exists
            if node['text']:
                text_display = node['text'][:50] + "..." if len(node['text']) > 50 else node['text']
                text_id = self.tree.insert(item_id, 'end', text=f'📝 "{text_display}"')
                self.dom_data[text_id] = {'type': 'text', 'content': node['text']}
            
            # Process children
            for child in node['children']:
                self.build_tree(child, item_id, level + 1)
                
    def detect_and_highlight_sinks(self, content):
        """Detect sinks and highlight them in the tree"""
        if not self.sink_detector.sinks_data:
            return
            
        self.detected_sinks = self.sink_detector.detect_sinks(content)
        
        # Update sink counters
        total_sinks = 0
        for category, sinks in self.detected_sinks.items():
            count = len(sinks)
            total_sinks += count
            if category in self.sink_counters:
                self.sink_counters[category].config(text=str(count))
                
        # Update tree items with sink indicators
        self.highlight_sink_items()
        
        # Show legend if sinks detected
        if total_sinks > 0:
            self.legend_frame.pack(side='right', padx=10)
            
    def highlight_sink_items(self):
        """Highlight tree items that contain sinks"""
        for item_id, node_data in self.dom_data.items():
            if isinstance(node_data, dict) and 'raw_html' in node_data:
                for category, sinks in self.detected_sinks.items():
                    for sink in sinks:
                        if sink['match'] in node_data.get('raw_html', ''):
                            current_text = self.tree.item(item_id, 'text')
                            if not current_text.startswith('⚠️'):
                                self.tree.item(item_id, text=f"⚠️ {current_text}", tags=('sink',))
                            self.sink_items[item_id].append(sink)
                            
    def on_select(self, event):
        """Handle tree selection with sink information"""
        selection = self.tree.selection()
        if not selection:
            return
            
        item_id = selection[0]
        if item_id not in self.dom_data:
            return
            
        node_data = self.dom_data[item_id]
        
        # Clear detail view
        self.detail_text.delete(1.0, 'end')
        
        if isinstance(node_data, dict):
            if node_data.get('type') == 'text':
                self.detail_text.insert('end', 'Text Content:\n\n', 'tag')
                self.detail_text.insert('end', node_data['content'], 'text')
            else:
                # Element details
                self.detail_text.insert('end', 'Element: ', 'attr_name')
                self.detail_text.insert('end', f"<{node_data['tag']}>\n\n", 'tag')
                
                if node_data.get('attrs'):
                    self.detail_text.insert('end', 'Attributes:\n', 'attr_name')
                    for key, value in node_data['attrs'].items():
                        self.detail_text.insert('end', f"  {key}", 'attr_name')
                        self.detail_text.insert('end', ' = ')
                        self.detail_text.insert('end', f'"{value}"\n', 'attr_value')
                    self.detail_text.insert('end', '\n')
                    
                if node_data.get('text'):
                    self.detail_text.insert('end', 'Text Content:\n', 'attr_name')
                    self.detail_text.insert('end', node_data['text'] + '\n', 'text')
                    
                if node_data.get('children'):
                    self.detail_text.insert('end', f"\nChildren: {len(node_data['children'])}\n", 'attr_name')
                    
                # Show sink warnings if any
                if item_id in self.sink_items:
                    self.detail_text.insert('end', '\n⚠️ SECURITY WARNINGS:\n', 'sink_warning')
                    for sink in self.sink_items[item_id]:
                        category = next((cat for cat, sinks in self.detected_sinks.items() 
                                       if sink in sinks), 'Unknown')
                        self.detail_text.insert('end', f"\n• {category} - {sink['subcategory']}\n", 'sink_warning')
                        self.detail_text.insert('end', f"  Match: {sink['match']}\n", 'text')
                        
    def toggle_item(self, event):
        """Toggle expand/collapse on double-click"""
        item = self.tree.identify('item', event.x, event.y)
        if item:
            if self.tree.item(item, 'open'):
                self.tree.item(item, open=False)
            else:
                self.tree.item(item, open=True)
                
    def live_search(self, event=None):
        """Live search with highlighting"""
        query = self.search_var.get().lower()
        
        # Clear previous search highlights
        for item in self.tree.get_children():
            self.clear_search_highlight(item)
            
        if not query:
            return
            
        # Search and highlight matches
        matches = []
        for item in self.tree.get_children():
            if self.search_and_highlight(item, query):
                matches.append(item)
                
        # Ensure first match is visible
        if matches:
            self.tree.see(matches[0])
            self.tree.selection_set(matches[0])
            
    def search_and_highlight(self, item, query):
        """Search and highlight matching items"""
        text = self.tree.item(item, 'text').lower()
        match_found = False
        
        if query in text:
            tags = list(self.tree.item(item, 'tags'))
            if 'search_match' not in tags:
                tags.append('search_match')
            self.tree.item(item, tags=tags)
            match_found = True
            
        # Search in children
        for child in self.tree.get_children(item):
            if self.search_and_highlight(child, query):
                match_found = True
                # Expand parent to show match
                self.tree.item(item, open=True)
                
        return match_found
        
    def clear_search_highlight(self, item):
        """Clear search highlighting from item and children"""
        tags = list(self.tree.item(item, 'tags'))
        if 'search_match' in tags:
            tags.remove('search_match')
            self.tree.item(item, tags=tags)
            
        for child in self.tree.get_children(item):
            self.clear_search_highlight(child)
            
    def search_dom(self, event=None):
        """Search with results summary"""
        self.live_search()
        query = self.search_var.get().lower()
        if query:
            matches = sum(1 for item in self.tree.get_children() 
                         if self.count_matches(item, query))
            messagebox.showinfo("Search Results", f"Found {matches} elements matching '{query}'")
            
    def count_matches(self, item, query):
        """Count matching items recursively"""
        count = 1 if query in self.tree.item(item, 'text').lower() else 0
        for child in self.tree.get_children(item):
            count += self.count_matches(child, query)
        return count
        
    def expand_all(self):
        """Expand all tree nodes with animation effect"""
        for item in self.tree.get_children():
            self.expand_recursive(item)
            
    def expand_recursive(self, item):
        """Recursively expand tree item"""
        self.tree.item(item, open=True)
        for child in self.tree.get_children(item):
            self.expand_recursive(child)
            
    def collapse_all(self):
        """Collapse all tree nodes"""
        for item in self.tree.get_children():
            self.collapse_recursive(item)
            
    def collapse_recursive(self, item):
        """Recursively collapse tree item"""
        self.tree.item(item, open=False)
        for child in self.tree.get_children(item):
            self.collapse_recursive(child)
            
    def show_sink_report(self):
        """Show detailed sink report in a new window"""
        if not self.detected_sinks:
            messagebox.showinfo("Sink Report", "No dangerous sinks detected!")
            return
            
        # Create report window
        report_window = tk.Toplevel(self.root)
        report_window.title("Security Sink Report")
        report_window.geometry("800x600")
        report_window.configure(bg=self.colors['bg'])
        
        # Header
        header = tk.Label(report_window, text="Security Sink Analysis Report",
                         bg=self.colors['bg'], fg=self.colors['fg'],
                         font=self.title_font)
        header.pack(pady=20)
        
        # Report text
        report_text = tk.Text(report_window, wrap='word',
                             bg=self.colors['tree_bg'], fg=self.colors['fg'],
                             padx=20, pady=20, font=self.normal_font)
        report_text.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Generate report
        report_text.insert('end', "SECURITY SINK ANALYSIS\n", 'title')
        report_text.insert('end', "=" * 50 + "\n\n")
        
        total_sinks = sum(len(sinks) for sinks in self.detected_sinks.values())
        report_text.insert('end', f"Total Sinks Detected: {total_sinks}\n\n")
        
        for category, sinks in self.detected_sinks.items():
            if sinks:
                info = self.sink_detector.sink_categories.get(category, {})
                report_text.insert('end', f"{info.get('icon', '')} {category} ({len(sinks)} found)\n", 'category')
                report_text.insert('end', "-" * 40 + "\n")
                
                for i, sink in enumerate(sinks, 1):
                    report_text.insert('end', f"\n{i}. {sink['subcategory']}\n", 'subcat')
                    report_text.insert('end', f"   Line: {sink['line']}\n")
                    report_text.insert('end', f"   Match: {sink['match']}\n", 'match')
                    
                report_text.insert('end', "\n\n")
                
        # Configure tags
        report_text.tag_configure('title', font=(self.normal_font.actual()['family'], 16, 'bold'))
        report_text.tag_configure('category', font=(self.normal_font.actual()['family'], 14, 'bold'),
                                 foreground=self.colors['sink_highlight'])
        report_text.tag_configure('subcat', font=(self.normal_font.actual()['family'], 12, 'bold'))
        report_text.tag_configure('match', foreground=self.colors['attr_value'])
        
        report_text.config(state='disabled')
        
    def export_json(self):
        """Export DOM structure with sink information as JSON"""
        try:
            from tkinter import filedialog
            
            # Prepare export data
            export_data = {
                "dom_structure": self._prepare_export_data(),
                "total_elements": len(self.dom_data),
                "security_analysis": {
                    "total_sinks": sum(len(sinks) for sinks in self.detected_sinks.values()),
                    "sinks_by_category": {cat: len(sinks) for cat, sinks in self.detected_sinks.items()},
                    "detailed_sinks": self.detected_sinks
                }
            }
            
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            
            if filename:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(export_data, f, indent=2)
                messagebox.showinfo("Export Successful", f"Analysis exported to {filename}")
                
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")
            
    def _prepare_export_data(self):
        """Prepare DOM data for export"""
        root_items = []
        for item in self.tree.get_children():
            if item in self.dom_data:
                node_data = self.dom_data[item].copy()
                # Add sink information if present
                if item in self.sink_items:
                    node_data['security_warnings'] = self.sink_items[item]
                root_items.append(node_data)
        return root_items
        
    def display_raw(self, content):
        """Display raw content when parsing fails"""
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if line.strip():
                item_id = self.tree.insert('', 'end', text=f"Line {i+1}: {line.strip()}")
                self.dom_data[item_id] = {'type': 'raw', 'content': line}

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Visualize DOM structure from a text file with security analysis')
    parser.add_argument('--DOM_File', required=True, help='Path to the DOM text file')
    parser.add_argument('--sinks', help='Path to the sinks.json file for security analysis')
    
    args = parser.parse_args()
    
    try:
        # Read the DOM file
        with open(args.DOM_File, 'r', encoding='utf-8') as f:
            dom_content = f.read()
            
        # Create and run the GUI
        root = tk.Tk()
        app = DOMVisualizer(root, dom_content, args.sinks)
        
        # Set window icon (if you have one)
        # root.iconbitmap('path/to/icon.ico')
        
        root.mainloop()
        
    except FileNotFoundError:
        print(f"Error: File '{args.DOM_File}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
