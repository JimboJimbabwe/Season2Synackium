import json
import os
import sys
import re
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import html
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class DOMScanner:
    def __init__(self, results_json_path, dom_capture_path, patterns_file="sink_patterns.json", output_dir="DOM_Analysis"):
        """
        Initialize the DOM Scanner with sink detection
        
        Args:
            results_json_path: Path to results.json from Burp analysis
            dom_capture_path: Path to dom-capture JSON from browser extension
            patterns_file: Path to sink patterns JSON file
            output_dir: Output directory for DOM analysis
        """
        self.results_json_path = results_json_path
        self.dom_capture_path = dom_capture_path
        self.patterns_file = patterns_file
        self.output_dir = output_dir
        
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"[*] Created directory: {self.output_dir}")
        
        # Load the data files
        self.results_data = self.load_results_json()
        self.dom_data = self.load_dom_capture()
        
        # Load sink patterns
        self.patterns = self.load_sink_patterns()
        
        # Create a URL to DOM mapping for faster lookup
        self.url_to_dom_map = self.create_url_dom_mapping()
        
        # Store sink findings
        self.sink_findings = defaultdict(list)
        
        # Define the execution order priority
        self.phase_order = {
            'Initialization': 1,
            'Manipulation': 2,
            'Processing': 3,
            'Execution': 4,
            'SpecialCases': 5
        }
    
    def normalize_url_for_matching(self, url):
        """Normalize URL for matching by removing fragments and sorting parameters"""
        try:
            parsed = urlparse(url)
            
            # Remove fragment
            parsed = parsed._replace(fragment='')
            
            # Sort query parameters for consistent comparison
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                # Sort parameters and rebuild query string
                sorted_params = sorted(params.items())
                new_query = urlencode(sorted_params, doseq=True)
                parsed = parsed._replace(query=new_query)
            
            # Ensure consistent trailing slash for paths
            path = parsed.path
            if path == '':
                path = '/'
            parsed = parsed._replace(path=path)
            
            normalized = urlunparse(parsed)
            return normalized
        except Exception as e:
            print(f"[!] Error normalizing URL {url}: {e}")
            return url
    
    def load_sink_patterns(self):
        """Load sink patterns from JSON file"""
        try:
            with open(self.patterns_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"[*] Loaded sink patterns from: {self.patterns_file}")
                return data.get('GeneralOrder', data)
        except FileNotFoundError:
            print(f"[!] Warning: Sink patterns file not found at {self.patterns_file}")
            print("[!] Continuing without sink analysis...")
            return {}
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing sink patterns: {e}")
            return {}
        except Exception as e:
            print(f"[!] Error loading sink patterns: {e}")
            return {}
    
    def load_results_json(self):
        """Load and parse results.json"""
        try:
            with open(self.results_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"[*] Loaded results.json: {self.results_json_path}")
                return data
        except FileNotFoundError:
            print(f"[!] Error: results.json not found at {self.results_json_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing results.json: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error loading results.json: {e}")
            sys.exit(1)
    
    def load_dom_capture(self):
        """Load and parse DOM capture file"""
        try:
            # Try UTF-8 first
            with open(self.dom_capture_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"[*] Loaded DOM capture: {self.dom_capture_path}")
                
                # Debug: Show structure
                print(f"[*] DOM capture structure: {list(data.keys())}")
                
                return data
        except UnicodeDecodeError:
            # If UTF-8 fails, try with error handling
            print("[!] Unicode decode error, trying with error handling...")
            try:
                with open(self.dom_capture_path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                    print(f"[*] Loaded DOM capture with ignored errors: {self.dom_capture_path}")
                    return data
            except Exception as e:
                print(f"[!] Error loading DOM capture with error handling: {e}")
                sys.exit(1)
        except FileNotFoundError:
            print(f"[!] Error: DOM capture file not found at {self.dom_capture_path}")
            sys.exit(1)
        except json.JSONDecodeError as e:
            print(f"[!] Error parsing DOM capture: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Error loading DOM capture: {e}")
            sys.exit(1)
    
    def create_url_dom_mapping(self):
        """Create a mapping of URLs to DOM data for faster lookup"""
        url_map = {}
        normalized_url_map = {}  # Additional map with normalized URLs
        
        # Get domStates from the capture
        dom_states = self.dom_data.get('domStates', {})
        
        if not dom_states:
            print("[!] Warning: No domStates found in DOM capture file")
            print(f"    Available keys in capture: {list(self.dom_data.keys())}")
            return url_map
        
        print(f"[*] Found {len(dom_states)} DOM states in capture file")
        
        # Iterate through all DOM states
        for key, state_data in dom_states.items():
            if isinstance(state_data, dict) and 'url' in state_data:
                url = state_data['url']
                normalized_url = self.normalize_url_for_matching(url)
                
                # Store with original URL
                if url not in url_map:
                    url_map[url] = []
                url_map[url].append(state_data)
                
                # Also store with normalized URL
                if normalized_url not in normalized_url_map:
                    normalized_url_map[normalized_url] = []
                normalized_url_map[normalized_url].append(state_data)
                
                # Debug output
                dom_preview = state_data.get('dom', '')[:50] + '...' if state_data.get('dom') else 'No DOM'
                print(f"  [+] Found DOM for URL: {url}")
                if url != normalized_url:
                    print(f"      Normalized to: {normalized_url}")
                print(f"      Request Index: {state_data.get('requestIndex', 'N/A')}")
                print(f"      DOM Preview: {dom_preview}")
        
        # Combine both maps for flexible matching
        self.normalized_url_map = normalized_url_map
        
        print(f"[*] Created URL mapping for {len(url_map)} unique URLs")
        print(f"[*] Created normalized URL mapping for {len(normalized_url_map)} unique normalized URLs")
        
        return url_map
    
    def find_dom_for_url(self, url):
        """Try to find DOM data for a URL using various matching strategies"""
        # Try exact match first
        if url in self.url_to_dom_map:
            print(f"  [+] Found exact URL match")
            return self.url_to_dom_map[url]
        
        # Try normalized URL
        normalized_url = self.normalize_url_for_matching(url)
        if normalized_url in self.normalized_url_map:
            print(f"  [+] Found normalized URL match")
            return self.normalized_url_map[normalized_url]
        
        # Try without query parameters
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Check if any captured URL starts with this base
        partial_matches = []
        for captured_url in self.url_to_dom_map.keys():
            if captured_url.startswith(base_url):
                partial_matches.append((captured_url, self.url_to_dom_map[captured_url]))
        
        if partial_matches:
            print(f"  [+] Found {len(partial_matches)} partial matches for base URL: {base_url}")
            for match_url, _ in partial_matches[:3]:
                print(f"      - {match_url}")
            # Return the first partial match
            return partial_matches[0][1]
        
        return None
    
    def extract_javascript_from_dom(self, dom_content):
        """Extract JavaScript code from DOM content"""
        js_blocks = []
        
        # Extract inline scripts
        script_pattern = r'<script[^>]*?>(.*?)</script>'
        scripts = re.findall(script_pattern, dom_content, re.DOTALL | re.IGNORECASE)
        js_blocks.extend([s for s in scripts if s.strip()])
        
        # Extract event handlers
        event_pattern = r'on\w+\s*=\s*["\']([^"\']+)["\']'
        events = re.findall(event_pattern, dom_content, re.IGNORECASE)
        js_blocks.extend(events)
        
        # Extract javascript: URLs
        js_url_pattern = r'(?:href|src)\s*=\s*["\']javascript:([^"\']+)["\']'
        js_urls = re.findall(js_url_pattern, dom_content, re.IGNORECASE)
        js_blocks.extend(js_urls)
        
        return js_blocks
    
    def analyze_for_sinks(self, index, url, dom_content):
        """Analyze DOM content for dangerous sinks"""
        if not self.patterns:
            return []
        
        findings = []
        
        # Extract JavaScript from DOM
        js_blocks = self.extract_javascript_from_dom(dom_content)
        
        if not js_blocks:
            print(f"  [-] No JavaScript found in DOM")
            return findings
        
        print(f"  [+] Found {len(js_blocks)} JavaScript blocks to analyze")
        
        # Analyze each JavaScript block
        for js_content in js_blocks:
            if not js_content.strip():
                continue
            
            # Run regex patterns from each phase
            for phase_name, phase_data in self.patterns.items():
                # Skip if phase_data is not a dictionary (handle the structure issue)
                if not isinstance(phase_data, dict):
                    print(f"  [!] Warning: Phase '{phase_name}' is not a dictionary, skipping")
                    continue
                
                if phase_name == 'DOMClobbering':
                    continue
                
                priority = self.phase_order.get(phase_name, 99)
                
                for context_name, context_data in phase_data.items():
                    # Skip if context_data is not a dictionary
                    if not isinstance(context_data, dict):
                        print(f"  [!] Warning: Context '{context_name}' in phase '{phase_name}' is not a dictionary, skipping")
                        continue
                    
                    if 'Regex' not in context_data or not context_data['Regex']:
                        continue
                    
                    # Find matches using the regex
                    matches = self.find_pattern_matches(
                        js_content,
                        context_data['Regex'],
                        phase_name,
                        context_name,
                        priority
                    )
                    
                    for match in matches:
                        finding = {
                            'index': index,
                            'url': url,
                            'phase': phase_name,
                            'context': context_name,
                            'priority': priority,
                            'match_data': match
                        }
                        findings.append(finding)
                        self.sink_findings[index].append(finding)
        
        return findings
    
    def find_pattern_matches(self, content, pattern, phase, context, priority):
        """Find all matches for a specific pattern"""
        matches = []
        
        if not pattern:
            return matches
        
        try:
            regex = re.compile(pattern, re.MULTILINE | re.DOTALL | re.IGNORECASE)
            
            for match in regex.finditer(content):
                # Calculate line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get context lines
                lines = content.split('\n')
                start_line = max(0, line_num - 3)
                end_line = min(len(lines), line_num + 3)
                
                context_lines = []
                for i in range(start_line, end_line):
                    if i == line_num - 1:
                        context_lines.append(f">>> {lines[i]} <<<")
                    else:
                        context_lines.append(f"    {lines[i]}")
                
                # Identify sink type
                sink_type = self.identify_sink_type(match.group(0))
                
                matches.append({
                    'matched_text': match.group(0),
                    'sink_type': sink_type,
                    'line_number': line_num,
                    'context': '\n'.join(context_lines),
                    'phase': phase,
                    'context_type': context
                })
                
        except re.error as e:
            print(f"[!] Regex error in {phase}.{context}: {e}")
            
        return matches
    
    def identify_sink_type(self, matched_text):
        """Identify the specific sink type from matched text"""
        sink_patterns = {
            'innerHTML': r'innerHTML',
            'outerHTML': r'outerHTML',
            'document.write': r'document\.write',
            'eval': r'\beval\s*\(',
            'Function': r'\bFunction\s*\(',
            'setTimeout': r'setTimeout',
            'location.href': r'location\.href',
            'document.cookie': r'document\.cookie',
            'localStorage': r'localStorage',
            'sessionStorage': r'sessionStorage',
            'XMLHttpRequest': r'XMLHttpRequest',
            'WebSocket': r'WebSocket',
            'postMessage': r'postMessage'
        }
        
        for sink_name, pattern in sink_patterns.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return sink_name
                
        return 'Unknown'
    
    def extract_target_requests(self):
        """Extract all requests with parameters from results.json"""
        target_requests = []
        
        # Extract requests with URL parameters
        if 'requests_with_url_params' in self.results_data:
            print(f"[*] Found {len(self.results_data['requests_with_url_params'])} requests with URL params")
            for request in self.results_data['requests_with_url_params']:
                target_requests.append({
                    'index': request['index'],
                    'url': request['url'],
                    'type': 'url_params',
                    'method': request.get('method', 'UNKNOWN'),
                    'params': request.get('params', [])
                })
        
        # Extract requests with body parameters
        if 'requests_with_body_params' in self.results_data:
            print(f"[*] Found {len(self.results_data['requests_with_body_params'])} requests with body params")
            for request in self.results_data['requests_with_body_params']:
                target_requests.append({
                    'index': request['index'],
                    'url': request['url'],
                    'type': 'body_params',
                    'method': request.get('method', 'UNKNOWN'),
                    'params': request.get('params', [])
                })
        
        print(f"[*] Total target requests to process: {len(target_requests)}")
        return target_requests
    
    def save_dom_and_analysis(self, index, url, dom_content, request_info, sink_findings, dom_capture_data):
        """Save DOM content and sink analysis to structured files"""
        # Create subfolder for this index
        index_folder = os.path.join(self.output_dir, str(index))
        if not os.path.exists(index_folder):
            os.makedirs(index_folder)
            print(f"  [+] Created folder: {index_folder}")
        
        # Save DOM content
        dom_file_path = os.path.join(index_folder, f"{index}_DOM.txt")
        try:
            with open(dom_file_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(dom_content)
            print(f"  [+] Saved DOM content to: {dom_file_path}")
        except Exception as e:
            print(f"  [!] Error saving DOM content: {e}")
            return None
        
        # Save metadata about the request
        metadata_file_path = os.path.join(index_folder, f"{index}_metadata.json")
        metadata = {
            'index': index,
            'url': url,
            'method': request_info['method'],
            'param_type': request_info['type'],
            'params': request_info['params'],
            'processed_timestamp': datetime.now().isoformat(),
            'sink_findings_count': len(sink_findings),
            'dom_capture_request_index': dom_capture_data.get('requestIndex', 'N/A'),
            'dom_capture_timestamp': dom_capture_data.get('timestamp', 'N/A')
        }
        
        with open(metadata_file_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
        
        # Save browser state if available
        if 'cookies' in dom_capture_data or 'localStorage' in dom_capture_data:
            browser_state_path = os.path.join(index_folder, f"{index}_browser_state.json")
            browser_state = {}
            
            if 'cookies' in dom_capture_data:
                browser_state['cookies'] = dom_capture_data['cookies']
            if 'localStorage' in dom_capture_data:
                browser_state['localStorage'] = dom_capture_data['localStorage']
            if 'sessionStorage' in dom_capture_data:
                browser_state['sessionStorage'] = dom_capture_data['sessionStorage']
            
            with open(browser_state_path, 'w', encoding='utf-8') as f:
                json.dump(browser_state, f, indent=2, ensure_ascii=False)
            print(f"  [+] Saved browser state data")
        
        # Save sink findings if any
        if sink_findings:
            sink_file_path = os.path.join(index_folder, f"{index}_sinks.json")
            with open(sink_file_path, 'w', encoding='utf-8') as f:
                json.dump(sink_findings, f, indent=2, ensure_ascii=False)
            
            # Also create a readable sink report
            sink_report_path = os.path.join(index_folder, f"{index}_sink_report.txt")
            with open(sink_report_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(f"SINK ANALYSIS REPORT\n")
                f.write(f"URL: {url}\n")
                f.write(f"Index: {index}\n")
                f.write(f"Total Sinks Found: {len(sink_findings)}\n")
                f.write("="*80 + "\n\n")
                
                for i, finding in enumerate(sink_findings, 1):
                    f.write(f"SINK #{i}\n")
                    f.write(f"Type: {finding['match_data']['sink_type']}\n")
                    f.write(f"Phase: {finding['phase']}\n")
                    f.write(f"Context: {finding['context']}\n")
                    f.write(f"Line: {finding['match_data']['line_number']}\n")
                    f.write(f"Match: {finding['match_data']['matched_text']}\n")
                    f.write(f"\nCode Context:\n{finding['match_data']['context']}\n")
                    f.write("-"*80 + "\n\n")
        
        return dom_file_path
    
    def process_requests(self):
        """Main processing function"""
        target_requests = self.extract_target_requests()
        
        if not target_requests:
            print("[!] No target requests found in results.json")
            return
        
        processed_count = 0
        missing_count = 0
        total_sinks = 0
        
        print("\n[*] Processing requests...")
        print("-" * 60)
        
        for request in target_requests:
            index = request['index']
            url = request['url']
            
            print(f"\n[*] Processing Index {index}: {url}")
            print(f"    Normalized URL: {self.normalize_url_for_matching(url)}")
            
            # Look for matching DOM capture (checks ALL URLs, not just first 5)
            dom_captures = self.find_dom_for_url(url)
            
            if dom_captures:
                if len(dom_captures) > 1:
                    print(f"  [!] Found {len(dom_captures)} DOM captures for this URL, using first")
                
                dom_capture = dom_captures[0]
                
                # Extract DOM content from the 'dom' field
                dom_content = dom_capture.get('dom', None)
                
                if dom_content:
                    print(f"  [+] Found DOM content (length: {len(dom_content)} chars)")
                    
                    # Analyze for sinks
                    sink_findings = self.analyze_for_sinks(index, url, dom_content)
                    
                    if sink_findings:
                        print(f"  [!] Found {len(sink_findings)} potential sinks!")
                        total_sinks += len(sink_findings)
                    
                    # Save DOM and analysis
                    saved_path = self.save_dom_and_analysis(
                        index, url, dom_content, request, sink_findings, dom_capture
                    )
                    
                    if saved_path:
                        processed_count += 1
                else:
                    print(f"  [!] Warning: DOM capture found but no 'dom' field in the data")
                    print(f"      Available fields: {list(dom_capture.keys())}")
                    missing_count += 1
            else:
                print(f"  [-] No DOM capture found for this URL")
                # Only SHOW first 5 for debugging, but the search checked ALL URLs
                print(f"      Showing first 5 available URLs in capture (out of {len(self.url_to_dom_map)} total):")
                for i, (captured_url, _) in enumerate(list(self.url_to_dom_map.items())[:5]):
                    print(f"      {i+1}. {captured_url}")
                missing_count += 1
        
        # Summary
        print("\n" + "=" * 60)
        print("PROCESSING SUMMARY")
        print("=" * 60)
        print(f"Total requests to process: {len(target_requests)}")
        print(f"Successfully processed: {processed_count}")
        print(f"Missing DOM captures: {missing_count}")
        print(f"Total sinks found: {total_sinks}")
        
        if missing_count > 0:
            print(f"\n[!] Warning: {missing_count} requests had no matching DOM captures")
            print("    This could mean:")
            print("    - The pages were not visited during the browser recording")
            print("    - The URLs don't match exactly (check for parameter differences)")
            print("    - The DOM capture failed for those pages")
    
    def generate_sink_summary_report(self):
        """Generate a comprehensive sink summary report"""
        report_path = os.path.join(self.output_dir, "sink_summary_report.html")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sink Analysis Summary - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; margin: -20px -20px 20px -20px; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 30px; }}
                .stat-box {{ background: white; padding: 15px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .finding {{ background: white; margin: 20px 0; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .sink-type {{ display: inline-block; background: #e74c3c; color: white; padding: 4px 8px; border-radius: 3px; font-size: 12px; }}
                .phase-1 {{ border-left: 4px solid #e74c3c; }}
                .phase-2 {{ border-left: 4px solid #f39c12; }}
                .phase-3 {{ border-left: 4px solid #27ae60; }}
                .phase-4 {{ border-left: 4px solid #3498db; }}
                .phase-5 {{ border-left: 4px solid #9b59b6; }}
                .code {{ background: #f8f8f8; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }}
                table {{ width: 100%; border-collapse: collapse; background: white; }}
                th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }}
                th {{ background: #34495e; color: white; }}
                .url {{ font-size: 12px; color: #666; word-break: break-all; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Sink Analysis Summary Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        """
        
        # Statistics
        total_sinks = sum(len(findings) for findings in self.sink_findings.values())
        phase_stats = defaultdict(int)
        sink_type_stats = defaultdict(int)
        
        for findings in self.sink_findings.values():
            for finding in findings:
                phase_stats[finding['phase']] += 1
                sink_type_stats[finding['match_data']['sink_type']] += 1
        
        html_content += '<div class="stats">'
        html_content += f'<div class="stat-box"><h3>Total Sinks</h3><p>{total_sinks}</p></div>'
        html_content += f'<div class="stat-box"><h3>Affected URLs</h3><p>{len(self.sink_findings)}</p></div>'
        
        for phase, count in sorted(phase_stats.items(), key=lambda x: self.phase_order.get(x[0], 99)):
            html_content += f'<div class="stat-box"><h3>{phase}</h3><p>{count} sinks</p></div>'
        
        html_content += '</div>'
        
        # Summary table
        html_content += '<h2>Sinks by Request</h2>'
        html_content += '<table>'
        html_content += '<tr><th>Index</th><th>URL</th><th>Sink Count</th><th>Types</th><th>Actions</th></tr>'
        
        for index in sorted(self.sink_findings.keys()):
            findings = self.sink_findings[index]
            url = findings[0]['url'] if findings else ''
            sink_types = list(set(f['match_data']['sink_type'] for f in findings))
            
            html_content += f'<tr>'
            html_content += f'<td>{index}</td>'
            html_content += f'<td class="url">{html.escape(url)}</td>'
            html_content += f'<td>{len(findings)}</td>'
            html_content += f'<td>{", ".join(sink_types)}</td>'
            html_content += f'<td><a href="{index}/{index}_sink_report.txt">View Report</a></td>'
            html_content += f'</tr>'
        
        html_content += '</table>'
        
        html_content += '</body></html>'
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n[*] Generated sink summary report: {report_path}")
    
    def generate_index_file(self):
        """Generate an index.html file for easy navigation of results"""
        index_path = os.path.join(self.output_dir, "index.html")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>DOM Analysis Index</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #4CAF50; color: white; }}
                tr:nth-child(even) {{ background-color: #f2f2f2; }}
                .url {{ word-break: break-all; font-size: 12px; }}
                .exists {{ color: green; font-weight: bold; }}
                .missing {{ color: red; font-weight: bold; }}
                .has-sinks {{ background-color: #fee; }}
                .sink-count {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>DOM Analysis Results</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><a href="sink_summary_report.html">View Sink Summary Report</a></p>
            <table>
                <tr>
                    <th>Index</th>
                    <th>URL</th>
                    <th>Method</th>
                    <th>Param Type</th>
                    <th>DOM Status</th>
                    <th>Sinks Found</th>
                    <th>Actions</th>
                </tr>
        """
        
        target_requests = self.extract_target_requests()
        
        for request in sorted(target_requests, key=lambda x: x['index']):
            index = request['index']
            dom_file = os.path.join(self.output_dir, str(index), f"{index}_DOM.txt")
            
            status = '<span class="exists">✓ Captured</span>' if os.path.exists(dom_file) else '<span class="missing">✗ Missing</span>'
            
            sink_count = len(self.sink_findings.get(index, []))
            row_class = 'has-sinks' if sink_count > 0 else ''
            sink_display = f'<span class="sink-count">{sink_count}</span>' if sink_count > 0 else '0'
            
            actions = ""
            if os.path.exists(dom_file):
                actions = f'<a href="{index}/{index}_DOM.txt">DOM</a> | <a href="{index}/{index}_metadata.json">Meta</a>'
                if sink_count > 0:
                    actions += f' | <a href="{index}/{index}_sink_report.txt">Sinks</a>'
            
            html_content += f'''
                <tr class="{row_class}">
                    <td>{index}</td>
                    <td class="url">{html.escape(request['url'])}</td>
                    <td>{request['method']}</td>
                    <td>{request['type']}</td>
                    <td>{status}</td>
                    <td>{sink_display}</td>
                    <td>{actions}</td>
                </tr>
            '''
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[*] Generated index file: {index_path}")

# Main execution
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python DOM_Scanner.py <results.json> <dom-capture.json> [patterns.json] [output_dir]")
        print("\nExample:")
        print("  python DOM_Scanner.py results.json dom-capture-1234567.json")
        print("  python DOM_Scanner.py results.json dom-capture-1234567.json sink_patterns.json")
        print("  python DOM_Scanner.py results.json dom-capture-1234567.json sink_patterns.json CustomOutput")
        sys.exit(1)
    
    results_json = sys.argv[1]
    dom_capture = sys.argv[2]
    
    # Check for optional parameters
    patterns_file = "sink_patterns.json"  # Default name
    output_dir = "DOM_Analysis"
    
    if len(sys.argv) > 3:
        # Check if third argument is a JSON file (patterns) or directory
        if sys.argv[3].endswith('.json'):
            patterns_file = sys.argv[3]
            if len(sys.argv) > 4:
                output_dir = sys.argv[4]
        else:
            output_dir = sys.argv[3]
    
    # Initialize and run scanner
    scanner = DOMScanner(results_json, dom_capture, patterns_file, output_dir)
    scanner.process_requests()
    scanner.generate_index_file()
    
    if scanner.sink_findings:
        scanner.generate_sink_summary_report()
    
    print(f"\n[*] DOM extraction and analysis complete!")
    print(f"[*] Check the '{output_dir}' folder for results.")
