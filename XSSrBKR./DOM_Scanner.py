import xml.etree.ElementTree as ET
import base64
import re
import json
from collections import defaultdict
from typing import List, Dict, Tuple
import html
from datetime import datetime

class SinkAnalyzer:
    def __init__(self, patterns_file: str):
        """Initialize with your JSON pattern file"""
        with open(patterns_file, 'r') as f:
            self.patterns = json.load(f)['GeneralOrder']
        
        # Define the execution order priority
        self.phase_order = {
            'Initialization': 1,
            'Manipulation': 2,
            'Processing': 3,
            'Execution': 4,
            'SpecialCases': 5
        }
        
        self.findings = defaultdict(list)
        self.stats = defaultdict(int)
        
    def analyze_burp_file(self, burp_xml_path: str):
        """Analyze a Burp Suite XML export file"""
        print(f"[*] Loading Burp file: {burp_xml_path}")
        tree = ET.parse(burp_xml_path)
        root = tree.getroot()
        
        items_processed = 0
        
        # Process each item in Burp history
        for item in root.findall('.//item'):
            url = item.find('./url').text if item.find('./url') is not None else 'Unknown'
            response = item.find('./response')
            
            if response is not None and response.text:
                try:
                    # Decode base64 response
                    response_text = base64.b64decode(response.text).decode('utf-8', errors='ignore')
                    
                    # Skip if response is too small to contain meaningful JS
                    if len(response_text) > 100:
                        self.analyze_response(response_text, url)
                        items_processed += 1
                        
                except Exception as e:
                    print(f"[!] Error decoding response for {url}: {e}")
        
        print(f"[*] Processed {items_processed} responses")
        print(f"[*] Found {sum(len(v) for v in self.findings.values())} total findings")
    
    def analyze_response(self, response_text: str, url: str):
        """Analyze a single response for all sink patterns"""
        # Extract JavaScript content
        js_blocks = self.extract_javascript(response_text)
        
        if not js_blocks:
            return
        
        # Analyze each JavaScript block
        for js_content in js_blocks:
            # Skip empty blocks
            if not js_content.strip():
                continue
                
            # Run regex patterns from each phase in order
            for phase_name, phase_data in self.patterns.items():
                # Skip DOM Clobbering as it needs HTML analysis
                if phase_name == 'DOMClobbering':
                    continue
                    
                priority = self.phase_order.get(phase_name, 99)
                
                # Process each context within the phase
                for context_name, context_data in phase_data.items():
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
                    
                    # Store findings
                    for match in matches:
                        finding = {
                            'url': url,
                            'phase': phase_name,
                            'context': context_name,
                            'priority': priority,
                            'match_data': match,
                            'timestamp': datetime.now().isoformat()
                        }
                        self.findings[url].append(finding)
                        self.stats[f"{phase_name}_{context_name}"] += 1
    
    def extract_javascript(self, content: str) -> List[str]:
        """Extract JavaScript from HTML responses"""
        js_blocks = []
        
        # Check if this is already a JS file
        content_lower = content.lower().strip()
        if (content_lower.startswith('function') or 
            content_lower.startswith('var ') or
            content_lower.startswith('const ') or
            content_lower.startswith('let ') or
            content_lower.startswith('//')):
            return [content]
        
        # Extract inline scripts
        script_pattern = r'<script[^>]*?>(.*?)</script>'
        scripts = re.findall(script_pattern, content, re.DOTALL | re.IGNORECASE)
        js_blocks.extend([s for s in scripts if s.strip()])
        
        # Extract event handlers
        event_pattern = r'on\w+\s*=\s*["\']([^"\']+)["\']'
        events = re.findall(event_pattern, content, re.IGNORECASE)
        js_blocks.extend(events)
        
        # Extract javascript: URLs
        js_url_pattern = r'(?:href|src)\s*=\s*["\']javascript:([^"\']+)["\']'
        js_urls = re.findall(js_url_pattern, content, re.IGNORECASE)
        js_blocks.extend(js_urls)
        
        return js_blocks
    
    def find_pattern_matches(self, content: str, pattern: str, 
                           phase: str, context: str, priority: int) -> List[Dict]:
        """Find all matches for a specific pattern"""
        matches = []
        
        if not pattern:
            return matches
        
        try:
            regex = re.compile(pattern, re.MULTILINE | re.DOTALL | re.IGNORECASE)
            
            for match in regex.finditer(content):
                # Calculate line number
                line_num = content[:match.start()].count('\n') + 1
                
                # Get context lines (30 before and after)
                lines = content.split('\n')
                start_line = max(0, line_num - 30)
                end_line = min(len(lines), line_num + 30)
                
                # Mark the matched line
                context_lines = []
                for i in range(start_line, end_line):
                    if i == line_num - 1:  # Current line
                        context_lines.append(f">>> {lines[i]} <<<")
                    else:
                        context_lines.append(f"    {lines[i]}")
                
                # Extract the sink type from the matched text
                sink_type = self.identify_sink_type(match.group(0))
                
                matches.append({
                    'matched_text': match.group(0),
                    'sink_type': sink_type,
                    'line_number': line_num,
                    'context': '\n'.join(context_lines),
                    'start_pos': match.start(),
                    'end_pos': match.end(),
                    'phase': phase,
                    'context_type': context
                })
                
        except re.error as e:
            print(f"[!] Regex error in {phase}.{context}: {e}")
            
        return matches
    
    def identify_sink_type(self, matched_text: str) -> str:
        """Identify the specific sink type from matched text"""
        # Common sink patterns
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
            'postMessage': r'postMessage',
            'setAttribute': r'setAttribute',
            'src': r'\.src\s*=',
            'href': r'\.href\s*=',
        }
        
        for sink_name, pattern in sink_patterns.items():
            if re.search(pattern, matched_text, re.IGNORECASE):
                return sink_name
                
        return 'Unknown'
    
    def generate_report(self, output_file: str = 'sink_analysis_report.html'):
        """Generate an organized HTML report"""
        print(f"[*] Generating report: {output_file}")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Sink Analysis Report - {datetime.now().strftime('%Y-%m-%d %H:%M')}</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Arial, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                }}
                .header {{
                    background: #2c3e50;
                    color: white;
                    padding: 20px;
                    margin: -20px -20px 20px -20px;
                }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-bottom: 30px;
                }}
                .stat-box {{
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .url-section {{
                    background: white;
                    margin: 20px 0;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .url-header {{
                    background: #34495e;
                    color: white;
                    padding: 15px;
                    font-weight: bold;
                    word-break: break-all;
                }}
                .phase-section {{
                    margin: 0;
                    border-top: 1px solid #e0e0e0;
                }}
                .phase-header {{
                    background: #ecf0f1;
                    padding: 10px 15px;
                    font-weight: bold;
                    cursor: pointer;
                }}
                .phase-header:hover {{
                    background: #d5dbdb;
                }}
                .finding {{
                    margin: 0;
                    padding: 15px;
                    border-bottom: 1px solid #f0f0f0;
                    position: relative;
                }}
                .finding:last-child {{
                    border-bottom: none;
                }}
                .sink-type {{
                    display: inline-block;
                    background: #3498db;
                    color: white;
                    padding: 2px 8px;
                    border-radius: 3px;
                    font-size: 12px;
                    margin-right: 10px;
                }}
                .line-number {{
                    color: #7f8c8d;
                    font-size: 12px;
                }}
                .matched-code {{
                    background: #fffacd;
                    padding: 2px 4px;
                    border-radius: 3px;
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 13px;
                    margin: 10px 0;
                    display: inline-block;
                }}
                .code-context {{
                    background: #f8f8f8;
                    border: 1px solid #e0e0e0;
                    border-radius: 4px;
                    padding: 10px;
                    margin-top: 10px;
                    overflow-x: auto;
                    display: none;
                }}
                .code-context pre {{
                    margin: 0;
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 12px;
                    line-height: 1.4;
                }}
                .show-context {{
                    color: #3498db;
                    cursor: pointer;
                    font-size: 12px;
                    text-decoration: underline;
                }}
                .priority-1 {{ border-left: 4px solid #e74c3c; }}
                .priority-2 {{ border-left: 4px solid #f39c12; }}
                .priority-3 {{ border-left: 4px solid #27ae60; }}
                .priority-4 {{ border-left: 4px solid #3498db; }}
                .priority-5 {{ border-left: 4px solid #9b59b6; }}
                .phase-1 {{ background-color: rgba(231, 76, 60, 0.05); }}
                .phase-2 {{ background-color: rgba(243, 156, 18, 0.05); }}
                .phase-3 {{ background-color: rgba(39, 174, 96, 0.05); }}
                .phase-4 {{ background-color: rgba(52, 152, 219, 0.05); }}
                .phase-5 {{ background-color: rgba(155, 89, 182, 0.05); }}
            </style>
            <script>
                function toggleContext(id) {{
                    var elem = document.getElementById(id);
                    elem.style.display = elem.style.display === 'none' ? 'block' : 'none';
                }}
                function togglePhase(phaseId) {{
                    var elem = document.getElementById(phaseId);
                    elem.style.display = elem.style.display === 'none' ? 'block' : 'none';
                }}
            </script>
        </head>
        <body>
            <div class="header">
                <h1>Sink Analysis Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
        """
        
        # Add statistics
        html_content += '<div class="stats">'
        html_content += f'<div class="stat-box"><h3>Total URLs</h3><p>{len(self.findings)}</p></div>'
        html_content += f'<div class="stat-box"><h3>Total Findings</h3><p>{sum(len(v) for v in self.findings.values())}</p></div>'
        
        # Stats by phase
        phase_stats = defaultdict(int)
        for findings in self.findings.values():
            for finding in findings:
                phase_stats[finding['phase']] += 1
        
        for phase, count in sorted(phase_stats.items(), key=lambda x: self.phase_order.get(x[0], 99)):
            html_content += f'<div class="stat-box"><h3>{phase}</h3><p>{count} findings</p></div>'
        
        html_content += '</div>'
        
        # Process findings by URL
        finding_id = 0
        for url, findings in sorted(self.findings.items()):
            html_content += f'<div class="url-section">'
            html_content += f'<div class="url-header">{html.escape(url)} ({len(findings)} findings)</div>'
            
            # Group findings by phase
            phase_groups = defaultdict(list)
            for finding in findings:
                phase_groups[finding['phase']].append(finding)
            
            # Display findings in phase order
            for phase in sorted(phase_groups.keys(), key=lambda x: self.phase_order.get(x, 99)):
                phase_findings = phase_groups[phase]
                phase_id = f"phase_{finding_id}"
                
                html_content += f'<div class="phase-section">'
                html_content += f'<div class="phase-header" onclick="togglePhase(\'{phase_id}\')">'
                html_content += f'{phase} ({len(phase_findings)} findings) - Click to toggle'
                html_content += f'</div>'
                html_content += f'<div id="{phase_id}" style="display: block;">'
                
                for finding in phase_findings:
                    match_data = finding['match_data']
                    priority = finding['priority']
                    
                    html_content += f'<div class="finding priority-{priority} phase-{priority}">'
                    html_content += f'<span class="sink-type">{match_data["sink_type"]}</span>'
                    html_content += f'<span class="line-number">Line {match_data["line_number"]}</span> - '
                    html_content += f'{finding["context"]}<br>'
                    html_content += f'<div class="matched-code">{html.escape(match_data["matched_text"])}</div><br>'
                    
                    context_id = f'context_{finding_id}'
                    html_content += f'<span class="show-context" onclick="toggleContext(\'{context_id}\')">Show context</span>'
                    html_content += f'<div id="{context_id}" class="code-context">'
                    html_content += f'<pre>{html.escape(match_data["context"])}</pre>'
                    html_content += f'</div>'
                    html_content += f'</div>'
                    
                    finding_id += 1
                
                html_content += '</div></div>'
            
            html_content += '</div>'
        
        html_content += '</body></html>'
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"[*] Report generated successfully!")
        
        # Print summary statistics
        print("\n[*] Summary Statistics:")
        for phase in sorted(phase_stats.keys(), key=lambda x: self.phase_order.get(x, 99)):
            print(f"    {phase}: {phase_stats[phase]} findings")
    
    def export_findings_json(self, output_file: str = 'findings.json'):
        """Export findings as JSON for further processing"""
        export_data = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_urls': len(self.findings),
                'total_findings': sum(len(v) for v in self.findings.values())
            },
            'findings': []
        }
        
        for url, findings in self.findings.items():
            for finding in sorted(findings, key=lambda x: x['priority']):
                export_data['findings'].append({
                    'url': url,
                    'phase': finding['phase'],
                    'context': finding['context'],
                    'priority': finding['priority'],
                    'sink_type': finding['match_data']['sink_type'],
                    'line_number': finding['match_data']['line_number'],
                    'matched_text': finding['match_data']['matched_text']
                })
        
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"[*] Findings exported to: {output_file}")

# Main execution
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python sink_analyzer.py <burp_export.xml> [patterns.json]")
        print("If patterns.json is not specified, will look for 'sink_patterns.json'")
        sys.exit(1)
    
    burp_file = sys.argv[1]
    patterns_file = sys.argv[2] if len(sys.argv) > 2 else 'sink_patterns.json'
    
    # Initialize analyzer with your patterns
    analyzer = SinkAnalyzer(patterns_file)
    
    # Analyze the Burp file
    analyzer.analyze_burp_file(burp_file)
    
    # Generate reports
    analyzer.generate_report()
    analyzer.export_findings_json()
    
    print("\n[*] Analysis complete!")
