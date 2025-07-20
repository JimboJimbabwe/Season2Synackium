#!/usr/bin/env python3
"""
Injection Context Analyzer
Automatically detects injection contexts in DOM content and generates appropriate payloads.
"""

import json
import re
import os
import argparse
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class InjectionContextAnalyzer:
    def __init__(self, contexts_file: str, user_input_replacement: str = "USER_INPUT"):
        """Initialize the analyzer with contexts JSON and user input replacement."""
        self.user_input_replacement = user_input_replacement
        self.contexts = self._load_contexts(contexts_file)
        self.detected_contexts = {}
        self.all_payloads = set()
        
    def _load_contexts(self, contexts_file: str) -> Dict:
        """Load injection contexts from JSON file."""
        try:
            with open(contexts_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('injection_contexts', {})
        except Exception as e:
            logger.error(f"Error loading contexts file: {e}")
            raise
    
    def _replace_user_input_in_regex(self, regex_pattern: str) -> str:
        """Replace USER_INPUT in regex pattern with custom replacement."""
        return regex_pattern.replace('USER_INPUT', self.user_input_replacement)
    
    def _extract_url_parameters(self, raw_xml_path: str) -> List[str]:
        """Extract URL parameter values from raw.xml file."""
        parameters = []
        try:
            tree = ET.parse(raw_xml_path)
            root = tree.getroot()
            
            # Look for URL elements in common Burp Suite XML structure
            url_elements = root.findall('.//url') + root.findall('.//URL')
            
            for url_elem in url_elements:
                if url_elem.text:
                    parsed_url = urlparse(url_elem.text)
                    if parsed_url.query:
                        query_params = parse_qs(parsed_url.query)
                        for param_name, param_values in query_params.items():
                            parameters.extend(param_values)
            
            # Also check request elements for POST data
            request_elements = root.findall('.//request') + root.findall('.//REQUEST')
            for req_elem in request_elements:
                if req_elem.text:
                    # Look for URL-encoded data in request body
                    request_text = req_elem.text
                    if '=' in request_text and '&' in request_text:
                        try:
                            post_params = parse_qs(request_text)
                            for param_name, param_values in post_params.items():
                                parameters.extend(param_values)
                        except:
                            pass
                            
        except Exception as e:
            logger.warning(f"Error parsing raw.xml file {raw_xml_path}: {e}")
        
        return list(set(parameters))  # Remove duplicates
    
    def _search_context_in_content(self, content: str, context_name: str, subcontext_name: str, 
                                 subcontext_data: Dict) -> Tuple[bool, List[str]]:
        """Search for specific context pattern in content."""
        if 'detection_regex' not in subcontext_data:
            return False, []
        
        regex_pattern = self._replace_user_input_in_regex(subcontext_data['detection_regex'])
        
        try:
            matches = re.findall(regex_pattern, content, re.IGNORECASE | re.MULTILINE)
            if matches:
                # Extract progressive testing steps
                progressive_testing = subcontext_data.get('progressive_testing', {})
                payloads = []
                for step_key in sorted(progressive_testing.keys()):
                    payload = progressive_testing[step_key]
                    if payload:
                        payloads.append(payload)
                
                return True, payloads
        except re.error as e:
            logger.warning(f"Invalid regex pattern for {context_name}.{subcontext_name}: {e}")
        
        return False, []
    
    def _search_parameters_for_contexts(self, parameters: List[str]) -> Dict[str, List[str]]:
        """Search URL parameters for injection contexts."""
        param_contexts = {}
        
        for param_value in parameters:
            if not param_value or len(param_value.strip()) < 3:
                continue
                
            logger.info(f"Analyzing parameter value: {param_value[:50]}...")
            
            for context_name, context_data in self.contexts.items():
                for subcontext_name, subcontext_data in context_data.items():
                    # Replace USER_INPUT with the actual parameter value for analysis
                    temp_replacement = self.user_input_replacement
                    self.user_input_replacement = re.escape(param_value)
                    
                    found, payloads = self._search_context_in_content(
                        param_value, context_name, subcontext_name, subcontext_data
                    )
                    
                    # Restore original replacement
                    self.user_input_replacement = temp_replacement
                    
                    if found:
                        key = f"{context_name}.{subcontext_name}"
                        if key not in param_contexts:
                            param_contexts[key] = []
                        param_contexts[key].extend(payloads)
        
        return param_contexts
    
    def analyze_dom_file(self, dom_file_path: str, index_folder: str, custom_raw_xml: str = None) -> Dict:
        """Analyze a single DOM file for injection contexts."""
        try:
            with open(dom_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            logger.error(f"Error reading DOM file {dom_file_path}: {e}")
            return {}
        
        detected = {}
        logger.info(f"Analyzing DOM file: {dom_file_path}")
        
        # Search for contexts in DOM content
        for context_name, context_data in self.contexts.items():
            for subcontext_name, subcontext_data in context_data.items():
                found, payloads = self._search_context_in_content(
                    content, context_name, subcontext_name, subcontext_data
                )
                
                if found:
                    key = f"{context_name}.{subcontext_name}"
                    detected[key] = payloads
                    self.all_payloads.update(payloads)
                    logger.info(f"Found context: {key}")
        
        # If no contexts found in DOM, try parameter analysis
        if not detected:
            logger.info("No contexts found in DOM content, attempting parameter analysis...")
            
            # Determine raw.xml file path
            raw_xml_path = None
            if custom_raw_xml:
                if os.path.isabs(custom_raw_xml):
                    # Absolute path provided
                    raw_xml_path = custom_raw_xml
                else:
                    # Relative filename provided, look in index folder
                    raw_xml_path = os.path.join(index_folder, custom_raw_xml)
            else:
                # Default: look for raw.xml in the same index folder
                raw_xml_path = os.path.join(index_folder, 'raw.xml')
            
            if os.path.exists(raw_xml_path):
                logger.info(f"Found XML file at: {raw_xml_path}")
                parameters = self._extract_url_parameters(raw_xml_path)
                
                if parameters:
                    logger.info(f"Extracted {len(parameters)} parameters for analysis")
                    param_contexts = self._search_parameters_for_contexts(parameters)
                    detected.update(param_contexts)
                    
                    # Add parameter payloads to all_payloads
                    for payloads in param_contexts.values():
                        self.all_payloads.update(payloads)
                else:
                    logger.info("No parameters found in XML file")
            else:
                logger.warning(f"XML file not found at: {raw_xml_path}")
        
        return detected
    
    def write_wordlist(self, payloads: List[str], output_file: str):
        """Write payloads to a wordlist file."""
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                for payload in payloads:
                    f.write(f"{payload}\n")
            logger.info(f"Wordlist written to: {output_file}")
        except Exception as e:
            logger.error(f"Error writing wordlist to {output_file}: {e}")
    
    def write_report(self, index_name: str, detected_contexts: Dict, output_file: str):
        """Write analysis report for an index."""
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"Injection Context Analysis Report\n")
                f.write(f"{'=' * 40}\n")
                f.write(f"Index: {index_name}\n")
                f.write(f"User Input Replacement: {self.user_input_replacement}\n\n")
                
                if detected_contexts:
                    f.write(f"Detected Contexts ({len(detected_contexts)}):\n")
                    f.write("-" * 30 + "\n")
                    
                    for context, payloads in detected_contexts.items():
                        f.write(f"\n[{context}]\n")
                        f.write(f"Payloads ({len(payloads)}):\n")
                        for i, payload in enumerate(payloads, 1):
                            f.write(f"  {i}. {payload}\n")
                else:
                    f.write("No injection contexts detected.\n")
                
                f.write(f"\nTotal unique payloads: {len(set().union(*detected_contexts.values()) if detected_contexts else set())}\n")
            
            logger.info(f"Report written to: {output_file}")
        except Exception as e:
            logger.error(f"Error writing report to {output_file}: {e}")
    
    def write_combined_report(self, all_results: Dict, output_file: str):
        """Write combined analysis report for all indexes."""
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(f"Combined Injection Context Analysis Report\n")
                f.write(f"{'=' * 50}\n")
                f.write(f"User Input Replacement: {self.user_input_replacement}\n")
                f.write(f"Total Indexes Analyzed: {len(all_results)}\n\n")
                
                # Summary of all detected contexts
                all_contexts = set()
                for results in all_results.values():
                    all_contexts.update(results.keys())
                
                f.write(f"All Detected Context Types ({len(all_contexts)}):\n")
                f.write("-" * 40 + "\n")
                for context in sorted(all_contexts):
                    indexes_with_context = [idx for idx, results in all_results.items() if context in results]
                    f.write(f"  {context}: {len(indexes_with_context)} indexes\n")
                
                f.write(f"\nDetailed Results by Index:\n")
                f.write("=" * 30 + "\n")
                
                for index_name, detected_contexts in all_results.items():
                    f.write(f"\n[{index_name}]\n")
                    if detected_contexts:
                        for context, payloads in detected_contexts.items():
                            f.write(f"  - {context}: {len(payloads)} payloads\n")
                    else:
                        f.write("  - No contexts detected\n")
                
                f.write(f"\nTotal Unique Payloads: {len(self.all_payloads)}\n")
            
            logger.info(f"Combined report written to: {output_file}")
        except Exception as e:
            logger.error(f"Error writing combined report to {output_file}: {e}")

def main():
    parser = argparse.ArgumentParser(description='Injection Context Analyzer')
    parser.add_argument('parent_folder', help='Path to parent folder containing index subfolders')
    parser.add_argument('contexts_file', help='Path to injection contexts JSON file')
    parser.add_argument('-o', '--output', default='./output', help='Output directory (default: ./output)')
    parser.add_argument('-r', '--replacement', default='USER_INPUT', 
                       help='String to replace USER_INPUT with in regex patterns (default: USER_INPUT)')
    parser.add_argument('-d', '--dom-file', default='dom.txt', 
                       help='Name of DOM content file in each index folder (default: dom.txt)')
    parser.add_argument('-x', '--xml-file', default=None,
                       help='Custom XML file name or absolute path for parameter extraction (default: raw.xml)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate inputs
    if not os.path.exists(args.parent_folder):
        logger.error(f"Parent folder does not exist: {args.parent_folder}")
        return 1
    
    if not os.path.exists(args.contexts_file):
        logger.error(f"Contexts file does not exist: {args.contexts_file}")
        return 1
    
    # If absolute path provided for XML file, validate it exists
    if args.xml_file and os.path.isabs(args.xml_file) and not os.path.exists(args.xml_file):
        logger.error(f"XML file does not exist: {args.xml_file}")
        return 1
    
    # Initialize analyzer
    try:
        analyzer = InjectionContextAnalyzer(args.contexts_file, args.replacement)
    except Exception as e:
        logger.error(f"Failed to initialize analyzer: {e}")
        return 1
    
    # Find all index folders
    index_folders = []
    for item in os.listdir(args.parent_folder):
        item_path = os.path.join(args.parent_folder, item)
        if os.path.isdir(item_path):
            dom_file_path = os.path.join(item_path, args.dom_file)
            if os.path.exists(dom_file_path):
                index_folders.append((item, item_path, dom_file_path))
    
    if not index_folders:
        logger.error(f"No index folders with {args.dom_file} found in {args.parent_folder}")
        return 1
    
    logger.info(f"Found {len(index_folders)} index folders to analyze")
    if args.xml_file:
        logger.info(f"Using XML file: {args.xml_file}")
    
    # Analyze each index
    all_results = {}
    for index_name, index_path, dom_file_path in index_folders:
        logger.info(f"Processing index: {index_name}")
        
        detected_contexts = analyzer.analyze_dom_file(dom_file_path, index_path, args.xml_file)
        all_results[index_name] = detected_contexts
        
        # Write individual wordlist for this index
        if detected_contexts:
            index_payloads = []
            for payloads in detected_contexts.values():
                index_payloads.extend(payloads)
            
            wordlist_file = os.path.join(args.output, 'wordlists', f"{index_name}_payloads.txt")
            analyzer.write_wordlist(list(set(index_payloads)), wordlist_file)
        
        # Write individual report for this index
        report_file = os.path.join(args.output, 'reports', f"{index_name}_report.txt")
        analyzer.write_report(index_name, detected_contexts, report_file)
    
    # Write combined wordlist
    if analyzer.all_payloads:
        combined_wordlist = os.path.join(args.output, 'combined_payloads.txt')
        analyzer.write_wordlist(list(analyzer.all_payloads), combined_wordlist)
    
    # Write combined report
    combined_report = os.path.join(args.output, 'combined_report.txt')
    analyzer.write_combined_report(all_results, combined_report)
    
    # Summary
    total_contexts = sum(len(results) for results in all_results.values())
    logger.info(f"Analysis complete!")
    logger.info(f"Total contexts detected: {total_contexts}")
    logger.info(f"Total unique payloads: {len(analyzer.all_payloads)}")
    logger.info(f"Output written to: {args.output}")
    
    return 0

if __name__ == "__main__":
    exit(main())
