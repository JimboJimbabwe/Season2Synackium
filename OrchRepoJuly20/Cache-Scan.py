import argparse
import xml.etree.ElementTree as ET
import base64
import sys
import os
import json
from collections import defaultdict
from urllib.parse import parse_qs, unquote

def parse_args():
    parser = argparse.ArgumentParser(description='Create cache key profiles from JSON results and Burp Suite XML file')
    parser.add_argument('-j', '--json', required=True, help='Path to results.json file')
    parser.add_argument('-x', '--xml', required=True, help='Path to original Burp Suite XML file')
    parser.add_argument('-o', '--output', required=True, help='Output directory path for cache profiles')
    return parser.parse_args()

def load_json_results(json_path):
    """Load and parse the results.json file"""
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        return data
    except FileNotFoundError:
        print(f"JSON file not found: {json_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Invalid JSON file: {json_path}")
        sys.exit(1)

def extract_target_indices(json_data):
    """Extract all indices from requests_with_url_params and requests_with_body_params"""
    target_indices = set()
    
    # Extract from requests_with_url_params
    if 'requests_with_url_params' in json_data:
        for request in json_data['requests_with_url_params']:
            if 'index' in request:
                target_indices.add(request['index'])
    
    # Extract from requests_with_body_params
    if 'requests_with_body_params' in json_data:
        for request in json_data['requests_with_body_params']:
            if 'index' in request:
                target_indices.add(request['index'])
    
    return sorted(list(target_indices))

def extract_request_data(request_base64):
    """Decode base64 request data and extract headers, body, and request line"""
    try:
        request_bytes = base64.b64decode(request_base64)
        request_text = request_bytes.decode('utf-8', errors='replace')
        
        # Split request into lines
        lines = request_text.split('\r\n')
        
        # First line contains the HTTP method, path, and version
        request_line = lines[0] if lines else ""
        
        # Extract headers with both names and values
        headers = []
        body_start_index = 1
        
        for i, line in enumerate(lines[1:], 1):  # Skip the first line (request line)
            if not line or line.isspace():
                body_start_index = i + 1
                break  # End of headers section
            
            # Split at the first colon
            parts = line.split(':', 1)
            if len(parts) == 2:
                header_name = parts[0].strip()
                header_value = parts[1].strip()
                headers.append(f"{header_name}: {header_value}")
        
        # Extract body if present
        body = ""
        if body_start_index < len(lines):
            body_lines = lines[body_start_index:]
            body = '\r\n'.join(body_lines).strip()
        
        return request_line, headers, body
    except Exception as e:
        print(f"Error decoding request: {e}")
        return "", [], ""

def parse_body_parameters(body, content_type=""):
    """Parse body parameters based on content type"""
    params = {}
    
    if not body:
        return params
    
    # Check if it's URL-encoded form data
    if 'application/x-www-form-urlencoded' in content_type.lower() or '&' in body and '=' in body:
        try:
            # Parse URL-encoded parameters
            parsed = parse_qs(body, keep_blank_values=True)
            for key, values in parsed.items():
                params[key] = values[0] if len(values) == 1 else values
        except Exception:
            # If parsing fails, treat as raw body
            params['_raw_body'] = body
    
    # Check if it's JSON
    elif 'application/json' in content_type.lower() or body.strip().startswith('{') or body.strip().startswith('['):
        try:
            json_data = json.loads(body)
            if isinstance(json_data, dict):
                params = json_data
            else:
                params['_json_body'] = json_data
        except json.JSONDecodeError:
            params['_raw_body'] = body
    
    # For other content types, store as raw
    else:
        params['_raw_body'] = body
    
    return params

def get_content_type_from_headers(headers):
    """Extract Content-Type from headers list"""
    for header in headers:
        if header.lower().startswith('content-type:'):
            return header.split(':', 1)[1].strip()
    return ""

def extract_method_and_path(request_line):
    """Extract HTTP method and path from request line"""
    method = "Unknown"
    path = "Unknown"
    
    parts = request_line.split(' ')
    if len(parts) >= 2:
        method = parts[0]
        path = parts[1]
    
    return method, path

def load_xml_requests(xml_path):
    """Load and parse the Burp Suite XML file"""
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        items = root.findall('.//item')
        
        if not items:
            print("No requests found in the XML file.")
            sys.exit(1)
        
        return items
    except FileNotFoundError:
        print(f"XML file not found: {xml_path}")
        sys.exit(1)
    except ET.ParseError:
        print(f"Invalid XML file: {xml_path}")
        sys.exit(1)

def create_output_directory(output_dir):
    """Create the output directory if it doesn't exist"""
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir)
            print(f"Created output directory: {output_dir}")
        except OSError as e:
            print(f"Error creating output directory {output_dir}: {e}")
            sys.exit(1)

def create_cache_repo_structure(output_dir):
    """Use the output directory as the cache-repo folder"""
    # Instead of creating a cache-repo subdirectory, use the output directory directly
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    return output_dir

def create_index_folder(cache_repo_path, index):
    """Create subfolder for specific index"""
    index_folder = os.path.join(cache_repo_path, str(index))
    if not os.path.exists(index_folder):
        os.makedirs(index_folder)
    return index_folder

def write_cache_key_file(folder_path, method, path, headers, body_params, index):
    """Create cache-key.txt file for the specific index"""
    file_path = os.path.join(folder_path, "cache-key.txt")
    with open(file_path, 'w') as f:
        f.write(f"Index: {index}\n")
        f.write(f"Method: {method}\n")
        f.write(f"Path: {path}\n")
        f.write("Headers:\n")
        for header in headers:
            f.write(f"  {header}\n")
        
        # Add body parameters if present
        if body_params:
            f.write("\nBody Parameters:\n")
            
            # Handle different types of body parameters
            if '_raw_body' in body_params:
                f.write(f"  [Raw Body]:\n")
                raw_body = body_params['_raw_body']
                # Indent raw body content
                for line in raw_body.split('\n'):
                    f.write(f"    {line}\n")
            elif '_json_body' in body_params:
                f.write(f"  [JSON Body]:\n")
                json_str = json.dumps(body_params['_json_body'], indent=4)
                for line in json_str.split('\n'):
                    f.write(f"    {line}\n")
            else:
                # Regular key-value parameters
                for key, value in body_params.items():
                    if isinstance(value, (list, dict)):
                        f.write(f"  {key}: {json.dumps(value)}\n")
                    else:
                        f.write(f"  {key}: {value}\n")
        else:
            f.write("\nBody Parameters: None\n")
    
    return file_path

def main():
    args = parse_args()
    
    # Create output directory if it doesn't exist
    create_output_directory(args.output)
    
    print("Loading JSON results...")
    json_data = load_json_results(args.json)
    
    print("Extracting target indices...")
    target_indices = extract_target_indices(json_data)
    
    if not target_indices:
        print("No indices found in requests_with_url_params or requests_with_body_params")
        sys.exit(1)
    
    print(f"Found {len(target_indices)} target indices: {target_indices}")
    
    print("Loading XML requests...")
    xml_items = load_xml_requests(args.xml)
    
    print(f"Found {len(xml_items)} total requests in XML file")
    
    # Create output directory structure
    cache_repo_path = create_cache_repo_structure(args.output)
    print(f"Using output directory: {cache_repo_path}")
    
    # Process each target index
    processed_count = 0
    failed_count = 0
    
    for target_index in target_indices:
        print(f"\nProcessing index {target_index}...")
        
        # Check if index exists in XML
        if target_index >= len(xml_items):
            print(f"Warning: Index {target_index} not found in XML file (max index: {len(xml_items) - 1})")
            failed_count += 1
            continue
        
        # Get the specific item from XML
        item = xml_items[target_index]
        
        # Extract request
        request_element = item.find('./request')
        if request_element is None or request_element.text is None:
            print(f"Warning: Request data not found for index {target_index}")
            failed_count += 1
            continue
        
        request_base64 = request_element.text
        
        # Extract headers, body, and request info
        request_line, headers, body = extract_request_data(request_base64)
        method, path = extract_method_and_path(request_line)
        
        # Get content type from headers
        content_type = get_content_type_from_headers(headers)
        
        # Parse body parameters
        body_params = parse_body_parameters(body, content_type)
        
        # Create folder for this index
        index_folder = create_index_folder(cache_repo_path, target_index)
        
        # Write cache-key file
        cache_key_path = write_cache_key_file(index_folder, method, path, headers, body_params, target_index)
        
        print(f"Created cache key for index {target_index}")
        print(f"  Method: {method}")
        print(f"  Path: {path}")
        print(f"  Headers: {len(headers)} found")
        print(f"  Body Parameters: {'Yes' if body_params else 'None'}")
        if body_params and not any(key.startswith('_') for key in body_params.keys()):
            print(f"    Parameters: {', '.join(body_params.keys())}")
        print(f"  Saved to: {cache_key_path}")
        
        processed_count += 1
    
    # Summary
    print(f"\n{'='*50}")
    print("SUMMARY")
    print(f"{'='*50}")
    print(f"Total target indices: {len(target_indices)}")
    print(f"Successfully processed: {processed_count}")
    print(f"Failed to process: {failed_count}")
    print(f"Cache keys saved to: {cache_repo_path}")
    
    if failed_count > 0:
        print(f"\nWarning: {failed_count} indices could not be processed. Check the logs above for details.")

if __name__ == "__main__":
    main()
