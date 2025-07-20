#!/usr/bin/env python3
"""
POST to GET Parameter Converter
Reads from cache-repo structure and converts POST requests to GET
"""
import os
import sys
import re
from urllib.parse import quote, urlparse, parse_qs
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Convert POST requests to GET from cache-repo')
    parser.add_argument('-c', '--cache-repo', required=True, help='Path to cache-repo folder')
    parser.add_argument('-i', '--index', type=int, help='Specific index to convert (optional)')
    parser.add_argument('-o', '--output', help='Output directory (default: cache-repo-get)')
    return parser.parse_args()

def parse_cache_key_file(file_path):
    """Parse cache-key.txt to extract request information"""
    request_info = {
        'index': None,
        'method': None,
        'path': None,
        'content_type': None,
        'body': None
    }
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        headers_section = False
        for line in lines:
            line = line.strip()
            
            if line.startswith('Index:'):
                request_info['index'] = line.split(':', 1)[1].strip()
            elif line.startswith('Method:'):
                request_info['method'] = line.split(':', 1)[1].strip()
            elif line.startswith('Path:'):
                request_info['path'] = line.split(':', 1)[1].strip()
            elif line == 'Headers:':
                headers_section = True
            elif headers_section and line:
                # Look for Content-Type header
                if line.lower().startswith('content-type:'):
                    request_info['content_type'] = line.split(':', 1)[1].strip()
                # Look for request body in headers (might be included)
                elif not line.startswith(('Host:', 'User-Agent:', 'Accept', 'Content-')):
                    # This might be body data if it doesn't look like a header
                    if '=' in line and not ':' in line:
                        request_info['body'] = line
        
        return request_info
    except Exception as e:
        print(f"Error reading cache-key file: {e}")
        return None

def extract_post_body(cache_folder):
    """Try to extract POST body from various possible locations"""
    # Check if there's a separate body file
    body_file = os.path.join(cache_folder, 'body.txt')
    if os.path.exists(body_file):
        with open(body_file, 'r') as f:
            return f.read().strip()
    
    # Check if there's a request file
    request_file = os.path.join(cache_folder, 'request.txt')
    if os.path.exists(request_file):
        with open(request_file, 'r') as f:
            content = f.read()
            # Find body after headers (double newline)
            parts = content.split('\n\n', 1)
            if len(parts) > 1:
                return parts[1].strip()
    
    return None

def parse_params(post_data):
    """Parse POST data into parameter-value pairs"""
    params = []
    
    if not post_data:
        return params
    
    # Split by & to get individual param=value pairs
    pairs = post_data.split('&')
    
    for pair in pairs:
        if '=' in pair:
            # Find the first = sign to split param and value
            first_equals = pair.index('=')
            param = pair[:first_equals]
            value = pair[first_equals + 1:]
            params.append((param, value))
        else:
            # Handle case where there's no value
            params.append((pair, ''))
    
    return params

def needs_encoding(text):
    """Check if text contains characters that need encoding"""
    # Characters that need encoding in URLs
    special_chars = [' ', '&', '=', '#', '%', '+', '?', '/', ':', '@', '!', '$', "'", '(', ')', '*', ',', ';']
    return any(char in text for char in special_chars)

def encode_param(text):
    """Encode parameter for URL"""
    if needs_encoding(text):
        return quote(text, safe='')
    return text

def convert_post_to_get(request_info, post_body):
    """Convert POST request to GET format"""
    if request_info['method'] != 'POST':
        return None
    
    # Parse the POST body
    params = parse_params(post_body)
    
    if not params:
        print(f"  No parameters found in POST body")
        return None
    
    # Encode parameters
    encoded_params = []
    for param, value in params:
        encoded_param = encode_param(param)
        encoded_value = encode_param(value)
        encoded_params.append(f"{encoded_param}={encoded_value}")
    
    # Join parameters
    query_string = '&'.join(encoded_params)
    
    # Construct the GET URL
    path = request_info['path']
    if '?' in path:
        # Path already has query parameters
        full_path = f"{path}&{query_string}"
    else:
        full_path = f"{path}?{query_string}"
    
    return {
        'method': 'GET',
        'path': full_path,
        'original_path': path,
        'query_string': query_string,
        'params': params
    }

def write_converted_request(output_dir, index, converted_info):
    """Write the converted GET request to output directory"""
    index_folder = os.path.join(output_dir, str(index))
    os.makedirs(index_folder, exist_ok=True)
    
    output_file = os.path.join(index_folder, 'get-request.txt')
    with open(output_file, 'w') as f:
        f.write(f"Method: GET\n")
        f.write(f"Path: {converted_info['path']}\n")
        f.write(f"Original Path: {converted_info['original_path']}\n")
        f.write(f"Query String: {converted_info['query_string']}\n")
        f.write(f"\nParameters:\n")
        for param, value in converted_info['params']:
            f.write(f"  {param} = {value}\n")
    
    return output_file

def process_cache_folder(cache_folder, output_dir):
    """Process a single cache folder"""
    cache_key_file = os.path.join(cache_folder, 'cache-key.txt')
    
    if not os.path.exists(cache_key_file):
        print(f"  No cache-key.txt found in {cache_folder}")
        return False
    
    # Parse cache key file
    request_info = parse_cache_key_file(cache_key_file)
    if not request_info:
        return False
    
    print(f"\nProcessing Index {request_info['index']}:")
    print(f"  Method: {request_info['method']}")
    print(f"  Path: {request_info['path']}")
    
    # Skip if not POST
    if request_info['method'] != 'POST':
        print(f"  Skipping - not a POST request")
        return False
    
    # Try to get POST body
    post_body = extract_post_body(cache_folder)
    if not post_body:
        # Try to extract from the cache-key file itself
        post_body = request_info.get('body')
    
    if not post_body:
        print(f"  Warning: No POST body found")
        # Check if there might be body data in the path (for debugging)
        if '?' in request_info['path']:
            print(f"  Note: Path contains query parameters already")
        return False
    
    print(f"  POST body: {post_body}")
    
    # Convert to GET
    converted = convert_post_to_get(request_info, post_body)
    if converted:
        output_file = write_converted_request(output_dir, request_info['index'], converted)
        print(f"  Converted to GET: {converted['path']}")
        print(f"  Saved to: {output_file}")
        return True
    
    return False

def main():
    args = parse_args()
    
    # Validate cache-repo path
    if not os.path.exists(args.cache_repo):
        print(f"Error: Cache-repo path not found: {args.cache_repo}")
        sys.exit(1)
    
    # Set output directory
    output_dir = args.output or 'cache-repo-get'
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"Reading from: {args.cache_repo}")
    print(f"Output to: {output_dir}")
    
    # Get all index folders
    index_folders = []
    for item in os.listdir(args.cache_repo):
        item_path = os.path.join(args.cache_repo, item)
        if os.path.isdir(item_path) and item.isdigit():
            if args.index is None or int(item) == args.index:
                index_folders.append((int(item), item_path))
    
    # Sort by index number
    index_folders.sort(key=lambda x: x[0])
    
    if not index_folders:
        print("No index folders found to process")
        sys.exit(1)
    
    print(f"Found {len(index_folders)} folders to process")
    
    # Process each folder
    success_count = 0
    skip_count = 0
    
    for index, folder_path in index_folders:
        if process_cache_folder(folder_path, output_dir):
            success_count += 1
        else:
            skip_count += 1
    
    # Summary
    print(f"\n{'='*50}")
    print("SUMMARY")
    print(f"{'='*50}")
    print(f"Total folders processed: {len(index_folders)}")
    print(f"Successfully converted: {success_count}")
    print(f"Skipped/Failed: {skip_count}")
    print(f"Output saved to: {output_dir}")

if __name__ == "__main__":
    main()
