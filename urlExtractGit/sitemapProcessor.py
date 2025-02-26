import subprocess
import argparse
from pathlib import Path
import time
import os

def curl_urls(input_filename, output_dir):
    try:
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Counter for output files
        file_counter = 1
        
        # Read input file
        with open(input_filename, 'r') as file:
            for line in file:
                url = line.strip()
                if url:  # Only process non-empty lines
                    try:
                        # Execute curl command and capture output
                        result = subprocess.run(['curl', '-k', url], 
                                             capture_output=True, 
                                             text=True)
                        
                        # Create output filename with full path
                        output_filename = os.path.join(output_dir, f'sitemap{file_counter}.txt')
                        with open(output_filename, 'w') as outfile:
                            outfile.write(result.stdout)
                        
                        print(f"Processed {url} -> {output_filename}")
                        file_counter += 1
                        
                        # Wait 10 seconds before next request
                        if file_counter > 1:  # If there are more lines to process
                            print("Waiting 10 seconds before next request...")
                            time.sleep(10)
                            
                    except subprocess.SubprocessError as e:
                        print(f"Error processing {url}: {e}")
                        
    except FileNotFoundError:
        print(f"Error: File '{input_filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Curl URLs from a text file')
    parser.add_argument('-f', '--file', type=str, default='sitemap.txt',
                      help='Input file containing URLs (default: sitemap.txt)')
    parser.add_argument('-d', '--directory', type=str, default='output',
                      help='Output directory for files (default: output)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Run the curl operations
    curl_urls(args.file, args.directory)
