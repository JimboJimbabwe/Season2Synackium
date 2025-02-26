import argparse

def search_file(input_filename, output_filename):
    # Get the search string from user
    search_term = input("Enter the string to search for: ")
    
    try:
        # Store matching lines
        matching_lines = []
        
        # Open and read the input file line by line
        with open(input_filename, 'r') as file:
            # Read line by line and check for matches
            for line_number, line in enumerate(file, 1):
                # Check if line starts with https:// AND contains search term
                if line.strip().startswith('https://') and search_term in line:
                    matching_lines.append(line.strip())
        
        # Write matching lines to output file
        with open(output_filename, 'w') as outfile:
            for line in matching_lines:
                outfile.write(line + '\n')
            
        # Print results
        if matching_lines:
            print(f"\nFound {len(matching_lines)} matches.")
            print(f"Results have been saved to {output_filename}")
        else:
            print(f"\nNo matches found for lines starting with 'https://' and containing '{search_term}'")
                
    except FileNotFoundError:
        print(f"Error: File '{input_filename}' not found.")

if __name__ == "__main__":
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Search for URLs in a text file')
    parser.add_argument('-f', '--file', type=str, required=True,
                      help='Input file to search through')
    parser.add_argument('-o', '--output', type=str, default='sitemap.txt',
                      help='Output file name (default: sitemap.txt)')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Run the search
    search_file(args.file, args.output)
