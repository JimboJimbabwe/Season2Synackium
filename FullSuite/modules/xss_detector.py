import os

def scan_for_pngs():
    # Get current directory
    base_dir = os.getcwd()
    
    # Get all subdirectories
    subdirs = [d for d in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, d))]
    
    # Create output file
    with open('png_list.txt', 'w') as f:
        for subdir in subdirs:
            # Get all PNGs in current subdirectory
            png_files = [f for f in os.listdir(os.path.join(base_dir, subdir)) 
                        if f.lower().endswith('.png')]
            
            if png_files:  # Only write directories that contain PNGs
                f.write(f"{subdir}:\n")
                for png in png_files:
                    f.write(f"{png}\n")
                f.write("\n")  # Add blank line between folders

if __name__ == "__main__":
    scan_for_pngs()
