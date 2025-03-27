import os
import json
import subprocess
import argparse

def run_tests(base_path, json_config_path, targets_folder):
    # Load the test configuration
    with open(json_config_path, 'r') as f:
        test_config = json.load(f)
    
    # Get list of targets from the targets folder
    targets = [d for d in os.listdir(os.path.join(base_path, targets_folder)) 
               if os.path.isdir(os.path.join(base_path, targets_folder, d))]
    
    # Authentication modes
    auth_modes = ["Auth", "Raw"]
    
    # Iterate through all combinations
    for target in targets:
        for auth_mode in auth_modes:
            # Build XML path - assumes XML file is named after the auth mode
            xml_path = os.path.join(base_path, targets_folder, target, auth_mode, f"{auth_mode.lower()}.xml")
            
            # Check if XML file exists before proceeding
            if not os.path.exists(xml_path):
                print(f"Warning: XML file not found: {xml_path}")
                continue
                
            # Iterate through categories and test types
            for category, category_data in test_config.items():
                for test in category_data["tests"]:
                    test_type = test["testType"]
                    script = test["script"]
                    
                    # Skip if no script is specified for this test
                    if not script:
                        print(f"Skipping {category} - {test_type}: No script specified")
                        continue
                    
                    # Build the command
                    cmd = [
                        "python", 
                        script,
                        "--base-path", base_path,
                        "--target", target,
                        "--auth-mode", auth_mode,
                        "--category", category,
                        "--test-type", test_type,
                        "--xml", xml_path
                    ]
                    
                    # Print and execute the command
                    print("=" * 80)
                    print(f"Running: {' '.join(cmd)}")
                    print("=" * 80)
                    
                    try:
                        # Execute the script
                        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                        
                        # Print output
                        print(result.stdout)
                        
                        if result.stderr:
                            print("ERRORS:")
                            print(result.stderr)
                            
                    except subprocess.CalledProcessError as e:
                        print(f"Error executing {script}:")
                        print(e.stderr)
                    except Exception as e:
                        print(f"Failed to run {script}: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Testing Automation")
    parser.add_argument("--base-path", required=True, help="Base path for all operations")
    parser.add_argument("--config", default="test_config.json", help="Path to test configuration JSON")
    parser.add_argument("--targets", default="targets", help="Name of the targets folder under base path")
    
    args = parser.parse_args()
    
    run_tests(args.base_path, args.config, args.targets)
