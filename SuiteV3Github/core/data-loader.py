"""
Data loading utilities for the Security Testing Directory Navigator
"""
import json
from pathlib import Path

def load_json_data(base_dir, target, section, category, test_type, filename):
    """
    Load JSON data from a results file.
    
    Args:
        base_dir (Path): Base directory path
        target (str): Target directory name
        section (str): Section name (Auth or raw)
        category (str): Category directory name
        test_type (str): Test type directory name
        filename (str): JSON file name
        
    Returns:
        dict: JSON data or error dictionary
    """
    file_path = base_dir / target / section / category / test_type / "results" / filename
    
    if file_path.exists():
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            return {"error": f"Invalid JSON format: {str(e)}"}
        except Exception as e:
            return {"error": f"Failed to load JSON: {str(e)}"}
    
    return {"error": "File not found"}
