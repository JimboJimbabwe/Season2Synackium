"""
File system utility functions for the Security Testing Directory Navigator
"""
from pathlib import Path

def sanitize_directory_name(name):
    """
    Sanitize directory name to be compatible with display purposes.
    
    Args:
        name (str): The directory name to sanitize
    
    Returns:
        str: Sanitized directory name for display
    """
    return name.replace('_', ' ')

def get_targets(base_dir):
    """
    Get all target directories (subfolders) in the base directory.
    
    Args:
        base_dir (Path): Base directory path
    
    Returns:
        list: List of target directory names
    """
    targets = []
    for item in base_dir.iterdir():
        if item.is_dir() and not item.name.startswith('.'):
            targets.append(item.name)
    return sorted(targets)

def get_categories(base_dir, target, section):
    """
    Get all categories in a target's section (Auth or raw).
    
    Args:
        base_dir (Path): Base directory path
        target (str): Target directory name
        section (str): Section name (Auth or raw)
        
    Returns:
        list: List of category directory names
    """
    categories = []
    section_path = base_dir / target / section
    
    if section_path.exists():
        for item in section_path.iterdir():
            if item.is_dir():
                categories.append(item.name)
    
    return sorted(categories)

def get_test_types(base_dir, target, section, category):
    """
    Get all test types in a category.
    
    Args:
        base_dir (Path): Base directory path
        target (str): Target directory name
        section (str): Section name (Auth or raw)
        category (str): Category directory name
        
    Returns:
        list: List of test type directory names
    """
    test_types = []
    test_path = base_dir / target / section / category
    
    if test_path.exists():
        for item in test_path.iterdir():
            if item.is_dir():
                test_types.append(item.name)
    
    return sorted(test_types)

def get_results_files(base_dir, target, section, category, test_type):
    """
    Get all JSON files in a test type's results directory.
    
    Args:
        base_dir (Path): Base directory path
        target (str): Target directory name
        section (str): Section name (Auth or raw)
        category (str): Category directory name
        test_type (str): Test type directory name
        
    Returns:
        list: List of JSON file names
    """
    results_path = base_dir / target / section / category / test_type / "results"
    json_files = []
    
    if results_path.exists():
        for item in results_path.glob("*.json"):
            if item.is_file():
                json_files.append(item.name)
    
    return sorted(json_files)
