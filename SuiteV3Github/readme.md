# Security Testing Directory Navigator

A modular application for navigating and visualizing security testing results.

## Project Structure

The application is organized into a modular architecture:

```
pentest_auditor/
├── main.py                    # Application entry point
├── config.py                  # Configuration settings
├── gui/                       # GUI components
│   ├── __init__.py
│   ├── app.py                 # Main application window
│   ├── navigation.py          # Tree navigation components
│   ├── content_view.py        # Content display components
│   └── renderers/             # Specialized renderers for different test types
│       ├── __init__.py
│       ├── base_renderer.py   # Base renderer class
│       ├── xpath_renderer.py
│       └── ...
├── core/                      # Core utilities
│   ├── __init__.py
│   ├── file_utils.py          # File system operations
│   └── data_loader.py         # JSON loading and handling
└── processors/                # Data processors
    ├── __init__.py
    ├── processor_interface.py # Define interface for all processors
    ├── xpath_processor.py
    └── ...
```

## Running the Application

```bash
python main.py --dir /path/to/test/results
```

## How It Works

1. The application scans the specified directory for test results
2. The navigation tree allows browsing through targets, sections, categories, test types, and result files
3. When a result file is selected, the data is loaded, processed, and rendered in a specialized view
4. Raw JSON data is always available in the "Raw JSON" tab

## Extending the Application

### Adding a New Test Type Processor

1. Create a new processor class in the `processors/` directory (e.g., `my_scan_processor.py`)
2. Implement the `ProcessorInterface` abstract class
3. Add the processor to the `_PROCESSOR_MAP` in `processors/__init__.py`

Example:

```python
# processors/my_scan_processor.py
from processors.processor_interface import ProcessorInterface

class MyScanProcessor(ProcessorInterface):
    def process(self, data):
        processed = {
            # Process the data as needed
            "title": data.get("title", ""),
            "custom_field": data.get("field", "default_value"),
            # ...
        }
        return processed
    
    def get_display_name(self):
        return "My Custom Scan"
```

```python
# Update processors/__init__.py
from processors.my_scan_processor import MyScanProcessor

# Update the processor map
_PROCESSOR_MAP = {
    # ...
    "My Custom Scan": MyScanProcessor,
    # ...
}
```

### Adding a New Renderer

1. Create a new renderer class in the `gui/renderers/` directory (e.g., `my_scan_renderer.py`)
2. Inherit from `BaseRenderer` and implement the `render_content` method
3. Add the renderer to the `_RENDERER_MAP` in `gui/renderers/__init__.py`

Example:

```python
# gui/renderers/my_scan_renderer.py
import customtkinter as ctk
from gui.renderers.base_renderer import BaseRenderer

class MyScanRenderer(BaseRenderer):
    def render_content(self):
        # Create header
        self.create_header("My Custom Scan Results")
        
        # Render specific sections
        if self.processed_data.get("title"):
            title_frame = self.create_section_frame()
            title_label = ctk.CTkLabel(
                title_frame,
                text=f"Title: {self.processed_data.get('title')}",
                font=("Arial", 14, "bold")
            )
            title_label.pack(anchor="w", pady=5, padx=10)
        
        # Render custom fields
        if self.processed_data.get("custom_field"):
            custom_frame = self.create_section_frame()
            custom_label = ctk.CTkLabel(
                custom_frame,
                text=f"Custom Field: {self.processed_data.get('custom_field')}",
                font=("Arial", 12)
            )
            custom_label.pack(anchor="w", pady=5, padx=10)
```

```python
# Update gui/renderers/__init__.py
from gui.renderers.my_scan_renderer import MyScanRenderer

# Update the renderer map
_RENDERER_MAP = {
    # ...
    "My Custom Scan": MyScanRenderer,
    # ...
}
```

## Benefits of This Architecture

1. **Separation of Concerns**: UI is separate from data processing
2. **Extensibility**: Easy to add new test types and renderers
3. **Maintainability**: Each component has a clear responsibility
4. **Code Reuse**: Common functionality is shared through base classes
