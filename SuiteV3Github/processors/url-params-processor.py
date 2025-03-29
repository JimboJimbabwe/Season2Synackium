"""
Processor for URL parameters test results
"""
from processors.processor_interface import ProcessorInterface

class URLParametersProcessor(ProcessorInterface):
    """Processor for URL parameters test results"""
    
    def process(self, data):
        """
        Process URL parameters test results.
        
        Args:
            data (dict): JSON data
            
        Returns:
            dict: Processed data for rendering
        """
        processed = {
            "urls": []
        }
        
        # Process each URL
        if "urls" in data:
            for idx, url_data in enumerate(data["urls"]):
                url_info = {
                    "index": idx,
                    "url": url_data.get("url", "Unknown"),
                    "method": url_data.get("method", "GET"),
                    "parameter_count": len(url_data.get("parameters", [])),
                    "parameters": url_data.get("parameters", [])
                }
                processed["urls"].append(url_info)
        
        # Add test type for the renderer
        processed["test_type"] = "URL Parameters"
        
        return processed
    
    def get_display_name(self):
        return "URL Parameters"
