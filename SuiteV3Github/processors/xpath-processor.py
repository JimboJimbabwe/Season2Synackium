"""
Processor for XPath/XQuery injection test results
"""
from processors.processor_interface import ProcessorInterface

class XPathProcessor(ProcessorInterface):
    """Processor for XPath/XQuery injection test results"""
    
    def process(self, data):
        """
        Process XPath test results.
        
        Args:
            data (dict): JSON data
            
        Returns:
            dict: Processed data for rendering
        """
        processed = {
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "vulnerable_parameters": data.get("vulnerable_parameters", {}),
            "request_count": data.get("request_count", 0),
            "requests_with_vulnerable_params": data.get("requests_with_vulnerable_params", 0),
            "total_vulnerable_params": data.get("total_vulnerable_params", 0),
            "high_risk_count": data.get("high_risk_count", 0),
            "medium_risk_count": data.get("medium_risk_count", 0),
            "low_risk_count": data.get("low_risk_count", 0),
            "requests": data.get("requests", [])
        }
        
        return processed
    
    def get_display_name(self):
        return "XPath/XQuery Injection"
