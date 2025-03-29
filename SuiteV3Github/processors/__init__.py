"""
Processor factory module for test result processors
"""
from processors.xpath_processor import XPathProcessor
from processors.sql_processor import SQLProcessor
from processors.url_parameters_processor import URLParametersProcessor
# Import other processors here

class ProcessorFactory:
    """Factory for creating processor instances"""
    
    # Map test types to their processor classes
    _PROCESSOR_MAP = {
        "XPath_XQuery Injection": XPathProcessor,
        "SQL Injection": SQLProcessor,
        "URL Parameters": URLParametersProcessor,
        # Add other processor mappings here
    }
    
    @classmethod
    def get_processor(cls, test_type):
        """
        Get the appropriate processor for a test type.
        
        Args:
            test_type (str): Test type name
            
        Returns:
            ProcessorInterface: Processor instance
        """
        processor_class = cls._PROCESSOR_MAP.get(test_type)
        if processor_class:
            return processor_class()
        
        # Return default processor for unknown test types
        return DefaultProcessor()


class DefaultProcessor:
    """Default processor for unknown test types"""
    
    def process(self, data):
        """
        Process data with no specific transformation.
        
        Args:
            data (dict): JSON data
            
        Returns:
            dict: Unmodified data
        """
        return data
    
    def get_display_name(self):
        return "Default"
