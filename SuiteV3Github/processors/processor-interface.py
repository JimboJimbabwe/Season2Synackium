"""
Interface for test result processors
"""
from abc import ABC, abstractmethod

class ProcessorInterface(ABC):
    """Abstract base class for all test result processors"""
    
    @abstractmethod
    def process(self, data):
        """
        Process test results data.
        
        Args:
            data (dict): Raw JSON data
            
        Returns:
            dict: Processed data for rendering
        """
        pass
    
    def get_display_name(self):
        """
        Get the human-readable display name for this processor.
        
        Returns:
            str: Display name
        """
        return self.__class__.__name__.replace('Processor', '')
