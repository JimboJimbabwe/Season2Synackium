"""
Renderer factory module
"""
from gui.renderers.xpath_renderer import XPathRenderer
# Import other renderers here

class RendererFactory:
    """Factory for creating renderer instances"""
    
    # Map test types to their renderer classes
    _RENDERER_MAP = {
        "XPath_XQuery Injection": XPathRenderer,
        # Add other renderer mappings here
    }
    
    @classmethod
    def get_renderer(cls, test_type, parent_frame):
        """
        Get the appropriate renderer for a test type.
        
        Args:
            test_type (str): Test type name
            parent_frame: Parent frame for the renderer
            
        Returns:
            BaseRenderer: Renderer instance
        """
        renderer_class = cls._RENDERER_MAP.get(test_type)
        if renderer_class:
            return renderer_class(parent_frame)
        
        # Use fallback renderer for test types without specific renderers
        from gui.renderers.default_renderer import DefaultRenderer
        return DefaultRenderer(parent_frame)
