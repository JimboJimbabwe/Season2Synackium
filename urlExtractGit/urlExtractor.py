from bs4 import BeautifulSoup
import re
import sys
from urllib.parse import urljoin, urlparse
from datetime import datetime

class URLExtractor:
    def __init__(self, base_url=None):
        self.base_url = base_url
        self.found_urls = set()
        
    def normalize_url(self, url):
        """Normalize URLs and handle relative paths"""
        if not url:
            return None
            
        # Remove whitespace and common unwanted prefixes
        url = url.strip()
        url = url.replace('\\', '/')  # Handle escaped backslashes
        
        # Filter out javascript: and data: URLs
        if url.startswith(('javascript:', 'data:', 'mailto:', 'tel:', '#')):
            return None
            
        # Handle relative URLs if base_url is provided
        if self.base_url and not urlparse(url).netloc:
            return urljoin(self.base_url, url)
            
        return url

    def extract_from_attributes(self, soup):
        """Extract URLs from common HTML attributes"""
        # Dictionary of elements and their URL-containing attributes
        elements_attrs = {
            'a': ['href'],
            'link': ['href'],
            'script': ['src'],
            'img': ['src', 'srcset'],
            'form': ['action'],
            'video': ['src', 'poster'],
            'audio': ['src'],
            'object': ['data'],
            'source': ['src', 'srcset'],
            'iframe': ['src'],
            'embed': ['src'],
            'meta': ['content']  # Will filter for relevant meta tags
        }
        
        for tag, attrs in elements_attrs.items():
            for element in soup.find_all(tag):
                for attr in attrs:
                    url = element.get(attr)
                    if url:
                        # Handle srcset attribute which may contain multiple URLs
                        if attr == 'srcset':
                            urls = url.split(',')
                            for srcset_url in urls:
                                # Extract URL from srcset format (ignore size)
                                src_url = srcset_url.strip().split(' ')[0]
                                normalized_url = self.normalize_url(src_url)
                                if normalized_url:
                                    self.found_urls.add(normalized_url)
                        else:
                            normalized_url = self.normalize_url(url)
                            if normalized_url:
                                self.found_urls.add(normalized_url)

    def extract_from_inline_js(self, soup):
        """Extract URLs from inline JavaScript"""
        # Common patterns for URLs in JavaScript
        js_patterns = [
            r'(?:"|\'|`)(\/[^\/][a-zA-Z0-9_\/-]*\.(?:php|html|js|css|jsp|do|aspx))["|\'|`]',  # Paths with extensions
            r'(?:"|\'|`)(\/api\/[^"\'`]*)["|\'|`]',  # API endpoints
            r'(?:"|\'|`)(\/v\d+\/[^"\'`]*)["|\'|`]',  # Versioned endpoints
            r'url:\s*["|\'|`]([^"\'`]+)["|\'|`]',  # URL properties
            r'fetch\(["|\'|`]([^"\'`]+)["|\'|`]\)',  # Fetch calls
            r'axios\.(?:get|post|put|delete|patch)\(["|\'|`]([^"\'`]+)["|\'|`]\)'  # Axios calls
        ]
        
        # Find all script tags
        for script in soup.find_all('script'):
            if script.string:  # Only process scripts with content
                for pattern in js_patterns:
                    matches = re.findall(pattern, script.string)
                    for url in matches:
                        normalized_url = self.normalize_url(url)
                        if normalized_url:
                            self.found_urls.add(normalized_url)

    def extract_from_styles(self, soup):
        """Extract URLs from CSS and style attributes"""
        # Find URLs in style tags and style attributes
        css_url_pattern = r'url\(["\']?([^"\'()]+)["\']?\)'
        
        # Check style tags
        for style in soup.find_all('style'):
            if style.string:
                matches = re.findall(css_url_pattern, style.string)
                for url in matches:
                    normalized_url = self.normalize_url(url)
                    if normalized_url:
                        self.found_urls.add(normalized_url)
        
        # Check style attributes
        for element in soup.find_all(style=True):
            matches = re.findall(css_url_pattern, element['style'])
            for url in matches:
                normalized_url = self.normalize_url(url)
                if normalized_url:
                    self.found_urls.add(normalized_url)

    def extract_from_framework_specific(self, soup):
        """Extract URLs from common framework-specific attributes"""
        framework_attrs = [
            'routerlink',  # Angular
            'to',         # React Router
            'data-url',   # Common custom attribute
            'ng-href',    # AngularJS
            'ui-sref',    # AngularJS UI-Router
        ]
        
        for attr in framework_attrs:
            for element in soup.find_all(attrs={attr: True}):
                url = element[attr]
                normalized_url = self.normalize_url(url)
                if normalized_url:
                    self.found_urls.add(normalized_url)

    def process_html(self, html_content):
        """Process HTML content and extract URLs"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract URLs from various sources
        self.extract_from_attributes(soup)
        self.extract_from_inline_js(soup)
        self.extract_from_styles(soup)
        self.extract_from_framework_specific(soup)
        
        return sorted(self.found_urls)

def main():
    # Get input and output file paths
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_html_file> <output_file>")
        sys.exit(1)
        
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        # Read HTML content
        with open(input_file, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Extract base URL if available (from base tag or first URL)
        soup = BeautifulSoup(html_content, 'html.parser')
        base_tag = soup.find('base', href=True)
        base_url = base_tag['href'] if base_tag else None
        
        # Process HTML
        extractor = URLExtractor(base_url)
        urls = extractor.process_html(html_content)
        
        # Write results to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(f"URL Extraction Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Source file: {input_file}\n")
            if base_url:
                f.write(f"Base URL: {base_url}\n")
            f.write(f"\nFound {len(urls)} unique URLs:\n\n")
            
            for url in urls:
                f.write(f"{url}\n")
                
        print(f"Successfully extracted {len(urls)} URLs to {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Could not find input file {input_file}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
