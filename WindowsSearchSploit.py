#!/usr/bin/env python3
import os
import json
import requests
import argparse
import sys
from datetime import datetime
from colorama import init, Fore, Style

# Initialize colorama
init()

def ensure_directory_exists(directory):
    """Create directory if it doesn't exist"""
    if not os.path.exists(directory):
        os.makedirs(directory)

def load_json_data(json_file):
    """Load JSON data from a file"""
    try:
        with open(json_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Fore.RED}Error loading JSON file: {e}{Style.RESET_ALL}")
        sys.exit(1)

def search_exploitdb(query, limit=15):
    """
    Search Exploit-DB for exploits matching the query
    """
    url = "https://www.exploit-db.com/search"
    
    # Headers to make the request appear as an AJAX request
    headers = {
        "Accept": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "https://www.exploit-db.com/search",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    # DataTables parameters that are required for the request
    params = {
        "q": query,
        "draw": "1",
        "columns[0][data]": "date_published",
        "columns[0][name]": "date_published",
        "columns[0][searchable]": "true",
        "columns[0][orderable]": "true",
        "columns[0][search][value]": "",
        "columns[0][search][regex]": "false",
        "columns[1][data]": "download",
        "columns[1][name]": "download",
        "columns[1][searchable]": "false",
        "columns[1][orderable]": "false",
        "columns[1][search][value]": "",
        "columns[1][search][regex]": "false",
        "columns[2][data]": "application_md5",
        "columns[2][name]": "application_md5",
        "columns[2][searchable]": "true",
        "columns[2][orderable]": "false",
        "columns[2][search][value]": "",
        "columns[2][search][regex]": "false",
        "columns[3][data]": "verified",
        "columns[3][name]": "verified",
        "columns[3][searchable]": "true",
        "columns[3][orderable]": "false",
        "columns[3][search][value]": "",
        "columns[3][search][regex]": "false",
        "columns[4][data]": "description",
        "columns[4][name]": "description",
        "columns[4][searchable]": "true",
        "columns[4][orderable]": "false",
        "columns[4][search][value]": "",
        "columns[4][search][regex]": "false",
        "columns[5][data]": "type_id",
        "columns[5][name]": "type_id",
        "columns[5][searchable]": "true",
        "columns[5][orderable]": "false",
        "columns[5][search][value]": "",
        "columns[5][search][regex]": "false",
        "columns[6][data]": "platform_id",
        "columns[6][name]": "platform_id",
        "columns[6][searchable]": "true",
        "columns[6][orderable]": "false",
        "columns[6][search][value]": "",
        "columns[6][search][regex]": "false",
        "columns[7][data]": "author_id",
        "columns[7][name]": "author_id",
        "columns[7][searchable]": "false",
        "columns[7][orderable]": "false",
        "columns[7][search][value]": "",
        "columns[7][search][regex]": "false",
        "order[0][column]": "0",
        "order[0][dir]": "desc",
        "start": "0",
        "length": str(limit),
        "search[value]": "",
        "search[regex]": "false"
    }
    
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  # Raise an exception for HTTP errors
        
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}Error making request: {e}{Style.RESET_ALL}")
        return {"data": []}
    except json.JSONDecodeError:
        print(f"{Fore.RED}Error decoding JSON response{Style.RESET_ALL}")
        return {"data": []}

def format_exploit_data(exploit_data):
    """
    Format exploit data into a readable string
    """
    # Extract basic information
    exploit_id = exploit_data["id"]
    title = exploit_data["description"][1] if len(exploit_data["description"]) > 1 else "Unknown"
    date = exploit_data["date_published"]
    platform = exploit_data["platform"]["platform"]
    exploit_type = exploit_data["type"]["display"]
    author = exploit_data["author"]["name"]
    
    # Extract CVEs if available
    cves = []
    if "code" in exploit_data:
        for code in exploit_data["code"]:
            if code["code_type"] == "cve":
                cves.append(code["code"])
    
    # Format output
    output = f"{Fore.GREEN}ID: {Fore.YELLOW}{exploit_id}{Style.RESET_ALL}\n"
    output += f"{Fore.GREEN}Title: {Fore.WHITE}{title}{Style.RESET_ALL}\n"
    output += f"{Fore.GREEN}Date: {Fore.CYAN}{date}{Style.RESET_ALL}\n"
    output += f"{Fore.GREEN}Platform: {Fore.MAGENTA}{platform}{Style.RESET_ALL}\n"
    output += f"{Fore.GREEN}Type: {Fore.BLUE}{exploit_type}{Style.RESET_ALL}\n"
    output += f"{Fore.GREEN}Author: {Fore.WHITE}{author}{Style.RESET_ALL}\n"
    
    if cves:
        output += f"{Fore.GREEN}CVEs: {Fore.RED}{', '.join(cves)}{Style.RESET_ALL}\n"
    
    output += f"{Fore.GREEN}URL: {Fore.CYAN}https://www.exploit-db.com/exploits/{exploit_id}{Style.RESET_ALL}\n"
    
    return output

def process_nmap_results(json_data, output_dir, limit=10):
    """
    Process NMAP results and search for exploits
    """
    # Create output directory structure
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_base = os.path.join(output_dir, f"vulnerability_report_{timestamp}")
    ensure_directory_exists(output_base)
    
    # Create a summary report file
    summary_file = os.path.join(output_base, "summary_report.txt")
    
    with open(summary_file, 'w') as summary:
        summary.write(f"Vulnerability Report Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        summary.write("=" * 80 + "\n\n")
        
        # Process each IP in the JSON data
        for ip_entry in json_data:
            ip_address = ip_entry.get("IP", "Unknown")
            services = ip_entry.get("services", [])
            
            if not services:
                continue
                
            # Print info about this IP
            ip_info = f"IP: {ip_address} has {len(services)} service(s) associated with it\n"
            print(f"\n{Fore.CYAN}{ip_info}{Style.RESET_ALL}")
            summary.write(ip_info + "\n")
            summary.write("Services:\n")
            
            # Create an IP-specific directory
            ip_dir = os.path.join(output_base, ip_address.replace(".", "_"))
            ensure_directory_exists(ip_dir)
            
            # Collect product-version pairs for searching
            search_queries = []
            
            # Process each service for this IP
            for service in services:
                product = service.get("Product", "")
                version = service.get("Version", "")
                port = service.get("Port", "")
                protocol = service.get("Protocol", "")
                service_name = service.get("Service", "")
                
                if product or version:
                    # Add service info to summary
                    service_info = f"  - Service: {service_name} ({protocol}/{port})\n"
                    service_info += f"    Product: {product}\n"
                    service_info += f"    Version: {version}\n"
                    summary.write(service_info)
                    print(f"{Fore.YELLOW}{service_info}{Style.RESET_ALL}")
                    
                    # Prepare search query
                    if product and version:
                        search_query = f"{product} {version}"
                    elif product:
                        search_query = product
                    elif version:
                        search_query = version
                    else:
                        continue
                        
                    search_queries.append({
                        "query": search_query,
                        "product": product,
                        "version": version,
                        "service": service_name,
                        "port": port,
                        "protocol": protocol
                    })
            
            # Now search ExploitDB for each query
            for query_info in search_queries:
                query = query_info["query"]
                product = query_info["product"]
                version = query_info["version"]
                service_name = query_info["service"]
                port = query_info["port"]
                
                # Replace special characters in the query for the filename
                safe_query = query.replace("/", "_").replace("\\", "_").replace(" ", "_")
                output_file = os.path.join(ip_dir, f"{safe_query}_exploits.txt")
                
                # Inform user
                search_msg = f"\nSearching exploit database for: \"{query}\"\n"
                print(f"{Fore.GREEN}{search_msg}{Style.RESET_ALL}")
                summary.write(f"\n{search_msg}")
                
                # Search ExploitDB
                results = search_exploitdb(query, limit)
                
                # Process results
                with open(output_file, 'w') as f:
                    f.write(f"Exploit-DB Search Results for {query}\n")
                    f.write(f"Service: {service_name} on port {port}\n")
                    f.write("=" * 80 + "\n\n")
                    
                    if not results["data"]:
                        no_results = "No exploits found.\n"
                        f.write(no_results)
                        summary.write(no_results)
                        print(f"{Fore.YELLOW}{no_results}{Style.RESET_ALL}")
                        continue
                    
                    count = len(results["data"])
                    found_msg = f"Found {count} potential exploit(s).\n"
                    f.write(found_msg)
                    summary.write(found_msg)
                    print(f"{Fore.GREEN}{found_msg}{Style.RESET_ALL}")
                    
                    # Write each exploit to the file
                    for exploit in results["data"]:
                        exploit_text = format_exploit_data(exploit)
                        # Remove color codes for file output
                        clean_text = exploit_text.replace(Fore.GREEN, "").replace(Fore.YELLOW, "").replace(Fore.WHITE, "")
                        clean_text = clean_text.replace(Fore.CYAN, "").replace(Fore.MAGENTA, "").replace(Fore.BLUE, "")
                        clean_text = clean_text.replace(Fore.RED, "").replace(Style.RESET_ALL, "")
                        
                        f.write(clean_text + "\n")
                        f.write("-" * 50 + "\n")
                        
                        # Add basic info to summary
                        exploit_id = exploit["id"]
                        title = exploit["description"][1] if len(exploit["description"]) > 1 else "Unknown"
                        summary.write(f"  - {title} (ID: {exploit_id})\n")
                        
                        # Print to console
                        print(exploit_text)
                        print("-" * 50)
    
    print(f"\n{Fore.GREEN}Report generated in: {output_base}{Style.RESET_ALL}")
    return output_base

def main():
    parser = argparse.ArgumentParser(description='Search for exploits based on NMAP scan results')
    parser.add_argument('json_file', help='Path to the JSON file with NMAP results')
    parser.add_argument('-o', '--output-dir', default='vulnerability_reports', help='Directory to save reports (default: vulnerability_reports)')
    parser.add_argument('-l', '--limit', type=int, default=10, help='Maximum number of exploits to retrieve per service (default: 10)')
    
    args = parser.parse_args()
    
    # Load the JSON data
    json_data = load_json_data(args.json_file)
    
    # Process the data and generate reports
    output_dir = process_nmap_results(json_data, args.output_dir, args.limit)
    
    print(f"\n{Fore.GREEN}Complete! All reports saved to: {output_dir}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
