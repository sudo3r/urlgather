import requests
import sys
import socket
import argparse
import concurrent.futures
import warnings
from netaddr import IPNetwork, IPAddress, iter_iprange
from urllib.parse import urlparse
from colorama import Fore, Style
import atexit

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

found_urls = set()
output_file = None
file_lock = None
VERBOSE = False

def log(message, level="i", verbose=False):
    if verbose and not VERBOSE:
        return
    
    levels = {
        "i": f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL}",  # info
        "s": f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL}",  # success
        "w": f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL}",  # warning
        "e": f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}",  # error
    }
    print(f"{levels.get(level, levels['i'])} {message}")

def show_banner():
    print(Fore.LIGHTBLUE_EX + r"""
  _____     _ _____     _   _           
 |  |  |___| |   __|___| |_| |_ ___ ___ 
 |  |  |  _| |  |  | .'|  _|   | -_|  _|
 |_____|_| |_|_____|__,|_| |_|_|___|_|

""" + Fore.RESET + "   [ URL Gathering Tool ]\n")

def cleanup_resources():
    global output_file, file_lock
    if output_file:
        try:
            output_file.close()
            log("Output file closed successfully", "s")
        except Exception as e:
            log(f"Error closing output file: {str(e)}", "e")
    if file_lock:
        file_lock.shutdown(wait=True)

def save_url(url):
    global found_urls, output_file, file_lock
    if url not in found_urls:
        found_urls.add(url)
        if output_file:
            try:
                future = file_lock.submit(lambda: output_file.write(url + '\n'))
                future.add_done_callback(lambda f: f.result())
                output_file.flush()
            except Exception as e:
                log(f"Error saving URL: {str(e)}", "e")

def ip_range_generator(ip_input):
    if '/' in ip_input:
        network = IPNetwork(ip_input)
        for ip in network:
            yield str(ip)
    elif '-' in ip_input:
        start_ip, end_ip = ip_input.split('-')
        start = IPAddress(start_ip.strip())
        end = IPAddress(end_ip.strip())
        for ip in iter_iprange(start, end):
            yield str(ip)
    else:
        yield ip_input

def resolve_dns(ip):
    try:
        hostnames = socket.gethostbyaddr(ip)
        return hostnames[0], hostnames[1]
    except (socket.herror, socket.gaierror):
        return None, []

def verify_connection(url, timeout=3):
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        if response.status_code < 400:
            return response.url
    except (requests.exceptions.RequestException, requests.exceptions.Timeout):
        pass
    return None

def check_web_service(ip, ports=[80, 443, 8080, 8443], schemes=['http', 'https']):
    for port in ports:
        for scheme in schemes:
            url = f"{scheme}://{ip}:{port}"
            final_url = verify_connection(url)
            if final_url:
                return final_url
    return None

def process_ip(ip, args):
    results = set()
    
    if args.check_ip:
        direct_url = check_web_service(ip)
        if direct_url:
            log(f"Direct access: {direct_url}", "s", True)
            results.add(direct_url)
    
    primary_host, aliases = resolve_dns(ip)
    hostnames = [primary_host] + aliases if primary_host else []
    
    for host in hostnames:
        if host:
            for scheme in ['http', 'https']:
                domain_url = f"{scheme}://{host}"
                final_url = verify_connection(domain_url, args.timeout)
                if final_url:
                    parsed = urlparse(final_url)
                    if parsed.hostname == host:
                        log(f"Verified domain: {final_url} (from {ip})", "s", True)
                        results.add(final_url)
                        break
    
    return results

def scan_ips(ip_generator, args):
    global found_urls
    processed = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = []
        
        for ip in ip_generator:
            futures.append(executor.submit(process_ip, ip, args))
            processed += 1
            
            if len(futures) >= args.threads * 2:
                for future in concurrent.futures.as_completed(futures):
                    try:
                        urls = future.result()
                        for url in urls:
                            save_url(url)
                    except Exception as e:
                        log(f"Error processing IP: {str(e)}", "e", True)
                    futures.remove(future)
                    break
            
            if processed % 1000 == 0:
                log(f"Processed {processed} IPs - Found {len(found_urls)} URLs", "i", True)
        
        for future in concurrent.futures.as_completed(futures):
            try:
                urls = future.result()
                for url in urls:
                    save_url(url)
            except Exception as e:
                log(f"Error: {str(e)}", "e", True)
    
    return processed

def main():
    global output_file, file_lock, found_urls, VERBOSE
    
    show_banner()
    
    parser = argparse.ArgumentParser(
        description='Domain discovery from IP ranges',
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  Find domains in range and verify connections
    python scanner.py 192.168.1.0/24 -v
  
  Scan large network and save results
    python scanner.py 10.0.0.0/16 -o domains.txt
  
  Fast scan with 100 threads
    python scanner.py 52.0.0.0/8 -t 100 --no-ip-check""")
    
    parser.add_argument('ip_range', help='IP range (CIDR or start-end)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                      help='Thread count (default: 50)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show detailed scanning progress')
    parser.add_argument('-to', '--timeout', type=int, default=3,
                      help='Connection timeout in seconds (default: 3)')
    parser.add_argument('--no-ip-check', dest='check_ip', action='store_false',
                      help='Skip direct IP access checking')
    
    args = parser.parse_args()
    VERBOSE = args.verbose
    
    atexit.register(cleanup_resources)
    
    try:
        ip_gen = ip_range_generator(args.ip_range)
        
        log(f"Starting scan with {args.threads} threads", "i")
        if '/' in args.ip_range:
            net = IPNetwork(args.ip_range)
            log(f"Scanning network: {net} ({net.size} IPs)", "i")
        
        if args.output:
            output_file = open(args.output, 'w')
        
        file_lock = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        
        total_processed = scan_ips(ip_gen, args)
        
        log(f"Scan completed. Processed {total_processed} IPs", "i")
        log(f"Found {len(found_urls)} unique URLs", "i")
        if args.output:
            log(f"Results saved to {args.output}", "i")
    
    except KeyboardInterrupt:
        log("Scan interrupted by user", "w")
        log(f"Saved {len(found_urls)} URLs before interruption", "i")
        if args.output:
            log(f"Results saved to {args.output}", "i")
        sys.exit(1)
    except Exception as e:
        log(f"Error: {str(e)}", "e")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
