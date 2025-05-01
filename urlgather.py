import aiohttp
import asyncio
import socket
from netaddr import IPNetwork, IPAddress, iter_iprange
import argparse
from colorama import Fore, Style
import atexit
from functools import lru_cache

found_urls = set()
output_file = None
VERBOSE = False

def log(message, level="i", verbose=False):
    if verbose and not VERBOSE:
        return
    
    levels = {
        "i": f"{Fore.LIGHTBLUE_EX}[*]{Style.RESET_ALL}",
        "s": f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL}",
        "w": f"{Fore.LIGHTYELLOW_EX}[!]{Style.RESET_ALL}",
        "e": f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}",
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
    global output_file
    if output_file:
        try:
            output_file.close()
            log("Output file closed successfully", "s")
        except Exception as e:
            log(f"Error closing output file: {str(e)}", "e")

async def save_url(url):
    global found_urls, output_file
    if url not in found_urls:
        found_urls.add(url)
        if output_file:
            try:
                output_file.write(url + '\n')
                output_file.flush()
            except Exception as e:
                log(f"Error saving URL: {str(e)}", "e")

@lru_cache(maxsize=10000)
async def resolve_dns(ip):
    try:
        hostname, _, _ = await asyncio.get_event_loop().run_in_executor(
            None, 
            lambda: socket.gethostbyaddr(ip)
        )
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        return None

async def check_http(session, hostname, timeout=3):
    for scheme in ['https', 'http']:
        url = f"{scheme}://{hostname}"
        try:
            async with session.get(url, timeout=timeout, ssl=False) as response:
                if response.status < 400:
                    return str(response.url)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            continue
    return None

async def process_ip(session, ip, args):
    hostname = await resolve_dns(ip)
    if not hostname:
        if VERBOSE:
            log(f"No DNS for {ip} - Skipped", "w", True)
        return None
    
    final_url = await check_http(session, hostname, args.timeout)
    if final_url:
        return final_url
    
    return None

async def batch_process(session, ip_batch, args):
    tasks = [process_ip(session, ip, args) for ip in ip_batch]
    return await asyncio.gather(*tasks)

async def scan_ips(ip_generator, args):
    connector = aiohttp.TCPConnector(
        limit=args.threads,
        limit_per_host=10,
        force_close=True,
        enable_cleanup_closed=True
    )
    timeout = aiohttp.ClientTimeout(total=args.timeout)
    
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={'User-Agent': 'Mozilla/5.0'}
    ) as session:
        
        batch_size = args.threads * 2
        ip_batch = []
        processed = 0
        
        async for ip in ip_generator:
            ip_batch.append(ip)
            processed += 1
            
            if len(ip_batch) >= batch_size:
                results = await batch_process(session, ip_batch, args)
                for url in results:
                    if url:
                        await save_url(url)
                        log(f"Found: {url}", "s", True)
                
                ip_batch = []
                
                if processed % 1000 == 0:
                    log(f"Processed {processed} IPs - Found {len(found_urls)} URLs", "i", True)
        
        if ip_batch:
            results = await batch_process(session, ip_batch, args)
            for url in results:
                if url:
                    await save_url(url)

    return processed

async def ip_range_generator(ip_input):
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

async def async_main():
    global output_file, found_urls, VERBOSE
    
    show_banner()
    
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  Fast scan:
    python scanner.py 192.168.1.0/24 -t 50
  
  Large network:
    python scanner.py 10.0.0.0/16 -o urls.txt -t 100 -to 3""")
    
    parser.add_argument('ip_range', help='IP range (CIDR or start-end)')
    parser.add_argument('-t', '--threads', type=int, default=50,
                      help='Thread count (default: 50)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Show detailed scanning progress')
    parser.add_argument('-to', '--timeout', type=int, default=5,
                      help='Connection timeout in seconds (default: 5)')
    
    args = parser.parse_args()
    VERBOSE = args.verbose
    
    atexit.register(cleanup_resources)
    
    try:
        if args.output:
            output_file = open(args.output, 'w')
        
        log(f"IP Range: {args.ip_range}", "i")
        log(f"Threads: {args.threads}", "i")
        log(f"Timeout: {args.timeout}s", "i")
        log(f"Output File: {args.output or 'None'}", "i")
        log(f"Verbose: {'Enabled' if args.verbose else 'Disabled'}\n", "i")
        
        ip_gen = ip_range_generator(args.ip_range)
        total_processed = await scan_ips(ip_gen, args)
        
        log(f"Scan completed. Processed {total_processed} IPs", "i")
        log(f"Found {len(found_urls)} unique URLs", "i")
        if args.output:
            log(f"Results saved to {args.output}", "i")
    
    except KeyboardInterrupt:
        log("Scan interrupted by user", "w")
        log(f"Saved {len(found_urls)} URLs before interruption", "i")
        if args.output:
            log(f"Results saved to {args.output}", "i")
    except Exception as e:
        log(f"Error: {str(e)}", "e")
        parser.print_help()

def main():
    asyncio.run(async_main())

if __name__ == "__main__":
    main()