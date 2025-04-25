# Url gathering tool
# @R00TUS3R

import requests, sys
from netaddr import *

print("""
  _____     _ _____     _   _           
 |  |  |___| |   __|___| |_| |_ ___ ___ 
 |  |  |  _| |  |  | .'|  _|   | -_|  _|
 |_____|_| |_|_____|__,|_| |_|_|___|_|

""", file=sys.stderr)

def usage():
    print("[*] Usage: python urlgather.py <ip range>\n[*] Ex: python urlgather.py 192.168.0.0 192.168.0.255\n", file=sys.stderr)

def get_range(start_ip, end_ip):
    start = int(IPAddress(start_ip))
    end = int(IPAddress(end_ip))
    ip_list = []
    for ip in range(start, end + 1):
        ip_list.append(str(IPAddress(ip)))
    return ip_list

def check_url(domain):
    try:
        url = f"https://{domain}"
        requests.get(url)
        return url
    except:
        try:
            url = f"http://{domain}"
            requests.get(url)
            return url
        except:
            return None

def get_url(ip):
    response = requests.get(f"https://internetdb.shodan.io/{ip}").json()
    if len(response) == 6 and len(response["hostnames"]) != 0:
        for domain in response["hostnames"]:
            url = check_url(domain)
            if url != None:
                print(url)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()
    else:
        ip_list = get_range(sys.argv[1], sys.argv[2])
        for ip in ip_list:
            get_url(ip)
