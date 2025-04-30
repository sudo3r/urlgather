# urlgather
Automatic URL gathering from IP ranges
## Usage
```
usage: urlgather.py [-h] [-t THREADS] [-o OUTPUT] [-v] [-to TIMEOUT] [--no-ip-check] ip_range

Domain discovery and verification from IP ranges

positional arguments:
  ip_range              IP range (CIDR or start-end)

options:
  -h, --help            show this help message and exit
  -t, --threads THREADS
                        Thread count (default: 50)
  -o, --output OUTPUT   Output file for results
  -v, --verbose         Show detailed scanning progress
  -to, --timeout TIMEOUT
                        Connection timeout in seconds (default: 3)
  --no-ip-check         Skip direct IP access checking

Examples:
  # Find domains in range and verify connections
  python scanner.py 192.168.1.0/24 -v
  
  # Scan large network and save results
  python scanner.py 10.0.0.0/16 -o domains.txt
  
  # Fast scan with 100 threads
  python scanner.py 52.0.0.0/8 -t 100 --no-ip-check
```
