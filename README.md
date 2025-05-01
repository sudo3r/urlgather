# urlgather
Automatic URL gathering from IP ranges
## Usage

### Installation
```shell
pip install -r requirements.txt
```
### Options
```
  _____     _ _____     _   _           
 |  |  |___| |   __|___| |_| |_ ___ ___ 
 |  |  |  _| |  |  | .'|  _|   | -_|  _|
 |_____|_| |_|_____|__,|_| |_|_|___|_|

   [ URL Gathering Tool ]

usage: urlgather.py [-h] [-t THREADS] [-o OUTPUT] [-v] [-to TIMEOUT] ip_range

positional arguments:
  ip_range              IP range (CIDR or start-end)

options:
  -h, --help            show this help message and exit
  -t, --threads THREADS
                        Thread count (default: 50)
  -o, --output OUTPUT   Output file for results
  -v, --verbose         Show detailed scanning progress
  -to, --timeout TIMEOUT
                        Connection timeout in seconds (default: 5)

Examples:
  Fast scan:
    python scanner.py 192.168.1.0/24 -t 50
  
  Large network:
    python scanner.py 10.0.0.0/16 -o urls.txt -t 100 -to 3
```
