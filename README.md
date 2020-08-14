### What is this repository for? ###

* `discovery.py` is a python adaptation of Handshake Networking's `discovery-asv.pl` script with a few improvements. It is used to discover live hosts on a network through TCP pinging and various ICMP types.
* This is version `0.3.6-p`

### Dependencies ###

* Python3
  * For Mac:
    * ```brew install python```
  * For Debian/Ubuntu/etc:
    * ```sudo apt install python3```
  * For CentOS/redhat:
    * ```yum install python3```
* Install required modules:
  * ```sudo python3 -m pip install pyinstaller argparse```

### Installation ###

Run ```sudo ./setup.py``` and the script will be automatically compiled into a single binary and installed in ```/usr/local/bin/```!

## Uninstallation ##

Run ```sudo ./uninstall.py``` or simply remove the ```/usr/local/bin/discovery``` binary

### Usage ###

```
usage:          discovery -t target(s) [options]
example:        discovery -t 192.168.1.0/24 -v -o myresults

This is discover-ng.pl revamped: A script to run nmap & ike-scan to discover
live hosts on a network through TCP Pinging and various ICMP types.

positional arguments:
  t           Target IPs to check status of
  stdin

optional arguments:
  -h, --help  show this help message and exit
  -f F        hosts file containing one host per line
  -v          verbose mode
  -o O        output file (default is JSON)
  --raw       output raw results to stdout without anything else (useful for
              piping JSON results to another script)
  --dry-run   dry run to see which IPs would be scanned
  --quick     quick host discovery with less hosts
```

### Who do I talk to? ###

* Santiago Espinosa github.com/santiago-espinosa
