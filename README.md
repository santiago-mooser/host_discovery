### What is this repository for? ###

* `discovery.py` is used to discover live hosts on a network through TCP pinging and various ICMP types.
* It is multithreaded, so it is extremely fast
* This is version `0.3.9-p`
* It can be run as a script through python or installed as a standalone binary
* It is not designed with subtelty in mind: this **will** get detected by firewalls and preventative systems

### Dependencies ###

* Python3
* (optional) Python3 modules for binary compilation:
  * `sudo python3 -m pip install PyInstaller`

### How to run the script ##

There are two ways of running this script:
1. Run the script as a standard python script and provide it arguments
2. Flatpack it into a standalone binary (that doesn't need python) and hav it installed under `/usr/local/bin`

## Installation and Uninstallation ##

To install it:

Run `sudo ./setup.py` and the script will be automatically compiled into a single binary and installed in `/usr/local/bin/`

This will also install a man page that you can read by typing `man discovery`

To uninstall it: 

Run `sudo ./uninstall.py` or simply remove the `/usr/local/bin/discovery` binary

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

## Example
(`time` was used to show how quick the script is)
```
$ time ./discovery.py scanme.nmap.org
* scanme.nmap.org
    ICMP: echo,time
    tcp: 21,25,53,80,113,139,256,264,265,443,445,1494,1720,1723,8080,8888
    ike-scan: 
./discovery.py scanme.nmap.org  0.41s user 0.26s system 13% cpu 4.825 total
```

### Who do I talk to? ###

* Santiago Espinosa github.com/santiago-espinosa
