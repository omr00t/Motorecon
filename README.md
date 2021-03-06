# Motorecon
Scan as fast as Masscan. Delve as deep as Nmap.
 ```
 usage: motorecon.py [-h] [-i IFACE] [-r RATE] [-o OUTPUT_FILE] [targets ...]

Scan targets with the speed of masscan. Enumerate ports with the functionality of Nmap.

positional arguments:
  targets               IP address(es) (e.g. 192.168.1.1 192.168.1.2 ...)

optional arguments:
  -h, --help            show this help message and exit
  -i IFACE, --interface IFACE
                        Interface to use while scanning. This is used during the Masscan process.
  -r RATE, --rate RATE  Transmit rate. This is used to tell Masscan how many packets it should send a second.
  -o OUTPUT_FILE, --output OUTPUT_FILE
                        Output file.
 ```
```
pip3  install -r requirements.txt
chmod +x motorecon.py
sudo ./motorecon.py -i eth1 192.168.10.1 192.168.10.2 192.168.10.59
```
![Alt text](screenshot.png?raw=true "Motorecon")

Scans the whole port range through `masscan`. Enumrate service versions through `nmap`.
Note that for Motorecon to work, you need `masscan` and `nmap` to be available on your machine.


You can customzie your `masscan` or `nmap` commands through modifying the config file `conf.toml`.
