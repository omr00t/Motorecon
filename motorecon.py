#!/usr/bin/python3

# Author: "omroot"
# omroot.io


import sys
import toml
import colorama
import subprocess
import datetime
import argparse
import ipaddress
import os
import re
import pathlib
import threading
import queue


# Colors: 
blue  = colorama.Fore.BLUE
white = colorama.Fore.WHITE
cyan  = colorama.Fore.CYAN
red   = colorama.Fore.RED
yellow= colorama.Fore.YELLOW
lb    = colorama.Fore.LIGHTBLACK_EX
reset = colorama.Fore.RESET
colors_list = [blue, white, cyan, red, yellow, lb, reset]

def run_motorecon(target, args, results):
	try:
		obj = Motorecon(target, args.iface, args.rate, args.config_file)
		results.put(str(obj))
	except KeyboardInterrupt:
		print("User interrupt.")
		sys.exit(1)

class Motorecon:
    def __init__(self, target, iface, rate, conf):
        self.target = target
        self.iface  = iface
        self.rate   = rate
        self.conf   = conf

        self.output = ""

        self.load_config()
        self.start()

    def __str__(self):
        self.output = self.output.replace(self.target, f"{yellow}{self.target}{reset}") # Highlight IP address.
        for port in self.ports:                                                         # Highlight ports.
            self.output = self.output.replace(f"\n{str(port)}/tcp", f"\n{yellow}{str(port)}{reset}/tcp") 
        return self.output

    def load_config(self):
        """
        Loads the toml configuration file.

        Priorities: 
        1. Open the config file from the user's current environment folder.
        If not found, then:
        2. Try to open it from Motorecon's source folder.
        """
        try:
            # Current folder
            self.config = toml.load(self.conf)
        except:
            try:
                # Motorecon's folder
                self.conf = os.path.join(pathlib.Path(__file__).parent.absolute(), self.conf)
                self.config = toml.load(self.conf)
            except:
                print(f"{red}Couldn't find the config file({self.conf}){reset}")
                sys.exit(1)

    @staticmethod
    def remove_colors(colored_text):
        uncolored_output = colored_text
        for color in colors_list:
            uncolored_output = uncolored_output.replace(color, "")
        return uncolored_output
    
    @staticmethod
    def is_ipv4(ip):
        try:
            ipaddress.IPv4Network(ip)
            return True
        except:
            return False
    
    @staticmethod
    def is_valid_iface(iface):
        ifaces = os.listdir('/sys/class/net/')
        if(iface in ifaces):
            return True
        return False

    @staticmethod
    def is_valid_rate(rate):
        try:
            if(int(rate) > 0):
                return True
            else:
                return False
        except:
            return False

    def motorecon_print(self, new_output, print_out=False, log_out=False):
        """
        Add string to Motorecon's result, and optionally print it.
        """
        if(print_out):
            print(new_output)
        if(log_out):
            self.output += new_output + "\n"

    def parse_item(self, element, **kwargs):
        """
        Set the value in the element to the target through kwargs.
        The element is usually a command loaded from the toml configuration file.
        """
        output = str(element)
        for key in list(kwargs.keys()):
            output = output.replace('{'+key+'}', kwargs[key])
        return output

    def start(self):
        """
        A wrapper for the core scan process.
        """
        start_time = datetime.datetime.now()

        # Phase 1 : Portscanning 
        self.motorecon_print(f"{white}Masscanning target: {reset}{cyan}{self.target}{reset}", True)
        self.masscan_cmd = self.parse_item(self.config["portscan"]["phase1"]["command"],\
                target=self.target, iface=self.iface, rate=self.rate)
        self.masscan_ports = self.masscan()
        if(self.masscan_ports == None):
            self.motorecon_print(f"{red}No open TCP ports for {self.target}{reset}", True, True)
            self.motorecon_print(\
                    f"{lb}========================================================================{reset}",\
                    False, True)
            return 0
        self.motorecon_print(f"{cyan}{self.target}{reset}{white} Masscanned successfully.{reset}", True)

        # Phase 2 : Service detection.
        self.motorecon_print(f"{white}Nmapping target: {reset}{cyan}{self.target}{reset}", True)
        self.nmap_cmd = self.parse_item(self.config["portscan"]["phase2"]["command"],\
                target=self.target, masscan_ports=self.masscan_ports)
        self.nmap()
        self.motorecon_print(f"{cyan}{self.target}{reset}{white} Nmapped sucessfully.{reset}", True)
        self.motorecon_print(f"{white}Scan has finished for {reset}{cyan}{self.target}{reset}", True)


        print(self) # print the result

        # Calculate & Print the time taken for the scan.
        time_taken = datetime.datetime.now() - start_time
        (lambda mins,secs: self.motorecon_print(\
                f"{white}Time taken: {reset}{blue}{mins} minutes and {secs} seconds{reset}", False, True))\
                (*divmod(time_taken.total_seconds(), 60))

        self.motorecon_print(\
                f"{lb}========================================================================{reset}", \
                False, True)

    def masscan(self):
        """
        Performs tcp scan for all specified (through the config file) ports using Masscan.
        """
        masscan_output = subprocess.run(self.masscan_cmd.split(' '), \
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        output_lines = str(masscan_output.stdout.decode('utf-8')).split("\n")
        self.ports = []
        for line in output_lines:
            try:
                port = line.split(" ")[3].split("/")[0]
                self.ports.append(port)
                self.motorecon_print(f"{white}Discovered open port " \
                        +f"{reset}{cyan}{port}{reset}{white}/tcp on {reset}{cyan}{self.target}{reset}", \
                        True, False)
            except IndexError:
                pass
        self.ports = sorted(self.ports)
        if(len(self.ports) > 0):
            return ','.join(self.ports)
        else:
            return None

    def nmap(self):
        """
        Performs tcp scan for all open ports provided by Masscan using Nmap. 
        This is performed to detect what service is running on each port.
        """
        nmap_output = subprocess.run(self.nmap_cmd.split(' '), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.motorecon_print(str(nmap_output.stdout.decode('utf-8')), False, True)


def main():
    parser = argparse.ArgumentParser(description=\
            "Scan targets with the speed of masscan. Enumerate ports with the functionality of Nmap.")
    parser.add_argument('targets', action='store', \
            help='IP address(es) (e.g. 192.168.1.1 192.168.1.2 ...)', nargs="*")
    parser.add_argument('-i', '--interface', action='store', type=str, default='tun0', dest='iface',\
            help='Interface to use while scanning. This is used during the Masscan process.')
    parser.add_argument('-r', '--rate', action='store', type=str, default='1000', dest='rate', \
            help='Transmit rate. This is used to tell Masscan how many packets it should send a second.')
    parser.add_argument('-o', '--output', action='store', type=str, dest='output_file', help='Output file.')
    parser.add_argument('-c', '--config', action='store', type=str, default='conf.toml', dest='config_file', help='toml config file.')

    args = parser.parse_args()

    if(not args.targets):
        parser.print_help()
        print(f"{red}No targets were supplied{reset}")
        sys.exit(1)
    
    if(not all(list(map(lambda ip: Motorecon.is_ipv4(ip), args.targets)))):
        print(f"{red}Invalid target format.{reset}{white} IPv4 format is needed for all targets{reset}.")
        sys.exit(1)

    if(not Motorecon.is_valid_iface(args.iface)):
        print(f"{red}Invalid interface. Couldn't find interface {args.iface}.{reset}")
        sys.exit(1)
    
    if(not Motorecon.is_valid_rate(args.rate)):
        print(f"{red}Invalid rate. It should be a number that's larger than 0.")
        sys.exit(1)
    
    if(os.getuid()):
        print(f"{red}Root permissions are required to the scan.{reset}")
        sys.exit(1)

    result = ""
    start_time = datetime.datetime.now()
    print(f"{yellow}{len(args.targets)}{reset}{white}",
            f"target{'s' if len(args.targets)>1 else ''} to scan..{reset}")
    try:
        threads = []
        results = queue.Queue()

        for target in args.targets:
            for host in ipaddress.IPv4Network(target):
                # Run Motorecon against each target.
                thread = threading.Thread(target=run_motorecon, args=(str(host), args, results))
                threads.append(thread)
                thread.start()
    except KeyboardInterrupt:
        print("User interrupt.")
        sys.exit(1)

    # Wait for all threads to complete
    for thread in threads:
        thread.join()

    # Print total time taken:
    time_taken = datetime.datetime.now() - start_time
    (lambda mins,secs: print(f"{lb}Total time taken: {reset}{blue}{mins} minutes and {secs} seconds{reset}"))\
            (*divmod(time_taken.total_seconds(), 60))


    # Retrieve the results from the queue
    while not results.empty():
        result += results.get()

    # Save output to a file (optionally)
    if(args.output_file):
        try:
            with open(args.output_file, "w") as f:
                f.write(Motorecon.remove_colors(result))
                print(f"{white}Output has been saved to: {reset}{cyan}{args.output_file}{reset}")
            with open(args.output_file+'.colored', "w") as f:
                f.write(result)
                print(f"{white}Colored output has been saved to: {reset}{cyan}{args.output_file}.colored{reset}")
        except:
            print(f"{red}Couldn't save output to file {args.output_file}{reset}")

if __name__ == "__main__":
    main()
