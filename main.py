import json
from aslookup import get_as_data
import subprocess
import os
import time
from pyfiglet import Figlet
import random
import argparse
import shutil
import requests
from bs4 import BeautifulSoup


def scan(num_threads, ports, gateway, target, target_is_file,output_filename):
    target_asns = []
    ips = []

    if target_is_file:
        with (open(target, "r") as target_file):
            for ip in target_file.read().split("\n"):
                if ip.strip() != "":
                    ips.append(ip)
    elif not target_is_file:
        ips.append(target)

    for ip in ips:
        print("Mapping " + ip + " to an ASN")
        data = get_as_data(ip, service="cymru")
        # Get the ASN for the known bad IP address
        target_asns.append(data.asn)

    print("Deduplicating list of ASNs")
    target_asns = list(dict.fromkeys(target_asns))

    if os.path.isfile("ranges.txt"):
        print("Delete existing temp file")
        os.remove("ranges.txt")

    print("Getting IP ranges for ASNs")
    # Classical whois
    for target_asn in target_asns:
        print("Processing AS" + target_asn)
        p = subprocess.Popen("whois -h whois.ripe.net -T route AS" + target_asn +
                         " -i origin | egrep 'route: ' | awk '{print $NF}' >> ranges.txt",
                         stdout=subprocess.PIPE, shell=True)

        time.sleep(3)

        found_ranges = []
        with open("ranges.txt", "r") as ranges_input:
            range = ranges_input.read().split("\n")
            for r in range:
                if r != "":
                    found_ranges.append(r)

        # Sometimes whois does not return all IP ranges therefor we also grab results from HE
        url = "https://bgp.he.net/AS" + target_asn + "#_prefixes"
        he_content = requests.get(url)
        page_content = BeautifulSoup(he_content.content, "html.parser")
        table = page_content.find(lambda tag: tag.name == 'table' and tag.has_attr('id') and tag['id'] == "table_prefixes4")

        for i, tr in enumerate(table.findAll('tr')):
            for td in tr.findAll('td'):
                links = td.findAll('a')
                for l in links:
                    found_ranges.append(l.get('href').replace("/net/", ""))
                    print(l.get('href').replace("/net/", ""))

        # Deduplicating IP ranges
        found_ranges = list(dict.fromkeys(found_ranges))
        with open("ranges.txt", "w") as range_output:
            for f in found_ranges:
                range_output.write(f + "\n")

    if os.path.isfile(output_filename):
        print("Delete existing output file " + output_filename)
        os.remove(output_filename)

    with open("ranges.txt", "r") as scan_input:
        ranges = scan_input.read().replace("\n", " ")
        for r in ranges.split(" "):
            if len(r) > 0:
                print("Added range " + r + " to scanning scope!")
        print("Starting masscan, this might take a while to complete")
        command = "sudo masscan -p" + ports + " " + ranges + "--rate " + str(num_threads) + " --retries=2 -e " + gateway + " --output_format=json --output_filename=" + output_filename
        subprocess.Popen(command, stderr=subprocess.PIPE, stdout=subprocess.PIPE, shell=True).communicate()
        print("Finished! Check " + output_filename + " for your results.")


def print_header():
    possible_fonts = ['banner', 'big', 'digital', 'shadow']
    f = Figlet(font=possible_fonts[random.randint(0, len(possible_fonts) - 1)])
    print(f.renderText("PyVot"))


if __name__ == '__main__':
    print_header()

    # masscan requires root privileges to run
    if os.geteuid() != 0:
        print("masscan requires root privileges to run. Please run script as root!")
        exit()

    path = shutil.which("masscan")
    if path is None:
        print("Couldn't find masscan binary. Please install it before using this script " +
              "(https://github.com/robertdavidgraham/masscan)")

    parser = argparse.ArgumentParser(
        prog='PyVot',
        description='Script which either takes a single IP as argument or a list of IPs and maps them to ASNs and ' +
                    'afterwards gets all IP ranges associated with those ASNs. Those gathered IPs are then scanned ' +
                    ' with masscan (https://github.com/robertdavidgraham/masscan)',
        epilog='Do not pwn what you do not own')

    parser.add_argument('-f', '--file', help='Path to a file which contains IP addresses (one per line)')
    parser.add_argument('-i', '--ip_address', help='Pivot on single IP address')
    parser.add_argument('-p', '--ports', help="Ports to scan in NMAP format (for example: 0-65535)", required=True)
    parser.add_argument('-g', '--gateway', help='Interface used for masscan (for example tun0)', required=True)
    parser.add_argument('-t', '--threads', help='Number of concurrent threads with masscan (Default: 10000)',
                        type=int, default=10000)
    parser.add_argument('-o', '--output', help="File used to store found servers")

    args = parser.parse_args()

    if args.file:
        scan(args.threads, args.ports, args.gateway, args.file, True, args.output)

    if args.ip_address:
        scan(args.threads, args.ports, args.gateway, args.ip_address, False, args.output)


