#!/usr/bin/env python3 

import ifaddr # module for fetching IP addresses of adapters
import nmap # module for network exploration and management
import json # module for json data handling
import argparse # module for parsing command-line options
import requests # module for sending HTTP requests

# Argument Parser to specify the network interface
ap = argparse.ArgumentParser()
ap.add_argument("-i", type=str, default="eth0", dest='interfaz')
args = ap.parse_args()
interfaz = args.interfaz

# Get all adapters and their IP addresses
adapters = ifaddr.get_adapters()
for adapter in adapters:
    if adapter.nice_name.startswith(interfaz):
        print(f"La subred para la interfaz {adapter.nice_name} es:")
        for ip in adapter.ips:
            subnet = f"   {ip.ip}/{ip.network_prefix}"
            print(subnet)
            break # break the loop once the subnet is found

# Network scanner using nmap library
nm = nmap.PortScanner()
print(f'\nEscaneando la red: {subnet}')
scan = nm.scan(hosts=subnet, arguments='-sV -sS -sU -p 21,22,53,80,88,139,445,8000,8081 -script=banner', sudo=True)
output = json.dumps(scan)
print('=========================================')

# Print scan results
for host in nm.all_hosts():
     print('=========================================')
     print(f'Host : {host} ({nm[host].hostname()})')
     print(f'Estado : {nm[host].state()}')
     for proto in nm[host].all_protocols():
         print('----------')
         print(f'Protocolo : {proto}')
         lport = nm[host][proto].keys()
         for port in lport:
             if nm[host][proto][port]['state'] == 'open':
                portinf = nm[host][proto][port]
                print(f'puerto : {port}\testado : {nm[host][proto][port]["state"]}\tbanner: {portinf["product"]} {portinf["extrainfo"]}\t')

# Send scan results to a URL
print("enviando resultados a la URL http://127.0.0.1/example/fake_url.php . . . ")
try:
    response = requests.post('http://127.0.0.1/example/fake_url.php', json=output)
		print("[OK]")
except Exception as e:
    print("[FAIL]")

# Generate output file
print("Generando fichero output.json . . . ")
try:
    jsonFile = open("output.json", "w")
    jsonFile.write(output)
    jsonFile.close()
    print('[OK]')
except Exception as e:
    print('[Error]')
