# nmap-scanner
Python script that scans the local network using nmap and exports results to .json file

This Python script scans a network using the nmap library, retrieves IP addresses of network adapters, and sends the scan results to a URL. The script uses several libraries, including ifaddr, nmap, json, argparse, and requests.

The script starts by importing the required libraries. The argparse library is used to specify the network interface. Then, it gets all adapters and their IP addresses using the ifaddr library. It prints the subnets for the specified interface.

The script uses the nmap library to scan the network. The scan function is called with arguments to scan specific ports and protocols. The output is stored in a JSON format using the json library.

After scanning the network, the script prints the scan results for each host, including the hostname, state, protocol, port, and banner information.

The script sends the scan results to a URL using the requests library. It sends an HTTP post request with the scan results in JSON format.

Finally, the script generates an output file in JSON format named "output.json" containing the scan results. It uses the json library to write the JSON data to the output file.
