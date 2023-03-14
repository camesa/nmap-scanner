<h1>Network Scanner README</h1>
<p>This Python script is used for scanning a network and retrieving information about open ports and services running on devices within the network. The script uses the <code>ifaddr</code> module for fetching IP addresses of adapters, the <code>nmap</code> module for network exploration and management, and the <code>requests</code> module for sending HTTP requests.</p>
<p>To use the script, simply specify the network interface with the <code>-i</code> flag when running the script. By default, the script will use the <code>eth0</code> interface. For example:</p>
<pre><code>python3 network_scanner.py -i wlan0</code></pre>
<p>The script will then retrieve the IP address of the specified interface, scan the network for open ports on devices within the network, and output the results to the console. The script will also send the scan results to a specified URL and generate an output file named <code>output.json</code> with the scan results.</p>
<p>By default, the script scans for open ports on the following ports:</p>
<ul>
  <li>21 (FTP)</li>
  <li>22 (SSH)</li>
  <li>53 (DNS)</li>
  <li>80 (HTTP)</li>
  <li>88 (Kerberos)</li>
  <li>139 (NetBIOS Session Service)</li>
  <li>445 (Microsoft-DS)</li>
  <li>8000 (HTTP alternate)</li>
  <li>8081 (HTTP alternate)</li>
</ul>
<p>If you want to change the ports to scan for, you can modify the <code>arguments</code> parameter in the <code>nm.scan()</code> function call. For example:</p>
<pre><code>scan = nm.scan(hosts=subnet, arguments='-sV -sS -sU -p 80,443 -script=banner', sudo=True)</code></pre>
<p>Finally, the script sends the scan results to a specified URL using the <code>requests.post()</code> function. By default, the script sends the scan results to <code>http://127.0.0.1/example/fake_url.php</code>. You can modify the URL by changing the <code>url</code> parameter in the <code>requests.post()</code> function call. For example:</p>
<pre><code>response = requests.post('http://example.com/upload_results', json=output)</code></pre>
<p>If the script encounters an error while sending the scan results to the URL or generating the output file, it will output an error message to the console.</p>
