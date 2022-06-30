import ifaddr
import nmap
import json
import argparse
import requests


#Tomar argumento de la linea de comando y parsearlo como variable para la interfaz a escanear.
ap = argparse.ArgumentParser()
ap.add_argument("-i", type=str, default="eth0", dest='interfaz')
args = ap.parse_args()
interfaz = args.interfaz

#Identificar la subred a la que pertenece la interfaz declarada por el usuario.
adapters = ifaddr.get_adapters()
for adapter in adapters:
    if adapter.nice_name.startswith(interfaz):
        print("La subred para la interfaz " + adapter.nice_name + " es:")
        for ip in adapter.ips:
            subnet = "   %s/%s" % (ip.ip, ip.network_prefix)
            print(subnet)

#Utilizando python-nmap para escanear la subred
nm = nmap.PortScanner()
print('\nEscaneando la red: '+ subnet)
scan = nm.scan(hosts=subnet, arguments='-sV -sS -sU --open -p 21,22,53,80,88,139,445,8000,8081 -script=banner', sudo=True)
output = json.dumps(scan)
print('=========================================')

#Mostrar en pantalla los resultados del scan aclarando IP, puerto, protocolo y banner
for host in nm.all_hosts():
     print('=========================================')
     print('Host : %s (%s)' % (host, nm[host].hostname()))
     print('Estado : %s' % nm[host].state())
     for proto in nm[host].all_protocols():
         print('----------')
         print('Protocolo : %s' % proto)
         lport = nm[host][proto].keys()
         for port in lport:
             if nm[host][proto][port]['state'] == 'open':
                portinf = nm[host][proto][port]
                print('puerto : %s\testado : %s\tbanner: %s %s\t' % (port, nm[host][proto][port]['state'], portinf['product'], portinf['extrainfo']))



#Enviando resultados del scan a la URL "http://127.0.0.1/example/fake_url.php" mediante peticion POST
print("enviando resultados a la URL http://127.0.0.1/example/fake_url.php . . . ")
try:
    response = requests.post('http://127.0.0.1/example/fake_url.php', json=output)
except Exception as e:
    print("[FAIL]")

#Exportando resultados como archivo .json
print("Generando fichero output.json . . . ")
try:
    jsonFile = open("output.json", "w")
    jsonFile.write(output)
    jsonFile.close()
    print('[OK]')
except Exception as e:
    print('[Error]')
