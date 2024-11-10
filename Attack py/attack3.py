import socket
import ssl
import requests
from scapy.all import *
from hpack import Encoder, Decoder
#Read from top alexa csv
header={}
rows=[]
f=open("top-1m.csv",'r')
e=Encoder()
p=rdpcap('curl_wwwgoogle.pcap')
for line in f:
    line=line.strip()
    domain=line.split(",")[1]
    rows.append(domain)

pref=p[3][Raw].load

for domain in rows:
        http_response = ''
        print(domain)
        # CREATE SOCKET
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        # WRAP SOCKET
        context = ssl.create_default_context()
        context.set_alpn_protocols(["h2"])
        wrappedSocket = context.wrap_socket(sock, server_hostname=domain)
        # Define the parameters
        HOST, PORT = domain, 443
        # CONNECT AND PRINT REPLY
        try:
                wrappedSocket.connect(('127.0.0.1', 10443))
                #wrappedSocket.connect((HOST, PORT))
                wrappedSocket.send(pref)                             #When payload is directly extracted from the scapy payload
                #wrappedSocket.send(payload.encode())   #Only when the packet payload is in string format and not extracted directly from scapy payload
                #response = wrappedSocket.recv(12800)
                #http_response = repr(response)
                #http_response_len = len(http_response)
                #wrappedSocket.send(p[8][Raw].load)     Don't acknowledge settings frame in attack-3
        except:
                print("Connection timed out")
        #if http_response!='':
                #print(http_response)
        # CLOSE SOCKET CONNECTION
        wrappedSocket.close()