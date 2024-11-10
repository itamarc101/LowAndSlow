import socket
import ssl
import requests
from scapy.all import *
from hpack import Encoder, Decoder
#Read from top alexa csv
header={}
rows=[]
f=open("http2_domains_round1.txt",'r')
e=Encoder()
p=rdpcap('curl_wwwgoogle.pcap')
for line in f:
    line=line.strip()
    domain=line.split(",")[1]
    rows.append(domain)

pref_settings_winupdate_frames=p[3][Raw].load+p[4][Raw].load+p[5][Raw].load
header_part1=p[6][Raw].load[0:2]
header_part3=p[6][Raw].load[3:4]
header_part5=p[6][Raw].load[5:12]
header_part7=p[6][Raw].load[25:35]
for domain in rows:
        http_response = ''
        print(domain)
        header[':authority']=domain     #domain input from the top alexa sites file
        encoded_bytes = e.encode(header)
        header_frag_length=len(encoded_bytes)+13        #13 instead of 18 to not send the last header i.e. :accept:
        header_part2=bytes.fromhex(hex(header_frag_length)[2:]) #Define length of payload
        header_part4=bytes.fromhex('01')        #End headers flag set while stream flag reset.
        header_part6=encoded_bytes
        payload=pref_settings_winupdate_frames+header_part1+header_part2+header_part3+header_part4+header_part5+header_part6+header_part7
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
                wrappedSocket.send(payload)                             #When payload is directly extracted from the scapy payload
                #wrappedSocket.send(payload.encode())   #Only when the packet payload is in string format and not extracted directly from scapy payload
                #response = wrappedSocket.recv(12800)
                #http_response = repr(response)
                #http_response_len = len(http_response)
                wrappedSocket.send(p[8][Raw].load)
        except:
                print("Connection timed out")
        #if http_response!='':
                #print(http_response)
        # CLOSE SOCKET CONNECTION
        wrappedSocket.close()