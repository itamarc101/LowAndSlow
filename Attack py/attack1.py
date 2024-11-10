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
count=0
for line in f:
    count+=1
    if count>69861:
        line=line.strip()
        domain=line.split(",")[1]
        rows.append(domain)
#rows=[]
#rows.append('10.160.0.2')
pref=p[3][Raw].load
settings_part1=p[4][Raw].load[0:2]
settings_part2=bytes.fromhex('0c')
settings_part3=p[4][Raw].load[3:9]
settings_part4=p[4][Raw].load[15:17]
settings_part5=bytes.fromhex('00')
settings_part6=p[4][Raw].load[18:27]
settings=settings_part1+settings_part2+settings_part3+settings_part4+settings_part5+settings_part6
header_part1=p[6][Raw].load[0:2]
header_part3=p[6][Raw].load[3:12]
header_part5=p[6][Raw].load[25:40]
for domain in rows:
        http_response = ''
        print(domain)
        header[':authority']=domain     #domain input from the top alexa sites file
        encoded_bytes = e.encode(header)
        header_frag_length=len(encoded_bytes)+18
        header_part2=bytes.fromhex(hex(header_frag_length)[2:]) #Define length of payload
        header_part4=encoded_bytes
        payload=pref+settings+header_part1+header_part2+header_part3+header_part4+header_part5
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
                #wrappedSocket.connect((HOST, PORT))
                wrappedSocket.connect(("127.0.0.1", 10443))
                wrappedSocket.send(payload)                             #When payload is directly extracted from the scapy payload
                #wrappedSocket.send(payload.encode())   #Only when the packet payload is in string format and not extracted directly from scapy payload
                #response = wrappedSocket.recv(12800)
                #http_response = repr(response)
                #http_response_len = len(http_response)
                wrappedSocket.send(p[8][Raw].load)
        except:
                print("Connection timed out")
        #if http_response!='':
               # print(http_response)
        #CLOSE SOCKET CONNECTION
        wrappedSocket.close()
        #break