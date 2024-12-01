import pyshark

def analyze_pcap(file):
    capture = pyshark.FileCapture(file, display_filter="http2")
    print("Analyzing packets...")
    for packet in capture:
        try:
            print(f"Packet {packet.number} Summary:")
            print(packet)  # Print full packet details for inspection
            stream_id = packet.tcp.stream
            time_delta = float(packet.frame_info.time_delta)
            print(f"Stream {stream_id}, Time Delta: {time_delta}s")
            if time_delta > 1.0:  # Delays over 1 second
                print(f"Stream {stream_id}: Delayed packet detected ({time_delta}s)")
            if "slow attack" in str(packet.http2):
                print(f"Stream {stream_id}: Possible attack payload detected")
        except AttributeError as e:
            print(f"Error: {e}")  # Debug unexpected packet issues
            continue


if __name__ == "__main__":
    analyze_pcap("qqq.pcap")
