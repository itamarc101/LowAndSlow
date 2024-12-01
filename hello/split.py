import os
import subprocess

# Path to the input PCAP file
input_pcap = "decqqq.pcap"  # Decrypted PCAP

# Output directory
output_dir = "split_streams"
os.makedirs(output_dir, exist_ok=True)

# Get unique HTTP/2 stream IDs
stream_ids = subprocess.check_output(
    ["tshark", "-r", input_pcap, "-Y", "http2", "-T", "fields", "-e", "http2.streamid"]
).decode().splitlines()
stream_ids = sorted(set(stream_ids))

# Extract each stream
for stream_id in stream_ids:
    output_pcap = os.path.join(output_dir, f"http2stream{stream_id}.pcap")
    print(f"Extracting stream ID {stream_id} to {output_pcap}")
    subprocess.run(
        ["tshark", "-r", input_pcap, "-Y", f"http2.streamid == {stream_id}", "-w", output_pcap]
    )
