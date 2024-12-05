import os
import subprocess

# Path to the input PCAP file
input_pcap = "attack1.pcap"  # Replace with your decrypted PCAP file path

# Output directory
output_dir = "split_tcpstreams"
os.makedirs(output_dir, exist_ok=True)

# Get unique HTTP/2 stream IDs from the PCAP
try:
    stream_ids = subprocess.check_output(
        ["tshark", "-r", input_pcap, "-Y", "http2", "-T", "fields", "-e", "tcp.stream"]
    ).decode().splitlines()

    # Remove duplicates and sort the stream IDs
    stream_ids = sorted(set(stream_ids))
    print(f"Found {len(stream_ids)} HTTP/2 streams.")
except subprocess.CalledProcessError as e:
    print(f"Error while extracting HTTP/2 stream IDs: {e}")
    exit(1)

# Extract each stream into a separate PCAP file
for stream_id in stream_ids:
    if stream_id.strip():  # Ensure the stream_id is not empty
        output_pcap = os.path.join(output_dir, f"http2stream{stream_id}.pcap")
        print(f"Extracting stream ID {stream_id} to {output_pcap}")
        try:
            subprocess.run(
                ["tshark", "-r", input_pcap, "-Y", f"tcp.stream == {stream_id}", "-w", output_pcap],
                check=True,
            )
        except subprocess.CalledProcessError as e:
            print(f"Error while extracting stream ID {stream_id}: {e}")
