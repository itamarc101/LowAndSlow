
# packet_processing.py
from scapy.layers.inet import IP, TCP
from scapy.all import PcapReader
import os, subprocess, shutil

def readPackets(_pcap_file):
    """Reads a PCAP file and extracts packets."""
    packets = []
    with PcapReader(_pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                flowID = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"
                data = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None
                packets.append({'flowID': flowID, 'data': data, 'time': pkt.time})
    return packets

def split_streams(input_pcap):
    """Splits PCAP into individual streams."""
    project_folder = os.getcwd()
    output_dir = f'split_streams_{input_pcap}'
    os.makedirs(output_dir, exist_ok=True)
    stream_ids = subprocess.check_output(
        ["tshark", "-r", input_pcap, "-Y", "http2", "-T", "fields", "-e", "tcp.stream"]
    ).decode().splitlines()
    stream_ids = sorted(set(stream_ids))
    for stream_id in stream_ids:
        if stream_id.strip():
            output_pcap = os.path.join(output_dir, f"http2stream{stream_id}.pcap")
            subprocess.run(
                ["tshark", "-r", input_pcap, "-Y", f"tcp.stream == {stream_id}", "-w", output_pcap],
                check=True,
            )
    return len(stream_ids), output_dir
