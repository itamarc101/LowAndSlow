
# main.py
from packet_processing import readPackets, split_streams
from learning import learning_phase
from detection import detection_phase, detection_phase_mismatch
from utils import export_dict_to_file, import_dict_from_file, write_to_file
import sys, os, time

def main_run(input_pcap, function_type=1, threshold=0.0):
    """Runs different phases of packet analysis based on the specified function type."""
    global seq_de, detect_count
    Dlookahead = {}
    Ddelay = {}
    total_packets = 0

    if function_type == 1:  # Learning phase
        stream_count, dest_folder = split_streams(input_pcap)
        for stream_index in range(1, stream_count + 1):
            packets = readPackets(f'{dest_folder}/input_pcap{stream_index}.pcap')
            Dlookahead, Ddelay, packets_count = learning_phase(Dlookahead, Ddelay, packets, window_size)
            total_packets += packets_count
        export_dict_to_file(Dlookahead, "Dlookahead.txt")
        export_dict_to_file(Ddelay, "Ddelay.txt")

    elif function_type == 2:  # Detection phase
        seq_de = ""
        Dlookahead = import_dict_from_file("Dlookahead.txt")
        Ddelay = import_dict_from_file("Ddelay.txt")
        packets = readPackets(input_pcap)
        detection_phase(Dlookahead, Ddelay, window_size, threshold, packets, input_pcap)

    elif function_type == 3:  # Mismatch detection
        stream_count, dest_folder = split_streams(input_pcap)
        seq_de = ""
        detect_count = 0
        Dlookahead = import_dict_from_file("Dlookahead.txt")
        Ddelay = import_dict_from_file("Ddelay.txt")
        for stream_index in range(1, stream_count + 1):
            packets = readPackets(f'{dest_folder}/{input_pcap}{stream_index}.pcap')
            detection_phase_mismatch(Dlookahead, Ddelay, window_size, threshold, packets, input_pcap)

if __name__ == '__main__':
    pcap_file = 'Google-Chrome.pcap'
    window_size = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    main_run(pcap_file, 3)
