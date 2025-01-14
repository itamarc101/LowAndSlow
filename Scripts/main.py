"""
Main entry point for the HTTP/2 traffic analysis tool.
"""
import os
import sys
import time
from learning import learning_phase
from detection import detection_phase, detection_phase_mismatch
from packet_processor import readPackets
from utils import split_streams, import_dict_from_file, export_dict_to_file, write_to_file
import config


def main_run(input_pcap, function_type=1, threshold=0.0):
    """
        Runs different phases of packet analysis based on the specified function type.

        Args:
            input_pcap (str): Path to the input PCAP file.
            function_type (int): Determines the phase of the pipeline to run (1: Learning, 2: Detection, 3: Mismatch Detection).
            threshold (float): A threshold value used in detection and mismatch detection phases.

        Returns:
            None
        """

    Dlookahead = {}
    Ddelay = {}
    total_packets = 0

    # Learning phase (Function Type 1)
    if function_type == 1:
        # Split the streams and get the count and destination folder
        stream_count, dest_folder = split_streams(input_pcap)

        for stream_index  in range(1, stream_count + 1):
            print(f"Open input_pcap{stream_index }.pcap")
            packets = readPackets(f'{dest_folder}/{input_pcap}{stream_index}.pcap')
            Dlookahead, Ddelay, packets_count = learning_phase(Dlookahead, Ddelay, packets, window_size)

            total_packets += packets_count

        print(f'Read {total_packets} packets')

        export_dict_to_file(Dlookahead, "Dlookahead.txt")
        export_dict_to_file(Ddelay, "Ddelay.txt")

    # Detection phase (Function Type 2)
    elif function_type == 2:
        seq_de = ""

        # Clear any existing mismatch detection result file
        if os.path.isfile(f'DetectMissmatch_{input_pcap}'):
            write_to_file(f'DetectMissmatch_{input_pcap}', "", 'w')


        # Import the data from the learning phase files
        Dlookahead = import_dict_from_file("Dlookahead.txt")
        Ddelay = import_dict_from_file("Ddelay.txt")

        # Read packets from the input pcap file for detection
        packets = readPackets(input_pcap)
        # Run the detection phase
        detection_phase(Dlookahead, Ddelay, window_size, threshold, packets, input_pcap)

    # Mismatch detection phase (Function Type 3)
    elif function_type == 3:
        # Clear any existing mismatch detection result file
        if os.path.isfile(f'DetectMissmatch_{input_pcap}'):
            write_to_file(f'DetectMissmatch_{input_pcap}', "", 'w')

        # Split the streams and get the count and destination folder
        stream_count, dest_folder = split_streams(input_pcap)

        Dlookahead = import_dict_from_file("Dlookahead.txt")
        Ddelay = import_dict_from_file("Ddelay.txt")

        # Process each stream and detect mismatches
        for stream_index  in range(1, stream_count + 1):
            print(f"Open {input_pcap}{stream_index }.pcap")
            packets = readPackets(f'{dest_folder}/{input_pcap}{stream_index }.pcap')
            detection_phase_mismatch(Dlookahead, Ddelay, window_size, threshold, packets, input_pcap)

        write_to_file(f'DetectMissmatch_{input_pcap}', f'detect {config.detect_count} anomalous', 'a')


if __name__ == '__main__':

    begin = time.time()
    # pcap_file = config.PCAP
    window_size = sys.argv[1] if len(sys.argv) > 1 else 2  # Default window size if not specified
    # packets = readPackets(pcap_file)  # Ensure this function reads the pcap file and returns packet data

    # open_datasets()

    # Dlookahead = import_dict_from_file("Dlookahead.txt")
    # Ddelay = import_dict_from_file("Ddelay.txt")

    main_run('attack1.pcap', 3)
    # # Check packets structure before passing to learning_phase
    # print("Packets structure check:", packets[:5])  # Print the first few packets to check structure
    # Dlookahead, Ddelay = learning_phase(packets, window_size)
    end = time.time()

