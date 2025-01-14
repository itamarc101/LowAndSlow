
"""
Filename: low_and_slow.py

Description:
This script processes PCAP files to analyze HTTP/2 traffic for low-and-slow attacks. It includes functions
for learning event sequences, calculating delays, and detecting anomalies.

Functions:
- main_run: Entry point to run the processing and detection phases.
- split_streams: Splits streams in a PCAP file.
- readPackets: Reads packets from a PCAP file.
- learning_phase: Analyzes packets to learn sequences and delays.
- detection_phase: Detects anomalies based on learned sequences and delays.
- detection_phase_mismatch: Detects mismatches between observed and learned sequences.
- ... (other utility functions).

Usage:
    python low_and_slow.py [window_size]

Dependencies:
- scapy
- tshark
"""

from scapy.all import *
from scapy.contrib.http2 import *
from collections import defaultdict
import os
import ast
import subprocess


PCAP = 'Google-Chrome.pcap'
flow_dict = {}  # Maps flow identifiers to consolidated event sequences
flow_dict_with_TO = {}  # Includes timeout events
last_event = {}  # Tracks the last event for each flow
delay_dictionary = {}  # Stores average delay between events
unique_event_sequences = []  # Stores unique sequences of events
event_timings = defaultdict(list)  # Maps events to their timestamps
lookahead_pairs = defaultdict(list)  # Stores lookahead pairs for event prediction
avg_delay_between_events = {}  # Average delay between two consecutive events
pair_count = []
incomplete_frame = {}  # Handles partial frames
SERVER_PORT = 80
seq_de = ""
detect_count = 0

from scapy.layers.inet import IP, TCP

def extractLookaheadPairs(seq, win_size):
    """
        Extracts lookahead pairs from a given sequence based on a specified window size.
        Args:
            seq (str): representing a sequence of events, separated by '->*'.
            win_size (int): lookahead window size for extracting pairs.

        Returns:
            dict: A dictionary where each event maps to a list of lookahead pairs.
                  Each pair consists of an event and its distance from the current event.
        """
    lookahead_pair = [] # Empty list to temp store lookahead pairs
    count = 0 # Counter to keep track of total number of pairs
    event_list = seq.split('->*') # Split the input sequence to list of events

    current_index = 0 # position of current event (event_list[index])
    while current_index + 1 < len(event_list):
        lookahead_distance = 1 # Lookahead distance for current event
        lookahead_index = current_index + 1 # Start checking from next event

        # Continue adding lookahead pairs within the window size
        while lookahead_index <= current_index + int(win_size):
            # Stop if reaches end of event list
            if lookahead_index == len(event_list):  # When the cursor reaches end of the sequence
                break
            # Add lookahead event and distance to temp list
            lookahead_pair.append(event_list[lookahead_index])
            lookahead_pair.append(lookahead_distance)

            # Check if lookahead pair is not in the dict for current event
            if lookahead_pair not in lookahead_pairs[event_list[current_index]]:
                temp = lookahead_pair.copy() # copy of temp list to avoid issues

                # Append new lookahead pair for the current event
                lookahead_pairs[event_list[current_index]].append(temp)
                count += 1 # Inc lookahead pair count

            lookahead_pair.clear() # Clear temp list for the next pair
            lookahead_index += 1 # Next lookahead event
            lookahead_distance += 1 # Next distance

        current_index += 1 # Next event in sequence

    pair_count.append(count) #Append total count of pairs to list

    # Sum up all lookahead pairs
    for item in lookahead_pairs:
        count += len(lookahead_pairs[item])

    return lookahead_pairs


def learning_phase(Dlookahead, Ddelay, F, n):
    """
        process frames and extract lookahead pairs, delays, and event sequences for analysis.

        Args:
            Dlookahead (dict): store lookahead pairs.
            Ddelay (dict): store delays between consecutive events.
            F (list): A list of frames, where each frame is a dictionary containing
                      'flowID', 'data', and 'time' keys.
            n (int): lookahead window size.

        Returns:
            tuple: Updated Dlookahead, Ddelay, and the total number of packets processed.
        """
    global lookahead_pairs, incomplete_frame

    events_timestamp = [] # List to store timestamp of events
    event_sequence = 'Start->*' #Start of the sequence

    # Append timestamp of first frame
    events_timestamp.append(F[0]['time'])

    packt_count = 1
    for frame in F:
        # check if frame is a valid dictionary
        if isinstance(frame, dict):
            # Get the details
            flow_id, current_frame, pkt_time = frame['flowID'], frame['data'], frame['time']
            # Find the event of the current frame
            event = findEvent(flow_id, current_frame, None, pkt_time, packt_count)
            if event is not None:
                # If found event add it to log file
                with open('FrameToEvent.txt', 'a') as f:
                    f.write('%s=%s' % (current_frame, event))
                    f.write('\n')
                events_timestamp.append(pkt_time) # Add packet timestamp
                event_sequence += f'{event}' # Add event to sequence
                packt_count += 1

    events_timestamp.append(F[-1]['time']) #Append timestamp of last frame
    event_sequence += 'End'
    # Extract the lookahead pairs from the sequence
    lookahead_pairs = extractLookaheadPairs(event_sequence, n)

    Dlookahead.update(lookahead_pairs) #Update with extracted pairs
    events = event_sequence.split('->*') #Split each event of the sequence

    # Calculate delays between consecutive events
    event_index = 1
    while event_index < packt_count:
        delay = events_timestamp[event_index] - events_timestamp[event_index - 1]
        event_transition_key = f'{events[event_index - 1]}{events[event_index]}'
        # Update the delay dict with max delay for transition
        if event_transition_key not in Ddelay:
            Ddelay[event_transition_key] = delay
        else:
            Ddelay[event_transition_key] = max(delay, Ddelay[event_transition_key])
        event_index += 1

    export_dict_to_file(Dlookahead, "Dlookahead.txt")
    export_dict_to_file(Ddelay, "Ddelay.txt")

    return Dlookahead, Ddelay, packt_count


def detection_phase(Dlookahead, Ddelay, n, t, packets, pcap_name):
    """
        Detects anomalies in packet delays by comparing actual event timings
        with expected delays stored in `Ddelay`.

        Ddelay (dict): maximum allowable delays for event transitions.
        packets (list): A list of packets, each packet contains flowID, data, and time information.
    """

    event_sequence = ''
    detected_events = []
    events_time = []
    current_event_index = 0
    delay_counter = 0

    for _packet in packets:
        frame_data = _packet['data']  # frame content
        # Map the frame to an event
        event = findEvent(_packet['flowID'], frame_data, None, _packet['time'], 0)  # translateToEvent in pseudocode
        if event:
            current_event_index += 1
            event_sequence += f'{event}' #Add event to sequence
            events_time.append(_packet['time']) #timestamp of event
            detected_events.append(event)
            findEventTiming(_packet['flowID'], event, _packet['time'])  # Update event timing

    # Split event sequence (individual events)
    new_events = event_sequence.split('->*')

    # Check for delays if there are at least 2 events
    if len(new_events) > 1:
        total_events = len(new_events)
        for event_index in range(1, total_events - 1):
            # Create key for transition between two consecutive events
            event_transition_key = f'{new_events[event_index - 1]}{new_events[event_index]}'

            write_to_file("DelaysDetect", event_transition_key, 'a')

            # Check if the transition exists in the delay dict
            if event_transition_key in Ddelay:
                max_delay = Ddelay[event_transition_key] # Check the last event's maximum delay
                if max_delay != 0:
                # Check time difference from the last event timing (2 events)
                    actual_delay = events_time[-1] - events_time[-2]
                    if actual_delay  > max_delay:
                        write_to_file(f'DelaysDetect_{pcap_name}', f'Attack: Delayyyyy", {event_transition_key}, " - {max}: ", {max_delay},"<", {actual_delay}', 'a')
                        delay_counter += 1
    write_to_file(f'DelaysDetect_{pcap_name}', f'Found {delay_counter} delays' ,'a')


def detection_phase_mismatch(Dlookahead, Ddelay, n, t, packets, pcap_name):
    """
       Detects anomalies in sequences by analyzing mismatched lookahead pairs
       and delay violations in packet sequences.

       Args:
           Dlookahead (dict): Dictionary of valid lookahead pairs.
           Ddelay (dict): Dictionary of maximum allowable delays for event transitions.
           n (int): Lookahead window size.
           t (float): Threshold for mismatch ratio to classify a sequence as anomalous.
           packets (list): List of packets, where each packet contains flowID, data, and time.
           pcap_name (str): Name of the pcap file used for logging detections.
    """

    global seq_de, detect_count, packet
    detected_events = []
    timeout_counter = 0

    # Build event sequence for each packet
    for packet in packets:
        frame_data = packet['data']
        #Map frame to event
        event = findEvent(packet['flowID'], frame_data, None, packet['time'], 0)
        if event:
            seq_de += f'{event}' #Add event to global sequence
            detected_events.append(event)
            # Update event timing (used for delay violation checks)
            findEventTiming(packet['flowID'], event, packet['time'])

    if not detected_events:
        return

    # Check for delay violations
    _last_event = detected_events[-1] # Last detected event
    max_delay = max(Ddelay.get(_last_event, {'*': 0}).values()) # Max delay for last event
    last_event_time = event_timings.get(packet['flowID'], [-1, None])[-1] # Last event's timing


    if last_event_time and (time.time() - last_event_time) > max_delay:
        # Append timeout marker to sequence and log the delay
        seq_de += f' → TO{timeout_counter} → *'
        write_to_file(f'DetectMissmatch_{pcap_name}', f'Delayyyyy - {_last_event}', 'a')
        timeout_counter += 1

    # Detect mismatched lookahead pairs
    mismatch = 0
    if len(detected_events) > n:
        # Extract lookahead pairs from the sequence
        _lookahead_pairs = extractLookaheadPairs(seq_de, n)
        for pair in _lookahead_pairs:
            if pair not in Dlookahead:
                mismatch += 1
                write_to_file(f'DetectMissmatch_{pcap_name}', "added1to_mismatch", 'a')

    # Calculate mismatch ratio
    mismatch_ratio = mismatch / (n * (len(detected_events) - (n + 1) / 2))

    # Log whether the sequence is anomalous or normal based on the mismatch ratio
    if mismatch_ratio > t:
        write_to_file(f'DetectMissmatch_{pcap_name}', "Sequence is anomalous", 'a')
        detect_count += 1
    elif mismatch_ratio < t and detected_events[-1] == '->Goaway->*':
        write_to_file(f'DetectMissmatch_{pcap_name}', "Sequence is normal", 'a')


# Find the timing of event occurrences
def findEventTiming(flowID, event, pkt_time):
    global last_event, event_timings
    event_timings[flowID].append(event)
    event_timings[flowID].append(pkt_time)
    last_event[flowID] = event


def findEvent(flowID, current_frame, event, pkt_time, pkt_count):
    """  Determines the event type from a given packet's data and flow ID.  """
    global last_event, event_timings, SERVER_PORT

    if flowID not in last_event:
        last_event[flowID] = ''

    # Check if current_frame(frame data) is None
    if current_frame is None:
        print("Error: current_frame is None. Skipping this packet.")
        return None

    # Check if the frame length is less than the minimum HTTP/2 header size
    if len(current_frame) < 9:
        print(f"Error: Frame length {len(current_frame)} is too short for a valid HTTP/2 frame for packet {pkt_count}.")
        return None

    # Parse flow ID to extract source and destination
    try:
        src_part, dst_part = flowID.split('->')
        # print(f' {src_part}  {dst_part} ')
        src_ip, src_port = src_part.split(':')
        src_port = int(src_port)
    except ValueError as ve:
        print(f"Error parsing flowID: {flowID}, error: {ve}")
        return None  # Handle the error appropriately, possibly by skipping this frame


    if src_port == SERVER_PORT:
        flowID = dst_part  # If the source port is the server port, consider the destination part
    else:
        flowID = src_part  # Otherwise, use the source part

    # Update timing for event
    if event:
        findEventTiming(flowID, event, pkt_time)
        return event

    # Begin processing the frame to determine the type of event
    event = ''
    do_nothing = 0

    # Check if current_frame has enough data to parse as an HTTP/2 frame
    if len(current_frame) < 9:  # HTTP/2 frame header is 9 bytes
        print("Error: current_frame is too short to be a valid HTTP/2 frame.")
        return None
    try:
        current_frame = H2Frame(current_frame)
    except Exception as e:
        print(f"Error processing HTTP/2 frame: {e}")
        return None

    current_frame_type = current_frame.type

    if current_frame_type == 0:  # Data Frame
        if 'ES' not in current_frame.flags and last_event.get(flowID, '') != '->Data_frame_!ES->*':
            event = '->Data_frame_!ES->*'
        elif 'ES' in current_frame.flags:
            event = '->Data_frame_ES->*'
    elif current_frame_type == 1:  # Headers Frame
        if 'ES' and 'EH' not in current_frame.flags:
            event = '->Hdr_frame_!(ESEH)->*'
        elif 'ES' not in current_frame.flags and 'EH' in current_frame.flags:
            event = '->Hdr_frame_!ES_EH->*'
        elif 'ES' in current_frame.flags and 'EH' not in current_frame.flags:
            event = '->Hdr_frame_ES_!EH->*'
        elif 'ES' and 'EH' in current_frame.flags:
            event = '->Hdr_frame_(ESEH)->*'
    elif current_frame_type == 3:  # RST_Stream Frame
        event = '->Rst_stream->*'
    elif current_frame_type == 2:  # Priority Frame
        event = '->Priority->*'
    elif current_frame_type == 6:  # PING Frame
        event = '->Ping->*'
    elif current_frame_type == 4:  # Settings Frame
        param = 0
        if current_frame.len == 0:
            if 'A' in current_frame.flags:
                event = '->Settings_ACK->*'
            else:
                event = '->Settings_UNACK->*'
        else:
            event += '->'
            # Check if the H2SettingsFrame layer exists before accessing it
            if H2SettingsFrame in current_frame:
                while param < len(current_frame[H2SettingsFrame].settings):
                    if current_frame[H2SettingsFrame].settings[param].id == 4:  # Initial window size
                        if current_frame[H2SettingsFrame].settings[param].value != 0:
                            event += 'Ini_Win_Size!0->'
                        else:
                            event += 'Ini_Win_Size0->'
                    elif current_frame[H2SettingsFrame].settings[param].id == 3:  # Max concurrent streams
                        if current_frame[H2SettingsFrame].settings[param].value != 0:
                            event += 'Max_Con_Strm!0->'
                        else:
                            event += 'Max_Con_Strm0->'
                    param += 1
            else:
                print("Warning: H2SettingsFrame layer not found in current_frame.")
            event += '*'
    elif current_frame_type == 8:  # Window_Update Frame
        if hasattr(current_frame[1], 'win_size_incr') and current_frame[1].win_size_incr == 0:
            event = '->win_size_incr0->*'
        else:
            event = '->win_size_incr!0->*'
    elif current_frame_type == 7:  # GOAWAY Frame
        event = '->Goaway->*'
    elif current_frame_type == 9:  # Continuation Frame
        event = '->Cont_Frame->*'
    else:
        do_nothing = 1

    if event != '':
        findEventTiming(flowID, event, pkt_time)
        return event
    elif event == '' and flowID in last_event and last_event[flowID] == '->Data_frame_!ES->*' and do_nothing == 0:
        findEventTiming(flowID, last_event[flowID], pkt_time)  # This line was corrected to call the findEventTiming function properly
        return last_event[flowID]



def findEventSequencesPerFlow():
    """
    Extracts and stores unique event sequences for each flow based on their timings.

    Updates:
        - flow_dict: with event sequences for each flow
        - unique_event_sequences: with any new sequences found.

    """
    global flow_dict, unique_event_sequences, event_timings, flow_dict_with_TO

    for flowID in event_timings:
        flow_dict[flowID] = ''
        index = 1
        for event in event_timings[flowID]:
            if index % 2 != 0:
                flow_dict[flowID] += event  # To store only the event names and not the timings
            index += 1

    for flowID in flow_dict:
        if flow_dict[flowID] not in unique_event_sequences:
            unique_event_sequences.append(flow_dict[flowID])


def calculateAvgDelayBetweenEvents():
    """
        Calculates the average delay between pairs of consecutive events for each flow ID
        in the `event_timings` dictionary and updates the `avg_delay_between_events` dictionary.

        Iterates through the events and their associated timings in the
        `event_timings` global dictionary. It computes the time difference between
        consecutive events and stores the maximum delay for each pair in the
        `avg_delay_between_events` global dictionary.

        Global Variables:
            event_timings (dict): Containing flow IDs as keys and lists
                of alternating events and their timings as values.
            avg_delay_between_events (dict): keys are concatenated
                pairs of events (as strings) and values are the maximum delay (float)
                between those events.
        """
    global event_timings, avg_delay_between_events

    for flow_id in event_timings:
        event_index = 0
        while event_index + 3 < len(event_timings[flow_id]):
            # Extract the first event and its timing
            first_event = event_timings[flow_id][event_index]
            first_event_timing = event_timings[flow_id][event_index + 1]

            # Extract the second event and its timing
            second_event = event_timings[flow_id][event_index + 2]
            second_event_timing = event_timings[flow_id][event_index + 3]

            # Create a combined key for the two events
            combined_events = first_event + second_event

            # Update the avg_delay_between_events dictionary with the maximum delay for the pair
            if combined_events in avg_delay_between_events:
                avg_delay_between_events[combined_events] = max(second_event_timing - first_event_timing, avg_delay_between_events[combined_events])
            else:
                avg_delay_between_events[combined_events] = second_event_timing - first_event_timing

            # Move to the next pair of events
            event_index += 2


def extractFrame(flowID, index, _packet, packet_count):
    """
        Extracts HTTP/2 frames from a packet, handles incomplete frames across packets, 
        and processes completed frames by calling the `findEvent` function.

        Parameters:
            flowID (str): The flow identifier for the packet.
            index (int): The current offset within the packet data.
            _packet (dict): The packet data containing the raw frame information.
            packet_count (int): The count of the packet being processed.

        Global Variables:
            incomplete_frame (dict): Stores incomplete frames for each flow ID.

        """
    global incomplete_frame

    if _packet['data'] is None:
        print("Error: current_frame is None. Skipping this packet.")
        return None

    packt_length = len(_packet['data']) #length of packet data

    if flowID in incomplete_frame:
        if incomplete_frame[flowID] != '':  # If partial content of the current flowID is already received in the previous frame
            if len(incomplete_frame[flowID]) >= 3:  # Since the length is present in the first 3 octet of HTTP2 header
                complete_frame_len = int(incomplete_frame[flowID][index:index + 3].hex(), 16)
            else:
                # If the first 3 octets of HTTP2 header is not present, read the length octets from incomplete_frame[flowID] and remaining length octets received in current packet.
                extract_len_bytes = incomplete_frame[flowID][index:] + _packet[Raw].load[:3 - len(incomplete_frame[flowID])]
                complete_frame_len = int(extract_len_bytes.hex(), 16)
            incomplete_frame_len = len(incomplete_frame[flowID]) - 9  # This can be negative, don't worry.
            remaining_frame_len = complete_frame_len - incomplete_frame_len  # Length of the remaining content of the frame.

            if remaining_frame_len <= packt_length:  # If whole remaining content is present in the current packet
                remaining_frame = _packet[Raw].load[index:remaining_frame_len]
                complete_frame = incomplete_frame[flowID] + remaining_frame
                print("before calling complete")
                findEvent(flowID, complete_frame, None, _packet.time, packet_count)
                print("after calling complete")
                index = remaining_frame_len
                incomplete_frame[flowID] = ''
            else:
                # If the remaining content is larger than the current packet, store the content received in current packet and then combine it with the contents in upcoming packets unless it becomes a complete frame.
                remaining_frame = _packet['data'][index:packt_length]
                incomplete_frame[flowID] += remaining_frame
                index = packt_length

    # Process the packet data to extract complete HTTP/2 frames
    while index < packt_length:  # Traverse through the whole packet in order to find the HTTP2 frames present into the packet.
        current_frame_len = int(_packet['data'][index:index + 3].hex(), 16)

        if index + current_frame_len + 9 <= packt_length:  # If one complete frame is present into the packet.
            current_frame = _packet['data'][index:index + current_frame_len + 9]
            findEvent(flowID, current_frame, None, _packet.time, packet_count)
        else:  # If only a part of the frame is present into the packet, store the remaining content into the incomplete frame[flowID].
            incomplete_frame[flowID] = _packet['data'][index:packt_length]

        index += current_frame_len + 9


def printEvents(print_options):
    """
        A function to save various datasets to text files based on the given print option.
    Args:
        print_options: Specifies what type of data to print:
             'avg_delay' - Prints average delays between events.
             'all' - Prints all datasets, including unique sequences, event timings, and flow dictionary.

    """
    global flow_dict, event_timings, avg_delay_between_events, unique_event_sequences, lookahead_pairs, pair_count

    if print_options == 'avg_delay':
        with open('avg_delay_dataset_new.txt', 'w') as f:
            for item in avg_delay_between_events:
                # Write each event pair and its average delay
                f.write('%s=%s' % (item, avg_delay_between_events[item]))
                f.write('\n')
    elif print_options == 'all':
        # Save the unique event sequences to a file
        with open('unique_sequences_new.txt', 'w') as f:
            for item in unique_event_sequences:
                f.write(item)
                f.write('\n')

        # Save the event timings dataset to a file
        with open('event_timings_new.txt', 'w') as f:
            for item in event_timings:
                f.write('%s %s' % (item, event_timings[item]))
                f.write('\n')

        # Save the flow dictionary dataset to a file
        with open('flowdict_new.txt', 'w') as f:
            for item in flow_dict:
                f.write('%s %s' % (item, flow_dict[item]))
                f.write('\n')


def readPackets(_pcap_file):
    """
     a pcap file, extracts packets that contain TCP data, and filters out packets
    associated with HTTP/1.1 clients. It also loads a pre-existing average delay dataset from a file if available.
    """
    global flow_dict, event_timings, delay_dictionary, incomplete_frame

    # List to track HTTP/1.1 clients and packets
    http11_clients = []  # To store flow IDs of clients using HTTP/1.1
    packets = []  # To store packet information

    # Load average delay dataset if it exists
    if os.path.exists("avg_delay_dataset_new.txt"):
        with open("avg_delay_dataset_new.txt", 'r') as f:
            lines = f.readlines()
            # Parse each line to extract event pair and time difference
            for line in lines:
                event, time_diff = line.strip().split('=')
                delay_dictionary[event] = float(time_diff)

    # Ensure pcap_file is a string path to a pcap file
    if not isinstance(_pcap_file, str):
        print(f"Expected a file path string, got {type(_pcap_file)} instead")
        return []  # Return an empty list if the input is invalid

    # Read the pcap file and process each packet
    with PcapReader(_pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            # Check if the packet has IP and TCP layers
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                # Construct a unique flow ID based on source and destination IPs and ports
                flowID = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"

                # Extract the packet payload, if available
                data = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None

                pkt_time = pkt.time  # timestamp of the packet

                packet_dict = {'flowID': flowID, 'data': data, 'time': pkt_time}
                packets.append(packet_dict)

                # Check if the packet is from a client using HTTP/1.1
                if pkt[TCP].sport == 80 and 'HTTP/1.1' in str(data):
                    http11_clients.append(flowID)

    # Filter the packets based on HTTP/1.1 clients if necessary
    filtered_packets = [pkt for pkt in packets if not any(client in pkt['flowID'] for client in http11_clients)]
    return filtered_packets


def import_dict_from_file(filename):

    """
    reads a file containing key-value pairs separated by '=' and imports them into a dictionary.
    The value is evaluated as a Python literal (if possible) to handle lists, booleans, or other Python data structures.
    If evaluation fails, the value is converted to a number (float or int) based on the format of the value.
    """
    dictionary = {}

    with open(filename, 'r') as file:
        for line in file:
            key, value = line.strip().split('=')  # Split the line into key and value by the '=' delimiter
            key = key.strip()  # Remove any leading/trailing whitespace from the key
            value = value.strip()  # Remove any leading/trailing whitespace from the value
            try:
                # Attempt to evaluate value as a Python expression
                # This will allow handling lists or other structures if they are in valid syntax
                value = ast.literal_eval(value)

            except (ValueError, SyntaxError):
                # Fall back to float or int if eval fails, treating value as simple number
                value = float(value) if '.' in value else int(value)
            dictionary[key] = value
    return dictionary


def copy_and_rename_files_in_folder(folder_path, new_name_prefix):
    """
    Copies and renames all files in the specified folder with a given prefix.

    Args:
        folder_path (str): Path to the folder containing files to copy and rename.
        new_name_prefix (str): Prefix for the new file names.

    Returns:
        None
    """
    try:
        # Check if the folder exists
        if not os.path.exists(folder_path):
            print(f"The folder {folder_path} does not exist.")
            return

        # Get the list of files in the folder
        files = os.listdir(folder_path)

        # Create a destination folder for the copied files
        destination_folder = os.path.join(f'{new_name_prefix}_streams')
        os.makedirs(destination_folder, exist_ok=True)
        index = 1
        # Iterate through the files and copy/rename them
        for index, file_name in enumerate(files):
            file_path = os.path.join(folder_path, file_name)

            # Skip if it's not a file
            if not os.path.isfile(file_path):
                continue

            # Get the file extension
            file_extension = os.path.splitext(file_name)[1]

            # Create the new file name
            new_file_name = f"{new_name_prefix}{index + 1}{file_extension}"
            new_file_path = os.path.join(destination_folder, new_file_name)

            # Copy and rename the file
            shutil.copy(file_path, new_file_path)

        print(f"Successfully copied and renamed files to {destination_folder}.")
        return index, destination_folder
    except Exception as e:
        print(f"An error occurred: {e}")



def split_streams(input_pcap):
    # Output directory
    output_dir = f'split_streams {input_pcap}'
    folder_dest = f'{input_pcap}_streams'
    if os.path.isdir(output_dir) or os.path.isdir(folder_dest):
        if os.path.isdir(folder_dest):
            return len(
                [f for f in os.listdir(folder_dest) if os.path.isfile(os.path.join(folder_dest, f))]), folder_dest
        else:
            return copy_and_rename_files_in_folder(output_dir, input_pcap)

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

    return copy_and_rename_files_in_folder(f'{output_dir}', input_pcap)


def export_dict_to_file(dictionary, filename):
    with open(filename, "w") as file:
        for key, value in dictionary.items():
            file.write(f"{key}={value}\n")


def write_to_file(file_name, text_to_append, mode):
    try:
        with open(file_name, mode) as file:  # 'a' mode creates the file if it doesn't exist and appends text
            file.write(text_to_append + '\n')  # Add a newline after the text
    except Exception as e:
        print(f"An error occurred: {e}")


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

    global seq_de, detect_count
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
        seq_de = ""
        detect_count = 0

        Dlookahead = import_dict_from_file("Dlookahead.txt")
        Ddelay = import_dict_from_file("Ddelay.txt")

        # Process each stream and detect mismatches
        for stream_index  in range(1, stream_count + 1):
            print(f"Open {input_pcap}{stream_index }.pcap")
            packets = readPackets(f'{dest_folder}/{input_pcap}{stream_index }.pcap')
            detection_phase_mismatch(Dlookahead, Ddelay, window_size, threshold, packets, input_pcap)

        write_to_file(f'DetectMissmatch_{input_pcap}', f'detect {detect_count} anomalous', 'a')



if __name__ == '__main__':

    begin = time.time()
    pcap_file = PCAP
    window_size = sys.argv[1] if len(sys.argv) > 1 else 2  # Default window size if not specified
    # packets = readPackets(pcap_file)  # Ensure this function reads the pcap file and returns packet data

    # open_datasets()

    # Dlookahead = import_dict_from_file("Dlookahead.txt")
    # Ddelay = import_dict_from_file("Ddelay.txt")

    main_run('proxy.pcap', 1)
    # # Check packets structure before passing to learning_phase
    # print("Packets structure check:", packets[:5])  # Print the first few packets to check structure
    # Dlookahead, Ddelay = learning_phase(packets, window_size)
    end = time.time()
