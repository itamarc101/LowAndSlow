import pyshark
from scapy.all import *
from scapy.contrib.http2 import *
from collections import defaultdict
import copy
import os
import ast

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
lookahead_pairs = defaultdict(list)  # to store the lookahead pairs

from scapy.layers.inet import IP, TCP

def extractLookaheadPairs(seq, window_size):
    unique_event_sequences = []
    pair_count = []
    l = []
    count = 0
    event_list = seq.split('->*')
    # print(f' event_list: {event_list}')

    i = 0
    while i + 1 < len(event_list):
        k = 1
        j = i + 1
        while j <= i + int(window_size):
            if j == len(event_list):  # When the cursor reaches end of the sequence
                break
            l.append(event_list[j])
            l.append(k)
            if l not in lookahead_pairs[event_list[i]]:
                temp = l.copy()
                lookahead_pairs[event_list[i]].append(temp)
                count += 1
            l.clear()
            j += 1
            k += 1
        i += 1
    pair_count.append(count)
    for item in lookahead_pairs:
        count += len(lookahead_pairs[item])
    end = time.time()
    # print('Execution Time: %s seconds' % (end - begin))
    # print('Total pairs processed: %s' % count)
    return lookahead_pairs
def learning_phase_2LOOPS(Dlookahead, Ddelay, F, n):
    global lookahead_pairs, incomplete_frame

    # Extract lookahead pairs for the given window size
    events_time = []
    events_time.append(F[0]['time'])

    pkt_count = 1  # Initialize packet count if needed for tracking within the flow
    for flow in F:
        seq = 'Start → ∗'  # Initialize sequence with 'Start'
        for frame in flow:
            if isinstance(frame, dict):  # Ensure the frame is a dictionary
                flowID, current_frame, pkt_time = frame['flowID'], frame['data'], frame['time']
                event = findEvent(flowID, current_frame, None, pkt_time, pkt_count)
                if event is not None:
                    with open('FrameToEvent.txt', 'a') as f:
                        f.write('%s=%s' % (current_frame, event))
                        f.write('\n')
                    events_time.append(pkt_time)
                    seq += f'{event}'
                    pkt_count += 1
        lookahead_pairs = extractLookaheadPairs(seq, n)

        Dlookahead.update(lookahead_pairs)
        events = seq.split('->*')

        i = 1
        while i < pkt_count:
            delay = events_time[i] - events_time[i - 1]
            str = f'{events[i - 1]}{events[i]}'
            if str not in Ddelay:
                Ddelay[str] = delay
            else:
                Ddelay[str] = max(delay, Ddelay[str])
            i += 1

        export_dict_to_file(Dlookahead, "Dlookahead.txt")
        export_dict_to_file(Ddelay, "Ddelay.txt")


def learning_phase(Dlookahead, Ddelay, F, n):
    global lookahead_pairs, incomplete_frame

    events_time = []
    seq = 'Start->*'

    events_time.append(F[0]['time'])

    pkt_count = 1
    for frame in F:
        if isinstance(frame, dict):
            flowID, current_frame, pkt_time = frame['flowID'], frame['data'], frame['time']
            event = findEvent(flowID, current_frame, None, pkt_time, pkt_count)
            if event is not None:
                with open('FrameToEvent.txt', 'a') as f:
                    f.write('%s=%s' % (current_frame, event))
                    f.write('\n')
                events_time.append(pkt_time)
                seq += f'{event}'
                pkt_count += 1

    events_time.append(F[-1]['time'])
    seq += 'End'
    lookahead_pairs = extractLookaheadPairs(seq, n)

    Dlookahead.update(lookahead_pairs)
    events = seq.split('->*')

    i = 1
    while i < pkt_count:
        delay = events_time[i] - events_time[i - 1]
        str = f'{events[i - 1]}{events[i]}'
        if str not in Ddelay:
            Ddelay[str] = delay
        else:
            Ddelay[str] = max(delay, Ddelay[str])
        i += 1

    export_dict_to_file(Dlookahead, "Dlookahead.txt")
    export_dict_to_file(Ddelay, "Ddelay.txt")

    return Dlookahead, Ddelay, pkt_count
def export_dict_to_file(dictionary, filename):
    with open(filename, "w") as file:
        for key, value in dictionary.items():
            file.write(f"{key}={value}\n")


def detection_phase(Dlookahead, Ddelay, n, t, packets, pcap_name):
    seq = ''
    events = []
    events_time = []
    i = 0
    index = 0
    delay_counter = 0
    # Assuming `packets` is a continuously updating list of packets
    for packet in packets:
        frame = packet['data']  # Assuming packet['data'] is the frame content
        event = findEvent(packet['flowID'], frame, None, packet['time'], 0)  # translateToEvent in pseudocode
        if event:
            index = index + 1
            seq += f'{event}'
            events_time.append(packet['time'])
            events.append(event)
            findEventTiming(packet['flowID'], event, packet['time'])  # Update event timing
    newevents = seq.split('->*')

    if(len(newevents) > 1):
        len_events = len(newevents)
        for i in range(1,len_events-1):
            twoevent = f'{newevents[i-1]}{newevents[i]}'

            write_to_file("DelaysDetect", twoevent)
            if twoevent in Ddelay:
                max_delay = Ddelay[twoevent] # Check the last event's maximum delay
                if(max_delay != 0):
                # Check time difference from the last event timing
                    last_event_time = events_time[-1] - events_time[-2]
                    if last_event_time  > max_delay:
                        write_to_file(f'DelaysDetect_{pcap_name}', f'Attack: Delayyyyy", {twoevent}, " - {max}: ", {max_delay},"<", {last_event_time}')
                        # print("Attack: Delayyyyy", twoevent, " - max: ", max_delay,"<", last_event_time)
                        delay_counter += 1
                        # return True
    write_to_file(f'DelaysDetect_{pcap_name}', f'Found {delay_counter} delays')
    # print(f'Found {delay_counter} delays')
    # return False

def write_to_file(file_name, text_to_append):
    try:
        with open(file_name, 'a') as file:  # 'a' mode creates the file if it doesn't exist and appends text
            file.write(text_to_append + '\n')  # Add a newline after the text
    except Exception as e:
        print(f"An error occurred: {e}")
def detection_phase_mismatch(Dlookahead, Ddelay, n, t, packets, pcap_name):
    global seq_de
    events = []
    i = 0

    for packet in packets:
        frame = packet['data']
        event = findEvent(packet['flowID'], frame, None, packet['time'], 0)
        if event:
            seq_de += f'{event}'
            events.append(event)
            findEventTiming(packet['flowID'], event, packet['time'])

    if not events:
        return

    last_event = events[-1]
    max_delay = max(Ddelay.get(last_event, {'*': 0}).values())
    last_event_time = event_timings.get(packet['flowID'], [-1, None])[-1]

    if last_event_time and (time.time() - last_event_time) > max_delay:
        seq_de += f' → TO{i} → *'
        print(f'Delayyyyy')
        i += 1

    mismatch = 0
    if len(events) > n:
        lookahead_pairs = extractLookaheadPairs(seq_de, n)
        for pair in lookahead_pairs:
            if pair not in Dlookahead:
                mismatch += 1
                print("added1tomismatch")

    mismatch_ratio = mismatch / (n * (len(events) - (n + 1) / 2))
    if mismatch_ratio > t:
        print("Sequence is anomalous")
    elif mismatch_ratio < t and events[-1] == '->Goaway->*':
        print("Sequence is normal")
    # else:
    #     print(events[-1])
    #     print(n * (len(events) - (n + 1) / 2))


def import_dict_from_file(filename):
    dictionary = {}
    with open(filename, 'r') as file:
        for line in file:
            key, value = line.strip().split('=')
            key = key.strip()
            value = value.strip()
            try:
                # Attempt to evaluate value as a Python expression
                # This will allow handling lists or other structures if they are in valid syntax
                value = ast.literal_eval(value)
            except (ValueError, SyntaxError):
                # Fall back to float or int if eval fails, treating value as simple number
                value = float(value) if '.' in value else int(value)
            dictionary[key] = value
    return dictionary


# Find the timing of event occurrences
def findEventTiming(flowID, event, pkt_time):
    global last_event, event_timings
    event_timings[flowID].append(event)
    event_timings[flowID].append(pkt_time)
    last_event[flowID] = event

def findEvent(flowID, current_frame, event, pkt_time, pkt_count):
    global last_event, event_timings, SERVER_PORT

    if flowID not in last_event:
        last_event[flowID] = ''

    # Check if current_frame is None
    if current_frame is None:
        print("Error: current_frame is None. Skipping this packet.")
        return None
    lenP = len(current_frame)
    # Check if the frame length is less than the minimum HTTP/2 header size
    if len(current_frame) < 9:
        print(f"Error: Frame length {len(current_frame)} is too short for a valid HTTP/2 frame for packet {pkt_count}.")
        return None

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

    if event is not None:
        findEventTiming(flowID, event, pkt_time)
        return event

    # Begin processing the frame to determine the type of event
    event = ''
    do_nothing = 0
    # print(f' current_frame: {current_frame}')

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
    global flow_dict, unique_event_sequences, event_timings, flow_dict_with_TO
    for flowID in event_timings:
        flow_dict[flowID] = ''
        i = 1
        for event in event_timings[flowID]:
            if i % 2 != 0:
                flow_dict[flowID] += event  # To store only the event names and not the timings
            i += 1

    for flowID in flow_dict:
        if flow_dict[flowID] not in unique_event_sequences:
            unique_event_sequences.append(flow_dict[flowID])

def calculateAvgDelayBetweenEvents():
    global event_timings, avg_delay_between_events
    for item in event_timings:
        i = 0
        while i + 3 < len(event_timings[item]):
            first_event = event_timings[item][i]
            first_event_timing = event_timings[item][i + 1]
            second_event = event_timings[item][i + 2]
            second_event_timing = event_timings[item][i + 3]
            combined_events = first_event + second_event
            if combined_events in avg_delay_between_events:
                avg_delay_between_events[combined_events] = max(second_event_timing - first_event_timing, avg_delay_between_events[combined_events])
            else:
                avg_delay_between_events[combined_events] = second_event_timing - first_event_timing
            i += 2

def extractFrame(flowID, index, pkt, pkt_count):
    global incomplete_frame
    if pkt['data'] is None:
        print("Error: current_frame is None. Skipping this packet.")
        return None
    pkt_length = len(pkt['data'])

    if flowID in incomplete_frame:
        if incomplete_frame[flowID] != '':  # If partial content of the current flowID is already received in the previous frame
            if len(incomplete_frame[flowID]) >= 3:  # Since the length is present in the first 3 octet of HTTP2 header
                complete_frame_len = int(incomplete_frame[flowID][index:index + 3].hex(), 16)
            else:
                # If the first 3 octets of HTTP2 header is not present, read the length octets from incomplete_frame[flowID] and remaining length octets received in current packet.
                extract_len_bytes = incomplete_frame[flowID][index:] + pkt[Raw].load[:3 - len(incomplete_frame[flowID])]
                complete_frame_len = int(extract_len_bytes.hex(), 16)
            incomplete_frame_len = len(incomplete_frame[flowID]) - 9  # This can be negative, don't worry.
            remaining_frame_len = complete_frame_len - incomplete_frame_len  # Length of the remaining content of the frame.
            if remaining_frame_len <= pkt_length:  # If whole remaining content is present in the current packet
                remaining_frame = pkt[Raw].load[index:remaining_frame_len]
                complete_frame = incomplete_frame[flowID] + remaining_frame
                print("before calling complete")
                findEvent(flowID, complete_frame, None, pkt.time, pkt_count)
                print("after calling complete")
                index = remaining_frame_len
                incomplete_frame[flowID] = ''
            else:
                # If the remaining content is larger than the current packet, store the content received in current packet and then combine it with the contents in upcoming packets unless it becomes a complete frame.
                remaining_frame = pkt['data'][index:pkt_length]
                incomplete_frame[flowID] += remaining_frame
                index = pkt_length
    while index < pkt_length:  # Traverse through the whole packet in order to find the HTTP2 frames present into the packet.
        current_frame_len = int(pkt['data'][index:index + 3].hex(), 16)
        if index + current_frame_len + 9 <= pkt_length:  # If one complete frame is present into the packet.
            current_frame = pkt['data'][index:index + current_frame_len + 9]
            findEvent(flowID, current_frame, None, pkt.time, pkt_count)
        else:  # If only a part of the frame is present into the packet, store the remaining content into the incomplete frame[flowID].
            incomplete_frame[flowID] = pkt['data'][index:pkt_length]
        index += current_frame_len + 9

def printEvents(print_options):
    global flow_dict, event_timings, avg_delay_between_events, unique_event_sequences, lookahead_pairs, pair_count
    if print_options == 'avg_delay':
        with open('avg_delay_dataset_new.txt', 'w') as f:
            for item in avg_delay_between_events:
                f.write('%s=%s' % (item, avg_delay_between_events[item]))
                f.write('\n')
    elif print_options == 'all':
        with open('unique_sequences_new.txt', 'w') as f:
            for item in unique_event_sequences:
                f.write(item)
                f.write('\n')
        with open('event_timings_new.txt', 'w') as f:
            for item in event_timings:
                f.write('%s %s' % (item, event_timings[item]))
                f.write('\n')
        with open('flowdict_new.txt', 'w') as f:
            for item in flow_dict:
                f.write('%s %s' % (item, flow_dict[item]))
                f.write('\n')

def readPackets(pcap_file):
    global flow_dict, event_timings, delay_dictionary, incomplete_frame
    http11_clients = []
    packets = []

    # Load average delay dataset if it exists
    if os.path.exists("avg_delay_dataset_new.txt"):
        with open("avg_delay_dataset_new.txt", 'r') as f:
            lines = f.readlines()
            for line in lines:
                event, time_diff = line.strip().split('=')
                delay_dictionary[event] = float(time_diff)

    # Ensure pcap_file is a string path to a pcap file
    if not isinstance(pcap_file, str):
        print(f"Expected a file path string, got {type(pcap_file)} instead")
        return []

    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            if pkt.haslayer(IP) and pkt.haslayer(TCP):
                flowID = f"{pkt[IP].src}:{pkt[TCP].sport}->{pkt[IP].dst}:{pkt[TCP].dport}"
                data = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else None
                pkt_time = pkt.time
                packet_dict = {'flowID': flowID, 'data': data, 'time': pkt_time}
                packets.append(packet_dict)
                if pkt[TCP].sport == 80 and 'HTTP/1.1' in str(data):
                    http11_clients.append(flowID)

    # Filter the packets based on HTTP/1.1 clients if necessary
    filtered_packets = [pkt for pkt in packets if not any(client in pkt['flowID'] for client in http11_clients)]
    return filtered_packets



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
        destination_folder = os.path.join(f'/home/dvir/PycharmProjects/FinalProj/{new_name_prefix}_streams')
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
    output_dir =  f'split_streams {input_pcap}'
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

    return copy_and_rename_files_in_folder(f'/home/dvir/PycharmProjects/FinalProj/{output_dir}', input_pcap)

def main_run(input_pcap, func=1, t=0.0):
    global seq_de
    Dlookahead = {}
    Ddelay = {}
    sum_packet = 0
    if func == 1:
        count, dest_folder = split_streams(input_pcap)

        for i in range(1, count + 1):
            print(f"Open input_pcap{i}.pcap")
            packets = readPackets(f'{dest_folder}/input_pcap{i}.pcap')
            Dlookahead, Ddelay, packets_count = learning_phase(Dlookahead, Ddelay, packets, window_size)

            sum_packet += packets_count
        print(f'Read {sum_packet} packets')
        export_dict_to_file(Dlookahead, "Dlookahead.txt")
        export_dict_to_file(Ddelay, "Ddelay.txt")
    elif func == 2:
        seq_de = ""
        Dlookahead = import_dict_from_file("Dlookahead.txt")
        Ddelay = import_dict_from_file("Ddelay.txt")
        # for i in range(1, count + 1):
        #     print(f"Open dataset{i}.pcap")
        packets = readPackets(input_pcap)
        detection_phase(Dlookahead, Ddelay, window_size, t, packets, input_pcap)

    elif func == 3:
        count, dest_folder = split_streams(input_pcap)
        seq_de = ""
        Dlookahead = import_dict_from_file("Dlookahead.txt")
        Ddelay = import_dict_from_file("Ddelay.txt")
        for i in range(1, count + 1):
            print(f"Open dataset{i}.pcap")
            packets = readPackets(f'{dest_folder}/{input_pcap}{i}.pcap')
            detection_phase_mismatch(Dlookahead, Ddelay, window_size, t, packets, input_pcap)

if __name__ == '__main__':

    begin = time.time()
    pcap_file = PCAP
    window_size = sys.argv[1] if len(sys.argv) > 1 else 2  # Default window size if not specified
    # packets = readPackets(pcap_file)  # Ensure this function reads the pcap file and returns packet data

    # open_datasets()

    # Dlookahead = import_dict_from_file("Dlookahead.txt")
    # Ddelay = import_dict_from_file("Ddelay.txt")

    main_run('attack1.pcap', 3, 0.01)
    # # Check packets structure before passing to learning_phase
    # print("Packets structure check:", packets[:5])  # Print the first few packets to check structure
    # Dlookahead, Ddelay = learning_phase(packets, window_size)
    end = time.time()

    # print("Lookahead Pairs:", Dlookahead)
    # print("Max Delays:", Ddelay)
    # print("Total Execution Time: %s seconds" % (end - begin))

    # pcap_detect = 'attack1.pcap'
    # packets_to_detect = readPackets(pcap_detect)  # Ensure this function reads the pcap file and returns packet data
    #
    # # Detect attack
    # attack_detected = detection_phase(Dlookahead, Ddelay, window_size, 6, packets_to_detect)
    # attack_detected = detection_phase_mismatch(Dlookahead, Ddelay, 5, 0.01, packets_to_detect)

    # if attack_detected:
    #     print("Attack detected!")
    # else:
    #     print("No attack detected.")
