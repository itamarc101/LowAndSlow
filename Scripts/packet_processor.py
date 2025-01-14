"""
Module for processing packets and extracting frames from HTTP/2 traffic.
"""
from scapy.all import *
from scapy.contrib.http2 import *
from scapy.layers.inet import IP, TCP
from collections import defaultdict
import config
from event_analyzer import findEventTiming


def readPackets(_pcap_file):
    """
     a pcap file, extracts packets that contain TCP data, and filters out packets
    associated with HTTP/1.1 clients. It also loads a pre-existing average delay dataset from a file if available.
    """

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
                config.delay_dictionary[event] = float(time_diff)

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

    if _packet['data'] is None:
        print("Error: current_frame is None. Skipping this packet.")
        return None

    packt_length = len(_packet['data']) #length of packet data

    if flowID in config.incomplete_frame:
        if config.incomplete_frame[flowID] != '':  # If partial content of the current flowID is already received in the previous frame
            if len(config.incomplete_frame[flowID]) >= 3:  # Since the length is present in the first 3 octet of HTTP2 header
                complete_frame_len = int(config.incomplete_frame[flowID][index:index + 3].hex(), 16)
            else:
                # If the first 3 octets of HTTP2 header is not present, read the length octets from incomplete_frame[flowID] and remaining length octets received in current packet.
                extract_len_bytes = config.incomplete_frame[flowID][index:] + _packet[Raw].load[:3 - len(config.incomplete_frame[flowID])]
                complete_frame_len = int(extract_len_bytes.hex(), 16)
            incomplete_frame_len = len(config.incomplete_frame[flowID]) - 9  # This can be negative, don't worry.
            remaining_frame_len = complete_frame_len - incomplete_frame_len  # Length of the remaining content of the frame.

            if remaining_frame_len <= packt_length:  # If whole remaining content is present in the current packet
                remaining_frame = _packet[Raw].load[index:remaining_frame_len]
                complete_frame = config.incomplete_frame[flowID] + remaining_frame
                print("before calling complete")
                findEvent(flowID, complete_frame, None, _packet.time, packet_count)
                print("after calling complete")
                index = remaining_frame_len
                config.incomplete_frame[flowID] = ''
            else:
                # If the remaining content is larger than the current packet, store the content received in current packet and then combine it with the contents in upcoming packets unless it becomes a complete frame.
                remaining_frame = _packet['data'][index:packt_length]
                config.incomplete_frame[flowID] += remaining_frame
                index = packt_length

    # Process the packet data to extract complete HTTP/2 frames
    while index < packt_length:  # Traverse through the whole packet in order to find the HTTP2 frames present into the packet.
        current_frame_len = int(_packet['data'][index:index + 3].hex(), 16)

        if index + current_frame_len + 9 <= packt_length:  # If one complete frame is present into the packet.
            current_frame = _packet['data'][index:index + current_frame_len + 9]
            findEvent(flowID, current_frame, None, _packet.time, packet_count)
        else:  # If only a part of the frame is present into the packet, store the remaining content into the incomplete frame[flowID].
            config.incomplete_frame[flowID] = _packet['data'][index:packt_length]

        index += current_frame_len + 9


def findEvent(flowID, current_frame, event, pkt_time, pkt_count):
    """  Determines the event type from a given packet's data and flow ID.  """

    if flowID not in config.last_event:
        config.last_event[flowID] = ''

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


    if src_port == config.SERVER_PORT:
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
        if 'ES' not in current_frame.flags and config.last_event.get(flowID, '') != '->Data_frame_!ES->*':
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
    elif event == '' and flowID in config.last_event and config.last_event[flowID] == '->Data_frame_!ES->*' and do_nothing == 0:
        findEventTiming(flowID, config.last_event[flowID], pkt_time)  # This line was corrected to call the findEventTiming function properly
        return config.last_event[flowID]