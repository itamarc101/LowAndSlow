from new_parser_client_side import *
from collections import defaultdict
import sys, time
from scapy.all import sniff

from new_parser_client_side import extractFrame

lookahead_pairs = defaultdict(list)  # to store the lookahead pairs

def extractLookaheadPairs(seq, window_size):
    unique_event_sequences = []
    pair_count = []
    l = []
    count = 0

    event_list = seq.split('->')
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
    count = 0
    for item in lookahead_pairs:
        count += len(lookahead_pairs[item])
    end = time.time()
    print('Execution Time: %s seconds' % (end - begin))
    print('Total pairs processed: %s' % count)
    return lookahead_pairs


def learning_phase(F, n):
    global lookahead_pairs
    Dlookahead = {}
    Ddelay = {}

    # Extract lookahead pairs for the given window size
    events_time = []
    seq = 'Start → '
    events_time.append(0)
    pkt_count = 1  # Initialize packet count if needed for tracking within the flow
    for frame in F:
        print("Processing frame:", frame)  # Debug output to check what `frame` contains
        print("Type of frame:", type(frame))  # Print the type to verify it's a dictionary
        # Proceed only if frame is a dictionary
        if isinstance(frame, dict):
            flowID, current_frame, pkt_time = frame['flowID'], frame['data'], frame['time']
            extractFrame(flowID, 0, frame, pkt_count)
            print("PRINTING FRAME DATA  == ", frame['data'])
            print("IN LEASRNING PHASE CALLING CURRENT FRAME WITH NONE")
            event = findEvent(flowID, current_frame, None, pkt_time, pkt_count)

            if event is not None:
                events_time.append(pkt_time)
                seq += f'{event} → '
                pkt_count += 1
        else:
            continue
            print("Error: Frame is not a dictionary", frame)
    
    seq += ' → End'
    Dlookahead.update(extractLookaheadPairs(seq, n) ) # This updates the global lookahead_pairs directly
    events = seq.split(' → ')
    print(pkt_count)
    print(len(events))
    print(len(events_time))
    i=1
    while i < pkt_count:
        delay = events_time[i]-events_time[i-1]
        str= f' {events[i-1]} → {events[i]}'
        if str not in Ddelay:
            Ddelay[str]=delay
        else:
            Ddelay[str]=max(delay, Ddelay[str])
        i += 1

    
    return Dlookahead, Ddelay

def detection_phase(Dlookahead, Ddelay, n, t, packets, dummy):
    seq = ''
    events = []
    while True:
        # Assuming `packets` is a continuously updating list of packets
        for packet in packets:
            frame = packet['data']  # Assuming packet['data'] is the frame content
            event = findEvent(packet['flowID'], frame, None, packet['time'], 0)  # translateToEvent in pseudocode
            if event:
                seq += f' → {event} → *'
                events.append(event)
                findEventTiming(packet['flowID'], event, packet['time'])  # Update event timing
                
        if not events:
            continue

        last_event = events[-1]
        max_delay = max(Ddelay.get(last_event, {'*': 0}).values())  # Check the last event's maximum delay
        
        # Check time difference from the last event timing
        last_event_time = event_timings.get(packet['flowID'], [-1, None])[-1]
        if last_event_time and (time.time() - last_event_time) > max_delay:
            seq += ' → TOi → *'  # Time-out injection
        
        mismatch = 0
        if len(events) > n:
            lookahead_pairs = extractLookaheadPairs(events, n)  # Assuming function to extract pairs from sequence
            for pair in lookahead_pairs:
                if pair not in Dlookahead:
                    mismatch += 1
            
            mismatch_ratio = mismatch / (n * (len(events) - (n + 1) / 2))
            if mismatch_ratio > t:
                print("Sequence is anomalous")
            elif mismatch_ratio < t and events[-1] == 'End':
                print("Sequence is normal")


if __name__ == '__main__':
    begin = time.time()
    pcap_file = 'http_slowloris.pcap'
    window_size = sys.argv[1] if len(sys.argv) > 1 else 2  # Default window size if not specified
    packets = readPackets(pcap_file)  # Ensure this function reads the pcap file and returns packet data

    # Check packets structure before passing to learning_phase
    print("Packets structure check:", packets[:5])  # Print the first few packets to check structure
    Dlookahead, Ddelay = learning_phase(packets, window_size)
    end = time.time()

    # print("Lookahead Pairs:", Dlookahead)
    # print("Max Delays:", Ddelay)
    # print("Total Execution Time: %s seconds" % (end - begin))

    # # Detect attack
    # attack_detected = detection_phase(Dlookahead, Ddelay, window_size, 6, packets, 10)
    # if attack_detected:
    #     print("Attack detected!")
    # else:
    #     print("No attack detected.")






















# # extract_lookahead_pairs.py
# from shared_functions import findEvent, extractFrame, findEventTiming, readPackets
# from collections import defaultdict
# import sys, time
# from scapy.all import sniff


# lookahead_pairs = defaultdict(list)  # to store the lookahead pairs

# def extractLookaheadPairs(window_size):
#     unique_event_sequences = []
#     pair_count = []
#     l = []
#     count = 0
#     with open('flowdict_new.txt') as f:
#         for sequence in f:
#             sequence = sequence.strip('\n')
#             sequence = sequence.split(' ')[1]  # NOTE: comment this line if generating lookaheads from unique sequences instead of flow dict.
#             unique_event_sequences.append(sequence)
    
#     for sequence in unique_event_sequences:
#         sequence = sequence.strip('->')
#         event_list = sequence.split('->')
#         i = 0
#         while i + 1 < len(event_list):
#             k = 1
#             j = i + 1
#             while j <= i + int(window_size):
#                 if j == len(event_list):  # When the cursor reaches end of the sequence
#                     break
#                 l.append(event_list[j])
#                 l.append(k)
#                 if l not in lookahead_pairs[event_list[i]]:
#                     temp = l.copy()
#                     lookahead_pairs[event_list[i]].append(temp)
#                     count += 1
#                 l.clear()
#                 j += 1
#                 k += 1
#             i += 1
#         pair_count.append(count)
#     count = 0
#     for item in lookahead_pairs:
#         count += len(lookahead_pairs[item])
#     end = time.time()
#     print('Execution Time: %s seconds' % (end - begin))
#     print('Total pairs processed: %s' % count)

# def learning_phase(F, n):
#     global lookahead_pairs
#     Dlookahead = defaultdict(list)
#     Ddelay = {}

#     # Extract lookahead pairs for the given window size
#     extractLookaheadPairs(n)  # This updates the global lookahead_pairs directly
#     seq = 'Start → *'
#     pkt_count = 0  # Initialize packet count if needed for tracking within the flow

#     for frame in F:
#         print("Processing frame:", frame)  # Debug output to check what `frame` contains
#         print("Type of frame:", type(frame))  # Print the type to verify it's a dictionary
#         # Proceed only if frame is a dictionary
            
#         if isinstance(frame, dict):
#             flowID, current_frame, pkt_time = frame['flowID'], frame['data'], frame['time']
#             event = findEvent(flowID, current_frame, None, pkt_time, pkt_count)
#             seq += f' → {event} → *'
#             pkt_count += 1
#         else:
#             print("Error: Frame is not a dictionary", frame)
#     seq += ' → End'

#         # Additional processing if required...
#     # Return or further processing...

#     return Dlookahead, Ddelay

# def detection_phase(Dlookahead, Ddelay, n, t, packets, sniff_duration):
#     seq = ''
#     start_time = time.time()

#     while time.time() - start_time < sniff_duration:
#         for packet in packets:
#             flowID = packet['flowID']
#             current_frame = packet['data']
#             pkt_time = packet['time']
#             pkt_count = 0  # Initialize or update this if necessary

#             event = findEvent(flowID, current_frame, None, pkt_time, pkt_count)
#             seq += f' → {event} → *'
#             findEventTiming(flowID, event, pkt_time)  # Call to log the event timing

#         events = extractFrame(seq)  # Assuming this function extracts list of events from the sequence
#         if events:
#             last_event = events[-1]
#             last_event_time = findEventTiming.get(flowID, [None] * 2)[1]  # Call to get the time of the last event
#             max_delay = max(Ddelay.get(last_event, {}).values(), default=0)

#             if last_event_time and (time.time() - last_event_time) > max_delay:
#                 seq += ' → TOi → *'  # Implementing timeout injection

#             mismatch = 0
#             if len(events) > n:
#                 l = extractLookaheadPairs(seq, n)  # Function to extract lookahead pairs from sequence
#                 for pair in l:
#                     if pair not in Dlookahead:
#                         mismatch += 1

#                 mismatch_ratio = mismatch / (n * (len(events) - (n + 1) / 2))
#                 if mismatch_ratio > t:
#                     print("Sequence is anomalous")
#                 elif mismatch_ratio < t and events[-1] == 'End':
#                     print("Sequence is normal")


# if __name__ == '__main__':
#     begin = time.time()
#     pcap_file = 'http-flood.pcap'
#     window_size = sys.argv[1] if len(sys.argv) > 1 else 2  # Default window size if not specified
#     packets = readPackets(pcap_file)  # Ensure this function reads the pcap file and returns packet data

#     # Check packets structure before passing to learning_phase
#     print("Packets structure check:", packets[:5])  # Print the first few packets to check structure
#     Dlookahead, Ddelay = learning_phase(packets, window_size)
#     end = time.time()

#     print("Lookahead Pairs:", Dlookahead)
#     print("Max Delays:", Ddelay)
#     print("Total Execution Time: %s seconds" % (end - begin))

#     # Detect attack
#     attack_detected = detection_phase(Dlookahead, Ddelay, window_size, 6, packets, 10)
#     if attack_detected:
#         print("Attack detected!")
#     else:
#         print("No attack detected.")
