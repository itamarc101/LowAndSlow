import time

import config
from event_analyzer import findEventTiming, extractLookaheadPairs
from packet_processor import findEvent
from utils import write_to_file


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

    detected_events = []
    timeout_counter = 0

    # Build event sequence for each packet
    for packet in packets:
        frame_data = packet['data']
        #Map frame to event
        event = findEvent(packet['flowID'], frame_data, None, packet['time'], 0)
        if event:
            config.seq_de += f'{event}' #Add event to global sequence
            detected_events.append(event)
            # Update event timing (used for delay violation checks)
            findEventTiming(packet['flowID'], event, packet['time'])

    if not detected_events:
        return

    # Check for delay violations
    _last_event = detected_events[-1] # Last detected event
    max_delay = max(Ddelay.get(_last_event, {'*': 0}).values()) # Max delay for last event
    last_event_time = config.event_timings.get(packet['flowID'], [-1, None])[-1] # Last event's timing


    if last_event_time and (time.time() - last_event_time) > max_delay:
        # Append timeout marker to sequence and log the delay
        config.seq_de += f' → TO{timeout_counter} → *'
        write_to_file(f'DetectMissmatch_{pcap_name}', f'Delayyyyy - {_last_event}', 'a')
        timeout_counter += 1

    # Detect mismatched lookahead pairs
    mismatch = 0
    if len(detected_events) > n:
        # Extract lookahead pairs from the sequence
        _lookahead_pairs = extractLookaheadPairs(config.seq_de, n)
        for pair in _lookahead_pairs:
            if pair not in Dlookahead:
                mismatch += 1
                write_to_file(f'DetectMissmatch_{pcap_name}', "added1to_mismatch", 'a')

    # Calculate mismatch ratio
    mismatch_ratio = mismatch / (n * (len(detected_events) - (n + 1) / 2))

    # Log whether the sequence is anomalous or normal based on the mismatch ratio
    if mismatch_ratio > t:
        write_to_file(f'DetectMissmatch_{pcap_name}', "Sequence is anomalous", 'a')
        config.detect_count += 1
    elif mismatch_ratio < t and detected_events[-1] == '->Goaway->*':
        write_to_file(f'DetectMissmatch_{pcap_name}', "Sequence is normal", 'a')
