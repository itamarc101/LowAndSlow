from event_analyzer import extractLookaheadPairs, findEventTiming
from packet_processor import findEvent
import config
from utils import export_dict_to_file


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
