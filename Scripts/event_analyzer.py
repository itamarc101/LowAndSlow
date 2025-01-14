"""
Module for analyzing events and sequences in HTTP/2 traffic.
"""

from collections import defaultdict
import config

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
            if lookahead_pair not in config.lookahead_pairs[event_list[current_index]]:
                temp = lookahead_pair.copy() # copy of temp list to avoid issues

                # Append new lookahead pair for the current event
                config.lookahead_pairs[event_list[current_index]].append(temp)
                count += 1 # Inc lookahead pair count

            lookahead_pair.clear() # Clear temp list for the next pair
            lookahead_index += 1 # Next lookahead event
            lookahead_distance += 1 # Next distance

        current_index += 1 # Next event in sequence

    config.pair_count.append(count) #Append total count of pairs to list

    # Sum up all lookahead pairs
    for item in config.lookahead_pairs:
        count += len(config.lookahead_pairs[item])

    return config.lookahead_pairs


# Find the timing of event occurrences
def findEventTiming(flowID, event, pkt_time):
    config.event_timings[flowID].append(event)
    config.event_timings[flowID].append(pkt_time)
    config.last_event[flowID] = event



def findEventSequencesPerFlow():
    """
    Extracts and stores unique event sequences for each flow based on their timings.

    Updates:
        - flow_dict: with event sequences for each flow
        - unique_event_sequences: with any new sequences found.

    """
    for flowID in config.event_timings:
        config.flow_dict[flowID] = ''
        index = 1
        for event in config.event_timings[flowID]:
            if index % 2 != 0:
                config.flow_dict[flowID] += event  # To store only the event names and not the timings
            index += 1

    for flowID in config.flow_dict:
        if config.flow_dict[flowID] not in config.unique_event_sequences:
            config.unique_event_sequences.append(config.flow_dict[flowID])


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

    for flow_id in config.event_timings:
        event_index = 0
        while event_index + 3 < len(config.event_timings[flow_id]):
            # Extract the first event and its timing
            first_event = config.event_timings[flow_id][event_index]
            first_event_timing = config.event_timings[flow_id][event_index + 1]

            # Extract the second event and its timing
            second_event = config.event_timings[flow_id][event_index + 2]
            second_event_timing = config.event_timings[flow_id][event_index + 3]

            # Create a combined key for the two events
            combined_events = first_event + second_event

            # Update the avg_delay_between_events dictionary with the maximum delay for the pair
            if combined_events in config.avg_delay_between_events:
                config.avg_delay_between_events[combined_events] = max(second_event_timing - first_event_timing, config.avg_delay_between_events[combined_events])
            else:
                config.avg_delay_between_events[combined_events] = second_event_timing - first_event_timing

            # Move to the next pair of events
            event_index += 2
