"""
Configuration file containing global variables and constants used across the project.
"""
from collections import defaultdict

SERVER_PORT = 80

# Global variables used across modules
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
seq_de = ""
detect_count = 0