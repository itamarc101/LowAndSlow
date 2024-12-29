
# learning.py
from collections import defaultdict

def extractLookaheadPairs(seq, win_size):
    """Extracts lookahead pairs from a sequence."""
    lookahead_pairs = defaultdict(list)
    event_list = seq.split('->*')
    for current_index in range(len(event_list) - 1):
        for lookahead_distance in range(1, win_size + 1):
            lookahead_index = current_index + lookahead_distance
            if lookahead_index < len(event_list):
                pair = (event_list[lookahead_index], lookahead_distance)
                if pair not in lookahead_pairs[event_list[current_index]]:
                    lookahead_pairs[event_list[current_index]].append(pair)
    return lookahead_pairs

def learning_phase(Dlookahead, Ddelay, F, n):
    """Processes frames to extract lookahead pairs and delays."""
    lookahead_pairs = extractLookaheadPairs('Start->*' + '->*'.join([f['data'] for f in F]) + 'End', n)
    Dlookahead.update(lookahead_pairs)
    return Dlookahead, Ddelay, len(F)
