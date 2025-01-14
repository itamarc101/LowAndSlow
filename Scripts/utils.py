import os
import ast
import shutil
import subprocess

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
