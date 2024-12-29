
# utils.py
import ast

def export_dict_to_file(dictionary, filename):
    """Exports a dictionary to a file."""
    with open(filename, "w") as file:
        for key, value in dictionary.items():
            file.write(f"{key}={value}\n")

def import_dict_from_file(filename):
    """Imports a dictionary from a file."""
    dictionary = {}
    with open(filename, 'r') as file:
        for line in file:
            key, value = line.strip().split('=')
            dictionary[key] = ast.literal_eval(value)
    return dictionary

def write_to_file(file_name, text_to_append, mode):
    """Appends text to a file."""
    with open(file_name, mode) as file:
        file.write(text_to_append + '\n')
