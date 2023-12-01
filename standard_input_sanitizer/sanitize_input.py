from typing import Any, Dict, List, Union
import html
import re

def sanitize_input(input_data: Union[str, List[Any], Dict[str, Any]]) -> Union[str, List[Any], Dict[str, Any]]:
    """
    :param input_data: The input data to be sanitized, can be a string, list, or dictionary.
    :return: The sanitized data.
    """

    if isinstance(input_data, dict):
        # Recursively sanitize dictionary
        return { sanitize_input(key): sanitize_input(value) for key, value in input_data.items()}

    elif isinstance(input_data, list):
        # Recursively sanitize list
        return [sanitize_input(element) for element in input_data]

    elif isinstance(input_data, str):
        # Apply all filters
        sanitized_str = html.escape(input_data, quote=False)
        sanitized_str = filter_payloads(sanitized_str)
        return remove_unprinted_characters(sanitized_str)

    else:
        # Return the input as is for other data types
        return input_data

def remove_unprinted_characters(s):
    # Remove unprinted characters from a string, but allow newlines, tabs, and unicode characters
    return re.sub(r'[^\x20-\x7E\n\t\u0080-\uFFFF]', '', s)

log4j_patterns = re.compile(r'\$\{(?:jndi:(ldap[s]?|rmi|dns|iiop|corba|nds|http|https)://|env|lower|upper)[^\}]+\}')
sql_injection_patterns = re.compile(r'\b(SELECT|UPDATE|DELETE|INSERT|TABLE|WHERE)\b\s*[\*;\'"\(\)]', re.IGNORECASE)
path_traversal_patterns = re.compile(r'(\.\./|\.\.\\)')

def filter_payloads(s):
    # Enhanced filter for Log4J and Shellshock payloads
    shellshock_patterns = re.compile(r'\(\)\s*{\s*:;\s*};\s*')

    s = log4j_patterns.sub('', s)
    s = shellshock_patterns.sub('', s)
    s = sql_injection_patterns.sub('', s)
    s = path_traversal_patterns.sub('', s)

    return s
