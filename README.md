# Standard Input Sanitizer for Python
Standard Input Sanitizer is a basic library to lazily filter input coming to your lambdas and servers.
Disclaimer: this will not filter all possible bad input. This is only a starting point for a filtering system.

## Features:

- XSS filtering.
- SQLi filtering.
- Log4J filtering.
- Shellshock filtering.
- Path traversal filtering.
- Null byte filtering.
- Recursive filtering filters of dictionaries and lists.
- Dictionary key sanitization.

## Install:
`pip install git+https://github.com/mirror12k/standard-input-sanitizer`

## Usage:
```py
from standard_input_sanitizer import sanitize_input

# start with some potentially dangerous input
nasty_input = '<script>alert(1)</script>'
# sanitize
sanitized_input = sanitize_input(nasty_input)
# view the sanitized result
print(f'got sanitized_input: {sanitized_input}') # prints "got sanitized_input: &lt;script&gt;alert(1)&lt;/script&gt;"

# or start with a dictionary of values:
dangerous_object = ["<List>", "() { :;}; echo shellshocked", {"nested_key": "<Nested>"}]
sanitized_object = sanitize_input(dangerous_object)
print(f'got sanitized_object: {sanitized_object}') # prints "got sanitized_object: ['&lt;List&gt;', 'echo shellshocked', {'nested_key': '&lt;Nested&gt;'}]"

```

