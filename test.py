import unittest
from unittest.mock import patch, MagicMock
from io import StringIO
import os
import hashlib
import datetime  # Correct import
from malware import *

class TestMalwareScanner(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory for testing
        self.test_dir = 'test_dir'
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        # Remove the temporary directory after testing
        if os.path.exists(self.test_dir):
            for file in os.listdir(self.test_dir):
                os.remove(os.path.join(self.test_dir, file))
            os.rmdir(self.test_dir)

    @patch('builtins.open', return_value=StringIO('hash1\nhash2\n'))
    def test_hash_exists_in_db(self, mock_open):
        # Set up the test scenario
        global _engine_extract_file_
        _engine_extract_file_ = "fake_database.txt"
        check_hash = "hash2"

        # Call the function under test
        result = hash_exists_in_db(check_hash)

        # Check the result
        self.assertTrue(result)

    def test_make_hash(self):
        # Create a temporary file and test its hash
        test_file = os.path.join(self.test_dir, 'test_file.txt')
        with open(test_file, 'w') as f:
            f.write('This is a test file.')
        expected_hash = hashlib.sha256(b'This is a test file.').hexdigest()
        self.assertEqual(make_hash(test_file), expected_hash)

    def test_contains_eicar_test_string(self):
        # Test for detecting the EICAR test string
        eicar_content = "This is a test EICAR string: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        self.assertTrue(contains_eicar_test_string(eicar_content))

        non_eicar_content = "This is a non-EICAR string."
        self.assertFalse(contains_eicar_test_string(non_eicar_content))

    @patch('malware.hash_exists_in_db')
    def test_scan_file(self, mock_hash_exists_in_db):
        # Mock hash_exists_in_db function
        mock_hash_exists_in_db.return_value = True

        # Create a temporary file
        with open('infected_file.txt', 'w') as f:
            f.write('Malware content')

        # Scan the infected file
        result = scan_file('infected_file.txt')

        # Check the scan result
        self.assertTrue(result['hash_match'])
        self.assertFalse(result['string_match'])

        # Remove the temporary file
        os.remove('infected_file.txt')

    def test_check_file_size(self):
        # Create a temporary file with large size
        large_file = os.path.join(self.test_dir, 'large_file.txt')
        with open(large_file, 'wb') as f:
            f.write(b'0' * 10485761)  # 10MB + 1 byte

        # Check if check_file_size returns False for large file
        self.assertFalse(check_file_size(large_file))

        # Remove the temporary file
        os.remove(large_file)

    def test_get_create_date(self):
        # Create a temporary file
        test_file = os.path.join(self.test_dir, 'test_file.txt')
        with open(test_file, 'w') as f:
            f.write('This is a test file.')

        # Get creation date of the file
        creation_date = get_create_date(test_file)

        # Check if the date is in the correct format
        self.assertIsInstance(datetime.strptime(creation_date, '%Y-%m-%d %H:%M:%S'), datetime)

        # Remove the temporary file
        os.remove(test_file)

    def test_get_modify_date(self):
        # Create a temporary file
        test_file = os.path.join(self.test_dir, 'test_file.txt')
        with open(test_file, 'w') as f:
            f.write('This is a test file.')

        # Get modification date of the file
        modify_date = get_modify_date(test_file)

        # Check if the date is in the correct format
        self.assertIsInstance(datetime.strptime(modify_date, '%Y-%m-%d %H:%M:%S'), datetime)

        # Remove the temporary file
        os.remove(test_file)

    @patch('socket.gethostbyname')
    @patch('socket.gethostname')
    def test_get_ip_address(self, mock_gethostname, mock_gethostbyname):
        # Mock the socket functions
        mock_gethostname.return_value = 'localhost'
        mock_gethostbyname.return_value = '192.168.1.1'

        # Get the IP address
        ip_address = get_ip_address()

        # Check if the IP address is returned correctly
        self.assertEqual(ip_address, '192.168.1.1')


if __name__ == '__main__':
    unittest.main()
