import unittest
from unittest import mock
from collections import namedtuple

import disk_tester


class TestDiskTester(unittest.TestCase):
    def test_get_platform_ioengine_linux(self):
        with mock.patch('platform.system', return_value='Linux'):
            self.assertEqual(disk_tester.get_platform_ioengine(), 'libaio')

    def test_get_platform_ioengine_windows(self):
        with mock.patch('platform.system', return_value='Windows'):
            self.assertEqual(disk_tester.get_platform_ioengine(), 'windowsaio')

    def test_get_platform_ioengine_other(self):
        with mock.patch('platform.system', return_value='Darwin'):
            self.assertEqual(disk_tester.get_platform_ioengine(), 'posixaio')

    def test_format_bytes(self):
        self.assertEqual(disk_tester.format_bytes(1024), '1024.00 B')
        self.assertEqual(disk_tester.format_bytes(1024**2), '1024.00 KB')

    def test_parse_size(self):
        self.assertEqual(disk_tester.parse_size('1K'), 1024)
        self.assertEqual(disk_tester.parse_size('1M'), 1024**2)
        self.assertEqual(disk_tester.parse_size('1G'), 1024**3)
        self.assertEqual(disk_tester.parse_size('1.5G'), int(1.5 * 1024**3))
        self.assertEqual(disk_tester.parse_size('2048'), 2048)
        with self.assertRaises(ValueError):
            disk_tester.parse_size('')
        with self.assertRaises(ValueError):
            disk_tester.parse_size('BAD')

    def test_get_test_size_directory(self):
        usage = namedtuple('usage', ['total', 'used', 'free'])(0, 0, 1000)
        with mock.patch('os.path.isdir', return_value=True), \
            mock.patch('os.path.exists', return_value=True), \
            mock.patch('shutil.disk_usage', return_value=usage):
            self.assertEqual(disk_tester.get_test_size('C:\\fake'), 900)

    def test_get_test_size_file(self):
        usage = namedtuple('usage', ['total', 'used', 'free'])(0, 0, 900)
        with mock.patch('os.path.isdir', return_value=False), \
            mock.patch('os.path.exists', return_value=True), \
            mock.patch('os.path.isfile', return_value=True), \
            mock.patch('os.path.getsize', return_value=100), \
            mock.patch('shutil.disk_usage', return_value=usage):
            self.assertEqual(disk_tester.get_test_size('C:\\fake\\disk_test.dat'), 900)


if __name__ == '__main__':
    unittest.main()
