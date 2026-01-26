import unittest
from unittest import mock
from collections import namedtuple
import io
import json
import dataclasses

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

    def test_log_line_timestamp(self):
        handle = io.StringIO()
        with mock.patch.object(disk_tester, "_now_ts", return_value="2026-01-01 01:02:03"):
            disk_tester._log_line("Hello", handle, also_print=False)
        self.assertEqual(handle.getvalue(), "[2026-01-01 01:02:03] Hello\n")

    def test_log_json_line(self):
        handle = io.StringIO()
        with mock.patch.object(disk_tester, "_now_ts", return_value="2026-01-01 01:02:03"):
            disk_tester._log_json("FIO_JSON test", {"b": 2, "a": 1}, handle)
        self.assertEqual(
            handle.getvalue(),
            "[2026-01-01 01:02:03] FIO_JSON test {\"a\":1,\"b\":2}\n"
        )

    def test_run_fio_job_allow_errors_nonzero(self):
        result = mock.Mock(returncode=1, stdout="", stderr="boom")
        with mock.patch('subprocess.run', return_value=result):
            res, err = disk_tester.run_fio_job(["--rw=read"], allow_errors=True)
        self.assertIsNone(res)
        self.assertEqual(err["returncode"], 1)
        self.assertEqual(err["stderr"], "boom")

    def test_run_fio_job_allow_errors_parse_error(self):
        result = mock.Mock(returncode=0, stdout="not-json", stderr="")
        with mock.patch('subprocess.run', return_value=result):
            res, err = disk_tester.run_fio_job(["--rw=read"], allow_errors=True)
        self.assertIsNone(res)
        self.assertIn("parse_error", err)

    def test_run_fio_job_allow_errors_ok(self):
        result = mock.Mock(returncode=0, stdout=json.dumps({"jobs": []}), stderr="")
        with mock.patch('subprocess.run', return_value=result):
            res, err = disk_tester.run_fio_job(["--rw=read"], allow_errors=True)
        self.assertEqual(res, {"jobs": []})
        self.assertIsNone(err)

    def test_apricorn_probe_skipped_when_missing(self):
        handle = io.StringIO()
        with mock.patch.object(disk_tester, "USB_TOOL_AVAILABLE", False):
            disk_tester._collect_apricorn_info("D:\\disk_test.dat", handle)
        self.assertIn("Apricorn probe skipped: usb_tool not installed", handle.getvalue())

    def test_apricorn_probe_handles_exception(self):
        handle = io.StringIO()
        fake_usb = mock.Mock()
        fake_usb.find_apricorn_device.side_effect = IndexError("boom")
        with mock.patch.object(disk_tester, "USB_TOOL_AVAILABLE", True), \
            mock.patch.object(disk_tester, "usb_tool", fake_usb):
            disk_tester._collect_apricorn_info("D:\\disk_test.dat", handle)
        self.assertIn("Apricorn probe failed: boom", handle.getvalue())

    def test_apricorn_probe_logs_when_none(self):
        handle = io.StringIO()
        fake_usb = mock.Mock()
        fake_usb.find_apricorn_device.return_value = []
        with mock.patch.object(disk_tester, "USB_TOOL_AVAILABLE", True), \
            mock.patch.object(disk_tester, "usb_tool", fake_usb):
            disk_tester._collect_apricorn_info("D:\\disk_test.dat", handle)
        self.assertIn("Apricorn device not found", handle.getvalue())

    def test_apricorn_probe_logs_json(self):
        handle = io.StringIO()

        @dataclasses.dataclass
        class Device:
            driveLetter: str = "D:"
            idVendor: str = "1234"

        fake_usb = mock.Mock()
        fake_usb.find_apricorn_device.return_value = [Device()]
        with mock.patch.object(disk_tester, "_now_ts", return_value="2026-01-01 01:02:03"), \
            mock.patch.object(disk_tester, "USB_TOOL_AVAILABLE", True), \
            mock.patch.object(disk_tester, "usb_tool", fake_usb):
            disk_tester._collect_apricorn_info("D:\\disk_test.dat", handle)

        log_output = handle.getvalue()
        self.assertIn("APRICORN_INFO", log_output)
        self.assertIn("\"target_drive\":\"D\"", log_output)


if __name__ == '__main__':
    unittest.main()
