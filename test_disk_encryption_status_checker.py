import unittest
from unittest.mock import patch

from disk_encryption_status_checker import (
    CommandResult,
    collect_status,
    infer_linux_luks,
)


class TestDiskEncryptionStatusChecker(unittest.TestCase):
    def test_linux_luks_indicator(self):
        results = [
            CommandResult(
                command="lsblk",
                available=True,
                returncode=0,
                stdout="NAME FSTYPE\nsda crypto_LUKS\n",
                stderr="",
            )
        ]
        self.assertIn("LUKS", infer_linux_luks(results))

    def test_linux_no_luks_indicator(self):
        results = [
            CommandResult(
                command="lsblk",
                available=True,
                returncode=0,
                stdout="NAME FSTYPE\nsda ext4\n",
                stderr="",
            )
        ]
        self.assertIn("No crypto_LUKS", infer_linux_luks(results))

    @patch("disk_encryption_status_checker.run_command")
    def test_linux_collects_expected_commands(self, mock_run):
        mock_run.return_value = CommandResult(
            command="placeholder",
            available=True,
            returncode=0,
            stdout="",
            stderr="",
        )

        platform_name, results = collect_status("Linux", 10)

        self.assertEqual(platform_name, "Linux / LUKS")
        self.assertEqual(mock_run.call_count, 2)

        commands = [
            call.args[0]
            for call in mock_run.call_args_list
        ]
        self.assertEqual(
            commands,
            [
                ("lsblk", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"),
                ("cryptsetup", "status"),
            ],
        )

    @patch("disk_encryption_status_checker.run_command")
    def test_windows_collects_bitlocker_command(self, mock_run):
        mock_run.return_value = CommandResult(
            command="manage-bde -status",
            available=True,
            returncode=0,
            stdout="",
            stderr="",
        )

        platform_name, results = collect_status("Windows", 10)

        self.assertEqual(platform_name, "Windows / BitLocker")
        self.assertEqual(len(results), 1)
        self.assertEqual(mock_run.call_args.args[0], ("manage-bde", "-status"))


if __name__ == "__main__":
    unittest.main()
