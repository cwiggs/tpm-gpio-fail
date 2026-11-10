# SPDX-License-Identifier: GPL-2.0-only
import pathlib
import subprocess
import unittest


BINARY = pathlib.Path(__file__).resolve().parent / "read-errors"


def audit(fail_at=0, short_read=-1, value="0xffffffff"):
    return subprocess.run(
        [str(BINARY), str(fail_at), str(short_read), value],
        capture_output=True,
        text=True,
        check=False,
    )


class ReadErrors(unittest.TestCase):
    def test_failed_reads_are_unknown(self):
        # PLTRST lock, TX lock, DW0, ownership, bus selector, bus lock/TX lock.
        for read in range(1, 8):
            for short_read in (-1, 0, 1, 2, 3):
                with self.subTest(read=read, short_read=short_read):
                    result = audit(read, short_read)
                    self.assertEqual(result.returncode, 127)
                    self.assertIn("hardware access error; lock state UNKNOWN", result.stdout)
                    self.assertNotIn("Vulnerability Classification", result.stdout)
                    self.assertNotIn("MITIGATED", result.stdout)
                    self.assertNotIn("RESULT: PLTRST# pad", result.stdout)
                    self.assertIn("/dev/mem: read port", result.stderr)
                    self.assertIn("offset 0x", result.stderr)
                    if short_read < 0:
                        self.assertIn("Operation not permitted", result.stderr)
                    else:
                        self.assertIn(f"short read ({short_read} of 4 bytes)", result.stderr)

    def test_first_failure_is_not_decoded_as_a_lock(self):
        result = audit(1)
        self.assertNotIn("0xffffffff", result.stdout)
        self.assertNotIn("(LOCKED)", result.stdout)

    def test_successful_all_ones_read_is_not_a_read_error(self):
        result = audit()
        self.assertEqual(result.returncode, 0)
        self.assertIn("RESULT: PLTRST# pad LOCKED", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_successful_unlocked_reads_preserve_count(self):
        result = audit(value="0")
        self.assertEqual(result.returncode, 2)
        self.assertIn("RESULT: PLTRST# pad UNLOCKED", result.stdout)
        self.assertIn("2 pins unlocked", result.stdout)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
