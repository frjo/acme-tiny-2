import subprocess
import unittest


class TestInstall(unittest.TestCase):
    def test_cli(self):
        subprocess.check_call(["uv", "run", "acme-tiny-2.py", "-h"])
