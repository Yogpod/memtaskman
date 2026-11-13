import tomllib
import unittest
from pathlib import Path

import memtaskman


class VersionTests(unittest.TestCase):
    def test_version_matches_pyproject(self):
        pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
        with open(pyproject, "rb") as f:
            expected = tomllib.load(f)["project"]["version"]
        self.assertEqual(memtaskman.__version__, expected)


if __name__ == "__main__":
    unittest.main()
