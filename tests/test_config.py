import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest import mock

from memtaskman import config


class ConfigTests(unittest.TestCase):
    def _file(self, text: str) -> Path:
        d = tempfile.mkdtemp()
        p = Path(d) / "config.toml"
        p.write_text(text, encoding="utf-8")
        return p

    def test_load_and_validate(self):
        p = self._file('interval = 2\nsort = "growth"\ntree = true\nunits = "decimal"\nbogus = 1\n'
                       'group = "sideways"\ntop = "many"\n')
        s, warnings = config.load(p)
        self.assertEqual(s, {"interval": 2.0, "sort": "growth", "tree": True, "units": "decimal"})
        self.assertEqual(len(warnings), 3)  # bogus, group choice, top type
        self.assertTrue(any("unknown setting 'bogus'" in w for w in warnings))

    def test_optional_section_and_dashes(self):
        s, w = config.load(self._file('[memtaskman]\nwsl-guest = false\n'))
        self.assertEqual((s, w), ({"wsl_guest": False}, []))

    def test_bad_toml_and_missing_file(self):
        s, w = config.load(self._file("interval = = 3"))
        self.assertEqual(s, {})
        self.assertIn("not valid TOML", w[0])
        self.assertEqual(config.load(Path(tempfile.mkdtemp()) / "nope.toml"), ({}, []))

    def test_interval_floor_and_bool_is_not_int(self):
        s, w = config.validate({"interval": 0.01, "top": True})
        self.assertEqual(s, {"interval": 0.25})
        self.assertEqual(len(w), 2)

    def test_flags_beat_config_beat_defaults(self):
        eff, src = config.resolve({"sort": "name", "interval": None}, {"sort": "growth", "interval": 3.0})
        self.assertEqual((eff["sort"], src["sort"]), ("name", "flag"))
        self.assertEqual((eff["interval"], src["interval"]), (3.0, "config"))
        self.assertEqual((eff["units"], src["units"]), ("binary", "default"))

    def test_render_round_trips_as_toml(self):
        eff, src = config.resolve({}, {"tree": True, "units": "decimal"})
        parsed = tomllib.loads(config.render(eff, src, Path("x.toml")))
        self.assertEqual(config.validate(parsed), (eff, []))

    def test_platform_paths(self):
        with mock.patch.dict(os.environ, {"MEMTASKMAN_CONFIG": "/tmp/custom.toml"}):
            self.assertEqual(config.config_path(), Path("/tmp/custom.toml"))
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("MEMTASKMAN_CONFIG", None)
            path = config.config_path()
        self.assertEqual((path.name, path.parent.name), ("config.toml", "memtaskman"))

    def test_print_config_cli(self):
        p = self._file('sort = "growth"\nslim = true\n')
        env = dict(os.environ, MEMTASKMAN_CONFIG=str(p), PYTHONUTF8="1")
        r = subprocess.run([sys.executable, "-m", "memtaskman", "--print-config", "--sort", "pid"],
                           capture_output=True, text=True, env=env, encoding="utf-8")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('sort = "pid"', r.stdout)  # the flag wins
        self.assertIn("from flag", r.stdout)
        self.assertIn("slim = true", r.stdout)  # from the file
        self.assertIn("from config", r.stdout)


if __name__ == "__main__":
    unittest.main()
