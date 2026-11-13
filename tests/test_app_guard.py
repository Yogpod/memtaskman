"""The guard on UI updates posted from worker threads (startup / shutdown races)."""

import unittest

from textual.css.query import NoMatches

from memtaskman.app import ui_callback


class FakeApp:
    def __init__(self, widgets_present: bool, running: bool = True):
        self._shutting_down = False
        self.is_running = running
        self.widgets_present = widgets_present
        self.calls = 0

    def query(self, selector):
        return ["#procs"] if self.widgets_present else []

    @ui_callback
    def apply(self):
        self.calls += 1
        raise NoMatches("No nodes match '#top'")

    @ui_callback
    def ok(self):
        self.calls += 1
        return "drawn"


class UiCallbackTests(unittest.TestCase):
    def test_skips_when_widgets_not_mounted_yet_or_already_gone(self):
        self.assertIsNone(FakeApp(widgets_present=False).apply())

    def test_skips_after_shutdown_started(self):
        app = FakeApp(widgets_present=True)
        app._shutting_down = True
        self.assertIsNone(app.ok())
        self.assertEqual(app.calls, 0)

    def test_skips_when_app_not_running(self):
        self.assertIsNone(FakeApp(widgets_present=True, running=False).apply())

    def test_real_bugs_still_raise(self):
        with self.assertRaises(NoMatches):
            FakeApp(widgets_present=True).apply()

    def test_normal_path(self):
        self.assertEqual(FakeApp(widgets_present=True).ok(), "drawn")


if __name__ == "__main__":
    unittest.main()
