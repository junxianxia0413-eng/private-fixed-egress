import os
import unittest

from scripts.memory_maintenance import abandoned_diagnostic, rotation_due


class MemoryMaintenanceTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "Linux process metadata and paths")
    def test_only_abandoned_missing_diagnostic_is_eligible(self):
        cases = [
            (1, 1200, "/tmp/tmpabcd/client.json", False, True),
            (1, 1200, "/etc/pfem-gateway/config.json", False, False),
            (1, 1200, "/tmp/tmpabcd/client.json", True, False),
            (2, 1200, "/tmp/tmpabcd/client.json", False, False),
            (1, 30, "/tmp/tmpabcd/client.json", False, False),
            (1, 1200, "/tmp/tmpabcd/another.json", False, False),
            (1, 1200, "/tmp/tmpabcd/../client.json", False, False),
        ]
        for parent, age, config, exists, expected in cases:
            with self.subTest(parent=parent, age=age, config=config, exists=exists):
                info = {
                    "parent": parent,
                    "start_ticks": (2000 - age) * os.sysconf("SC_CLK_TCK"),
                    "command": ["/usr/local/bin/pfem-sing-box", "run", "-c", config],
                }
                self.assertEqual(abandoned_diagnostic(info, 2000, exists), expected)

    def test_rotation_requires_large_rss_and_cooldown(self):
        self.assertTrue(rotation_due(100 * 1024 * 1024, 0, 30000))
        self.assertFalse(rotation_due(100 * 1024 * 1024, 29999, 30000))
        self.assertFalse(rotation_due(10 * 1024 * 1024, 0, 30000))
