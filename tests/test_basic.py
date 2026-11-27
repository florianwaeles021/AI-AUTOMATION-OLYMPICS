import os, sys, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class Smoke(unittest.TestCase):
    def test_config_importable(self):
        import config
        self.assertTrue(hasattr(config, "SECRET_KEY"))


if __name__ == "__main__":
    unittest.main()
