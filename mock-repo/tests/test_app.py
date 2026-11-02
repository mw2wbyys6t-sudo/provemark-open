import unittest

from src.app import fetch


class FetchTests(unittest.TestCase):
    def test_callable(self) -> None:
        self.assertTrue(callable(fetch))


if __name__ == "__main__":
    unittest.main()
