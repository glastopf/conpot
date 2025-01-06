import unittest

from conpot.utils.greenlet import spawn_test_server, teardown_test_server
from conpot.protocols.triconex.triconex_server import TriconexServer


class TestTriconexServer(unittest.TestCase):
    def setUp(self):
        self.triconex_server, self.greenlet = spawn_test_server(
            TriconexServer, template="default", protocol="triconex"
        )

    def tearDown(self):
        teardown_test_server(self.triconex_server, self.greenlet)


if __name__ == "__main__":
    unittest.main()
