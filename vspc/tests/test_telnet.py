import asyncio

import mock
import testtools

from vspc.async_telnet import IAC, SB, SE, AsyncTelnet


def _run_async(awaitable):
    loop = asyncio.get_event_loop()
    return loop.run_until_complete(awaitable)


class AsyncTelnetTest(testtools.TestCase):
    # this data is taken from the Python standard library tests
    VALIDATION_DATA = (
        IAC + SB + IAC + SE +
        IAC + SB + IAC + IAC + IAC + SE +
        IAC + SB + IAC + IAC + b'aa' + IAC + SE +
        IAC + SB + b'bb' + IAC + IAC + IAC + SE +
        IAC + SB + b'cc' + IAC + IAC + b'dd' + IAC + SE +
        IAC + SB + b'ee' + IAC + IAC + SE + b'ff' + IAC + SE
    )

    def setUp(self):
        super().setUp()
        self.telnet = AsyncTelnet(mock.AsyncMock(), mock.AsyncMock())

    def _parse_input(self, data):
        """Parse the given data through the AsyncTelnet() and return the result"""
        self.telnet.rawq = data
        _run_async(self.telnet.process_rawq())
        return self.telnet.cookedq

    def test_simple(self):
        """Show that the testing works by inputting some data and checking the output"""
        data = b'foo' + IAC + SB + IAC + SE + b'bar'
        self.assertEqual(b'foobar', self._parse_input(data))

    def test_validate(self):
        """Specially crafted validation data ensures that special cases are met

        To verify, that we actually parsed the data, we put a surround it by
        "foo" and "bar" and thus only expect "foobar" as output, as the other
        stuff should be parsed as commands.
        """
        data = b'foo' + self.VALIDATION_DATA + b'bar'
        self.assertEqual(b'foobar', self._parse_input(data))

    def test_performance_lots_of_commands(self):
        """This is less a test and more a way to show performance of the parser"""
        data = b'foo' + self.VALIDATION_DATA * 100000 + b'bar'
        self.assertEqual(b'foobar', self._parse_input(data))

    def test_performance_lots_of_escaped_iac(self):
        """This is less a test and more a way to show performance of the parser"""
        data = self._parse_input(
            b'\xff\xfb\xe8\xff\xfa\xe8\x00\x00\x01()+,-.0PQRSFGI\xff\xf0' +
            b'\xff\xfa\xe8Pliveness-probe\xff\xf0' +
            (b'asdf' + IAC + IAC + b'asdf') * 100000)
        self.assertEqual((b'asdf' + IAC + b'asdf') * 100000, data)

    def test_performance_lots_of_data(self):
        """This is less a test and more a way to show performance of the parser"""
        self._parse_input(
            b'\xff\xfb\xe8\xff\xfa\xe8\x00\x00\x01()+,-.0PQRSFGI\xff\xf0' +
            b'\xff\xfa\xe8Pliveness-probe\xff\xf0' +
            b'asdfxaasdf' * 100000)

    def test_performance_mixed(self):
        """This is less a test and more a way to show performance of the parser"""
        data = self._parse_input(
            (b'asdfasdf' + b'\xff\xfb\xe8\xff\xfa\xe8\x00\x00\x01()+,-.0PQRSFGI\xff\xf0') * 100000)
        self.assertEqual(b'asdfasdf' * 100000, data)
