import mock
import testtools

from vspc.async_telnet import IAC, SB, SE, AsyncTelnet
from vspc.tests.utils import run_async


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
        self.telnet._reader = mock.AsyncMock()
        self.telnet._reader.read.side_effect = (data, b'')
        text = run_async(self.telnet.read_some())
        values = text
        while text:
            text = run_async(self.telnet.read_some())
            values += text
        return values

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
