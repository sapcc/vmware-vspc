# Copyright (c) 2017 VMware Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import asyncio
from pathlib import Path
import tempfile

import mock
import testtools

from vspc import async_telnet, server
from vspc.tests.utils import run_async


class VspcServerTest(testtools.TestCase):

    def setUp(self):
        super().setUp()
        self._readers = {}

    def test_handle_vm_vc_uuid(self):
        mock_socket = mock.Mock()
        srv = server.VspcServer()
        data = b'68 4c 91 6c 5f 6c 4c 2f-aa 50 df d6 61 a2 2e 0d'
        srv.handle_vm_vc_uuid(mock_socket, data)
        actual_uuid = srv.sock_to_uuid[mock_socket]
        self.assertEqual('684c916c5f6c4c2faa50dfd661a22e0d', actual_uuid)

    def _create_test_writer_coro(self, srv, fake_read_some, data):
        socket = mock.Mock()

        writer = mock.Mock()
        writer.get_extra_info.return_value = socket
        writer.wait_closed = mock.AsyncMock()

        reader = mock.Mock()
        # reversed, so we can use pop()
        self._readers[reader] = iter(data)
        reader_uuid = f"{id(reader)}-uuid"
        srv.sock_to_uuid[socket] = reader_uuid
        myself = self

        async def read_some(self):
            # let other coroutines run. this simulates reading from a socket
            await asyncio.sleep(0)
            return next(myself._readers[self._reader])

        fake_read_some.side_effect = read_some

        return reader_uuid, srv.handle_telnet(reader, writer)

    @mock.patch.object(async_telnet.AsyncTelnet, 'read_some', autospec=True)
    def test_performance_save_to_log_single(self, fake_read_some):
        """This is less of a test and more of a performance indicator for saving data to file.

        Starts a single write with lots of data.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            server.CONF.set_override('serial_log_dir', tmpdir)

            read_some_data = [b'asdf' * 4 + b'\n' for _ in range(20000)] + [b'']

            srv = server.VspcServer()
            reader_uuid, coro = self._create_test_writer_coro(srv, fake_read_some, read_some_data)

            run_async(coro)
            p = Path(tmpdir) / reader_uuid
            self.assertTrue(p.exists())
            self.assertEqual(b''.join(read_some_data).decode(), p.open().read())

    @mock.patch.object(async_telnet.AsyncTelnet, 'read_some', autospec=True)
    def test_performance_save_to_log_multiple(self, fake_read_some):
        """This is less of a test and more of a performance indicator for saving data to file.

        Starts multiple writes with lots of data.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            server.CONF.set_override('serial_log_dir', tmpdir)

            read_some_data = [b'asdf' * 4 + b'\n' for _ in range(20000)] + [b'']

            srv = server.VspcServer()

            coros = dict(self._create_test_writer_coro(srv, fake_read_some, read_some_data)
                         for i in range(20))

            run_async(coros.values())

            for i, reader_uuid in enumerate(coros):
                p = Path(tmpdir) / reader_uuid
                self.assertTrue(p.exists())
                self.assertEqual(b''.join(read_some_data).decode(), p.open().read(),
                                 f"coro {i} did not write out all data")
