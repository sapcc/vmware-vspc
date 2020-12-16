#!/usr/bin/env python3
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
import functools
import os
import ssl
import sys
from aiohttp import web
from aiohttp_basicauth import BasicAuthMiddleware
from uuid import UUID

import aiofiles
from oslo_config import cfg
from oslo_log import log as logging

from vspc import async_telnet
from vspc.async_telnet import IAC, SB, SE, DO, DONT, WILL, WONT

opts = [
    cfg.StrOpt('host',
               default='0.0.0.0',
               help='Host on which to listen for incoming requests'),
    cfg.IntOpt('port',
               default=13370,
               help='Port on which to listen for incoming telnet requests'),
    cfg.IntOpt('web_port',
               default=13371,
               help='Port on which to listen for incoming rest requests'),
    cfg.StrOpt('cert', help='SSL certificate file'),
    cfg.StrOpt('key', help='SSL key file (if separate from cert)'),
    cfg.StrOpt('uri', help='VSPC URI'),
    cfg.StrOpt('serial_log_dir', help='The directory where serial logs are '
                                      'saved'),
    cfg.StrOpt('username', help='The username for serial logs web endpoint '),
    cfg.StrOpt('password', help='The password for serial logs web endpoint '),
]

CONF = cfg.CONF
CONF.register_opts(opts)

LOG = logging.getLogger(__name__)

BINARY = bytes([0])  # 8-bit data path
SGA = bytes([3])  # suppress go ahead
VMWARE_EXT = bytes([232])

KNOWN_SUBOPTIONS_1 = bytes([0])
KNOWN_SUBOPTIONS_2 = bytes([1])
VMOTION_BEGIN = bytes([40])
VMOTION_GOAHEAD = bytes([41])
VMOTION_NOTNOW = bytes([43])
VMOTION_PEER = bytes([44])
VMOTION_PEER_OK = bytes([45])
VMOTION_COMPLETE = bytes([46])
VMOTION_ABORT = bytes([48])
VM_VC_UUID = bytes([80])
GET_VM_VC_UUID = bytes([81])
VM_NAME = bytes([82])
GET_VM_NAME = bytes([83])
DO_PROXY = bytes([70])
WILL_PROXY = bytes([71])
WONT_PROXY = bytes([73])

SUPPORTED_OPTS = (KNOWN_SUBOPTIONS_1 + KNOWN_SUBOPTIONS_2 + VMOTION_BEGIN +
                  VMOTION_GOAHEAD + VMOTION_NOTNOW + VMOTION_PEER +
                  VMOTION_PEER_OK + VMOTION_COMPLETE + VMOTION_ABORT +
                  VM_VC_UUID + GET_VM_VC_UUID + VM_NAME + GET_VM_NAME +
                  DO_PROXY + WILL_PROXY + WONT_PROXY)


class VspcServer(object):
    def __init__(self):
        self.sock_to_uuid = dict()

    async def handle_known_suboptions(self, writer, data, vm_uuid):
        socket = writer.get_extra_info('socket')
        peer = socket.getpeername()
        LOG.debug(
            "%s << %s KNOWN-SUBOPTIONS-1 %s",
            vm_uuid, peer, data
        )
        LOG.debug(
            "%s >> %s KNOWN-SUBOPTIONS-2 %s",
            vm_uuid, peer, SUPPORTED_OPTS
        )
        writer.write(IAC + SB + VMWARE_EXT + KNOWN_SUBOPTIONS_2 +
                     SUPPORTED_OPTS + IAC + SE)
        LOG.debug("%s >> %s GET-VM-VC-UUID", vm_uuid, peer)
        writer.write(IAC + SB + VMWARE_EXT + GET_VM_VC_UUID + IAC + SE)
        await writer.drain()

    async def handle_do_proxy(self, writer, data, vm_uuid):
        socket = writer.get_extra_info('socket')
        peer = socket.getpeername()
        dir, uri = data[0], data[1:].decode('ascii')
        LOG.debug(
            "%s << %s DO-PROXY %c %s",
            vm_uuid, peer, dir, uri
        )
        if chr(dir) != 'S' or uri != CONF.uri:
            LOG.debug("%s >> %s WONT-PROXY", vm_uuid, peer)
            writer.write(IAC + SB + VMWARE_EXT + WONT_PROXY + IAC + SE)
            await writer.drain()
            writer.close()
        else:
            LOG.debug("%s >> %s WILL-PROXY", vm_uuid, peer)
            writer.write(IAC + SB + VMWARE_EXT + WILL_PROXY + IAC + SE)
            await writer.drain()

    def handle_vm_vc_uuid(self, socket, data):
        peer = socket.getpeername()
        uuid = data.decode('ascii')
        LOG.debug("<< %s VM-VC-UUID %s", peer, uuid)
        uuid = uuid.replace(' ', '')
        uuid = uuid.replace('-', '')
        self.sock_to_uuid[socket] = uuid

    async def handle_vmotion_begin(self, writer, data, vm_uuid):
        socket = writer.get_extra_info('socket')
        peer = socket.getpeername()
        LOG.debug(
            "%s << %s VMOTION-BEGIN %s",
            vm_uuid, peer, data
        )
        secret = os.urandom(4)
        LOG.debug(
            "%s >> %s VMOTION-GOAHEAD %s %s",
            vm_uuid, peer, data, secret
        )
        writer.write(IAC + SB + VMWARE_EXT + VMOTION_GOAHEAD +
                     data + secret + IAC + SE)
        await writer.drain()

    async def handle_vmotion_peer(self, writer, data, vm_uuid):
        socket = writer.get_extra_info('socket')
        peer = socket.getpeername()
        LOG.debug("%s << %s VMOTION-PEER %s", vm_uuid, peer, data)
        LOG.debug(
            "%s << %s VMOTION-PEER-OK %s",
            vm_uuid, peer, data
        )
        writer.write(IAC + SB + VMWARE_EXT + VMOTION_PEER_OK + data + IAC + SE)
        await writer.drain()

    def handle_vmotion_complete(self, socket, data, vm_uuid):
        peer = socket.getpeername()
        LOG.debug(
            "%s << %s VMOTION-COMPLETE %s",
            vm_uuid, peer, data
        )

    def handle_vmotion_abort(self, writer, data, vm_uuid):
        socket = writer.get_extra_info('socket')
        peer = socket.getpeername()
        LOG.debug("%s << %s VMOTION-ABORT %s", vm_uuid, peer, data)

    async def handle_do(self, writer, opt, vm_uuid):
        socket = writer.get_extra_info('socket')
        peer = socket.getpeername()
        LOG.debug("%s << %s DO %s", vm_uuid, peer, opt)
        if opt in (BINARY, SGA):
            LOG.debug("%s >> %s WILL", vm_uuid, peer)
            writer.write(IAC + WILL + opt)
            await writer.drain()
        else:
            LOG.debug("%s >> %s WONT", vm_uuid, peer)
            writer.write(IAC + WONT + opt)
            await writer.drain()

    async def handle_will(self, writer, opt, vm_uuid):
        socket = writer.get_extra_info('socket')
        peer = socket.getpeername()
        LOG.debug("%s << %s WILL %s", vm_uuid, peer, opt)
        if opt in (BINARY, SGA, VMWARE_EXT):
            LOG.debug("%s >> %s DO", vm_uuid, peer)
            writer.write(IAC + DO + opt)
            await writer.drain()
        else:
            LOG.debug("%s >> %s DONT", vm_uuid, peer)
            writer.write(IAC + DONT + opt)
            await writer.drain()

    async def option_handler(self, cmd, opt, writer, data=None):
        socket = writer.get_extra_info('socket')
        uuid = self.sock_to_uuid.get(socket)
        if uuid:
            uuid = str(UUID(uuid))
        if cmd == SE and data[0:1] == VMWARE_EXT:
            vmw_cmd = data[1:2]
            if vmw_cmd == KNOWN_SUBOPTIONS_1:
                await self.handle_known_suboptions(writer, data[2:], uuid)
            elif vmw_cmd == DO_PROXY:
                await self.handle_do_proxy(writer, data[2:], uuid)
            elif vmw_cmd == VM_VC_UUID:
                self.handle_vm_vc_uuid(socket, data[2:])
            elif vmw_cmd == VMOTION_BEGIN:
                await self.handle_vmotion_begin(writer, data[2:], uuid)
            elif vmw_cmd == VMOTION_PEER:
                await self.handle_vmotion_peer(writer, data[2:], uuid)
            elif vmw_cmd == VMOTION_COMPLETE:
                self.handle_vmotion_complete(socket, data[2:], uuid)
            elif vmw_cmd == VMOTION_ABORT:
                self.handle_vmotion_abort(writer, data[2:], uuid)
            else:
                LOG.error(
                    "%s Unknown VMware cmd: %s %s",
                    uuid, vmw_cmd, data[2:]
                )
                writer.close()
        elif cmd == DO:
            await self.handle_do(writer, opt, uuid)
        elif cmd == WILL:
            await self.handle_will(writer, opt, uuid)

    async def save_to_log(self, uuid, data):
        fpath = os.path.join(CONF.serial_log_dir, uuid)
        async with aiofiles.open(fpath, 'ab') as f:
            await f.write(data)

    async def handle_telnet(self, reader, writer):
        opt_handler = functools.partial(self.option_handler, writer=writer)
        telnet = async_telnet.AsyncTelnet(reader, opt_handler)
        socket = writer.get_extra_info('socket')
        peer = socket.getpeername()
        LOG.info("%s connected", peer)
        data = await telnet.read_some()
        uuid = self.sock_to_uuid.get(socket)
        if uuid is None:
            LOG.error("%s didn't present UUID", peer)
            writer.close()
            return
        try:
            while data:
                await self.save_to_log(uuid, data)
                data = await telnet.read_some()
        finally:
            self.sock_to_uuid.pop(socket, None)
        LOG.info("%s disconnected", peer)
        writer.close()

    async def handle_get_consolelog(self, request):
        uuid = request.match_info.get('uuid')
        if not uuid:
            raise web.HTTPNotFound()

        uuid = uuid.replace('-', '').strip()

        LOG.info('Reading file %s/%s ...', CONF.serial_log_dir, uuid)
        file_path = CONF.serial_log_dir + "/" + uuid

        if os.path.isfile(file_path) is False:
            LOG.error('File path %s not found!', file_path)
            raise web.HTTPNotFound()

        async with aiofiles.open(file_path, 'r') as f:
            file_content = await f.read()

        return web.Response(text=file_content)

    def start(self):
        loop = asyncio.get_event_loop()
        ssl_context = None
        if CONF.cert:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            ssl_context.load_cert_chain(certfile=CONF.cert, keyfile=CONF.key)

        if CONF.username:
            auth = BasicAuthMiddleware(username=CONF.username, password=CONF.password)
            app = web.Application(middlewares=[auth])
        else:
            app = web.Application()
        app.router.add_get('/console_log/{uuid}', self.handle_get_consolelog)
        web_server = app.make_handler()

        coro = asyncio.start_server(self.handle_telnet,
                                    CONF.host,
                                    CONF.port,
                                    ssl=ssl_context,
                                    loop=loop)
        webserv = loop.create_server(web_server,
                                      CONF.host,
                                      CONF.web_port,
                                      ssl=ssl_context)
        telnet_server = loop.run_until_complete(coro)
        rest_server = loop.run_until_complete(webserv)

        # Serve requests until Ctrl+C is pressed
        LOG.info("Serving telnet on %s", telnet_server.sockets[0].getsockname())
        LOG.info("Serving rest api on %s", rest_server.sockets[0].getsockname())
        LOG.info("Log directory: %s", CONF.serial_log_dir)
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass

        # Close the server
        telnet_server.close()
        rest_server.close()
        loop.run_until_complete(telnet_server.wait_closed())
        loop.run_until_complete(rest_server.wait_closed())
        loop.close()


def main():
    logging.register_options(CONF)
    CONF(sys.argv[1:], prog='vspc')
    logging.setup(CONF, "vspc")
    if not CONF.serial_log_dir:
        LOG.error("serial_log_dir is not specified")
        sys.exit(1)
    if not os.path.exists(CONF.serial_log_dir):
        LOG.info("Creating log directory: %s", CONF.serial_log_dir)
        os.makedirs(CONF.serial_log_dir)
    srv = VspcServer()
    srv.start()


if __name__ == '__main__':
    main()
