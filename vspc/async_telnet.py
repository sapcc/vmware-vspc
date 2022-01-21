# Copyright (c) 2001-2016 Python Software Foundation
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
"""
Telnet server class using asyncio.
"""
# Telnet protocol characters (don't change)
IAC = bytes([255])  # "Interpret As Command"
DONT = bytes([254])
DO = bytes([253])
WONT = bytes([252])
WILL = bytes([251])
theNULL = bytes([0])
SE = bytes([240])  # Subnegotiation End
NOP = bytes([241])  # No Operation
SB = bytes([250])  # Subnegotiation Begin
NOOPT = bytes([0])


class AsyncTelnet:
    def __init__(self, reader, opt_handler):
        self._reader = reader
        self._opt_handler = opt_handler
        self._raw_data = b''
        self._telnet_q = b''
        self._eof = False
        self._read_bytes = 4096

    def _process_telnet_data(self, telnet_data):
        """Process data found after a single IAC

        The IAC is included in the data for performance reasons (we don't have
        to create a new string).

        This function returns fully parsed telnet commands as tuple
        (command-byte, command-opt-byte, command-data) and an unparsed rest. We
        might return None instead of a tuple, if we couldn't parse a full
        command.

        We use string indexing for SB, because that's fast and we know the end
        string we're looking for. We also use bytearray delete here, because
        that's faster than creating new strings from a slice.

        """
        # first char after IAC is the command. string splicing to keep it a
        # byte-string
        c = telnet_data[1:2]

        # these are simple commands without parameter, that are followed by a
        # single byte opt we return with it - if we have enough data to do
        # this. Otherwise, we return unparsed data to retrieve more from the
        # socket
        if c in (DO, DONT, WILL, WONT):
            if len(telnet_data) > 2:
                opt = telnet_data[2:3]
                del telnet_data[:3]
                return (c, opt, None), telnet_data
            else:
                return None, telnet_data

        # this starts an SB block ended by IAC SE.
        if c == SB:
            # set to 2 to start looking after the first char we already know to
            # be SB
            i = 2
            while True:
                # search for the end IAC SE
                try:
                    j = telnet_data.index(IAC + SE, i)
                except ValueError:
                    # we did not find the end sequence and thus return no
                    # parsed command - only rest. caller needs to provide more
                    # data and call us again
                    return None, telnet_data

                # we found IAC SE, but it might have been escaped by an IAC
                # before and thus wouldn't count.
                # if we just check for one IAC before, this could be escaped,
                # too, so we need to find the number of escaped IACs. We do
                # this by walking backwards from our found IAC SE position j
                # and see how many IAC we find.
                for k in range(j):
                    if telnet_data[j - k - 1:j - k] == IAC:
                        continue
                    break
                # a non-even number of IACs means, there was also one for us in
                # the mix (and maybe a couple more escaped IACs before), so we
                # ignore the IAC SE and continue our search for an IAC SE
                # after it
                if k % 2 == 1:
                    i = j + 1
                    continue

                # we found a valid end and can return the cmd and its data.
                # SB/SE commands have no opts, so we return NOOPT as the
                # option. escaped IACs need to be replaced by a single IAC. We
                # return SE here, as we only contain data when we encounter SE.
                # In theory, one would also have to return an SB command with
                # empty data ...
                cmd_data = telnet_data[2:j].replace(IAC + IAC, IAC)
                del telnet_data[:j + 2]

                return (SE, NOOPT, cmd_data), telnet_data

        if c == IAC:
            # this probably means, our telnet_data was borked and
            # _process_raw_data() didn't handle an escaped IAC properly or we
            # fetched more data and
            raise RuntimeError('We got an IAC after what should be an IAC')

        # We encountered a telnet command we don't understand.
        raise RuntimeError('unknown start: 0x{:x} ({:d})'.format(c[0], c[0]))

    def _process_raw_data(self, raw_data):
        """Process raw data bytearray into text, telnet_queue and rest

        We use string indexing here, because that's fast and we know that any
        telnet command has to start with IAC. We also use bytearray delete
        here, because that's faster than creating new strings from a slice.

        At least one of telnet_queue and rest is None on every return.
        """
        i = 0
        contains_escaped_iac = False
        while True:
            try:
                # search for IAC occurrences at or after start index i
                j = raw_data.index(IAC, i)
            except ValueError:
                # there was no IAC in the whole rest of data -> everything is
                # text
                if contains_escaped_iac:
                    return raw_data.replace(IAC + IAC, IAC), None, None
                else:
                    return raw_data, None, None

            if len(raw_data) < j + 2:
                # we need to get more data to decide if this is an IAC IAC. we
                # return what we found - it is text - , so we don't have to
                # rescan again. it's faster than scanning the whole raw_data
                # again once it is extended.
                # + 2 because j is an index and we compare with a length and
                # we need one more char afterwards
                text = raw_data[:j]
                if contains_escaped_iac:
                    text = text.replace(IAC + IAC, IAC)
                del raw_data[:j]
                return text, None, raw_data

            if raw_data[j + 1:j + 2] == IAC:
                # escaped IAC (IAC IAC). we need to put 1 IAC into output, but
                # we don't do it here in case we have lots of them, because
                # byte-concat does take some time. we just mark it and replace
                # every occurrence at the end. this is another scan, but is
                # still faster.
                contains_escaped_iac = True
                # this is now one step after the IAC IAC
                i = j + 2
                continue

            # we found an IAC in j and it wasn't one of the special cases
            # above, so we return text and telnet data with IAC (without would
            # cost more as it creates a new string)
            text = raw_data[:j]
            if contains_escaped_iac:
                text = text.replace(IAC + IAC, IAC)
            del raw_data[:j]
            return text, raw_data, None

    async def _read_raw_data(self):
        """Read from our reader and set EOF if it occurs"""
        buf = await self._reader.read(self._read_bytes)
        if not buf:
            self._eof = True
        return bytearray(buf)

    async def read_some(self):
        """Read currently available data

        Return b'' if EOF is hit.
        """
        # fetch something if we don't have anything
        if not self._raw_data and not self._telnet_q:
            self._raw_data = await self._read_raw_data()

        while not self._eof:
            if not self._telnet_q:
                text, self._telnet_q, self._raw_data = self._process_raw_data(self._raw_data)
                if text:
                    return bytes(text)

            if self._telnet_q:
                telnet_cmd, rest = self._process_telnet_data(self._telnet_q)
                if telnet_cmd:
                    self._telnet_q = b''
                    self._raw_data = rest
                    await self._opt_handler(telnet_cmd[0], telnet_cmd[1], data=telnet_cmd[2])
                else:
                    self._telnet_q = rest + await self._read_raw_data()
            else:
                if self._raw_data:
                    self._raw_data = self._raw_data + await self._read_raw_data()
                else:
                    self._raw_data = await self._read_raw_data()

        return b''
