# Copyright (C) 2014  Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import binascii
import logging
import random
import socket
from gevent.server import StreamServer
import gevent
import conpot.core as conpot_core
from conpot.utils.networking import chr_py3
from .request_parser import KamstrupRequestParser
from .command_responder import CommandResponder
from conpot.core.protocol_wrapper import conpot_protocol
from conpot.core import attack_session

logger = logging.getLogger(__name__)


@conpot_protocol
class KamstrupServer(object):
    def __init__(self, template, template_directory, args):
        self.command_responder = CommandResponder(template)
        self.server_active = True
        self.server = None
        conpot_core.get_databus().observe_value("reboot_signal", self.reboot)
        logger.info("Kamstrup protocol server initialized.")

    # pretending reboot... really just closing connecting while "rebooting"
    def reboot(self, key):
        assert key == "reboot_signal"
        self.server_active = False
        logger.info("Pretending server reboot")
        gevent.spawn_later(2, self.set_reboot_done)

    def set_reboot_done(self):
        logger.info("Stopped pretending reboot")
        self.server_active = True

    def handle(self, sock, address):
        session = conpot_core.get_session(
            "kamstrup_protocol",
            address[0],
            address[1],
            sock.getsockname()[0],
            sock.getsockname()[1],
        )
        logger.info(
            "New Kamstrup connection from %s:%s. (%s)",
            address[0],
            address[1],
            session.id,
        )
        session.add_event({"type": attack_session.NEW_CONNECTION})

        self.server_active = True

        parser = KamstrupRequestParser()
        try:
            while self.server_active:
                raw_request = sock.recv(1024)

                if not raw_request:
                    logger.info("Kamstrup client disconnected. (%s)", session.id)
                    session.add_event({"type": attack_session.CONNECTION_LOST})
                    break

                for x in raw_request:
                    parser.add_byte(chr_py3(x))

                while True:
                    request = parser.get_request()
                    if not request:
                        session.add_event({"type": attack_session.CONNECTION_LOST})
                        break
                    else:
                        logdata = {
                            "request": binascii.hexlify(
                                bytearray(request.message_bytes)
                            )
                        }
                        response = self.command_responder.respond(request)
                        # real Kamstrup meters has delay in this interval
                        gevent.sleep(random.uniform(0.24, 0.34))
                        if response:
                            serialized_response = response.serialize()
                            logdata["response"] = binascii.hexlify(serialized_response)
                            logger.info(
                                "Kamstrup traffic from %s: %s (%s)",
                                address[0],
                                logdata,
                                session.id,
                            )
                            sock.send(serialized_response)
                            session.add_event(logdata)
                        else:
                            session.add_event(logdata)
                            break

        except socket.timeout:
            logger.debug("Socket timeout, remote: %s. (%s)", address[0], session.id)
            session.add_event({"type": attack_session.CONNECTION_LOST})

        sock.close()

    def start(self, host, port):
        self.host = host
        self.port = port
        connection = (host, port)
        self.server = StreamServer(connection, self.handle)
        logger.info("Kamstrup protocol server started on: %s", connection)
        self.server.serve_forever()

    def stop(self):
        self.server.stop()
