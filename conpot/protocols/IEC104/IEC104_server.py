# Copyright (C) 2017  Patrick Reichenberger (University of Passau) <patrick.reichenberger@t-online.de>
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
from conpot.protocols.IEC104.DeviceDataController import DeviceDataController
from conpot.protocols.IEC104.IEC104 import IEC104
from .frames import struct, TESTFR_act, socket, errno
import logging
import conpot.core as conpot_core
from conpot.core import attack_session
from gevent.server import StreamServer
import gevent
from .errors import Timeout_t3
from conpot.core.protocol_wrapper import conpot_protocol

logger = logging.getLogger(__name__)


@conpot_protocol
class IEC104Server(object):
    def __init__(self, template, template_directory, args):
        self.timeout = conpot_core.get_databus().get_value("T_0")
        self.device_data_controller = DeviceDataController(template)
        self.server_active = True
        self.server = None
        logger.info("IEC 104 Server up")
        self.template = template

    def handle(self, sock, address):
        sock.settimeout(self.timeout)
        session = conpot_core.get_session(
            "IEC104",
            address[0],
            address[1],
            sock.getsockname()[0],
            sock.getsockname()[1],
        )
        logger.info(
            "New IEC 104 connection from %s:%s. (%s)",
            address[0],
            address[1],
            session.id,
        )
        session.add_event({"type": attack_session.NEW_CONNECTION})
        iec104_handler = IEC104(self.device_data_controller, sock, address, session.id)
        try:
            while True:
                timeout_t3 = gevent.Timeout(
                    conpot_core.get_databus().get_value("T_3"), Timeout_t3
                )
                timeout_t3.start()
                try:
                    try:
                        request = sock.recv(6)
                        if not request:
                            logger.info("IEC104 Station disconnected. (%s)", session.id)
                            session.add_event({"type": attack.session.CONNECTION_LOST})
                            iec104_handler.disconnect()
                            break
                        while request and len(request) < 2:
                            new_byte = sock.recv(1)
                            request += new_byte

                        _, length = struct.unpack(">BB", request[:2])
                        while len(request) < (length + 2):
                            new_byte = sock.recv(1)
                            if not new_byte:
                                break
                            request += new_byte

                        # check if IEC 104 packet or for the first occurrence of the indication 0x68 for IEC 104
                        for elem in list(request):
                            if 0x68 == elem:
                                index = request.index(elem)

                                iec_request = request[index:]
                                timeout_t3.cancel()
                                response = None
                                # check which frame type
                                if not (iec_request[2] & 0x01):  # i_frame
                                    response = iec104_handler.handle_i_frame(
                                        iec_request
                                    )
                                elif iec_request[2] & 0x01 and not (
                                    iec_request[2] & 0x02
                                ):  # s_frame
                                    iec104_handler.handle_s_frame(iec_request)
                                elif iec_request[2] & 0x03:  # u_frame
                                    response = iec104_handler.handle_u_frame(
                                        iec_request
                                    )
                                else:
                                    logger.warning(
                                        "%s ---> No valid IEC104 type (%s)",
                                        address,
                                        session.id,
                                    )

                                if response:
                                    for resp_packet in response:
                                        if resp_packet:
                                            sock.send(resp_packet)
                                break

                    except Timeout_t3:
                        pkt = iec104_handler.send_104frame(TESTFR_act)
                        if pkt:
                            sock.send(pkt)
                    finally:
                        timeout_t3.cancel()
                except gevent.Timeout:
                    logger.warning("T1 timed out. (%s)", session.id)
                    logger.info("IEC104 Station disconnected. (%s)", session.id)
                    session.add_event({"type": attack_session.CONNECTION_LOST})
                    iec104_handler.disconnect()
                    break
        except socket.timeout:
            logger.debug("Socket timeout, remote: %s. (%s)", address[0], session.id)
            session.add_event({"type": attack_session.CONNECTION_LOST})
        except socket.error as err:
            if isinstance(err.args, tuple):
                if err.errno == errno.EPIPE:
                    # remote peer disconnected
                    logger.info("IEC104 Station disconnected. (%s)", session.id)
                    session.add_event({"type": attack_session.CONNECTION_LOST})
                else:
                    # determine and handle different error
                    pass
            else:
                print(("socket error ", err))
            iec104_handler.disconnect()

    def start(self, host, port):
        connection = (host, port)
        self.server = StreamServer(connection, self.handle)
        logger.info("IEC 60870-5-104 protocol server started on: %s", connection)
        self.server.serve_forever()

    def stop(self):
        self.server.stop()
