# Copyright (C) 2013  Johnny Vestergaard <jkv@unixcluster.dk>
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

import time

from gevent.server import StreamServer
import codecs
import socket
from struct import unpack
from conpot.protocols.s7comm.tpkt import TPKT
from conpot.protocols.s7comm.cotp import COTP as COTP_BASE_packet
from conpot.protocols.s7comm.cotp import COTP_ConnectionRequest
from conpot.protocols.s7comm.cotp import COTP_ConnectionConfirm
from conpot.protocols.s7comm.s7 import S7
import conpot.core as conpot_core
from conpot.core import attack_session
from conpot.core.protocol_wrapper import conpot_protocol
from lxml import etree

import logging

logger = logging.getLogger(__name__)


def cleanse_byte_string(packet):
    new_packet = packet.decode("latin-1").replace("b", "")
    return new_packet.encode("latin-1")


@conpot_protocol
class S7Server(object):
    def __init__(self, template, template_directory, args):
        self.timeout = 5
        self.ssl_lists = {}
        self.server = None
        S7.ssl_lists = self.ssl_lists
        self.start_time = None  # Initialize later
        dom = etree.parse(template)

        system_status_lists = dom.xpath("//s7comm/system_status_lists/*")
        for ssl in system_status_lists:
            ssl_id = ssl.attrib["id"]
            ssl_dict = {}
            self.ssl_lists[ssl_id] = ssl_dict
            items = ssl.xpath("./*")
            for item in items:
                item_id = item.attrib["id"]
                databus_key = (
                    item.xpath("./text()")[0] if len(item.xpath("./text()")) else ""
                )
                ssl_dict[item_id] = databus_key

        logger.debug("Conpot debug info: S7 SSL/SZL: {0}".format(self.ssl_lists))
        logger.info("Conpot S7Comm initialized")

    def handle(self, sock, address):
        sock.settimeout(self.timeout)
        session = conpot_core.get_session(
            "s7comm",
            address[0],
            address[1],
            sock.getsockname()[0],
            sock.getsockname()[1],
        )
        self.start_time = time.time()
        logger.info(
            "New S7 connection from {0}:{1}. ({2})".format(
                address[0], address[1], session.id
            )
        )
        session.add_event({"type": attack_session.NEW_CONNECTION})

        try:
            while True:
                data = sock.recv(4, socket.MSG_WAITALL)
                if len(data) == 0:
                    session.add_event({"type": attack_session.CONNECTION_LOST})
                    break

                _, _, length = unpack("!BBH", data[:4])
                # check for length
                if length <= 4:
                    logger.info("S7 error: Invalid length")
                    session.add_event({"error": "S7 error: Invalid length"})
                    break
                data += sock.recv(length - 4, socket.MSG_WAITALL)

                tpkt_packet = TPKT().parse(cleanse_byte_string(data))
                cotp_base_packet = COTP_BASE_packet().parse(tpkt_packet.payload)
                if cotp_base_packet.tpdu_type == 0xE0:
                    # connection request
                    cotp_cr_request = COTP_ConnectionRequest().dissect(
                        cotp_base_packet.payload
                    )
                    logger.info(
                        "Received COTP Connection Request: dst-ref:{0} src-ref:{1} dst-tsap:{2} src-tsap:{3} "
                        "tpdu-size:{4}. ({5})".format(
                            cotp_cr_request.dst_ref,
                            cotp_cr_request.src_ref,
                            cotp_cr_request.dst_tsap,
                            cotp_cr_request.src_tsap,
                            cotp_cr_request.tpdu_size,
                            session.id,
                        )
                    )

                    # confirm connection response
                    cotp_cc_response = COTP_ConnectionConfirm(
                        cotp_cr_request.src_ref,
                        cotp_cr_request.dst_ref,
                        0,
                        cotp_cr_request.src_tsap,
                        cotp_cr_request.dst_tsap,
                        0x0A,
                    ).assemble()

                    # encapsulate and transmit
                    cotp_resp_base_packet = COTP_BASE_packet(
                        0xD0, 0, cotp_cc_response
                    ).pack()
                    tpkt_resp_packet = TPKT(3, cotp_resp_base_packet).pack()
                    sock.send(tpkt_resp_packet)

                    session.add_event(
                        {
                            "request": codecs.encode(data, "hex"),
                            "response": codecs.encode(tpkt_resp_packet, "hex"),
                        }
                    )

                    data = sock.recv(1024)

                    # another round of parsing payloads
                    tpkt_packet = TPKT().parse(data)
                    cotp_base_packet = COTP_BASE_packet().parse(tpkt_packet.payload)

                    if cotp_base_packet.tpdu_type == 0xF0:
                        logger.info(
                            "Received known COTP TPDU: {0}. ({1})".format(
                                cotp_base_packet.tpdu_type, session.id
                            )
                        )

                        # will throw exception if the packet does not contain the S7 magic number (0x32)
                        S7_packet = S7().parse(cotp_base_packet.trailer)
                        logger.info(
                            "Received S7 packet: magic:%s pdu_type:%s reserved:%s req_id:%s param_len:%s "
                            "data_len:%s result_inf:%s session_id:%s",
                            S7_packet.magic,
                            S7_packet.pdu_type,
                            S7_packet.reserved,
                            S7_packet.request_id,
                            S7_packet.param_length,
                            S7_packet.data_length,
                            S7_packet.result_info,
                            session.id,
                        )

                        # request pdu
                        if S7_packet.pdu_type == 1:
                            # 0xf0 == Request for connect / pdu negotiate
                            if S7_packet.param == 0xF0:
                                # create S7 response packet
                                s7_resp_negotiate_packet = S7(
                                    3, 0, S7_packet.request_id, 0, S7_packet.parameters
                                ).pack()
                                # wrap s7 the packet in cotp
                                cotp_resp_negotiate_packet = COTP_BASE_packet(
                                    0xF0, 0x80, s7_resp_negotiate_packet
                                ).pack()
                                # wrap the cotp packet
                                tpkt_resp_packet = TPKT(
                                    3, cotp_resp_negotiate_packet
                                ).pack()
                                sock.send(tpkt_resp_packet)

                                session.add_event(
                                    {
                                        "request": codecs.encode(data, "hex"),
                                        "response": codecs.encode(
                                            tpkt_resp_packet, "hex"
                                        ),
                                    }
                                )

                                # handshake done, give some more data.
                                data = sock.recv(1024)

                                while data:
                                    tpkt_packet = TPKT().parse(data)
                                    cotp_base_packet = COTP_BASE_packet().parse(
                                        tpkt_packet.payload
                                    )

                                    if cotp_base_packet.tpdu_type == 0xF0:
                                        S7_packet = S7().parse(cotp_base_packet.trailer)
                                        logger.info(
                                            "Received S7 packet: magic:%s pdu_type:%s reserved:%s "
                                            "req_id:%s param_len:%s data_len:%s result_inf:%s session_id:%s",
                                            S7_packet.magic,
                                            S7_packet.pdu_type,
                                            S7_packet.reserved,
                                            S7_packet.request_id,
                                            S7_packet.param_length,
                                            S7_packet.data_length,
                                            S7_packet.result_info,
                                            session.id,
                                        )

                                        (
                                            response_param,
                                            response_data,
                                        ) = S7_packet.handle(address[0])
                                        s7_resp_ssl_packet = S7(
                                            7,
                                            0,
                                            S7_packet.request_id,
                                            0,
                                            response_param,
                                            response_data,
                                        ).pack()
                                        cotp_resp_ssl_packet = COTP_BASE_packet(
                                            0xF0, 0x80, s7_resp_ssl_packet
                                        ).pack()
                                        tpkt_resp_packet = TPKT(
                                            3, cotp_resp_ssl_packet
                                        ).pack()
                                        sock.send(tpkt_resp_packet)

                                        session.add_event(
                                            {
                                                "request": codecs.encode(data, "hex"),
                                                "response": codecs.encode(
                                                    tpkt_resp_packet, "hex"
                                                ),
                                            }
                                        )

                                    data = sock.recv(1024)
                    else:
                        logger.info(
                            "Received unknown COTP TPDU after handshake: {0}".format(
                                cotp_base_packet.tpdu_type
                            )
                        )
                        session.add_event(
                            {
                                "error": "Received unknown COTP TPDU after handshake: {0}".format(
                                    cotp_base_packet.tpdu_type
                                )
                            }
                        )
                else:
                    logger.info(
                        "Received unknown COTP TPDU before handshake: {0}".format(
                            cotp_base_packet.tpdu_type
                        )
                    )
                    session.add_event(
                        {
                            "error": "Received unknown COTP TPDU before handshake: {0}".format(
                                cotp_base_packet.tpdu_type
                            )
                        }
                    )

        except socket.timeout:
            session.add_event({"type": attack_session.CONNECTION_LOST})
            logger.debug(
                "Socket timeout, remote: {0}. ({1})".format(address[0], session.id)
            )
        except socket.error:
            session.add_event({"type": attack_session.CONNECTION_LOST})
            logger.debug(
                "Connection reset by peer, remote: {0}. ({1})".format(
                    address[0], session.id
                )
            )
        except Exception as e:
            logger.exception(
                "Exception caught {0}, remote: {1}. ({2})".format(
                    e, address[0], session.id
                )
            )

    def start(self, host, port):
        self.host = host
        self.port = port
        connection = (host, port)
        self.server = StreamServer(connection, self.handle)
        logger.info("S7Comm server started on: {0}".format(connection))
        self.server.serve_forever()

    def stop(self):
        self.server.stop()
