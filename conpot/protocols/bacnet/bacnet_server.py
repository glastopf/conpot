# Copyright (C) 2015  Peter Sooky <xsooky00@stud.fit.vubtr.cz>
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

# Author: Peter Sooky <xsooky00@stud.fit.vubtr.cz>
# Brno University of Technology, Faculty of Information Technology

import socket
from lxml import etree
from gevent.server import DatagramServer
from bacpypes.local.device import LocalDeviceObject
from bacpypes.apdu import APDU
from bacpypes.pdu import PDU
from bacpypes.errors import DecodingError
import conpot.core as conpot_core
from conpot.protocols.bacnet.bacnet_app import BACnetApp
from conpot.core.protocol_wrapper import conpot_protocol
from conpot.core import attack_session
from conpot.utils.networking import get_interface_ip
import logging

logger = logging.getLogger(__name__)


@conpot_protocol
class BacnetServer(object):
    def __init__(self, template, template_directory, args):
        self.dom = etree.parse(template)
        device_info_root = self.dom.xpath("//bacnet/device_info")[0]
        name_key = device_info_root.xpath("./device_name/text()")[0]
        id_key = device_info_root.xpath("./device_identifier/text()")[0]
        vendor_name_key = device_info_root.xpath("./vendor_name/text()")[0]
        vendor_identifier_key = device_info_root.xpath("./vendor_identifier/text()")[0]
        apdu_length_key = device_info_root.xpath("./max_apdu_length_accepted/text()")[0]
        segmentation_key = device_info_root.xpath("./segmentation_supported/text()")[0]

        self.thisDevice = LocalDeviceObject(
            objectName=name_key,
            objectIdentifier=int(id_key),
            maxApduLengthAccepted=int(apdu_length_key),
            segmentationSupported=segmentation_key,
            vendorName=vendor_name_key,
            vendorIdentifier=int(vendor_identifier_key),
        )
        self.bacnet_app = None
        self.server = None  # Initialize later
        logger.info("Conpot Bacnet initialized using the %s template.", template)

    def handle(self, data, address):
        session = conpot_core.get_session(
            "bacnet",
            address[0],
            address[1],
            get_interface_ip(address[0]),
            self.server.server_port,
        )
        logger.info(
            "New Bacnet connection from %s:%d. (%s)", address[0], address[1], session.id
        )
        session.add_event({"type": attack_session.NEW_CONNECTION})
        # I'm not sure if gevent DatagramServer handles issues where the
        # received data is over the MTU -> fragmentation
        if data:
            pdu = PDU()
            pdu.pduData = bytearray(data)
            apdu = APDU()
            try:
                apdu.decode(pdu)
            except DecodingError:
                logger.warning("DecodingError - PDU: {}".format(pdu))
                return
            self.bacnet_app.indication(apdu, address, self.thisDevice)
            # send an appropriate response from BACnet app to the attacker
            self.bacnet_app.response(self.bacnet_app._response, address)
        logger.info(
            "Bacnet client disconnected %s:%d. (%s)", address[0], address[1], session.id
        )

    def start(self, host, port):
        connection = (host, port)
        self.server = DatagramServer(connection, self.handle)
        # start to init the socket
        self.server.start()
        self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.host = self.server.server_host
        self.port = self.server.server_port
        # create application instance
        # not too beautiful, but the BACnetApp needs access to the socket's sendto method
        # this could properly be refactored in a way such that sending operates on it's own
        # (non-bound) socket.
        self.bacnet_app = BACnetApp(self.thisDevice, self.server)
        # get object_list and properties
        self.bacnet_app.get_objects_and_properties(self.dom)

        logger.info("Bacnet server started on: %s", (self.host, self.port))
        self.server.serve_forever()

    def stop(self):
        self.server.stop()
