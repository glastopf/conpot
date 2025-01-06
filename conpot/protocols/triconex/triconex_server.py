# BSD 3-Clause License
#
# Copyright (c) 2018, Nozomi Networks
# Copyright (c) 2020, MushMush
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import socket
import struct
from lxml import etree
from gevent.server import DatagramServer
import conpot.core as conpot_core
from conpot.utils.networking import get_interface_ip
from conpot.core.protocol_wrapper import conpot_protocol
from conpot.core import attack_session
import crcmod
import time
import logging

logger = logging.getLogger(__name__)
cf = crcmod.mkCrcFun(0x18005, rev=True, initCrc=0, xorOut=0)


def build_slot(leds0, leds1, model, color):
    slotfmt = "<" + 32 * "B"
    return struct.pack(
        slotfmt,
        leds0,
        leds1,
        model,
        color,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    )


# Construct slots
mps = {
    "active": build_slot(0x15, 0x21, 0xF0, 0x01),
    "passive": build_slot(0x02, 0x01, 0xF0, 0x02),
}

slotsdesc = {
    "empty": build_slot(0, 0, 0, 0),
    "com": build_slot(5, 33, 55, 1),
    "do": build_slot(5, 16, 20, 1),
    "di": build_slot(5, 32, 11, 1),
    "him": build_slot(5, 22, 53, 1),
    "ddo": build_slot(0x4F, 0x21, 0x5C, 0x2),
}


def build_chassis_status_response(
    triconId=0,
    seq=0,
    node=2,
    projname="FIRSTPROJ",
    activemp=0,
    mpmodel=1,
    slots=["com"],
):
    # Project segment
    data = struct.pack(
        "<HBBHHHIIIHIIccccccccccI",
        2,
        0xFF,
        0x00,
        1,
        4,
        3,
        int(time.time() - 24 * 3600),
        200,
        200,
        181,
        0,
        1,
        projname[0],
        projname[1],
        projname[2],
        projname[3],
        projname[4],
        projname[5],
        projname[6],
        projname[7],
        projname[8],
        "\0",
        int(time.time()),
    )

    # Memory segment
    data += struct.pack(
        "<BBBBIIII", 0x56, 0x02, 0x00, 0x00, 8340703, 8251952, 0x1B, 0x32
    )

    # MPS segment
    for i in range(3):
        data += mps["active" if i == activemp else "passive"]

    # Unknown segment
    data += struct.pack("<HH", 0xA6, 1024)

    # Slots segment
    for i in range(3):
        data += mps["active" if i == activemp else "passive"]
    for s in slots:
        data += slotsdesc[s] if s in slotsdesc else build_slot(*s)
    for i in range(13 - len(slots)):
        data += slotsdesc["empty"]

    return build_packet(triconId, 119, seq, data)


def build_CP_status_response(triconId=0, seq=0):
    """
    # Collapsed structure
    data = struct.pack('<' + 186*'B',
            0x00, 0x01, 0x00, 0x00, 0x0d, 0x00, 0x01, 0x01,
            0x01, 0x00, 0x00, 0x50, 0x80, 0x00, 0x00, 0x00,
            0x80, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
            0x60, 0x00, 0x00, 0x50, 0xfe, 0x00, 0xff, 0xaf,
            0xff, 0x00, 0x00, 0x20, 0x00, 0x20, 0x00, 0x20,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x1b,
            0x00, 0x00, 0xc8, 0x00, 0xc8, 0x00, 0xba, 0x00,
            0x5c, 0x98, 0x00, 0x00, 0x35, 0x00, 0x4f, 0xb6,
            0xe1, 0x5a, 0x45, 0x4d, 0x50, 0x54, 0x59, 0x00,
            0xad, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x00,
            0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x4d, 0x61, 0x6e, 0x61,
            0x67, 0x65, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00
            )
    return build_packet(triconId, 108, seq, data)
    """

    data = struct.pack(
        "<HBBBBBBB",
        1,
        0x0,  # loadIn
        0x0,  # modIn
        0xD,  # loadState
        0x0,  # singleScan
        0x1,  # cpValid
        0x1,  # keyState
        0x1,  # runState
    )

    data += struct.pack("<BBBBB", 0x0, 0x0, 0x50, 0x80, 0x0)

    data += struct.pack(
        "<IIIII",
        0x00800000,  # my: 8388608
        0x00400000,  # us: 4194304
        0x00600000,  # ds: 6291456
        0x00FE5000,  # heap_min: 16666624
        0x00FFAFFF,  # heap_max: 16756735
    )

    data += struct.pack(
        "<BBBBBBBBBBBB", 0x0, 0x20, 0x0, 0x20, 0x0, 0x20, 0x0, 0x0, 0x0, 0x00, 0x0, 0x0
    )
    data += struct.pack(
        "<BBBBBBBBBBBB",
        0x14,
        0x1B,
        0x00,
        0x00,
        0xC8,
        0x00,
        0xC8,
        0x00,
        0xBA,
        0x00,
        0x5C,
        0x98,
    )

    data += struct.pack("<HH", 4, 3)  # Minor, major
    data += struct.pack("<I", time.time())  # Timestamp
    data += struct.pack(
        "<cccccccccc", "E", "C", "C", "E", "C", "C", "A", "H", "H", "\0"
    )

    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    data += struct.pack("<BBBBBB", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)

    return build_packet(triconId, 108, seq, data)


def build_packet(triconId, funccode, seq, data):
    # Subheader without checksum
    datalength = len(data) + 10
    subheader = struct.pack("<BBBBHHH", 1, 0, funccode, seq, 0, 0, datalength)

    # Compute checksum
    checksum = datalength
    for c in subheader:
        checksum += ord(c)
    for c in data:
        checksum += ord(c)

    # Header and subheader with checksum
    header = struct.pack("<BBH", 5, triconId, datalength)
    subheader = struct.pack("<BBBBHHH", 1, 0, funccode, seq, 0, checksum, datalength)

    # Entire packet, except CRC
    packet = header + subheader + data

    # Compute CRC
    crc = cf(packet)
    packet += struct.pack("<H", crc)

    return packet


def build_tricon_attached(triconId=0, seq=0, string="\x03\x00\x33\x0a\x04\x00"):
    return build_packet(triconId, 0x6A, seq, string)


@conpot_protocol
class TriconexServer(object):
    def __init__(self, template, template_directory, args):
        self.dom = etree.parse(template)
        self.slots = {}
        self.get_slots()

    def get_slots(self):
        slots = self.dom.xpath("//triconex/slots/*")
        for slot in slots:
            print(slot)

    def handle(self, data, addr):
        session = conpot_core.get_session(
            "triconex",
            addr[0],
            addr[1],
            get_interface_ip(addr[0]),
            self.server._socket.getsockname()[1],
        )
        # mcode, chan, dlen, crc16 = struct.unpack("<BBHH", data[0:6])
        mcode, _, _, _ = struct.unpack("<BBHH", data[0:6])

        # CONNECT REQUEST
        if mcode == 0x1:
            logger.info("CONNECT REQUEST")
            session.add_event({"type": attack_session.NEW_CONNECTION})
            # CONNECT REPLY
            self.server.sendto("\x02\x00\x00\x00\x01\xb8", addr)

        # COMMAND REPLY
        elif mcode == 0x5:
            # Get the function code
            fcode, pseq = struct.unpack("<BB", data[6:8])
            if fcode == 0xD:
                logger.info("ATTACH REQUEST")
                self.server.sendto(build_tricon_attached(), addr)
            elif fcode == 0x13:
                # time.sleep(5)
                logger.info("GET CP STATUS")
                self.server.sendto(build_CP_status_response(seq=pseq), addr)
            elif fcode == 0x18:
                logger.info("GET CHASSIS STATUS")
                self.server.sendto(
                    build_chassis_status_response(
                        seq=pseq,
                        mpmodel=0,
                        activemp=2,
                        slots=[
                            "com",
                            self.slots["slot1"],
                            "empty",
                            self.slots["slot2"],
                            "empty",
                            self.slots["slot3"],
                            "empty",
                            self.slots["slot4"],
                        ],
                    ),
                    addr,
                )
            else:
                logger.info("UNKNOWN: %s" % hex(fcode))

    def stop(self):
        self.server.stop()

    def start(self, host, port):
        self.server = DatagramServer((host, port), self.handle)
        self.server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        logger.info("Triconex server started on: {}:{}".format(host, port))
        self.server.serve_forever()
