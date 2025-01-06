# Copyright (C) 2015  Lukas Rist <glaslos@gmail.com>
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

"""
Service support based on gaspot.py [https://github.com/sjhilt/GasPot]
Original authors: Kyle Wilhoit and Stephen Hilt
"""

from gevent.server import StreamServer
import datetime
import logging
import random
import conpot.core as conpot_core
from conpot.core import attack_session
from conpot.core.protocol_wrapper import conpot_protocol
from conpot.utils.networking import str_to_bytes

logger = logging.getLogger(__name__)

# 9999 indicates that the command was not understood and
# FF1B is the checksum for the 9999
AST_ERROR = "9999FF1B\n"


@conpot_protocol
class GuardianASTServer(object):
    def __init__(self, template, template_directory, args):
        self.server = None
        self.databus = conpot_core.get_databus()
        # dom = etree.parse(template)
        self.fill_offset_time = datetime.datetime.utcnow()
        logger.info("Conpot GuardianAST initialized")

    def handle(self, sock, addr):
        session = conpot_core.get_session(
            "guardian_ast",
            addr[0],
            addr[1],
            sock.getsockname()[0],
            sock.getsockname()[1],
        )
        logger.info(
            "New GuardianAST connection from %s:%d. (%s)", addr[0], addr[1], session.id
        )
        session.add_event({"type": attack_session.NEW_CONNECTION})
        current_time = datetime.datetime.utcnow()
        fill_start = self.fill_offset_time - datetime.timedelta(minutes=313)
        fill_stop = self.fill_offset_time - datetime.timedelta(minutes=303)
        # Default Product names, change based off country needs
        product1 = self.databus.get_value("product1").ljust(22)
        product1 = self.databus.get_value("product1").ljust(22)
        product2 = self.databus.get_value("product2").ljust(22)
        product3 = self.databus.get_value("product3").ljust(22)
        product4 = self.databus.get_value("product4").ljust(22)

        # Create random Numbers for the volumes
        #
        # this will crate an initial Volume and then the second value based
        # off the orig value.
        vol1 = self.databus.get_value("vol1")
        vol1tc = random.randint(vol1, vol1 + 200)
        vol2 = self.databus.get_value("vol2")
        vol2tc = random.randint(vol2, vol2 + 200)
        vol3 = self.databus.get_value("vol3")
        vol3tc = random.randint(vol3, vol3 + 200)
        vol4 = self.databus.get_value("vol4")
        vol4tc = random.randint(vol4, vol4 + 200)

        # unfilled space ULLAGE
        ullage1 = str(self.databus.get_value("ullage1"))
        ullage2 = str(self.databus.get_value("ullage2"))
        ullage3 = str(self.databus.get_value("ullage3"))
        ullage4 = str(self.databus.get_value("ullage3"))

        # Height of tank
        height1 = str(self.databus.get_value("height1")).ljust(5, "0")
        height2 = str(self.databus.get_value("height2")).ljust(5, "0")
        height3 = str(self.databus.get_value("height3")).ljust(5, "0")
        height4 = str(self.databus.get_value("height4")).ljust(5, "0")

        # Water in tank, this is a variable that needs to be low
        h2o1 = str(self.databus.get_value("h2o1")).ljust(4, "0")
        h2o2 = str(self.databus.get_value("h2o2")).ljust(4, "0")
        h2o3 = str(self.databus.get_value("h2o3")).ljust(4, "0")
        h2o4 = str(self.databus.get_value("h2o4")).ljust(4, "0")

        # Temperature of the tank, this will need to be between 50 - 60
        temp1 = str(self.databus.get_value("temp1")).ljust(5, "0")
        temp2 = str(self.databus.get_value("temp2")).ljust(5, "0")
        temp3 = str(self.databus.get_value("temp3")).ljust(5, "0")
        temp4 = str(self.databus.get_value("temp4")).ljust(5, "0")

        station = self.databus.get_value("station_name")

        # This function is to set-up up the message to be sent upon a successful I20100 command being sent
        # The final message is sent with a current date/time stamp inside of the main loop.
        def I20100():
            ret = "\nI20100\n" + str(current_time.strftime("%m/%d/%Y %H:%M"))
            ret += "\n\n" + station + "\n\n\n\nIN-TANK INVENTORY\n\n"
            ret += "TANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP"
            ret += (
                "\n  1  "
                + product1
                + str(vol1)
                + "      "
                + str(vol1tc)
                + "     "
                + ullage1
                + "    "
                + height1
                + "     "
                + h2o1
                + "    "
                + temp1
            )
            ret += (
                "\n  2  "
                + product2
                + str(vol2)
                + "      "
                + str(vol2tc)
                + "     "
                + ullage2
                + "    "
                + height2
                + "     "
                + h2o2
                + "    "
                + temp2
            )
            ret += (
                "\n  3  "
                + product3
                + str(vol3)
                + "      "
                + str(vol3tc)
                + "     "
                + ullage3
                + "    "
                + height3
                + "     "
                + h2o3
                + "    "
                + temp3
            )
            ret += (
                "\n  4  "
                + product4
                + str(vol4)
                + "      "
                + str(vol4tc)
                + "     "
                + ullage4
                + "    "
                + height4
                + "     "
                + h2o4
                + "    "
                + temp4
            )
            ret += "\n"
            return ret

        ###########################################################################
        #
        # Only one Tank is listed currently in the I20200 command
        #
        ###########################################################################
        def I20200():
            ret = "\nI20200\n" + str(current_time.strftime("%m/%d/%Y %H:%M"))
            ret += "\n\n" + station + "\n\n\n\nDELIVERY REPORT\n\n"
            ret += (
                "T 1:"
                + product1
                + "\nINCREASE   DATE / TIME             GALLONS TC GALLONS WATER  TEMP DEG F  HEIGHT\n\n"
            )

            ret += (
                "      END: "
                + str(fill_stop.strftime("%m/%d/%Y %H:%M"))
                + "         "
                + str(vol1 + 300)
                + "       "
                + str(vol1tc + 300)
                + "   "
                + h2o1
                + "      "
                + temp1
                + "    "
                + height1
                + "\n"
            )
            ret += (
                "    START: "
                + str(fill_start.strftime("%m/%d/%Y %H:%M"))
                + "         "
                + str(vol1 - 300)
                + "       "
                + str(vol1tc - 300)
                + "   "
                + h2o1
                + "      "
                + temp1
                + "    "
                + str(float(height1) - 23)
                + "\n"
            )
            ret += (
                "   AMOUNT:                          "
                + str(vol1)
                + "       "
                + str(vol1tc)
                + "\n\n"
            )
            return ret

        ###########################################################################
        #
        # I20300 In-Tank Leak Detect Report
        #
        ###########################################################################
        def I20300():
            ret = "\nI20300\n" + str(current_time.strftime("%m/%d/%Y %H:%M"))
            ret += "\n\n" + station + "\n\n\n"
            ret += (
                "TANK 1    "
                + product1
                + "\n    TEST STATUS: OFF\nLEAK DATA NOT AVAILABLE ON THIS TANK\n\n"
            )
            ret += (
                "TANK 2    "
                + product2
                + "\n    TEST STATUS: OFF\nLEAK DATA NOT AVAILABLE ON THIS TANK\n\n"
            )
            ret += (
                "TANK 3    "
                + product3
                + "\n    TEST STATUS: OFF\nLEAK DATA NOT AVAILABLE ON THIS TANK\n\n"
            )
            ret += (
                "TANK 4    "
                + product4
                + "\n    TEST STATUS: OFF\nLEAK DATA NOT AVAILABLE ON THIS TANK\n\n"
            )
            return ret

        ###########################################################################
        # Shift report command I20400 only one item in report at this time,
        # but can always add more if needed
        ###########################################################################
        def I20400():
            ret = "\nI20400\n" + str(current_time.strftime("%m/%d/%Y %H:%M"))
            ret += "\n\n" + station + "\n\n\n\nSHIFT REPORT\n\n"
            ret += "SHIFT 1 TIME: 12:00 AM\n\nTANK PRODUCT\n\n"
            ret += (
                "  1  " + product1 + " VOLUME TC VOLUME  ULLAGE  HEIGHT  WATER   TEMP\n"
            )
            ret += (
                "SHIFT  1 STARTING VALUES      "
                + str(vol1)
                + "     "
                + str(vol1tc)
                + "    "
                + ullage1
                + "   "
                + height1
                + "   "
                + h2o1
                + "    "
                + temp1
                + "\n"
            )
            ret += (
                "         ENDING VALUES        "
                + str(vol1 + 940)
                + "     "
                + str(vol1tc + 886)
                + "    "
                + str(int(ullage1) + 345)
                + "   "
                + str(float(height1) + 53)
                + "  "
                + h2o1
                + "    "
                + temp1
                + "\n"
            )
            ret += "         DELIVERY VALUE          0\n"
            ret += "         TOTALS                940\n\n"
            return ret

        ###########################################################################
        # I20500 In-Tank Status Report
        ###########################################################################
        def I20500():
            ret = "\nI20500\n" + str(current_time.strftime("%m/%d/%Y %H:%M"))
            ret += "\n\n\n" + station + "\n\n\n"
            ret += "TANK   PRODUCT                 STATUS\n\n"
            ret += "  1    " + product1 + "  NORMAL\n\n"
            ret += "  2    " + product2 + "  HIGH WATER ALARM\n"
            ret += "                               HIGH WATER WARNING\n\n"
            ret += "  3    " + product3 + "  NORMAL\n\n"
            ret += "  4    " + product4 + "  NORMAL\n\n"
            return ret

        while True:
            try:
                # Get the initial data
                request = sock.recv(4096)
                # The connection has been closed
                if not request:
                    break
                while not (b"\n" in request or b"00" in request):
                    request += sock.recv(4096)
                # if first value is not ^A then do nothing
                # thanks John(achillean) for the help
                if request[:1] != b"\x01":
                    logger.info(
                        "Non ^A command attempt %s:%d. (%s)",
                        addr[0],
                        addr[1],
                        session.id,
                    )
                    break
                # if request is less than 6, than do nothing
                if len(request) < 6:
                    logger.info(
                        "Invalid command attempt %s:%d. (%s)",
                        addr[0],
                        addr[1],
                        session.id,
                    )
                    break

                cmds = {
                    "I20100": I20100,
                    "I20200": I20200,
                    "I20300": I20300,
                    "I20400": I20400,
                    "I20500": I20500,
                }
                cmd = request[1:7].decode()  # strip ^A and \n out
                response = None
                if cmd in cmds:
                    logger.info(
                        "%s command attempt %s:%d. (%s)",
                        cmd,
                        addr[0],
                        addr[1],
                        session.id,
                    )
                    response = cmds[cmd]()
                elif cmd.startswith("S6020"):
                    # change the tank name
                    if cmd.startswith("S60201"):
                        # split string into two, the command, and the data
                        TEMP = request.split(b"S60201")
                        # if length is less than two, print error
                        if len(TEMP) < 2:
                            response = AST_ERROR
                        # Else the command was entered correctly and continue
                        else:
                            # Strip off the carrage returns and new lines
                            TEMP1 = TEMP[1].rstrip(b"\r\n").decode()
                            # if Length is less than 22
                            if len(TEMP1) < 22:
                                # pad the result to have 22 chars
                                product1 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                # else only print 22 chars if the result was longer
                                product1 = TEMP1[:20] + "  "
                            else:
                                # else it fits fine (22 chars)
                                product1 = TEMP1
                        logger.info(
                            "S60201: %s command attempt %s:%d. (%s)",
                            TEMP1,
                            addr[0],
                            addr[1],
                            session.id,
                        )
                    # Follows format for S60201 for comments
                    elif cmd.startswith("S60202"):
                        TEMP = request.split(b"S60202")
                        if len(TEMP) < 2:
                            response = AST_ERROR
                        else:
                            TEMP1 = TEMP[1].rstrip(b"\r\n").decode()
                            if len(TEMP1) < 22:
                                product2 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                product2 = TEMP1[:20] + "  "
                            else:
                                product2 = TEMP1
                        logger.info(
                            "S60202: %s command attempt %s:%d. (%s)",
                            TEMP1,
                            addr[0],
                            addr[1],
                            session.id,
                        )
                    # Follows format for S60201 for comments
                    elif cmd.startswith("S60203"):
                        TEMP = request.split(b"S60203")
                        if len(TEMP) < 2:
                            response = AST_ERROR
                        else:
                            TEMP1 = TEMP[1].rstrip(b"\r\n").decode()
                            if len(TEMP1) < 22:
                                product3 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                product3 = TEMP1[:20] + "  "
                            else:
                                product3 = TEMP1
                        logger.info(
                            "S60203: %s command attempt %s:%d. (%s)",
                            TEMP1,
                            addr[0],
                            addr[1],
                            session.id,
                        )
                    # Follows format for S60201 for comments
                    elif cmd.startswith("S60204"):
                        TEMP = request.split(b"S60204")
                        if len(TEMP) < 2:
                            response = AST_ERROR
                        else:
                            TEMP1 = TEMP[1].rstrip(b"\r\n").decode()
                            if len(TEMP1) < 22:
                                product4 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                product4 = TEMP1[:20] + "  "
                            else:
                                product4 = TEMP1
                        logger.info(
                            "S60204: %s command attempt %s:%d. (%s)",
                            TEMP1,
                            addr[0],
                            addr[1],
                            session.id,
                        )
                    # Follows format for S60201 for comments
                    elif cmd.startswith("S60200"):
                        TEMP = request.split(b"S60200")
                        if len(TEMP) < 2:
                            response = AST_ERROR
                        else:
                            TEMP1 = TEMP[1].rstrip(b"\r\n").decode()
                            if len(TEMP1) < 22:
                                product1 = TEMP1.ljust(22)
                                product2 = TEMP1.ljust(22)
                                product3 = TEMP1.ljust(22)
                                product4 = TEMP1.ljust(22)
                            elif len(TEMP1) > 22:
                                product1 = TEMP1[:20] + "  "
                                product2 = TEMP1[:20] + "  "
                                product3 = TEMP1[:20] + "  "
                                product4 = TEMP1[:20] + "  "
                            else:
                                product1 = TEMP1
                                product2 = TEMP1
                                product3 = TEMP1
                                product4 = TEMP1
                        logger.info(
                            "S60200: %s command attempt %s:%d. (%s)",
                            TEMP1,
                            addr[0],
                            addr[1],
                            session.id,
                        )
                    else:
                        response = AST_ERROR
                else:
                    response = AST_ERROR
                    # log what was entered
                    logger.info(
                        "%s command attempt %s:%d. (%s)",
                        request,
                        addr[0],
                        addr[1],
                        session.id,
                    )
                if response:
                    sock.send(str_to_bytes(response))
                session.add_event(
                    {
                        "type": "AST {0}".format(cmd),
                        "request": request,
                        "response": response,
                    }
                )
            except Exception as e:
                logger.exception(("Unknown Error: {}".format(str(e))))
        logger.info(
            "GuardianAST client disconnected %s:%d. (%s)", addr[0], addr[1], session.id
        )
        session.add_event({"type": attack_session.CONNECTION_LOST})

    def start(self, host, port):
        connection = (host, port)
        self.server = StreamServer(connection, self.handle)
        logger.info("GuardianAST server started on: {0}".format(connection))
        self.server.serve_forever()

    def stop(self):
        self.server.stop()
