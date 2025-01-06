# Copyright (C) 2013  Daniel creo Haslinger <creo-conpot@blackmesa.at>
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

import logging
import socket

from logging.handlers import SysLogHandler


class SysLogger(object):
    def __init__(self, host, port, facility, logdevice, logsocket):
        self.logger = logging.getLogger("conpot")
        handler = logging.StreamHandler()

        if str(logsocket).lower() == "udp":
            handler = SysLogHandler(
                address=(host, port),
                facility=getattr(SysLogHandler, "LOG_" + str(facility).upper()),
                socktype=socket.SOCK_DGRAM,
            )
        elif str(logsocket).lower() == "dev":
            handler = SysLogHandler(address=logdevice)

        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def log(self, event):
        self.logger.info(event)
