# Copyright (C) 2014 Johnny Vestergaard <jkv@unixcluster.dk>
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
import uuid

from datetime import datetime

logger = logging.getLogger(__name__)


NEW_CONNECTION = "NEW_CONNECTION"
CONNECTION_LOST = "CONNECTION_LOST"
CONNECTION_CLOSED = "CONNECTION_CLOSED"
CONNECTION_FAILED = "CONNECTION_FAILED"
CONNECTION_TERMINATED = "CONNECTION_TERMINATED"
CONNECTION_QUIT = "CONNECTION_QUIT"
CONNECTION_TIMEOUT = "CONNECTION_TIMEOUT"


# one instance per connection
class AttackSession(object):
    def __init__(
        self,
        protocol,
        source_ip,
        source_port,
        destination_ip,
        destination_port,
        log_queue,
    ):
        self.log_queue = log_queue
        self.id = uuid.uuid4()
        logger.info("New %s session from %s (%s)", protocol, source_ip, self.id)
        self.protocol = protocol
        self.source_ip = source_ip
        self.source_port = source_port
        self.destination_ip = destination_ip
        self.destination_port = destination_port
        self.timestamp = datetime.utcnow()
        self.public_ip = None
        self.data = dict()
        self._ended = False

    def _dump_data(self, data):
        return {
            "id": self.id,
            "remote": (self.source_ip, self.source_port),
            "src_ip": self.source_ip,
            "src_port": self.source_port,
            "local": (self.destination_ip, self.destination_port),
            "dst_ip": self.destination_ip,
            "dst_port": self.destination_port,
            "data_type": self.protocol,
            "timestamp": self.timestamp,
            "public_ip": self.public_ip,
            "data": data,
        }

    def add_event(self, event_data):
        sec_elapsed = (datetime.utcnow() - self.timestamp).total_seconds()
        elapse_ms = int(sec_elapsed * 1000)
        while elapse_ms in self.data:
            elapse_ms += 1
        self.data[elapse_ms] = event_data
        # TODO: We should only log the session when it is finished
        self.log_queue.put(self._dump_data(event_data))

    def dump(self):
        return self._dump_data(self.data)

    def set_ended(self):
        self._ended = True
