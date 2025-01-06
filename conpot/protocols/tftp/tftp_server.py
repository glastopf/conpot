# Copyright (C) 2018  Abhinav Saxena <xandfury@gmail.com>
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

# Author: Abhinav Saxena <xandfury@gmail.com>
# Institute of Informatics and Communication, University of Delhi, South Campus.

import gevent
import os
from lxml import etree
from conpot.protocols.tftp import tftp_handler
from gevent.server import DatagramServer
import conpot.core as conpot_core
from conpot.core import attack_session
from conpot.core.protocol_wrapper import conpot_protocol
from conpot.utils.networking import get_interface_ip
from tftpy import TftpException, TftpTimeout
import logging

logger = logging.getLogger(__name__)


@conpot_protocol
class TftpServer(object):
    """TFTP Server"""

    TIMEOUT_RETRIES = 5

    def __init__(self, template, template_directory, args, timeout=5):
        self.timeout = float(timeout)
        self.server = None  # server attr - Initialize in start
        self.root = None
        self.listener = None  # listener socket
        # A dict of sessions, where each session is keyed by a string like
        # ip:tid for the remote end.
        self.sessions = {}
        # A threading event to help threads synchronize with the server is_running state.
        self.is_running = gevent.event.Event()

        self.shutdown = False
        self._init_vfs(template)
        logger.debug("TFTP server initialized.")

    def _init_vfs(self, template):
        dom = etree.parse(template)
        self.root_path = dom.xpath("//tftp/tftp_root_path/text()")[0].lower()
        if len(dom.xpath("//tftp/add_src/text()")) == 0:
            self.add_src = None
        else:
            self.add_src = dom.xpath("//tftp/add_src/text()")[0].lower()
        self.data_fs_subdir = dom.xpath("//tftp/data_fs_subdir/text()")[0].lower()
        # Create a file system.
        self.vfs, self.data_fs = conpot_core.add_protocol(
            protocol_name="tftp",
            data_fs_subdir=self.data_fs_subdir,
            vfs_dst_path=self.root_path,
            src_path=self.add_src,
        )
        if self.add_src:
            logger.info(
                "TFTP Serving File System from {} at {} in vfs. TFTP data_fs sub directory: {}".format(
                    self.add_src, self.root_path, self.data_fs._sub_dir
                )
            )
        else:
            logger.info(
                "TFTP Serving File System at {} in vfs. TFTP data_fs sub directory: {}".format(
                    self.root_path, self.data_fs._sub_dir
                )
            )
        logger.debug(
            "TFTP serving list of files : {}".format(", ".join(self.vfs.listdir(".")))
        )
        self.root = "/"  # Setup root dir.
        # check for permissions etc.
        logger.debug(
            "TFTP root {} is a directory".format(self.vfs.getcwd() + self.root)
        )
        if self.vfs.access(self.root, 0, os.R_OK):
            logger.debug(
                "TFTP root {} is readable".format(self.vfs.getcwd() + self.root)
            )
        else:
            raise TftpException("The TFTP root must be readable")
        if self.vfs.access(self.root, 0, os.W_OK):
            logger.debug(
                "TFTP root {} is writable".format(self.vfs.getcwd() + self.root)
            )
        else:
            logger.warning(
                "The TFTP root {} is not writable".format(self.vfs.getcwd() + self.root)
            )

    def handle(self, buffer, client_addr):
        session = conpot_core.get_session(
            "tftp",
            client_addr[0],
            client_addr[1],
            get_interface_ip(client_addr[0]),
            self.server._socket.getsockname()[1],
        )
        logger.info(
            "New TFTP client has connected. Connection from {}:{}. ".format(
                client_addr[0], client_addr[1]
            )
        )
        session.add_event({"type": attack_session.NEW_CONNECTION})
        logger.debug("Read %d bytes", len(buffer))
        context = tftp_handler.TFTPContextServer(
            client_addr[0], client_addr[1], self.timeout, self.root, None, None
        )
        context.vfs, context.data_fs = self.vfs, self.data_fs
        if self.shutdown:
            logger.info("Shutting down now. Disconnecting {}".format(client_addr))
            session.add_event({"type": attack_session.CONNECTION_TERMINATED})
        try:
            context.start(buffer)
            context.cycle()
        except TftpTimeout as err:
            logger.info("Timeout occurred %s: %s" % (context, str(err)))
            session.add_event({"type": attack_session.CONNECTION_TIMEOUT})
            context.retry_count += 1
            # TODO: We should accept retries from the user.
            if context.retry_count >= self.TIMEOUT_RETRIES:
                logger.info(
                    "TFTP: Hit max {} retries on {}, giving up".format(
                        self.TIMEOUT_RETRIES, context
                    )
                )
            else:
                logger.info("TFTP: resending on session %s" % context)
                context.state.resendLast()
        except TftpException as err:
            logger.info(
                "TFTP: Fatal exception thrown from session {}: {}".format(
                    context, str(err)
                )
            )
            session.add_event({"type": attack_session.CONNECTION_LOST})
        logger.info("TFTP: terminating connection: {}".format(context))
        session.set_ended()
        context.end()
        # Gathering up metrics before terminating the connection.
        metrics = context.metrics
        if metrics.duration == 0:
            logger.info("Duration too short, rate undetermined")
        else:
            logger.info(
                "Transferred %d bytes in %.2f seconds"
                % (metrics.bytes, metrics.duration)
            )
            logger.info("Average rate: %.2f kbps" % metrics.kbps)
        logger.info("%.2f bytes in resent data" % metrics.resent_bytes)
        logger.info("%d duplicate packets" % metrics.dupcount)
        del context

    def start(self, host, port):
        conn = (host, port)
        # FIXME - sockets should be non-blocking
        self.listener = gevent.socket.socket(
            gevent.socket.AF_INET, gevent.socket.SOCK_DGRAM
        )
        self.listener.bind(conn)
        self.listener.settimeout(self.timeout)
        self.server = DatagramServer(self.listener, self.handle)
        logger.info("Starting TFTP server at {}".format(conn))
        self.server.serve_forever()

    def stop(self):
        self.server.close()
