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

import socketserver
import gevent
import conpot.core as conpot_core
from conpot.core.filesystem import FilesystemError
from conpot.core import attack_session
import logging
import errno
import time
import fs
from datetime import datetime
import os
from conpot.protocols.ftp.ftp_utils import FTPPrivilegeException
from conpot.utils.networking import sanitize_file_name
from gevent import socket

logger = logging.getLogger(__name__)

# -----------------------------------------------------------
# Implementation Note: DTP channel that would have two queues for Input and Output (separate for producer and consumer.)
# There would be 3 threads (greenlets) in place. One for handling the command_channel, one for handling the input/
# output of the data_channel and one that would run the command processor.
# Commands class inheriting this base handler is independent of the **green drama** and may be considered on as is basis
# when migrating to async/io.
# -----------------------------------------------------------


class FTPMetrics(object):
    """Simple class to track total bytes transferred, login attempts etc."""

    def __init__(self):
        self.start_time = time.time()
        self.data_channel_bytes_recv = 0
        self.data_channel_bytes_send = 0
        self.command_chanel_bytes_send = 0
        self.command_chanel_bytes_recv = 0
        self.last_active = self.start_time
        # basically we need a timeout time composite of timeout for
        # data_sock and client_sock. Let us say that timeout of 5 sec for data_sock
        # and command_sock is 300.
        # Implementation note: Data sock is non-blocking. So the connection is closed when there is no data.

    @property
    def timeout(self):
        if self.last_active:
            return lambda: int(time.time() - self.last_active)
        else:
            return lambda: int(time.time() - self.start_time)

    def get_elapsed_time(self):
        return self.last_active - self.start_time

    def __repr__(self):
        tot = (
            self.data_channel_bytes_recv
            + self.data_channel_bytes_send
            + self.command_chanel_bytes_recv
            + self.command_chanel_bytes_send
        )
        s = """ 
        Total data transferred      : {}  (bytes)
        Command channel sent        : {}  (bytes)
        Command channel received    : {}  (bytes)
        Data channel sent           : {}  (bytes)
        Data channel received       : {}  (bytes)""".format(
            tot,
            self.command_chanel_bytes_send,
            self.command_chanel_bytes_recv,
            self.data_channel_bytes_send,
            self.data_channel_bytes_recv,
        )
        return s

    def get_metrics(
        self, user_name, uid, failed_login_attempts, max_login_attempts, client_address
    ):
        s = """
        FTP statistics for client     : {}
        ----------------------------------
        Logged in as user :{} with uid: {}
        Failed login attempts         : {}/{}
        Start time                    : {}
        Last active on                : {}
        ----------------------------------
        """.format(
            client_address,
            user_name,
            uid,
            failed_login_attempts,
            max_login_attempts,
            datetime.fromtimestamp(self.start_time).ctime(),
            datetime.fromtimestamp(self.last_active).ctime(),
        )
        s += self.__repr__()
        return s


class FTPHandlerBase(socketserver.BaseRequestHandler):
    """Base class for a full duplex connection"""

    config = None  # Config of FTP server. FTPConfig class instance.
    host, port = None, None  # FTP Sever's host and port.
    _local_ip = "127.0.0.1"  # IP to bind the _data_listener_sock with.
    _ac_in_buffer_size = 4096  # incoming data buffer size (defaults 4096)
    _ac_out_buffer_size = 4096  # outgoing data buffer size (defaults 4096)

    def __init__(self, request, client_address, server):
        # ------------------------ Environment -------------------------
        self.client_sock = request._sock
        # only commands that are enabled should work! This is configured in the FTPConfig class.
        if not self._local_ip:
            self._local_ip = self.client_sock.getsockname()[
                0
            ]  # for masquerading.. Local IP would work just fine.
        # Username of the current user
        self.username = None
        self._uid = None  # UID of the current username
        # The flag to check whether a user is already authenticated!
        self.authenticated = False

        # What commands does this FTP support
        self.COMMANDS = {}
        # conpot session
        self.session = None
        # terminate character - CR+LF
        self.terminator = b"\r\n"
        # tracking login attempts
        self.invalid_login_attempt = 0
        # max login attempts
        self.max_login_attempts = self.config.max_login_attempts

        # ftp absolute path of the file system
        self.root = self.config.vfs.getcwd()
        # get the current working directory of the current user
        self.working_dir = "/"
        # flag to check whether we need to disconnect the client
        self.disconnect_client = False
        # keep state of the last command/response
        self._last_command = None
        # Note: From stream, block or compressed - only stream is supported.
        self._transfer_mode = None  # For APPE and REST commands
        self._restart_position = 0  # For APPE and REST commands
        # binary ('i') or ascii mode ('a')
        self._current_type = "a"
        # buffer-size for FTP **commands**, send error if this is exceeded
        self.buffer_limit = 2048  # command channel would not accept more data than this for one command.
        self.active_passive_mode = (
            None  # Flag to check the current mode. Would be set to 'PASV' or 'PORT'
        )

        self._data_channel = False  # check whether the data channel is running or not. This would trigger
        # the start and end of the data channel.
        self._data_channel_send = (
            gevent.event.Event()
        )  # Event when we are trying to send a file.
        self._data_channel_recv = gevent.event.Event()  # Event for receiving a file.
        self.cli_ip, self.cli_port = (
            None,
            None,
        )  # IP and port received from client in active/passive mode.
        self._data_sock = None
        self._data_listener_sock = None
        # socket for accepting cli_ip and cli_port in passive mode.

        self._rnfr = None  # For RNFR and RNTO
        self.metrics = FTPMetrics()  # track session related metrics.

        # Input and output queues.
        self._command_channel_input_q = gevent.queue.Queue()
        self._command_channel_output_q = gevent.queue.Queue()
        self._data_channel_output_q = gevent.queue.Queue()
        self._data_channel_input_q = gevent.queue.Queue()
        self.ftp_greenlets = None  # Keep track of all greenlets
        socketserver.BaseRequestHandler.__init__(
            self, request=request, client_address=client_address, server=server
        )

    def ftp_path(self, path):
        """Clean and sanitize ftp paths relative fs instance it is hosted in."""
        _path = self.config.vfs.norm_path(os.path.join(self.working_dir, path))
        _path = _path.replace(self.root, "/")
        return _path

    # -- Wrappers for gevent StreamServer -------

    class false_request(object):
        def __init__(self):
            self._sock = None

        def __del__(self):
            if self._sock:
                if self._sock.fileno() != -1:
                    self._sock.close()
                del self._sock

    @classmethod
    def stream_server_handle(cls, sock, address):
        """Translate this class for use in a StreamServer"""
        request = cls.false_request()
        request._sock = sock
        server = None
        _ftp = None
        try:
            _ftp = cls(request, address, server)
        except socket.error:
            logger.warning("Unexpected Error Occurred!")
            del _ftp

    def setup(self):
        """Connect incoming connection to a FTP session"""
        self.session = conpot_core.get_session(
            "ftp",
            self.client_address[0],
            self.client_address[1],
            self.request._sock.getsockname()[0],
            self.request._sock.getsockname()[1],
        )
        logger.info(
            "New FTP connection from {}:{}. ({})".format(
                self.client_address[0], self.client_address[1], self.session.id
            )
        )
        self.session.add_event({"type": attack_session.NEW_CONNECTION})
        # send 200 + banner -- new client has connected!
        self.respond(b"200 " + self.config.banner.encode())
        #  Is there a delay in command response? < gevent.sleep(0.5) ?
        return socketserver.BaseRequestHandler.setup(self)

    def finish(self):
        """End this client session"""
        if self.disconnect_client is False:
            logger.info(
                "FTP client {} disconnected. ({})".format(
                    self.client_address, self.session.id
                )
            )
            self.stop_data_channel(
                abort=True,
                purge=True,
                reason="Closing connection to {}. "
                "Client disconnected".format(self.client_address),
            )
            if self._data_listener_sock:
                if self._data_listener_sock.fileno() != -1:
                    self._data_sock.close()
            socketserver.BaseRequestHandler.finish(self)
            self.client_sock.close()
            logger.info(
                "{}".format(
                    self.metrics.get_metrics(
                        client_address=self.client_address,
                        user_name=self.username,
                        uid=self._uid,
                        failed_login_attempts=self.invalid_login_attempt,
                        max_login_attempts=self.max_login_attempts,
                    )
                )
            )
            self.disconnect_client = True
        else:
            logger.debug("Client {} already disconnected.".format(self.client_address))

    def __del__(self):
        if self.disconnect_client is False:
            self.finish()

    # -- FTP Command Channel ------------

    def handle_cmd_channel(self):
        """Read data from the socket and add it to the _command_channel_input_q for processing"""
        log_data = dict()
        try:
            if self.client_sock.closed:
                logger.info(
                    "FTP socket is closed, connection lost. Remote: {} ({}).".format(
                        self.client_address, self.session.id
                    )
                )
                self.session.add_event({"type": attack_session.CONNECTION_LOST})
                self.finish()
                return
            socket_read, socket_write, _ = gevent.select.select(
                [self.client_sock], [self.client_sock], [], 1
            )
            # make sure the socket is ready to read - we would read from the command channel.
            if self.client_sock in socket_read:
                data = self.client_sock.recv(self.buffer_limit)
                # put the data in the _input_q for processing
                if data and data != b"":
                    log_data["request"] = data
                    if self._command_channel_input_q.qsize() > self.buffer_limit:
                        # Flush buffer if it gets too long (possible DOS condition). RFC-959 specifies that
                        # 500 response should be given in such cases.
                        logger.info(
                            "FTP command input exceeded buffer from client {}".format(
                                self.client_address
                            )
                        )
                        self.respond(b"500 Command too long.")
                    else:
                        self.metrics.command_chanel_bytes_recv += len(data)
                        self.metrics.last_active = time.time()
                        self._command_channel_input_q.put(data)
            # make sure the socket is ready to write
            elif self.client_sock in socket_write and (
                not self._command_channel_output_q.empty()
            ):
                response = self._command_channel_output_q.get()
                if response is not None:
                    logger.debug(
                        "Sending packet {} to client {}".format(
                            self.client_address, response
                        )
                    )
                    log_data["response"] = response
                    # add len to metrics
                    self.metrics.command_chanel_bytes_send += len(response)
                    self.metrics.last_active = time.time()
                    self.client_sock.send(response)
            if "request" in log_data or "response" in log_data:
                logger.info(
                    "FTP traffic to {}: {} ({})".format(
                        self.client_address, log_data, self.session.id
                    )
                )
                self.session.add_event(log_data)
        except socket.error as se:
            if se.errno == errno.EWOULDBLOCK:
                gevent.sleep(0.1)
            else:
                logger.info(
                    "Socket error, remote: {}. ({}). Error {}".format(
                        self.client_address, self.session.id, se
                    )
                )
                self.session.add_event({"type": attack_session.CONNECTION_LOST})
                self.finish()

    def respond(self, response):
        """Send processed command/data as reply to the client"""
        response = (
            response.encode("utf-8") if not isinstance(response, bytes) else response
        )
        response = (
            response + self.terminator if response[-2:] != self.terminator else response
        )
        self._command_channel_output_q.put(response)

    def process_ftp_command(self):
        raise NotImplementedError

    # -- FTP Data Channel --------------

    def start_data_channel(self, send_recv="send"):
        """
        Starts the data channel. To be called from the command process greenlet.
        :param send_recv: Whether the event is a send event or recv event. When set to 'send' data channel's socket
        writes data in the output queues else when set to 'read' data channel's socket reads data into the input queue.
        :type send_recv: str
        """
        try:
            assert self.cli_port and self.cli_port and self._data_sock
            if self._data_channel is True:
                logger.debug("Already sending some data that has to finish first.")
                # waait till that process finishes.
                self._data_channel_send.wait()
                self._data_channel_recv.wait()
            if send_recv == "send":
                # we just want to do send and not receive
                self._data_channel_send.clear()
                self._data_channel_recv.set()
            else:
                # we just want to do receive and not send
                self._data_channel_recv.clear()
                self._data_channel_send.set()
            self._data_channel = True
        except AssertionError:
            self.respond(b"425 Use PORT or PASV first.")
            logger.info(
                "Can't initiate {} mode since either of IP or Port supplied by the "
                "client are None".format(self.active_passive_mode)
            )

    def stop_data_channel(self, abort=False, purge=False, reason=None):
        if reason:
            logger.info("Closing data channel. Reason: {}".format(reason))
        if (not self._data_channel_output_q.empty()) or (
            not self._command_channel_input_q.empty()
        ):
            if not abort:
                # Wait for all transfers to complete.
                self._data_channel_send.wait()
                self._data_channel_recv.wait()
        self._data_channel = False
        if self._data_sock and self._data_sock.fileno() != -1:
            self._data_sock.close()
        # don't want to do either send and receive.
        # Although this is done while sending - we're doing it just to be safe.
        self._data_channel_recv.set()
        self._data_channel_send.set()
        if purge:
            self.cli_ip = None
            self.cli_port = None
            # purge data in buffers .i.e the data queues.
            while self._data_channel_input_q.qsize() != 0:
                _ = self._data_channel_input_q.get()
            while self._data_channel_output_q.qsize() != 0:
                _ = self._data_channel_output_q.get()

    def handle_data_channel(self):
        if self._data_channel:
            try:
                # Need to know what kind of event are we expecting.
                if not self._data_channel_send.is_set():
                    # must be a sending event. Get from the output_q and write it to socket.
                    # pick an item from the _data_channel_output_q and send it to the requisite socket
                    if not self._data_channel_output_q.empty():
                        # Consumes data from the data channel output queue. Log it and sends it across to the client.
                        # If a file needs to be send, pass the file name directly as file parameter. sendfile is used
                        # in this case.
                        data = self._data_channel_output_q.get()
                        if data["type"] == "raw_data":
                            logger.info(
                                "Send data {} at {}:{} for client : {}".format(
                                    data["data"],
                                    self.cli_ip,
                                    self.cli_port,
                                    self.client_address,
                                )
                            )
                            self.metrics.last_active = time.time()
                            self._data_sock.send(data=data["data"])
                            self.metrics.data_channel_bytes_send += len(data)
                        elif data["type"] == "file":
                            file_name = data["file"]
                            if self.config.vfs.isfile(file_name):
                                logger.info(
                                    "Sending file {} to client {} at {}:{}".format(
                                        file_name,
                                        self.client_address,
                                        self.cli_ip,
                                        self.cli_port,
                                    )
                                )
                                try:
                                    self.metrics.last_active = time.time()
                                    with self.config.vfs.open(
                                        file_name, mode="rb"
                                    ) as file_:
                                        self._data_sock.sendfile(file_, 0)
                                    _size = self.config.vfs.getsize(file_name)
                                    self.metrics.data_channel_bytes_send += _size
                                except (fs.errors.FSError, FilesystemError):
                                    raise
                        if self._data_channel_output_q.qsize() == 0:
                            logger.debug(
                                "No more data to read. Either transfer finished or error occurred."
                            )
                            self._data_channel_send.set()
                            self.respond(b"226 Transfer complete.")
                elif not self._data_channel_recv.is_set():
                    # must be a receiving event. Get data from socket and add it to input_q
                    # Receive data, log it and add it to the data channel input queue.
                    self.respond(b"125 Transfer starting.")
                    data = self._data_sock.recv(self._ac_in_buffer_size)
                    if data and data != b"":
                        self.metrics.last_active = time.time()
                        # There is some data -- could be a file.
                        logger.debug(
                            "Received {} from client {} on {}:{}".format(
                                data, self.client_address, self.cli_ip, self.cli_port
                            )
                        )
                        self.metrics.data_channel_bytes_recv += len(data)
                        self._data_channel_input_q.put(data)
                        while data and data != b"":
                            self.metrics.last_active = time.time()
                            data = self._data_sock.recv(self._ac_in_buffer_size)
                            logger.debug(
                                "Received {} from client {} on {}:{}".format(
                                    data,
                                    self.client_address,
                                    self.cli_ip,
                                    self.cli_port,
                                )
                            )
                            self.metrics.data_channel_bytes_recv += len(data)
                            self._data_channel_input_q.put(data)
                    # we have received all data. Time to finish this process.
                    # set the writing event to set - so that we can write this data to files.
                    self._data_channel_recv.set()
                    self.respond(b"226 Transfer complete.")
                else:
                    # assume that the read/write event has finished
                    # send a nice resp to the client saying everything has finished.
                    # set the self._data_channel(_recv/_send) markers. This would also wait for read write to finish.
                    self.stop_data_channel(reason="Transfer has completed!.")
            except (socket.error, socket.timeout) as se:
                # TODO: send appropriate response
                # Flush contents of the data channel
                reason = (
                    "connection timed out"
                    if isinstance(se, socket.timeout)
                    else "socket error"
                )
                msg = "Stopping FTP data channel {}:{}. Reason: {}".format(
                    self.cli_ip, self.cli_port, reason
                )
                self.stop_data_channel(abort=True, purge=True, reason=msg)
            except (
                fs.errors.FSError,
                FilesystemError,
                FTPPrivilegeException,
                FilesystemError,
            ) as fe:
                self.respond(b"550 Transfer failed.")
                self.stop_data_channel(
                    abort=True,
                    reason="VFS related exception occurred: {}".format(str(fe)),
                )

    def recv_file(self, _file, _file_pos=0, cmd="STOR"):
        """
        Receive a file - to be used with STOR, REST and APPE. A copy would be made on the _data_fs.
        :param _file: File Name to the file that would be written to fs.
        :param _file_pos: Seek file to position before receiving.
        :param cmd: Command used for receiving file.
        """
        # FIXME: acquire lock to files - both data_fs and vfs.
        with self.config.vfs.lock():
            self.start_data_channel(send_recv="recv")
            recv_err = None
            logger.info("Receiving data from {}:{}".format(self.cli_ip, self.cli_port))
            _data_fs_file = sanitize_file_name(
                _file, self.client_address[0], str(self.client_address[1])
            )
            _data_fs_d = None
            _file_d = None
            # wait till all transfer has finished.
            self._data_channel_recv.wait()
            try:
                # we are blocking on queue for 10 seconds to wait for incoming data.
                # If there is no data in the queue. We assume that transfer has been completed.
                _data = self._data_channel_input_q.get()
                _data_fs_d = self.config.data_fs.open(path=_data_fs_file, mode="wb")
                if _file_pos == 0 and cmd == "STOR":
                    # overwrite file or create a new one.
                    # we don't need to seek at all. Normal write process by STOR
                    _file_d = self.config.vfs.open(path=_file, mode="wb")
                else:
                    assert _file_pos != 0
                    # must seek file. This is done in append or rest(resume transfer) command.
                    # in that case, we should create a duplicate copy of this file till that seek position.
                    with self.config.vfs.open(path=_file, mode="rb") as _file_d:
                        _data_fs_d.write(_file_d.read(_file_pos))
                    # finally we should let the file to be written as requested.
                    if cmd == "APPE":
                        _file_d = self.config.vfs.open(path=_file, mode="ab")
                    else:
                        # cmd is REST
                        _file_d = self.config.vfs.open(path=_file, mode="rb+")
                        _file_d.seek(_file_pos)
                _file_d.write(_data)
                _data_fs_d.write(_data)
                while not self._data_channel_input_q.empty():
                    _data = self._data_channel_input_q.get()
                    _file_d.write(_data)
                    _data_fs_d.write(_data)
                logger.info(
                    "Files {} and {} written successfully to disk".format(
                        _file, _data_fs_file
                    )
                )
            except (
                AssertionError,
                IOError,
                fs.errors.FSError,
                FilesystemError,
                FTPPrivilegeException,
            ) as fe:
                recv_err = fe
                self.stop_data_channel(abort=True, reason=str(fe))
                self.respond("554 {} command failed.".format(cmd))
            finally:
                if _file_d and _file_d.fileno() != -1:
                    _file_d.close()
                if _data_fs_d and _data_fs_d.fileno() != -1:
                    _data_fs_d.close()
                if not recv_err:
                    self.config.vfs.chmod(_file, self.config.file_default_perms)
                    if cmd == "STOR":
                        self.config.vfs.chown(
                            _file, uid=self._uid, gid=self.config.get_gid(self._uid)
                        )
                    self.config.vfs.settimes(
                        _file, accessed=datetime.now(), modified=datetime.now()
                    )
                    self.respond(b"226 Transfer complete.")

    def push_data(self, data):
        """Handy utility to push some data using the data channel"""
        # ensure data is encoded in bytes
        data = data.encode("utf8") if not isinstance(data, bytes) else data
        self._data_channel_output_q.put({"type": "raw_data", "data": data})

    def send_file(self, file_name):
        """Handy utility to send a file using the data channel"""
        if self._data_channel:
            self.respond("125 Data connection already open. Transfer starting.")
        else:
            self.respond("150 File status okay. About to open data connection.")
        self._data_channel_output_q.put({"type": "file", "file": file_name})
        self.start_data_channel()

    # -- FTP Authentication and other unities --------

    # FIXME: Refactor this. Move this to the auth module.
    def authentication_ok(self, user_pass):
        """
        Verifies authentication and sets the username of the currently connected client. Returns True or False
        Checks user names and passwords pairs. Sets the current user and uid.
        """
        # if anonymous ftp is enabled - accept any password.
        try:
            if self.username == "anonymous" and self.config.anon_auth:
                self.authenticated = True
                self._uid = self.config.anon_uid
                self.username = self.config.user_db[self._uid]["uname"]
                return True
            else:
                if (self.username, user_pass) in self.config.user_pass:
                    # user/pass match and correct!
                    self.authenticated = True
                    self._uid = self.config.get_uid(self.username)
                    return True
                return False
        except (KeyError, ValueError):
            return False

    # -- Actual FTP Handler -----------

    def handle(self):
        """Actual FTP service to which the user has connected."""
        while not self.disconnect_client:
            try:
                # These greenlets would be running forever. During the connection.
                # first two are for duplex command channel. Final one is for storing files on file-system.
                self.ftp_greenlets = [
                    gevent.spawn(self.handle_cmd_channel),
                    gevent.spawn(self.process_ftp_command),
                    gevent.spawn(self.handle_data_channel),
                ]
                gevent.joinall(self.ftp_greenlets)
                # Block till all jobs are not finished
            except KeyboardInterrupt:
                logger.info("Shutting FTP server.")
            finally:
                gevent.killall(self.ftp_greenlets)
