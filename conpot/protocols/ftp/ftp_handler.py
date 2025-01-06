# This module is based on the original work done by Giampaolo Rodola and pyftpdlib authors.
# This is a heavily customized version that supports Conpot's virtual file system os.* wrappers and gevent support.

from conpot.protocols.ftp.ftp_base_handler import FTPHandlerBase
import logging
import fs
import os
import glob
import sys
import tempfile
from datetime import datetime
import gevent
from gevent import socket
from conpot.core.filesystem import FilesystemError, FSOperationNotPermitted
from conpot.core import attack_session
from conpot.protocols.ftp.ftp_utils import FTPPrivilegeException, get_data_from_iter

logger = logging.getLogger(__name__)

# -----------------------------------------------------
# *Implementation Note*: Regarding Permissions:
# -----------------------------------------------------
# To change a directory as current directory we need permissions : rwx (CWD)| Also it has to be a directory. |
# To read a file we need : r permissions - It has to be a file | list files (LIST, NLST, STAT, SIZE, MDTM
# RETR commands)
# To store a file to the server we need 'w' permissions - (STOR, STOU commands)
# To rename file or directory we need 'w' permissions (RNFR, RNTO)
# To delete file or directory we need 'w' permissions (DELE, RMD commands)
# To append data to an existing file (APPE command) we need 'w' permissions
# -----------------------------------------------------


class FTPCommandChannel(FTPHandlerBase):
    """
    FTP Command Responder. Implementation of RFC 959.
    """

    # -----------------------------------------------------------------------
    # There are some commands that do not require any kind of auth and permissions to run.
    # These also do not require us to have an established data channel. So let us get rid of those first.
    # Btw: These are - USER, PASS, HELP, NOOP, SYST, QUIT, SITE HELP, PWD, TYPE
    # All commands assume that the path supplied have been cleaned and sanitized.

    # The USER command is used to verify users as they try to login.
    def do_USER(self, arg):
        """
        USER FTP command. If the user is already logged in, return 530 else 331 for the PASS command
        :param arg: username specified by the client/attacker
        """
        # first we need to check if the user is authenticated?
        if self.authenticated:
            self.respond(b"530 Cannot switch to another user.")
        else:
            self.username = arg
            self.respond(b"331 Now specify the Password.")

    def do_PASS(self, arg):
        if self.authenticated:
            self.respond(b"503 User already authenticated.")
        if not self.username:
            self.respond(b"503 Login with USER first.")
        if self.authentication_ok(user_pass=arg):
            if not self.config.motd:
                self.respond(b"230 Log in Successful.")
            else:
                _msg = "220-{}\r\n".format(self.config.motd)
                self.respond(_msg)
                self.respond(b"220 ")
        else:
            self.invalid_login_attempt += 1
            self.respond(b"530 Authentication Failed.")

    def do_HELP(self, arg):
        """Return help text to the client."""
        if arg:
            line = arg.upper()
            if line in self.config.COMMANDS:
                self.respond(b"214 %a" % self.config.COMMANDS[line]["help"])
            else:
                self.respond(b"501 Unrecognized command.")
        else:
            # provide a compact list of recognized commands
            def formatted_help():
                cmds = []
                keys = sorted(
                    [
                        x
                        for x in self.config.COMMANDS.keys()
                        if not x.startswith("SITE ")
                    ]
                )
                while keys:
                    elems = tuple((keys[0:8]))
                    cmds.append(b" %-6a" * len(elems) % elems + b"\r\n")
                    del keys[0:8]
                return b"".join(cmds)

            _buffer = b"214-The following commands are recognized:\r\n"
            _buffer += formatted_help()
            self.respond(_buffer + b"214 Help command successful.")

    def do_NOOP(self, arg):
        """Do nothing. No params required. No auth required and no permissions required."""
        self.respond(b"200 I successfully done nothin'.")

    def do_SYST(self, arg):
        """Return system type (always returns UNIX type: L8)."""
        # This command is used to find out the type of operating system
        # at the server.  The reply shall have as its first word one of
        # the system names listed in RFC-943.
        # Since that we always return a "/bin/ls -lA"-like output on
        # LIST we  prefer to respond as if we would on Unix in any case.
        self.respond(b"215 UNIX Type: L8")

    def do_QUIT(self, arg):
        self.respond(b"221 Bye.")
        self.session.add_event({"type": attack_session.CONNECTION_TERMINATED})
        self.disconnect_client = True

    def do_SITE_HELP(self, line):
        """Return help text to the client for a given SITE command."""
        if line:
            line = line.upper()
            if line in self.config.COMMANDS:
                self.respond(b"214 %a" % self.config.COMMANDS[line]["help"])
            else:
                self.respond(b"501 Unrecognized SITE command.")
        else:
            _buffer = b"214-The following SITE commands are recognized:\r\n"
            site_cmds = []
            for cmd in sorted(self.config.COMMANDS.keys()):
                if cmd.startswith("SITE "):
                    site_cmds.append(b" %a\r\n" % cmd[5:])
            _buffer_cmds = b"".join(site_cmds)
            self.respond(_buffer + _buffer_cmds + b"214 Help SITE command successful.")

    def do_MODE(self, line):
        """Set data transfer mode ("S" is the only one supported (noop))."""
        mode = line.upper()
        if mode == "S":
            self.respond(b"200 Transfer mode set to: S")
        elif mode in ("B", "C"):
            self.respond(b"504 Unimplemented MODE type.")
        else:
            self.respond(b"501 Unrecognized MODE type.")

    def do_PWD(self, arg):
        """Return the name of the current working directory to the client."""
        pwd = self.working_dir
        try:
            assert isinstance(pwd, str), pwd
            _pwd = '257 "{}" is the current directory.'.format(pwd)
            self.respond(_pwd.encode())
        except AssertionError:
            logger.info("FTP CWD specified is not unicode. {}".format(pwd))
            self.respond(b"FTP CWD not unicode.")

    def do_TYPE(self, line):
        """Set current type data type to binary/ascii"""
        data_type = line.upper().replace(" ", "")
        if data_type in ("A", "L7"):
            self.respond(b"200 Type set to: ASCII.")
            self._current_type = "a"
        elif data_type in ("I", "L8"):
            self.respond(b"200 Type set to: Binary.")
            self._current_type = "i"
        else:
            self.respond(b'504 Unsupported type "%a".' % line)

    def do_STRU(self, line):
        """Set file structure ("F" is the only one supported (noop))."""
        stru = line.upper()
        if stru == "F":
            self.respond(b"200 File transfer structure set to: F.")
        elif stru in ("P", "R"):
            self.respond(b"504 Unimplemented STRU type.")
        else:
            self.respond(b"501 Unrecognized STRU type.")

    def do_ALLO(self, arg):
        """Allocate bytes for storage (noop)."""
        # not necessary (always respond with 202)
        self.respond(b"202 No storage allocation necessary.")

    def do_REIN(self, arg):
        """Reinitialize user's current session."""
        self.stop_data_channel()
        self.username = None
        self._uid = None
        self.authenticated = False
        self.respond(b"230 Ready for new user.")

    # -----------------------------------------------------------------------
    # Next up we have commands that may require some kind of auth and permissions to run.
    # These also do not require us to have an established data channel.
    # These commands are -
    #  - {MDTM, SIZE, STAT, DELE, RNFR, RNTO} - require read permissions
    #  - {MKD, RMD} - require write permissions + path should be files
    #  - {CDUP, CWD and CHMOD} - require 'rwx' permissions + path should be folders
    # Again all commands assume that the path supplied have been cleaned and sanitized.

    def do_MDTM(self, path):
        """Return last modification time of file to the client as an ISO
        3307 style timestamp (YYYYMMDDHHMMSS) as defined in RFC-3659.
        On success return the file path, else None.
        """
        try:
            path = self.ftp_path(path)
            if not self.config.vfs.isfile(path):
                _msg = "550 {} is not retrievable".format(path)
                self.respond(_msg.encode())
                return
            with self.config.vfs.check_access(path=path, user=self._uid, perms="r"):
                m_time = "213 {}".format(
                    self.config.vfs.getmtime(path).strftime("%Y%m%d%H%M%S")
                )
                self.respond(m_time.encode())
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (ValueError, fs.errors.FSError, FilesystemError, FTPPrivilegeException):
            # It could happen if file's last modification time
            # happens to be too old (prior to year 1900)
            self.respond(b"550 Can't determine file's last modification time.")

    def do_SIZE(self, path):
        """Return size of file in a format suitable for using with RESTart as defined in RFC-3659."""
        try:
            path = self.ftp_path(path)
            if self._current_type == "a":
                self.respond(b"550 SIZE not allowed in ASCII mode.")
                return
            # If the file is a sym-link i.e. not readable, send not retrievable
            if not self.config.vfs.isfile(path):
                self.respond(b"550 is not retrievable.")
                return
            else:
                with self.config.vfs.check_access(path=path, user=self._uid, perms="r"):
                    size = self.config.vfs.getsize(path)
                    self.respond(b"213 %a" % size)
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (OSError, fs.errors.FSError) as err:
            self.respond(b"550 %a." % self._log_err(err))

    def do_STAT(self, path):
        """If invoked without parameters, returns general status information about the FTP server process.
        If a parameter is given, acts like the LIST command, except that data is sent over the command
        channel (no PORT or PASV command is required).
        """
        # return STATus information about ftp data connection
        if not path:
            s = list()
            s.append("Connected to: {}:{}".format(self.host, self.port))
            if self.authenticated:
                s.append("Logged in as: {}".format(self.username))
            else:
                if not self.username:
                    s.append("Waiting for username.")
                else:
                    s.append("Waiting for password.")
            if self._current_type == "a":
                _type = "ASCII"
            else:
                _type = "Binary"
            s.append("TYPE: {}; STRUcture: File; MODE: Stream".format(_type))
            if self._data_sock is not None and self._data_channel is False:
                s.append("Passive data channel waiting for connection.")
            elif self._data_channel is True:
                bytes_sent = (
                    self.metrics.data_channel_bytes_send
                    + self.metrics.command_chanel_bytes_send
                )
                bytes_recv = (
                    self.metrics.command_chanel_bytes_recv
                    + self.metrics.data_channel_bytes_recv
                )
                elapsed_time = self.metrics.get_elapsed_time()
                s.append("Data connection open:")
                s.append("Total bytes sent: {}".format(bytes_sent))
                s.append("Total bytes received: {}".format(bytes_recv))
                s.append("Transfer elapsed time: {} secs".format(elapsed_time))
            else:
                s.append("Data connection closed.")

            self.respond("211-FTP server status:\r\n")
            self.respond("".join([" {}\r\n".format(item) for item in s]))
            self.respond("211 End of status.")
        # return directory LISTing over the command channel
        else:
            try:
                line = self.ftp_path(path)
                with self.config.vfs.check_access(path=line, user=self._uid, perms="r"):
                    if self.config.vfs.isdir(path):
                        listing = self.config.vfs.listdir(path)
                        # RFC 959 recommends the listing to be sorted.
                        listing.sort()
                        iterator = self.config.vfs.format_list(path, listing)
                    else:
                        basedir, filename = os.path.split(path)
                        self.config.stat(path)
                        iterator = self.config.vfs.format_list(basedir, [filename])
                    _status = '213-Status of "{}":\r\n'.format(line)
                    _status += get_data_from_iter(iterator)
                    _status += "213 End of status."
                    self.respond(_status.encode())
            except FSOperationNotPermitted:
                self.respond(b"500 Operation not permitted.")
            except (
                OSError,
                FilesystemError,
                AssertionError,
                fs.errors.FSError,
                FTPPrivilegeException,
            ):
                self.respond(b"550 STAT command failed.")

    def do_MKD(self, path):
        """
        Create the specified directory. On success return the directory path, else None.
        """
        try:
            # In order to create a directory the current user must have 'w' permissions for the parent directory
            # of current path.
            _dir = self.ftp_path(path)
            with self.config.vfs.check_access(
                path=self.working_dir, user=self._uid, perms="w"
            ):
                self.config.vfs.makedir(_dir)
            _mkd = '257 "{}" directory created.'.format(_dir)
            self.respond(_mkd)
            self.config.vfs.chmod(_dir, self.config.dir_default_perms)
            self.config.vfs.chown(
                _dir, uid=self._uid, gid=self.config.get_gid(self._uid)
            )
            self.config.vfs.settimes(_dir, datetime.now(), datetime.now())
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (FilesystemError, fs.errors.FSError, FTPPrivilegeException):
            self.respond(b"550 Create directory operation failed.")

    def do_RMD(self, path):
        """Remove the specified directory. On success return the directory path, else None."""
        if self.ftp_path(path) == self.working_dir or path == "/":
            self.respond(b"550 Can't remove root directory.")
            return
        try:
            _path = self.ftp_path(self.working_dir + path)
            # In order to create a directory the current user must have 'w' permissions for the current directory
            with self.config.vfs.check_access(
                path=self.ftp_path(os.path.join(path, "../")), user=self._uid, perms="w"
            ):
                self.config.vfs.removedir(_path)
            self.respond(b"250 Directory removed.")
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (fs.errors.FSError, FilesystemError, FTPPrivilegeException):
            self.respond(b"550 Remove directory operation failed.")

    def do_CWD(self, path):
        """Change the current working directory."""
        # Temporarily join the specified directory to see if we have permissions to do so, then get back to original
        # process's current working directory.
        try:
            init_cwd = self.working_dir
            if not self.config.vfs.isdir(path):
                raise FSOperationNotPermitted
            # make sure the current user has permissions to the new dir. To change the directory, user needs to have
            # executable permissions for the directory
            with self.config.vfs.check_access(path=path, user=self._uid, perms="rwx"):
                self.working_dir = self.ftp_path(path)
            logger.info(
                "Changing current directory {} to {}".format(init_cwd, self.working_dir)
            )
            _cwd = '250 "{}" is the current directory.'.format(self.working_dir)
            self.respond(_cwd.encode())
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (fs.errors.FSError, FilesystemError, FTPPrivilegeException):
            self.respond(b"550 Failed to change directory.")

    def do_CDUP(self, arg):
        """
        Change into the parent directory. On success return the new directory, else None.
        """
        # Note: RFC-959 says that code 200 is required but it also says
        # that CDUP uses the same codes as CWD.
        return self.do_CWD(path="/".join([self.ftp_path(self.working_dir), "../"]))

    def do_DELE(self, path):
        """Delete the specified file."""
        try:
            path = self.ftp_path(path)
            if not self.config.vfs.isfile(path):
                self.respond(b"550 Failed to delete file.")
            else:
                with self.config.vfs.check_access(path=path, user=self._uid, perms="w"):
                    self.config.vfs.remove(path)
                    self.respond(b"250 File removed.")
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (fs.errors.FSError, FilesystemError, FTPPrivilegeException):
            self.respond(b"550 Failed to delete file.")

    def do_RNFR(self, path):
        """Rename the specified (only the source name is specified
        here, see RNTO command)"""
        try:
            path = self.ftp_path(path)
            if self.config.vfs.isfile(path) or self.config.vfs.isdir(path):
                with self.config.vfs.check_access(path=path, user=self._uid, perms="w"):
                    assert isinstance(path, str)
                    if path == "/":
                        self.respond(b"550 Can't rename home directory.")
                    else:
                        self._rnfr = path
                        self.respond(b"350 Ready for destination name.")
            else:
                # file neither a file or a directory.
                raise AssertionError
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (
            AssertionError,
            KeyError,
            fs.errors.FSError,
            FilesystemError,
            FTPPrivilegeException,
        ):
            self.respond(b"550 No such file or directory.")

    def do_RNTO(self, dst_path):
        """Rename file (destination name only, source is specified with RNFR)."""
        try:
            assert isinstance(dst_path, str)
            if not self._rnfr:
                self.respond(b"503 Bad sequence of commands: use RNFR first.")
                return
            src = self.ftp_path(self._rnfr)
            self._rnfr = None
            if self.config.vfs.isdir(src):
                _move = self.config.vfs.movedir
            elif self.config.vfs.isfile(src):
                _move = self.config.vfs.move
            else:
                raise FilesystemError
            with self.config.vfs.check_access(path=src, user=self._uid, perms="w"):
                _path, _file = os.path.split(src)
                _, _dst_file = os.path.split(dst_path)
                # create new paths
                _file = os.path.join(_path, _file)
                _dst_file = os.path.join(_path, _dst_file)
                if _file != _dst_file:
                    logger.info("Renaming file from {} to {}".format(_file, _dst_file))
                    _move(_file, _dst_file, overwrite=True)
                self.respond(b"250 Renaming ok.")
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (ValueError, fs.errors.FSError, FilesystemError, FTPPrivilegeException):
            self.respond(b"550 File rename operation failed.")

    def do_SITE_CHMOD(self, path, mode):
        """Change file mode. On success return a (file_path, mode) tuple."""
        try:
            # Note: although most UNIX servers implement it, SITE CHMOD is not
            # defined in any official RFC.
            path = self.ftp_path(path)
            with self.config.vfs.check_access(path=path, user=self._uid, perms="rwx"):
                assert len(mode) in (3, 4)
                for x in mode:
                    assert 0 <= int(x) <= 7
                mode = int(mode, 8)
                # To do a chmod user needs to be the owner of the file.
                self.config.vfs.chmod(path, mode)
                self.respond(b"200 SITE CHMOD successful.")
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (AssertionError, ValueError):
            self.respond(b"501 Invalid SITE CHMOD format.")
        except (fs.errors.FSError, FilesystemError, FTPPrivilegeException):
            self.respond(b"550 SITE CHMOD command failed.")

    # -----------------------------------------------------------------------
    # Following up we have the PORT(active) and PASV(passive) commnads.
    # These setup the data channel for data transfer.

    def do_PASV(self, arg):
        """
        Starts a Passive Data Channel using IPv4. We don't actually need to start the full duplex connection here.
        Just need to figure the host ip and the port. The DTP connection would start in each command.
        """
        if self._data_channel:
            self.stop_data_channel(purge=True, reason="Switching from PASV mode.")
        self.active_passive_mode = "PASV"
        # We are in passive mode. Here we would create a simple socket listener.
        self._data_listener_sock = gevent.socket.socket()
        self._data_listener_sock.bind((self._local_ip, 0))
        ip, port = self._data_listener_sock.getsockname()
        self.respond(
            "227 Entering Passive Mode (%s,%u,%u)."
            % (",".join(ip.split(".")), port >> 8 & 0xFF, port & 0xFF)
        )
        try:
            self._data_listener_sock.listen(1)
            self._data_listener_sock.settimeout(
                5
            )  # Timeout for ftp client to send info
            logger.info(
                "Client {} entering FTP passive mode".format(self.client_address)
            )
            (
                self._data_sock,
                (self.cli_ip, self.cli_port),
            ) = self._data_listener_sock.accept()
            logger.info(
                "Client {} provided ({}:{}) for PASV connection.".format(
                    self.client_address, self.cli_ip, self.cli_port
                )
            )
            logger.info(
                "FTP: starting data channel for client {}".format(self.client_address)
            )
            self._data_listener_sock.close()
        except (socket.error, socket.timeout) as se:
            logger.info(
                "Can't switch to PASV mode.  Error occurred: {}".format(str(se))
            )
            self.respond(b"550 PASV command failed.")

    def do_PORT(self, arg):
        """
        Starts an active data channel by using IPv4. We don't actually need to start the full duplex connection here.
        Just need to figure the host ip and the port. The DTP connection would start in each command.
        """
        if self._data_channel:
            self.stop_data_channel(purge=True, reason="Switching from PORT mode.")
        self.active_passive_mode = "PORT"
        try:
            addr = list(map(int, arg.split(",")))
            if len(addr) != 6:
                raise ValueError
            for x in addr[:4]:
                if not 0 <= x <= 255:
                    raise ValueError
            ip = "%d.%d.%d.%d" % tuple(addr[:4])
            port = (addr[4] * 256) + addr[5]
            if not 0 <= port <= 65535:
                raise ValueError
            self.cli_ip, self.cli_port = ip, port
            self._data_sock = gevent.socket.socket()
            self._data_sock.connect((self.cli_ip, self.cli_port))
            logger.info("Client {} entered FTP active mode".format(self.client_address))
            logger.info(
                "Client {} provided {}:{} for PORT connection.".format(
                    self.client_address, self.cli_ip, self.cli_port
                )
            )
            self.respond(b"200 PORT Command Successful. Consider using PASV.")
            logger.info(
                "FTP: configured data channel for client {}".format(self.client_address)
            )
        except (ValueError, OverflowError):
            self.respond("501 Invalid PORT format.")
        except socket.error as se:
            if self._data_channel:
                self.stop_data_channel(
                    reason="Can't switch to Active(PORT) mode. Error occurred: {}".format(
                        str(se)
                    )
                )

    # -- Data Channel related commands --

    def do_LIST(self, path):
        try:
            _path = self.ftp_path(path)
            with self.config.vfs.check_access(path=_path, user=self._uid, perms="r"):
                listing = self.config.vfs.listdir(_path)
                if isinstance(listing, list):
                    # RFC 959 recommends the listing to be sorted.
                    listing.sort()
                    iterator = self.config.vfs.format_list(_path, listing)
                    self.respond("150 Here comes the directory listing.")
                    _list_data = get_data_from_iter(iterator)
                    # Push data to the data channel
                    self.push_data(_list_data.encode())
                    # start the command channel
                    self.start_data_channel()
                    self.respond(b"226 Directory send OK.")
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (
            OSError,
            fs.errors.FSError,
            FilesystemError,
            FTPPrivilegeException,
        ) as err:
            self._log_err(err)
            self.respond(b"550 LIST command failed.")

    def do_NLST(self, path):
        """Return a list of files in the specified directory in a compact form to the client."""
        try:
            _path = self.ftp_path(path)
            with self.config.vfs.check_access(path=_path, user=self._uid, perms="r"):
                listing = self.config.vfs.listdir(_path)
                data = ""
                if listing:
                    listing.sort()
                    data = "\r\n".join(listing) + "\r\n"
                self.respond(b"150 Here comes the directory listing.")
                # Push data to the data channel
                self.push_data(data=data)
                # start the command channel
                self.start_data_channel()
                self.respond(b"226 Directory send OK.")
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (
            OSError,
            fs.errors.FSError,
            FilesystemError,
            FTPPrivilegeException,
        ) as err:
            self._log_err(err)
            self.respond(b"550 NLST command failed.")

    def do_RETR(self, arg):
        """
        Fetch and send a file.
        :param arg: Filename that is to be retrieved
        """
        try:
            filename = self.ftp_path(arg)
            with self.config.vfs.check_access(path=filename, user=self._uid, perms="r"):
                if self.config.vfs.isfile(filename):
                    self.send_file(file_name=filename)
                else:
                    raise FilesystemError("cmd: RETR. Path requested {} is not a file.")
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except (
            OSError,
            fs.errors.FSError,
            FilesystemError,
            FTPPrivilegeException,
        ) as err:
            self._log_err(err)
            self.respond(b"550 The system cannot find the file specified.")

    def do_ABOR(self, arg):
        """Aborts a file transfer currently in progress."""
        if self.active_passive_mode is None:
            self.respond(b"225 No transfer to abort.")
        else:
            # a PASV or PORT was received but connection wasn't made yet
            if not self._data_channel:
                self.stop_data_channel(abort=True, purge=True, reason="ABOR called.")
                self.respond(b"225 ABOR command successful; data channel closed.")
            else:
                self.stop_data_channel(abort=True, purge=True, reason="ABOR called.")
                self.respond(b"426 Transfer aborted via ABOR.")
                self.respond(b"226 ABOR command successful.")

    def do_STOR(self, file, mode="w"):
        """Store a file (transfer from the client to the server)."""
        # A resume could occur in case of APPE or REST commands.
        # In that case we have to open file object in different ways:
        # STOR: mode = 'w'
        # APPE: mode = 'a'
        # REST: mode = 'r+' (to permit seeking on file object)
        if "a" in mode:
            cmd = "APPE"
        else:
            cmd = "STOR"
        try:
            with self.config.vfs.check_access(
                path=self.working_dir, user=self._uid, perms="w"
            ):
                rest_pos = self._restart_position
                self._restart_position = 0
                if rest_pos:
                    if rest_pos > self.config.vfs.getsize(file):
                        raise ValueError("Can't seek file more than its size.")
                    # rest_pos != 0 and not None. Must be REST cmd
                    cmd = "REST"
                else:
                    rest_pos = 0
                if cmd == "APPE":
                    _file_seek = self.config.vfs.getsize(file)
                elif cmd == "REST":
                    _file_seek = rest_pos
                else:
                    assert cmd == "STOR"
                    _file_seek = 0
                self.recv_file(
                    os.path.join(self.working_dir, file), _file_seek, cmd=cmd
                )
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")
        except ValueError as err:
            self._log_err(err)
            self.respond(
                b"550 STOR command failed. Can't seek file more than its size."
            )
        except (
            OSError,
            AssertionError,
            fs.errors.FSError,
            FilesystemError,
            FTPPrivilegeException,
        ) as err:
            self._log_err(err)
            self.respond(b"550 STOR command failed. .")

    def do_REST(self, line):
        """Restart a file transfer from a previous mark."""
        if self._current_type == "a":
            self.respond(b"501 Resuming transfers not allowed in ASCII mode.")
            return
        try:
            marker = int(line)
            if marker < 0:
                raise ValueError
            else:
                self.respond("350 Restarting at position {}.".format(marker))
                self._restart_position = marker
        except (ValueError, OverflowError):
            self.respond(b"501 Invalid parameter.")

    def do_APPE(self, file):
        """Append data to an existing file on the server.
        On success return the file path, else None.
        """
        # watch for APPE preceded by REST, which makes no sense.
        if self._restart_position:
            self.respond(b"450 Can't APPE while REST request is pending.")
        else:
            return self.do_STOR(file, mode="a")

    def do_STOU(self, line):
        """Store a file on the server with a unique name."""
        try:
            if self._restart_position:
                self.respond(b"450 Can't STOU while REST request is pending.")
                return
            _, _file_name = os.path.split(tempfile.NamedTemporaryFile().name)
            if line:
                line = self.ftp_path(line)
                basedir, _ = os.path.split(line)
                _file_name = "." + _file_name
            else:
                basedir = self.working_dir
                if self.config.stou_suffix:
                    _file_name = _file_name + self.config.stou_suffix
                if self.config.stou_prefix:
                    _file_name = self.config.stou_prefix + _file_name
            with self.config.vfs.check_access(path=basedir, user=self._uid, perms="w"):
                self.respond(b"150 FILE: %a" % _file_name)
                self.recv_file(os.path.join(basedir, _file_name), 0, cmd="STOR")
        except FSOperationNotPermitted:
            self.respond(b"500 Operation not permitted.")

    # -----------------------------------------------------------------
    # Depreciated/alias commands
    # RFC-1123 requires that the server treat XCUP, XCWD, XMKD, XPWD and XRMD commands as synonyms for CDUP, CWD, MKD,
    # LIST and RMD. Such commands are obsoleted but some ftp clients (e.g. Windows ftp.exe) still use them.

    # Change to the parent directory. Synonym for CDUP. Deprecated.
    do_XCUP = do_CDUP
    # Change the current working directory. Synonym for CWD. Deprecated.
    do_XCWD = do_CWD
    # Create the specified directory. Synonym for MKD. Deprecated.
    do_XMKD = do_MKD
    # Return the current working directory. Synonym for PWD. Deprecated.
    do_XPWD = do_PWD
    # Remove the specified directory. Synonym for RMD. Deprecated.
    do_XRMD = do_RMD
    # Quit and end the current ftp session. Synonym for QUIT
    do_BYE = do_QUIT

    # -----------------------------------------------------------------
    # Helper methods and Command Processors.
    def _log_err(self, err):
        """
        Log errors and send an unexpected response standard message to the client.
        :param err: Exception object
        :return: 500 msg to be sent to the client.
        """
        logger.info(
            "FTP error occurred. Client: {} error {}".format(
                self.client_address, str(err)
            )
        )

    # clean things, sanity checks and more
    def _pre_process_cmd(self, line, cmd, arg):
        kwargs = {}
        if cmd == "SITE" and arg:
            cmd = "SITE %s" % arg.split(" ")[0].upper()
            arg = line[len(cmd) + 1 :]

        logger.info(
            "Received command {} : {} from FTP client {}: {}".format(
                cmd, line, self.client_address, self.session.id
            )
        )
        if cmd not in self.config.COMMANDS:
            if cmd[-4:] in ("ABOR", "STAT", "QUIT"):
                cmd = cmd[-4:]
            else:
                self.respond(b"500 Command %a not understood" % cmd)
                return

        # - checking for valid arguments
        if not arg and self.config.COMMANDS[cmd]["arg"] is True:
            self.respond(b"501 Syntax error: command needs an argument")
            return
        if arg and self.config.COMMANDS[cmd]["arg"] is False:
            self.respond(b"501 Syntax error: command does not accept arguments.")
            return

        if not self.authenticated:
            if self.config.COMMANDS[cmd]["auth"] or (cmd == "STAT" and arg):
                self.respond(b"530 Log in with USER and PASS first.")
                return
            else:
                # call the proper do_* method
                self._process_command(cmd, arg)
                return
        else:
            if (cmd == "STAT") and not arg:
                self.do_STAT(path=None)
                return

            # for file-system related commands check whether real path
            # destination is valid
            if self.config.COMMANDS[cmd]["perm"] and (cmd != "STOU"):
                if cmd in ("CWD", "XCWD"):
                    if arg and self.working_dir != "/":
                        arg = os.path.join(self.working_dir, arg)
                    else:
                        arg = arg or "/"
                elif cmd in ("CDUP", "XCUP"):
                    arg = ""
                elif cmd == "STAT":
                    if glob.has_magic(arg):
                        self.respond(b"550 Globbing not supported.")
                        return
                    arg = self.ftp_path(arg or self.working_dir)
                elif cmd == "SITE CHMOD":
                    if " " not in arg:
                        self.respond(b"501 Syntax error: command needs two arguments.")
                        return
                    else:
                        mode, arg = arg.split(" ", 1)
                        arg = self.ftp_path(arg)
                        kwargs = dict(mode=mode)
                else:
                    if cmd == "LIST":
                        if arg.lower() in ("-a", "-l", "-al", "-la"):
                            arg = self.working_dir
                        else:
                            arg = arg or self.working_dir
                    if glob.has_magic(arg):
                        self.respond(b"550 Globbing not supported.")
                        return
                    else:
                        arg = glob.escape(arg)
                        arg = arg or self.working_dir
                        arg = line.split(" ", 1)[1] if arg is None else arg

            # call the proper do_* method
            self._process_command(cmd, arg, **kwargs)

    def _process_command(self, cmd, *args, **kwargs):
        """Process command by calling the corresponding do_* class method (e.g. for received command "MKD pathname",
        do_MKD() method is called with "pathname" as the argument).
        """
        if self.invalid_login_attempt >= self.max_login_attempts:
            self.respond(b"421 Too many connections. Service temporarily unavailable.")
            self.disconnect_client = True
            self.session.add_event({"type": attack_session.CONNECTION_TERMINATED})
        else:
            try:
                method = getattr(self, "do_" + cmd.replace(" ", "_"))
                self._last_command = cmd
                method(*args, **kwargs)
            except (fs.errors.FSError, FilesystemError):
                raise

    # - main command processor
    def process_ftp_command(self):
        """
        Handle an incoming handle request - pick and item from the input_q, reads the contents of the message and
        dispatch contents to the appropriate do_* method.
        :param: (bytes) line - incoming request
        :return: (bytes) response - reply in respect to the request
        """
        try:
            if not self._command_channel_input_q.empty() and (
                self.metrics.timeout() < self.config.timeout
            ):
                # decoding should be done using utf-8
                line = self._command_channel_input_q.get().decode()
                # Remove any CR+LF if present
                line = line[:-2] if line[-2:] == "\r\n" else line
                if line:
                    cmd = line.split(" ")[0].upper()
                    arg = line[len(cmd) + 1 :]
                    try:
                        self._pre_process_cmd(line, cmd, arg)
                    except UnicodeEncodeError:
                        self.respond(
                            b"501 can't decode path (server filesystem encoding is %a)"
                            % sys.getfilesystemencoding()
                        )
                    except (fs.errors.PermissionDenied, FSOperationNotPermitted):
                        # TODO: log user as well.
                        logger.info(
                            "Client {} requested path: {} trying to access directory to which it has "
                            "no access to.".format(self.client_address, line)
                        )
                        self.respond(b"500 Permission denied")
                    except fs.errors.IllegalBackReference:
                        # Trying to access the directory which the current user has no access to
                        self.respond(
                            b"550 %a points to a path which is outside the user's root directory."
                            % line
                        )
                    except FTPPrivilegeException:
                        self.respond(b"550 Not enough privileges.")
                    except (fs.errors.FSError, FilesystemError) as fe:
                        logger.info(
                            "FTP client {} Unexpected error occurred : {}".format(
                                self.client_address, fe
                            )
                        )
                        # TODO: what to respond here? For now just terminate the session
                        self.disconnect_client = True
                        self.session.add_event(
                            {"type": attack_session.CONNECTION_TERMINATED}
                        )
            elif not (self.metrics.timeout() < self.config.timeout) and (
                not self._data_channel
            ):
                logger.info(
                    "FTP connection timeout, remote: {}. ({}). Disconnecting client".format(
                        self.client_address, self.session.id
                    )
                )
                self.session.add_event({"type": attack_session.CONNECTION_TIMEOUT})
                self.respond(b"421 Timeout.")
                self.disconnect_client = True
            else:
                gevent.sleep(0)

        except UnicodeDecodeError:
            # RFC-2640 doesn't mention what to do in this case. So we'll just return 501
            self.respond(b"501 can't decode command.")
