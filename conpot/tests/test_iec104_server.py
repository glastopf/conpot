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
from gevent import monkey

monkey.patch_all()
import socket
import time
import unittest
from unittest.mock import patch
import conpot.core as conpot_core
from conpot.protocols.IEC104 import IEC104_server, frames
from conpot.utils.greenlet import spawn_test_server, teardown_test_server


class TestIEC104Server(unittest.TestCase):
    def setUp(self):
        self.databus = conpot_core.get_databus()

        self.iec104_inst, self.greenlet = spawn_test_server(
            IEC104_server.IEC104Server, "IEC104", "IEC104", port=2404
        )

        self.coa = self.iec104_inst.device_data_controller.common_address

    def tearDown(self):
        teardown_test_server(self.iec104_inst, self.greenlet)

    def test_startdt(self):
        """
        Objective: Test if answered correctly to STARTDT act
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))
        s.send(frames.STARTDT_act.build())
        data = s.recv(6)
        self.assertSequenceEqual(data, frames.STARTDT_con.build())

    def test_testfr(self):
        """
        Objective: Test if answered correctly to TESTFR act
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))
        s.send(frames.TESTFR_act.build())
        data = s.recv(6)
        self.assertEqual(data, frames.TESTFR_con.build())

    def test_write_for_non_existing(self):
        """
        Objective: Test answer for a command to a device that doesn't exist
        (Correct behaviour of the IEC104 protocol is not known exactly. Other case is test for no answer)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_45(IOA=0xEEEEEE, SCS=1)
        )
        s.send(single_command.build())
        data = s.recv(16)

        bad_addr = (
            frames.i_frame(RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=47)
            / frames.asdu_infobj_45(IOA=0xEEEEEE, SCS=1)
        )
        self.assertSequenceEqual(data, bad_addr.build())

    def test_write_relation_for_existing(self):
        """
        Objective: Test answer for a correct command to a device that does exist and has a related sensor
        (Actuator 22_20 (Type 45: Single Command) will be tested,
        the corresponding(!) sensor 13_20 (Type 1: Single Point Information) changes the value
        and the termination confirmation is returned)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        self.databus.set_value("22_20", 0)  # Must be in template and relation to 13_20
        self.databus.set_value("13_20", 0)  # Must be in template

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_45(IOA=0x141600, SCS=1)
        )
        s.send(single_command.build())

        data = s.recv(16)
        act_conf = (
            frames.i_frame(RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=7)
            / frames.asdu_infobj_45(IOA=0x141600, SCS=1)
        )
        self.assertSequenceEqual(data, act_conf.build())

        data = s.recv(16)
        info = (
            frames.i_frame(SendSeq=0x0002, RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=11)
            / frames.asdu_infobj_1(IOA=0x140D00)
        )
        info.SIQ = frames.SIQ(SPI=1)
        self.assertSequenceEqual(data, info.build())

        data = s.recv(16)
        act_term = (
            frames.i_frame(SendSeq=0x0004, RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=10)
            / frames.asdu_infobj_45(IOA=0x141600, SCS=1)
        )
        self.assertSequenceEqual(data, act_term.build())

    def test_write_no_relation_for_existing(self):
        """
        Objective: Test answer for a correct command to a device that does exist and has no related sensor
        (Actuator 22_19 (Type 45: Single Command) will be tested, the corresponding(!) sensor is not existent)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        self.databus.set_value("22_19", 0)  # Must be in template and no relation

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_45(IOA=0x131600, SCS=0)
        )
        s.send(single_command.build())

        data = s.recv(16)
        act_conf = (
            frames.i_frame(RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=7)
            / frames.asdu_infobj_45(IOA=0x131600, SCS=0)
        )
        self.assertSequenceEqual(data, act_conf.build())

        data = s.recv(16)
        act_term = (
            frames.i_frame(SendSeq=0x0002, RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, COT=10)
            / frames.asdu_infobj_45(IOA=0x131600, SCS=0)
        )
        self.assertSequenceEqual(data, act_term.build())

    def test_write_wrong_type_for_existing(self):
        """
        Objective: Test answer for a command of wrong type to a device that does exist
        (Actuator 22_20 (Type 45: Single Command) will be tested,
        but a wrong command type (Double Commands instead of Single Command) is sent to device)
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))

        s.send(frames.STARTDT_act.build())
        s.recv(6)

        self.databus.set_value("22_20", 0)  # Must be in template

        single_command = (
            frames.i_frame()
            / frames.asdu_head(COA=self.coa, COT=6)
            / frames.asdu_infobj_46(IOA=0x141600, DCS=1)
        )
        s.send(single_command.build())

        data = s.recv(16)
        act_conf = (
            frames.i_frame(RecvSeq=0x0002)
            / frames.asdu_head(COA=self.coa, PN=1, COT=7)
            / frames.asdu_infobj_46(IOA=0x141600, DCS=1)
        )
        self.assertSequenceEqual(data, act_conf.build())

    @patch("conpot.protocols.IEC104.IEC104_server.gevent._socket3.socket.recv")
    def test_failing_connection_connection_lost_event(self, mock_timeout):
        """
        Objective: Test if correct exception is executed when a socket.error
        with EPIPE occurs
        """
        mock_timeout.side_effect = OSError(32, "Socket Error")
        conpot_core.get_sessionManager().purge_sessions()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 2404))
        time.sleep(0.1)
        log_queue = conpot_core.get_sessionManager().log_queue
        con_new_event = log_queue.get()
        con_lost_event = log_queue.get(timeout=1)

        self.assertEqual("NEW_CONNECTION", con_new_event["data"]["type"])
        self.assertEqual("CONNECTION_LOST", con_lost_event["data"]["type"])

        s.close()

    @patch("conpot.protocols.IEC104.IEC104_server.gevent._socket3.socket.recv")
    def test_connection_times_out_if_traffic_starts_with_wrong_prefix(
        self, mock_timeout
    ):
        """
        Objective: Test if server ignores traffic starting with wrong prefix
        """
        mock_timeout.side_effect = TimeoutError()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect(("127.0.0.1", 2404))
        packet = frames.u_frame(Start=0x67).build()
        s.send(packet)
        with self.assertRaises(TimeoutError):
            s.recv(6)
