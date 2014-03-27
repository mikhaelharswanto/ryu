# Copyright (C) 2012 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# vim: tabstop=4 shiftwidth=4 softtabstop=4

import time
import logging

from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.tests.integrated import tester

LOG = logging.getLogger(__name__)


class RunTest(tester.TestFlowBase):
    """ Test case for Request-Reply messages.

        Some tests need attached port to switch.
        If use the OVS, can do it with the following commands.
            # ip link add <port> type dummy
            # ovs-vsctl add-port <bridge> <port>
    """

    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RunTest, self).__init__(*args, **kwargs)

        self._verify = None
        self.n_tables = ofproto_v1_4.OFPTT_MAX

    def start_next_test(self, dp):
        self._verify = None
        self.delete_all_flows(dp)
        dp.send_barrier()
        if len(self.pending):
            t = self.pending.pop()
            if self.is_supported(t):
                LOG.info(tester.LOG_TEST_START, t)
                self.current = t
                getattr(self, t)(dp)
            else:
                self.results[t] = 'SKIP (unsupported)'
                self.unclear -= 1
                self.start_next_test(dp)
        else:
            self.print_results()

    def run_verify(self, ev):
        msg = ev.msg
        dp = msg.datapath

        verify_func = self.verify_default
        v = "verify" + self.current[4:]
        if v in dir(self):
            verify_func = getattr(self, v)

        result = verify_func(dp, msg)
        if result is True:
            self.unclear -= 1

        self.results[self.current] = result
        self.start_next_test(dp)

    def verify_default(self, dp, msg):
        type_ = self._verify

        if msg.msg_type == dp.ofproto.OFPT_STATS_REPLY:
            return self.verify_stats(dp, msg.body, type_)
        elif msg.msg_type == type_:
            return True
        else:
            return 'Reply msg_type %s expected %s' \
                   % (msg.msg_type, type_)

    def verify_stats(self, dp, stats, type_):
        stats_types = dp.ofproto_parser.OFPStatsReply._STATS_TYPES
        expect = stats_types.get(type_).__name__

        if isinstance(stats, list):
            for s in stats:
                if expect == s.__class__.__name__:
                    return True
        else:
            if expect == stats.__class__.__name__:
                return True
        return 'Reply msg has not \'%s\' class.\n%s' % (expect, stats)

    def mod_flow(self, dp, cookie=0, cookie_mask=0, table_id=0,
                 command=None, idle_timeout=0, hard_timeout=0,
                 priority=0xff, buffer_id=0xffffffff, match=None,
                 actions=None, inst_type=None, out_port=None,
                 out_group=None, flags=0, inst=None):

        if command is None:
            command = dp.ofproto.OFPFC_ADD

        if inst is None:
            if inst_type is None:
                inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS

            inst = []
            if actions is not None:
                inst = [dp.ofproto_parser.OFPInstructionActions(
                        inst_type, actions)]

        if match is None:
            match = dp.ofproto_parser.OFPMatch()

        if out_port is None:
            out_port = dp.ofproto.OFPP_ANY

        if out_group is None:
            out_group = dp.ofproto.OFPG_ANY

        m = dp.ofproto_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                         table_id, command,
                                         idle_timeout, hard_timeout,
                                         priority, buffer_id,
                                         out_port, out_group,
                                         flags, match, inst)

        dp.send_msg(m)

    def get_port(self, dp):
        for port_no, port in dp.ports.items():
            if port_no != dp.ofproto.OFPP_LOCAL:
                return port
        return None

    # Test for Reply message type
    def test_flow_monitor_request(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        monitor_flags = [ofp.OFPFMF_INITIAL, ofp.OFPFMF_ONLY_OWN]
        match = ofp_parser.OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowMonitorRequest(datapath, 0, 10000,
                                                   ofp.OFPP_ANY, ofp.OFPG_ANY,     
                                                   monitor_flags,                  
                                                   ofp.OFPTT_ALL,                  
                                                   ofp.OFPFMC_ADD, match)          
        datapath.send_msg(req)

    # handler
    @set_ev_cls(ofp_event.EventOFPFlowMonitorReply, MAIN_DISPATCHER)
    def flow_monitor_reply_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        flow_updates = []

        for update in msg.body:
            update_str = 'length=%d event=%d' % (update.length, update.event)
            if (update.event == ofp.OFPFME_INITIAL or
                update.event == ofp.OFPFME_ADDED or
                update.event == ofp.OFPFME_REMOVED or
                update.event == ofp.OFPFME_MODIFIED):
                update_str += 'table_id=%d reason=%d idle_timeout=%d hard_timeout=%d priority=%d cookie=%d match=%d instructions=%s' % (stat.table_id, stat.reason, stat.idle_timeout, stat.hard_timeout, stat.priority, stat.cookie, stat.match, stat.instructions)
            elif update.event == ofp.OFPFME_ABBREV:
                update_str += 'xid=%d' % (stat.xid)
            flow_updates.append(update_str)
        self.logger.debug('FlowUpdates: %s', flow_updates)



    def error_handler(self, ev):
        if self.current.find('error') > 0:
            self.run_verify(ev)

    def is_supported(self, t):
        unsupported = [
        ]
        for u in unsupported:
            if t.find(u) != -1:
                return False

        return True
