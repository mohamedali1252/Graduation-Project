# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import pcaplib
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub

counter = 0
flag = False
dst = "00:00:00:00:00:02"

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.pcap_writer = pcaplib.Writer(open('/home/kali/mypcap.pcap', 'wb'))
        self.datapaths = {}
        self.ips = []
        self.attack_mac = ""
        self.monitor_thread = hub.spawn(self.monitor)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    def monitor(self):
        global dst
        while True:
                hub.sleep(5)
                for datapath in self.datapaths.values():
                        ofp = datapath.ofproto
                        ofp_parser = datapath.ofproto_parser
                        cookie = cookie_mask = 0
                        match = ofp_parser.OFPMatch(eth_dst=dst)
                        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY,ofp.OFPG_ANY,cookie, cookie_mask,match)
                        datapath.send_msg(req)
                self.take_action()
    
    def unique(self,list1):
    	unique_list = []
    	for x in list1:
    		if x not in unique_list:
    			unique_list.append(x)
    	return unique_list
    def take_action(self):
    	f = open("/home/kali/Desktop/ML/test.csv")
    	lst = f.readlines()
    	f.close()
    	for i in lst:
    		rule = i.strip()
    		rule = rule.split(',')
    		src_ip = rule[0]
    		dst_ip = rule[1]
    		if rule[2] =="attack":
    			print(src_ip)
    			for datapath in self.datapaths.values():
    			        ofproto = datapath.ofproto
    			        parser = datapath.ofproto_parser
    			        
    			        for st in self.ips:
    			        	st_temp = st.split('#')
    			        	mac_temp = st_temp[0]
    			        	ip_temp = st_temp[1]
    			        	if ip_temp == src_ip:
    			        		self.attack_mac = mac_temp
    			        if self.attack_mac == "":
    			        	return
    			        match = parser.OFPMatch(eth_src=self.attack_mac)
    			        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
    			        msg = parser.OFPFlowMod(datapath,0,priority = 1,command = ofproto.OFPFC_MODIFY,match = match,instructions = instruction)
    			        datapath.send_msg(msg)
    			        print("Host with mac address:",self.attack_mac," ,and ip:",src_ip," ,was blocked for attacking host with ip:",dst_ip)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        global flag,dst
        for stat in ev.msg.body:
                dur = stat.duration_sec
                if dur != 0:
                        ratio = stat.packet_count/dur
                        print(ratio)
                        if ratio > 80 and (not flag):
                                flag = True 
                                msg = ev.msg
                                datapath = msg.datapath
                                ofproto = datapath.ofproto
                                parser = datapath.ofproto_parser
                                match = parser.OFPMatch(eth_dst=dst)
                                instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
                                msg = parser.OFPFlowMod(datapath,0,priority = 1,command = ofproto.OFPFC_MODIFY,match = match,instructions = instruction)
                                datapath.send_msg(msg)
                                self.logger.info("Time limit Exceed DOS attack")

    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global counter
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        self.pcap_writer.write_pkt(ev.msg.data)
        

        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src
        if eth.ethertype == ether_types.ETH_TYPE_IP:
	        ip = pkt.get_protocol(ipv4.ipv4)
	        srcip = ip.src
	        dstip = ip.dst
	        self.ips.append(dst+"#"+dstip)
	        self.ips.append(src+"#"+srcip)
	        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src=srcip,ipv4_dst=dstip)
        dpid = format(datapath.id, "d").zfill(16)
        self.ips = self.unique(self.ips)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        #actions = [parser.OFPActionOutput(out_port),parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                actions = [parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                if counter < 2:
                        counter = counter + 1          
                        actions = [parser.OFPActionOutput(out_port),parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,ofproto.OFPCML_NO_BUFFER)]
                        self.add_flow(datapath, 1, match, actions)
                else:
                        return       
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        actions = [parser.OFPActionOutput(out_port)]	
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
     