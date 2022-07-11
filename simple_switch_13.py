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
from ryu.lib.packet import tcp ,arp
from ryu.lib.packet import udp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
import array
import os
import sys
import datetime
from time import strftime
import time
import csv


counter = 0
flag = False
dst = "00:00:00:00:00:02"
UI_path = "/home/kali/Downloads/Graduation_Project-UI/sample.csv"
ML_path = "/home/kali/Desktop/ML/test.csv"
blocked = []



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        global UI_path
        self.sample=[]
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.ips = []
        self.attack_mac = ""
        self.monitor_thread = hub.spawn(self.monitor)
        self.f = open(UI_path,'w') #the file to UI

        
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
        global dst,ML_path
        while True:
                hub.sleep(5)
                for datapath in self.datapaths.values():
                        ofp = datapath.ofproto
                        ofp_parser = datapath.ofproto_parser
                        cookie = cookie_mask = 0
                        match = ofp_parser.OFPMatch(eth_dst=dst)
                        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,ofp.OFPTT_ALL,ofp.OFPP_ANY,ofp.OFPG_ANY,cookie, cookie_mask,match)
                        datapath.send_msg(req)
                file_size=os.path.getsize(ML_path) 
                if file_size == 0:
                        #os.system("pip install tensorflow")
                        os.system('python /home/kali/Desktop/HoneyPot-Neural-network-classifier/readfrom_db.py')
                        os.system("python /home/kali/Desktop/HoneyPot-Neural-network-classifier/classifier.py")
                        print("da5al fel if /n ****************************")        
                        self.take_action()
                        
                        #with open("/home/kali/Desktop/ML/test.csv","w") as f:
                         #       pass    
                #os.system("python3 /home/kali/UI/main.py")
    
    def unique(self,list1):
        unique_list = []
        for x in list1:
            if x not in unique_list:
                unique_list.append(x)
        return unique_list
    def take_action(self):
        global ML_path,UI_path
        self.f = open(UI_path,'a') #the file to UI
        m = open(ML_path,'r')
        lst = m.readlines()
        m.close()
        for i in lst:
            rule = i.strip()
            rule = rule.split(',')
            src_ip = rule[0]
            dst_ip = rule[1]
            time = rule[3]
            date = rule[4]
            honeypot = rule[5]
            rows = [[time,date,src_ip,dst_ip,rule[2],honeypot]]
            sample = time+date+src_ip+dst_ip+rule[2]+honeypot
            if (sample not in self.sample):
               csvwriter = csv.writer(self.f)
               csvwriter.writerows(rows)   
               self.sample.append(sample)
            
            #f.write(time,",",date,",",src_ip,",",dst_ip,",",rule[2],",",honeypot)
            #scr_ip,dst_ip,attack_type,time,date,honeypot
            print ("before if condition")
            print(rule[2])
            if rule[2] !="normal":
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
                        print("**********************************")
        self.f.close()
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def stats_reply_handler(self, ev):
        global flag,dst,UI_path,blocked
        self.f = open(UI_path,'a') #the file to UI
        src_ip = ""
        dst_ip = ""
        for stat in ev.msg.body:
                dur = stat.duration_sec
                if dur != 0:
                        ratio = stat.packet_count/dur
                        print(ratio)
                        if ratio > 100 and (stat.match['eth_src'] not in blocked):
                                flag = True 
                                msg = ev.msg
                                datapath = msg.datapath
                                ofproto = datapath.ofproto
                                parser = datapath.ofproto_parser
                                match = parser.OFPMatch(eth_src=stat.match['eth_src'])
                                instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
                                msg = parser.OFPFlowMod(datapath,0,priority = 1,command = ofproto.OFPFC_MODIFY,match = match,instructions = instruction)
                                datapath.send_msg(msg)
                                for st in self.ips:
                                        st_temp = st.split('#')
                                        mac_temp = st_temp[0]
                                        ip_temp = st_temp[1]
                                        if mac_temp == stat.match['eth_src']:
                                                src_ip = ip_temp
                                        elif mac_temp == stat.match['eth_dst']:
                                                dst_ip = ip_temp
                                t = time.time()
                                h = time.localtime(t + 6 * 60 * 60)
                                time_string = time.strftime("%d/%b/%Y,%H:%M:%S", h)
                                time_after = time_string.split(",")
                                date = time_after[0]
                                ti = time_after[1]
                                rows = [[ date,ti,src_ip,dst_ip,'DOS' ,'Controller' ]]
                                csvwriter = csv.writer(self.f)
                                csvwriter.writerows(rows)
                                self.logger.info("Time limit Exceed DOS attack")
                                blocked.append(stat.match['eth_src'])
        self.f.close()
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
        

        pkt = packet.Packet(array.array('B', msg.data))
        #pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        if arp_pkt:
                pak = arp_pkt
        elif ip4_pkt:
                pak = ip4_pkt
        else:
                pak = eth_pkt
        self.logger.info('  _packet_in_handler: src_mac -> %s' % eth_pkt.src)
        self.logger.info('  _packet_in_handler: dst_mac -> %s' % eth_pkt.dst)
        self.logger.info('  _packet_in_handler: %s' % pak)
        self.logger.info('  ------')
        
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
        actions = [parser.OFPActionOutput(out_port)]
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
