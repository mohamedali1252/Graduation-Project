#!/usr/bin/env python

"""
Example to create a Mininet topology and connect it to the internet via NAT
"""

from mininet.topo import Topo

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import Intf
from mininet.topolib import TreeNet
from mininet.node import OVSSwitch, Controller, RemoteController

class RoutingTopo( Topo ):
    def build(self):
        # Add hosts and switches
        h1 = self.addHost( 'h1',mac="00:00:00:00:00:01",ip="10.0.0.1/24")
        h2 = self.addHost( 'h2',mac="00:00:00:00:00:02",ip="10.0.0.2/24")
        h3 = self.addHost( 'h3',mac="00:00:00:00:00:03",ip="10.0.0.3/24")
        s1 = self.addSwitch('s1',mac="00:00:00:00:00:05",ip="10.0.0.5/24")
        # Add links
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1)
        

if __name__ == '__main__':
    lg.setLogLevel( 'info')
    topo = RoutingTopo()
    c1 = RemoteController('c1',ip='127.0.0.1')
    net = Mininet(topo=topo,controller=c1)
    # Add NAT connectivity
    s1 = net.switches[0]
    net.addNAT().configDefault()
    net.start()
    info( "*** Hosts are running and should have internet connectivity\n" )
    info( "*** Type 'exit' or control-D to shut down network\n" )
    CLI( net )
    # Shut down NAT
    net.stop()
