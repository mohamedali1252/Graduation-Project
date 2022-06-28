from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import OVSSwitch, Controller, RemoteController
from mininet.util import pmonitor
from signal import SIGINT


class RoutingTopo( Topo ):
    def build(self):
        # Add hosts and switches
        h1 = self.addHost( 'h1',mac="00:00:00:00:00:01",ip="10.0.0.1/24")
        h2 = self.addHost( 'h2',mac="00:00:00:00:00:02",ip="10.0.0.2/24")
        h3 = self.addHost( 'h3',mac="00:00:00:00:00:03",ip="10.0.0.3/24")
        s1 = self.addSwitch('s1')
        # Add links
        self.addLink( h1, s1 )
        self.addLink( h2, s1 )
        self.addLink( h3, s1)

if __name__=="__main__":
    setLogLevel('info')
    topo = RoutingTopo()
    c1 = RemoteController('c1',ip='127.0.0.1')
    net = Mininet(topo=topo,controller=c1)
    net.start()
    print("Dumping host connections")
    
    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    CLI(net)
    net.stop()
    
#sudo python3 topo.py
#mn --custom topo.py --topo=mytopo
#sudo mn --controller=remote,ip=127.0.0.1 --switch=ovsk,protcols=OpenFlow13 --topo=single,5 --mac