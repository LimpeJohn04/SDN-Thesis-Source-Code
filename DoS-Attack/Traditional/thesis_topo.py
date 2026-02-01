from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
import time

class ThesisTopo(Topo):
    def build(self):
        # switches and hosts
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='10.0.0.1', mac='00:00:00:00:00:01') # Attacker
        h2 = self.addHost('h2', ip='10.0.0.2', mac='00:00:00:00:00:02') # Normal User
        h3 = self.addHost('h3', ip='10.0.0.3', mac='00:00:00:00:00:03') # Victim

        # connections up to 10Mbps
        self.addLink(h1, s1, cls=TCLink, bw=10)
        self.addLink(h2, s1, cls=TCLink, bw=10)
        self.addLink(h3, s1, cls=TCLink, bw=10)

def run():
    topo = ThesisTopo()
    net = Mininet(topo=topo, controller=RemoteController, link=TCLink)
    net.start()
    print("topology is ready,  Mininet CL runs...")
    time.sleep(5)
    print("Creating traffic via ICMP (and eventually flows)...")
    time.sleep(5)
    for i in range(3):
        print(f"Check {i+1}/3:")
        net.pingAll()
        time.sleep(1)
    print("\n----------Dumping flows for s1 [NORMAL TRAFFIC FLOWS]----------")
    time.sleep(3)
    s1 = net.get('s1')
    flows = s1.dpctl('dump-flows')
    print(flows)
    time.sleep(3)

    h1 = net.get('h1') 
    h2 = net.get('h2')
    h3 = net.get('h3')

    print("Running iperf....\n")
    h3.cmd('iperf -s -i 1 > traditional_server.txt &')
    time.sleep(2)

    h2.cmd(f'iperf -c {h3.IP()} -t 60 > traditional_client.txt &') 
 
    time.sleep(15)
 
    # 3. Launch Attack
    print(f"--- Starting UDP Flood (No Mitigation Expected) ---")
    print("--- h1 hping3 --flood --udp h3---")
    h1.cmd(f'hping3 --flood --udp {h3.IP()} &')
    
    # We let the attack run longer to prove it NEVER recovers
    attack_duration = 10
    print(f"Flooding for {attack_duration} seconds...")
    time.sleep(attack_duration)
    
    print("--- Stopping Flood ---")
    h1.cmd('killall -SIGINT hping3')
    time.sleep(2)

    print("\n----------Dumping flows for s1 [NO FLOWS CHANGED]----------")
    time.sleep(2)
    s1 = net.get('s1')
    flows = s1.dpctl('dump-flows')
    print(flows)
    
    # Cleanup
    h3.cmd('killall -SIGINT iperf')
    h2.cmd('killall -SIGINT iperf')
    time.sleep(3)
    net.stop()

if __name__ == '__main__':
    run()
