from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import time
import csv
from operator import attrgetter
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER,  set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types


class MyFirewall(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(MyFirewall, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor) # <--- Spawns a background thread
        # Create the CSV file to store thesis results
        self.csv_file = open('results_sdn.csv', 'w')
        self.writer = csv.writer(self.csv_file)
        self.writer.writerow(['Event', 'MAC', 'Detection Timestamp', 'Response Timestamp', 
                              'Response Time since Detection'])
        print("[*] IDS/IPS Module Loaded. Logging to results_sdn.csv")

        self.arp_table = {'10.0.0.1': '00:00:00:00:00:01', '10.0.0.2': '00:00:00:00:00:02', '10.0.0.3': '00:00:00:00:00:03'}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Look for EtherType 0x0806 (ARP)
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)

        # Send to Controller
        # OFPCML_NO_BUFFER tells the switch to send the *entire* packet, not just the header.
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        # INSTALL THE FLOW
        # Priority must be > 0 (e.g., 1) so it overrides the default "table-miss" flow.
        self.add_flow(datapath, 1, match, actions)
        match_default = parser.OFPMatch()
        actions_default = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                  ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match_default, actions_default)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            arp_spoofing_attack_detection = self.detect_spoofing(arp_pkt)
            if arp_spoofing_attack_detection:
                src_mac = arp_pkt.src_mac
                self.mitigate_attack(datapath, src_mac)
                response_time = time.time()
                self.writer.writerow(['DETECTION & RESPONSE (ARP SPOOFING ATTACK)', src_mac, arp_spoofing_attack_detection, response_time, response_time - arp_spoofing_attack_detection])
                self.csv_file.flush()

                potential_attacker_key = (datapath.id, src_mac)

                self.blocked_hosts[potential_attacker_key] = time.time()
                return  # do not send packet out
        # if not arp packet proceed with the usual flow
        super(MyFirewall, self)._packet_in_handler(ev)

    def detect_spoofing(self, arp_pkt):
        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        # Logic: Check if IP is known
        if src_ip in self.arp_table:
            # Check if the MAC matches the known MAC
            if self.arp_table[src_ip] != src_mac:
                self.logger.warning(
                    "\n[ALERT] ARP SPOOFING DETECTED!\n"
                    "IP: %s is known at MAC: %s\n"
                    "But packet received from MAC: %s\n",
                    src_ip, self.arp_table[src_ip], src_mac
                )
                return time.time()  # detection time
            else:
                # Normal traffic
                return False

    # Keep track of switches
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    # 2. The Monitor (Runs every 1 second)
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)  # Wait 1 second

    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    # Analyze the Reply (The Real IDS Logic)
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        # Initialize the 'previous stats' memory if it doesn't exist yet
        # Structure: self.prev_stats = { (dpid, src_mac, dst_mac): packet_count }
        if not hasattr(self, 'prev_stats'):
            self.prev_stats = {}
            self.blocked_hosts = {}

        for stat in body:
            # print("stat->", stat)
            # 1. Skip Drop Rules (Priority 100) and Default Rules (Priority 0)
            if stat.priority != 1:
                continue

            # 2. Extract MACs
            eth_src = stat.match.get('eth_src')
            eth_dst = stat.match.get('eth_dst')

            if not eth_src or not eth_dst:
                continue # Skip rules that don't have specific MACs

            # 3. Calculate PPS (Delta)
            flow_id = (dpid, eth_src, eth_dst)

            current_count = stat.packet_count
            prev_count = self.prev_stats.get(flow_id, 0)

            # PPS calculation
            pps = current_count - prev_count

            # Update memory
            self.prev_stats[flow_id] = current_count

            potential_attacker_key = (dpid, eth_src)
            is_blocked = potential_attacker_key in self.blocked_hosts

            # Detection Logic
            # If a single MAC is sending >500 packets/sec to a target
            if pps > 500:
                detection_time = time.time()
                print(f"\n[ALERT] High Speed DoS detected!")
                print(f"    Attacker MAC: {eth_src}")
                print(f"    Victim MAC:   {eth_dst}")
                print(f"    Speed:        {pps} packets/sec")

                if not is_blocked:
                    self.mitigate_attack(ev.msg.datapath, eth_src)
                    response_time = time.time()
                    # Log data to CSV for the thesis
                    self.writer.writerow(['DETECTION & RESPONSE (DOS ATTACK)', eth_src, detection_time, response_time, response_time - detection_time])
                    self.csv_file.flush()
                    self.blocked_hosts[potential_attacker_key] = time.time()

            elif is_blocked:
                # We only check unblocking logic if they are actually in the blocked list
                block_time = self.blocked_hosts[potential_attacker_key]

                if time.time() - block_time > 10:
                    print(f"\nTime expired for {eth_src}. Unblocking...")
                    self.remove_flow(ev.msg.datapath, eth_src)

                    # Remove them from the blocked list, so they can be monitored normally again
                    del self.blocked_hosts[potential_attacker_key]

    def remove_flow(self, datapath, attacker_mac):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(eth_src=attacker_mac)
        # Command: OFPFC_DELETE (Strict means "Match exactly this priority and match fields")
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            priority=100,  # matches the priority of the Drop Rule
            match=match
        )
        datapath.send_msg(mod)
        print("Unblocked MAC " + attacker_mac + "\n")

    def mitigate_attack(self, datapath, attacker_mac):
        # Block this MAC from sending ANYTHING
        parser = datapath.ofproto_parser

        # Match ANY traffic coming from this MAC
        match = parser.OFPMatch(eth_src=attacker_mac)

        # Priority 100, Empty Actions = DROP
        self.add_flow(datapath, 100, match, [])
        print(f"MITIGATION: Blocked MAC {attacker_mac}")
