#!/bin/bash

# Clean up previous mininet runs to avoid errors
echo "Cleaning up Mininet..."
sudo mn -c > /dev/null 2>&1
sleep 2

echo "Removing old experiment files..."
sudo rm -rf iperf_client_log.txt \
            iperf_server_log.txt \
            openflow_capture.pcap \
            results_sdn.csv \
            __pycache__ \
            bandwidth_graph.png
sleep 2


echo "Cleanup done."
sleep 1


echo "Opening ryu-manager..."
xterm -e "ryu-manager my_firewall_dos.py" &
sleep 10


echo "Starting capturing traffic and setting topology...."
sudo tcpdump -U -i lo -w openflow_capture.pcap port 6653 &
sudo python3 thesis_topo.py
echo "Done!"


echo "Stopping Capture..."
sudo pkill -2 -f "tcpdump -U -i lo"
sleep 2


echo "Done. File saved as openflow_capture.pcap"
sleep 2


echo "Killing Ryu..."
echo -ne '\n' 
sleep 3
sudo pkill -f ryu-manager
sleep 1


echo "Creating and opening bandwidth graph..."
python3 plot_results.py iperf_server_log.txt
sleep 2


echo "Mitigation results:"
python3 show_table.py results_sdn.csv


sleep 3
echo "Done! SDN for the Win!!"
sleep 2
