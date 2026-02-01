#!/bin/bash

# Clean up previous mininet runs to avoid errors
echo "Cleaning up Mininet..."
sudo mn -c > /dev/null 2>&1
sleep 2


echo "Removing old experiment files..."
sudo rm -rf __pycache__ \
           trad_capture.pcap
sleep 2


echo "Cleanup done."
sleep 1


echo "Opening ryu-manager..."
xterm -e "ryu-manager ryu.app.simple_switch_13" &
sleep 10


echo "Starting capturing traffic and setting topology..."
sleep 5
sudo tcpdump -U -i any -w trad_capture.pcap &
sudo python3 thesis_topo.py
echo "Done!"


echo "Stopping Capture..."
sudo pkill -2 -f "tcpdump -U -i any"
sleep 2


echo "Done. File saved as trad_capture.pcap"
sleep 2


echo "Killing Ryu..."
echo -ne '\n'
sleep 3
sudo pkill -f ryu-manager
sleep 1


echo "Done!"
