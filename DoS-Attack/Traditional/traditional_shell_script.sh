#!/bin/bash

# Clean up previous mininet runs to avoid errors
echo "Cleaning up Mininet..."
sudo mn -c > /dev/null 2>&1
sleep 2


echo "Removing old experiment files..."
sudo rm -rf traditional_client.txt \
            traditional_server.txt \
            __pycache__ \
            bandwidth_graph.png
sleep 2


echo "Cleanup done."
sleep 1


echo "Opening ryu-manager..."
xterm -e "ryu-manager ryu.app.simple_switch_13" &
sleep 10


echo "Setting topology and running pingall multiple times to simulate normal netwrok traffic..."
sudo python3 thesis_topo.py
echo "Done!"


echo "Killing Ryu..."
echo -ne '\n'
sleep 3
sudo pkill -f ryu-manager
sleep 1


echo "Creating and opening bandwidth graph..."
python3 plot_results.py


sleep 2
echo "Done!"
