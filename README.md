# Comparative Analysis of Security in SDN vs. Traditional Networks

This repository contains the source code and experimental data for my Bachelor's Thesis. The project evaluates the security performance of **Software-Defined Networking (SDN)** compared to traditional network architectures, with a specific focus on detection and mitigation efficiency.

> ⚠️ **All experiments are designed to run inside a Mininet environment.** The scripts create virtual hosts and switches with Mininet and control them with the Ryu controller, so they will not work on a regular desktop OS (Windows/macOS) or on a Linux machine without Mininet. The easiest way to reproduce them is the official **Mininet VM** (see [Setting up the Mininet environment](#%EF%B8%8F-setting-up-the-mininet-environment)).

## 📌 Project Overview

The study focuses on two specific network attack vectors:
1.  **Denial of Service (DoS):** High-rate UDP flooding.
2.  **ARP Spoofing:** Man-in-the-Middle (MitM) attacks.

The experiments utilize **Mininet** for network emulation and the **Ryu Controller** for implementing SDN logic (IDS/IPS).

## 📂 Repository Structure

The repository is organized by attack type to allow for isolated testing:

```text
├── DoS-Attack/
│   ├── SDN/                   # Ryu application for DoS detection (my_firewall_dos.py)
│   └── Traditional/           # Baseline: plain learning switch (ryu.app.simple_switch_13)
│
├── ARP-Spoofing/
│   ├── SDN/                   # Ryu application for ARP spoofing detection (my_firewall_arp_spoofing.py)
│   └── Traditional/           # Baseline: plain learning switch (ryu.app.simple_switch_13)
```

Each folder is self-contained: it has its own topology (`thesis_topo.py`) and its own shell script that runs the whole experiment.

## 🖥️ Setting up the Mininet environment

### 1. Get Mininet
The recommended option is the **official Mininet VM**, which comes with Mininet, Open vSwitch and most networking tools preinstalled:

1. Download the VM image from [mininet.org/download](https://mininet.org/download/).
2. Import it into VirtualBox or VMware and boot it (default login: `mininet` / `mininet`).
3. Make sure the VM has internet access (needed to install the remaining tools below).

Alternatively, you can install Mininet natively on Ubuntu by following the instructions on the same page.

### 2. Make sure you have a graphical session
The scripts open the Ryu controller in a separate `xterm` window and display the bandwidth graph with Matplotlib, so they need a display:
* either use a desktop environment inside the VM, **or**
* connect to the VM with X11 forwarding: `ssh -X mininet@<vm-ip>`

### 3. Install the remaining tools
Inside the Mininet VM:

```bash
sudo apt update
sudo apt install -y hping3 dsniff iperf xterm tcpdump python3-pip
```

* `hping3`: generates the UDP flood (DoS attack)
* `dsniff`: provides `arpspoof` (ARP Spoofing attack)
* `iperf`: generates the legitimate TCP traffic and measures throughput
* `tcpdump`: captures the OpenFlow traffic into `.pcap` files for Wireshark

### 4. Install the Python dependencies
Mininet itself is already provided by the VM; install Ryu and Matplotlib:

```bash
pip3 install -r requirements.txt
```

> 💡 If the Ryu installation fails with an `eventlet` error, install a compatible version first: `pip3 install eventlet==0.30.2` and then run the command above again.

### 5. Get the code
```bash
git clone https://github.com/LimpeJohn04/SDN-Thesis-Source-Code.git
cd SDN-Thesis-Source-Code
```

## 🚀 Running the Experiments

Every experiment is run **from inside its own folder, within the Mininet environment, with root privileges** (Mininet needs `sudo` to create the virtual network).

| Experiment | Folder | Script |
|---|---|---|
| DoS on SDN (with IDS/IPS) | `DoS-Attack/SDN/` | `sdn_shell_script.sh` |
| DoS on traditional network | `DoS-Attack/Traditional/` | `traditional_shell_script.sh` |
| ARP Spoofing on SDN (with IDS/IPS) | `ARP-Spoofing/SDN/` | `sdn_shell_script.sh` |
| ARP Spoofing on traditional network | `ARP-Spoofing/Traditional/` | `traditional_shell_script.sh` |

Example (DoS attack on the SDN network):

```bash
cd DoS-Attack/SDN
chmod +x sdn_shell_script.sh     # only needed the first time
sudo ./sdn_shell_script.sh
```

For the traditional baseline, use the corresponding script in the `Traditional/` folder:

```bash
cd DoS-Attack/Traditional
chmod +x traditional_shell_script.sh
sudo ./traditional_shell_script.sh
```

> ⚠️ Run only **one** experiment at a time. Each script starts its own Ryu controller and Mininet topology, and cleans up the previous run (`sudo mn -c`) before starting.

### 📋 Automated Workflow
Upon execution, each shell script automatically performs the following sequence of operations:

1.  **Environment Sanitization:** Executes `sudo mn -c` to clear stale Mininet states and removes previous log artifacts (e.g., old `.pcap` or `.csv` files) to guarantee a pristine testing environment.

2.  **Controller Initialization:** Launches the required Ryu application in a separate `xterm` window. The SDN experiments load the IDS/IPS module; the traditional experiments load the plain learning switch (`simple_switch_13`). Keep an eye on this window: detection alerts and unblocking messages are printed there.

3.  **Traffic Acquisition:** Initiates `tcpdump` in the background to capture network traffic for subsequent analysis in Wireshark.

4.  **Simulation Orchestration:** Executes `thesis_topo.py` with Mininet to build the star topology (1 Open vSwitch, 3 hosts, 10 Mbps links), generate benign user traffic (`pingall`, `iperf`), and automatically trigger the specific attack.

5.  **Teardown & Analysis:** Gracefully terminates all background processes upon completion and displays the results (bandwidth graph and/or detection/mitigation table).

### 📁 Output files
After a run, the following files are created in the experiment's folder (depending on the experiment):

| File | Content |
|---|---|
| `results_sdn.csv` | Detection and response timestamps of the IDS/IPS (SDN only) |
| `openflow_capture.pcap` / `trad_capture.pcap` | Captured traffic, can be opened with Wireshark |
| `iperf_server_log.txt` / `traditional_server.txt` | Per-second throughput of the legitimate user (DoS only) |
| `bandwidth_graph.png` | Throughput graph during the attack (DoS only) |
