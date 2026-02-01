# Comparative Analysis of Security in SDN vs. Traditional Networks

This repository contains the source code and experimental data for my Master's Thesis. The project evaluates the security performance of **Software-Defined Networking (SDN)** compared to traditional network architectures, with a specific focus on detection and mitigation efficiency.

## 📌 Project Overview

The study focuses on two specific network attack vectors:
1.  **Denial of Service (DoS):** High-rate UDP flooding.
2.  **ARP Spoofing:** Man-in-the-Middle (MitM) attacks.

The experiments utilize **Mininet** for network emulation and the **Ryu Controller** for implementing SDN logic (IDS/IPS).

## 📂 Repository Structure

The repository is organized by attack type to allow for isolated testing:

```text
├── DoS-Attack/
│   ├── SDN/                   # Ryu application for DoS detection
│   └── Traditional/           # Scripts for traditional network baseline
│
├── ARP-Spoofing/
│   ├── SDN/                   # Ryu application for ARP spoofing detection
│   └── Traditional/           # Scripts for traditional network baseline
│
├── thesis_topo.py             # Mininet topology script (Automated scenarios)
├── plot_results.py            # Generates bandwidth graphs (Matplotlib)
├── show_table.py              # CLI tool to view CSV results formatted
└── requirements.txt           # Python dependencies
```

## ⚙️ Prerequisites

To replicate these experiments, you need a Linux environment (Ubuntu recommended) with the following installed:

* **Python 3.x**
* **Mininet** (Network Emulator)
* **Ryu** (SDN Controller)
* **Network Tools:** `hping3`, `dsniff` (for arpspoof), `iperf`

### Python Dependencies
Install the required Python libraries using:
```bash
pip install -r requirements.txt
```

## 🚀 Experimental Execution

To ensure reproducibility and streamline the testing process, the repository includes multiple automated shell scripts. This script orchestrates the experimental workflow of each folder, including environment cleanup, controller initialization, traffic capturing, and topology deployment.

### 1. Setup and Permissions
First, clone the repository into your Mininet-supported Linux environment. Before running the experiment for the first time, you must grant execution permissions to the respective script found in each folder:

```bash
chmod +x sdn_shell_script.sh
```

### 2. Running the Automated Experiment
Execute the shell script with root privileges to start the full simulation lifecycle:

```bash
sudo ./sdn_shell_script.sh
```

### 📋 Automated Workflow
Upon execution, the shell script automatically performs the following sequence of operations:

1.  **Environment Sanitization:** Executes `sudo mn -c` to clear stale Mininet states and removes previous log artifacts (e.g., old `.pcap` or `.csv` files) to guarantee a pristine testing environment.
2.  
3.  **Controller Initialization:** Launches the required Ryu SDN application (IDS/IPS module) in a dedicated process to monitor network events.
4.  
5.  **Traffic Acquisition:** Initiates `tcpdump` in the background to capture network traffic for subsequent forensic analysis.
6.  
7.  **Simulation Orchestration:** Executes `thesis_topo.py` to build the network topology, generate benign user traffic, and automatically trigger the specific attack vectors.
8.  
9.  **Teardown & Analysis:** Gracefully terminates all background processes upon completion and immediately aggregates and displays the detection/mitigation results table.
