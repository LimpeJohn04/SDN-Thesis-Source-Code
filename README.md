# Comparative Analysis of Security in SDN vs. Traditional Networks

This repository contains the source code and experimental data for my Bachelor's Thesis. The project evaluates the security performance of **Software-Defined Networking (SDN)** compared to traditional network architectures, with a specific focus on detection and mitigation efficiency.

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
