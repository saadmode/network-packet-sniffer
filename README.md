# Network Packet Sniffer Using Python

## Overview

I worked on this project as part of my cybersecurity internship to gain practical exposure to network packet capture and traffic analysis using Python and Scapy.

The purpose of this project is to capture network packets, display basic packet information, identify common protocols, and save captured traffic for further analysis.

## Project Setup

* Python 3
* Scapy
* Npcap (Windows) or libpcap (Linux)
* Kali Linux
* Administrator/root privileges for packet capture

## Features

The packet sniffer provides the following features:

* List available network interfaces
* Capture network packets from a selected interface
* Filter traffic by TCP, UDP, ICMP, ARP, or DNS-related traffic
* Display source and destination addresses
* Show packet timestamps, lengths, ports, and TCP flags where applicable
* Display packet capture statistics
* Save captured packets to a PCAP file for further analysis

## Activity Performed

During this project, I worked with a Python-based packet sniffer to:

* Select a network interface for packet capture
* Capture network traffic
* Examine source and destination addresses
* Identify common network protocols
* Filter packets using capture filters
* Save captured packets for later inspection

## How to Run

### 1. Install the Requirements

```bash
python -m pip install -r requirements.txt
```

Install Npcap on Windows or the appropriate libpcap support on Linux if required.

### 2. List Available Interfaces

```bash
python packet_sniffer.py --list
```

### 3. Capture TCP Traffic

```bash
python packet_sniffer.py --proto tcp --count 50
```

### 4. Capture Traffic on Port 443

```bash
python packet_sniffer.py --filter "port 443" --write capture.pcap
```

Run packet capture with the required privileges. On Linux, this may require `sudo`.

## What I Learned

This project helped me explore how network packets can be captured and examined using Python and Scapy.

I also gained exposure to network protocols, source and destination addresses, packet filtering, and saving packet captures for further analysis.

## Skills Practiced

* Python
* Scapy
* Network Traffic Analysis
* TCP/IP Fundamentals
* Packet Capture
* Basic Network Security

## Limitations

This project displays and records captured packets. It does not independently identify malicious activity or function as a complete intrusion detection system.

The packets visible to the program depend on the selected network interface, operating system, permissions, and capture configuration.

## Disclaimer

This tool should only be used to monitor networks and devices that you own or have explicit permission to inspect.

## Project Evidence

Screenshots and a demonstration video can be added to document the program running and capturing packets successfully.
