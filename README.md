# Real-Time Network Monitoring with Automated PowerShell Mitigation for Low-Bandwidth Environments

An autonomous, host-level Quality of Service (QoS) enforcement platform built with Java and PowerShell.

## Key Features
* **Live Packet Inspection:** Java + Pcap4j/Npcap to detect high-priority traffic signatures (Zoom/Teams/VoIP).
* **3-Second Hysteresis Trigger:** Prevents rule flickering by waiting for 3 consecutive seconds of congestion.
* **Automated Mitigation:** Executes PowerShell scripts to update Windows Defender Firewall rules and stop BITS & Windows Update (`wuauserv`).
* **JavaFX Interface:** Real-time monitoring dashboard and logs.

## Tech Stack
* Java (JDK 17+) | JavaFX | Windows PowerShell | Pcap4j | Maven