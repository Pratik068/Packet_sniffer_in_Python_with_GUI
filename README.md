Network Packet Sniffer with GUI
A Wireshark-style network packet analyzer built with Python and Tkinter, featuring a modern dark theme interface and comprehensive packet analysis capabilities.
📋 Project Overview
This packet sniffer captures and analyzes network traffic in real-time, providing detailed insights into network packets with an intuitive graphical interface.
Collaborators: Pratik Prasai, Rupak Raj Pandey, Sparsha Poudel
Academic Project: Semester 3
✨ Features

Real-time Packet Capture - Live network traffic monitoring
Protocol Analysis - Support for TCP, UDP, ICMP, ARP, IPv6, DNS, HTTP, HTTPS
Dark Theme UI - Modern Wireshark-inspired interface
Zoom Functionality - Adjustable zoom (50%-200%) for better visibility
Detailed Packet View - Layer-by-layer packet inspection
Color-coded Protocols - Visual distinction between different protocols
Packet Filtering - Easy identification of specific traffic types
Added a feature for capturing login credentials from unsecured HTTP websites.

🛠️ Technologies Used

Python 3.x
Scapy - Packet manipulation and analysis
Tkinter - GUI framework
Threading - Concurrent packet capture

📦 Installation
Prerequisites
bash# Install required packages
pip install scapy
Linux Setup
bash# Clone the repository
git clone https://github.com/Pratik068/Packet_sniffer_in_Python_with_GUI.git
cd Packet_sniffer_in_Python_with_GUI

# Run with root privileges (required for packet capture)
sudo python3 packet_sniffer_gui.py
🚀 Usage

Start the application with root/administrator privileges
Click "▶ Start Capture" to begin monitoring network traffic
Select packets from the list to view detailed information
Use zoom controls (Ctrl+Plus, Ctrl+Minus, Ctrl+0) for better readability
Click "⏹ Stop Capture" to pause monitoring
Use "🗑 Clear" to reset the packet list

Keyboard Shortcuts

Ctrl + Plus / Ctrl + = - Zoom In
Ctrl + Minus - Zoom Out
Ctrl + 0 - Reset Zoom

📊 Supported Protocols
ProtocolColor CodeDescriptionTCPBlueTransmission Control ProtocolUDPPurpleUser Datagram ProtocolICMPPinkInternet Control Message ProtocolARPYellowAddress Resolution ProtocolDNSCoralDomain Name SystemHTTPOrangeHypertext Transfer ProtocolHTTPSPurpleSecure HTTPIPv6GreenInternet Protocol Version 6
⚠️ Requirements

Operating System: Linux (root access required)
Python Version: 3.6 or higher
Network Interface: Active network adapter
Privileges: Root/Administrator access for packet capture

📝 Notes

This tool requires root privileges to capture network packets
Raw socket access is necessary for packet sniffing
Use responsibly and only on networks you own or have permission to monitor

🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page.
📄 License
This project is created for educational purposes as part of a Semester 3 academic project.
👥 Team

Pratik Prasai - @Pratik068
Rupak Raj Pandey - @yami05-05
Sparsha Poudel - @SparshaPoudel


Note: This packet sniffer is designed for educational and network diagnostic purposes. Always ensure you have proper authorization before monitoring network traffic.
