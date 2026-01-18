#!/usr/bin/env python3
"""
Network Packet Sniffer GUI - Python Implementation for Linux
Advanced packet capture and analysis with HTTP credential detection
"""

import sys
import os
import threading
import re
from datetime import datetime
from collections import deque

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, IPv6, Raw
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext
except ImportError as e:
    print(f"Error: Required module not installed - {e}")
    print("Install with: pip install scapy")
    sys.exit(1)

# Global variables
packet_count = 0
packet_list = deque(maxlen=1000)
credentials_list = []
is_capturing = False
capture_thread = None

# Color scheme for different protocols - Dark theme
PROTOCOL_COLORS = {
    'TCP': '#1a3a4a',
    'UDP': '#2a2a3a',
    'ICMP': '#3a2a3a',
    'ARP': '#3a3a2a',
    'IPv6': '#2a3a2a',
    'DNS': '#3a2a2a',
    'HTTP': '#3a2a1a',
    'HTTPS': '#2a1a3a',
    'Other': '#2a2a2a'
}

PROTOCOL_TEXT_COLORS = {
    'TCP': '#5eb3e0',
    'UDP': '#9a9ad4',
    'ICMP': '#d49ad4',
    'ARP': '#d4d49a',
    'IPv6': '#9ad49a',
    'DNS': '#d4a09a',
    'HTTP': '#d4b09a',
    'HTTPS': '#b09ad4',
    'Other': '#aaaaaa'
}

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer - HTTP Credential Monitor")
        self.root.geometry("1400x900")
        self.root.minsize(1000, 700)
        
        self.root.configure(bg='#1e1e1e')
        
        self.zoom_level = 1.0
        self.base_font_size = 9
        self.base_treeview_font_size = 10
        self.base_heading_font_size = 9
        
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='#d4d4d4')
        style.configure('TButton', background='#2d2d30', foreground='#d4d4d4')
        style.map('TButton', background=[('active', '#3e3e42')])
        style.configure('Treeview', background='#252526', foreground='#d4d4d4', 
                       fieldbackground='#252526', borderwidth=0, rowheight=20)
        style.configure('Treeview.Heading', background='#2d2d30', foreground='#d4d4d4')
        style.map('Treeview.Heading', background=[('active', '#3e3e42')])
        
        # Warning style for credentials
        style.configure('Warning.TLabel', background='#4a1a1a', foreground='#ff6b6b',
                       font=('Arial', 10, 'bold'))
        
        self.style = style
        
        self.create_menu_bar()
        self.create_toolbar()
        self.create_main_layout()
        self.create_statusbar()
        
        self.root.bind('<Control-plus>', self.zoom_in)
        self.root.bind('<Control-equal>', self.zoom_in)
        self.root.bind('<Control-minus>', self.zoom_out)
        self.root.bind('<Control-0>', self.zoom_reset)
        
        global packet_count
        packet_count = 0

    def create_menu_bar(self):
        menubar = tk.Menu(self.root, bg='#2d2d30', fg='#d4d4d4', 
                         activebackground='#3e3e42', activeforeground='#ffffff')
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d30', fg='#d4d4d4',
                           activebackground='#3e3e42', activeforeground='#ffffff')
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Clear Packets", command=self.clear_packets)
        file_menu.add_command(label="Clear Credentials", command=self.clear_credentials)
        file_menu.add_separator()
        file_menu.add_command(label="Export Credentials", command=self.export_credentials)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        capture_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d30', fg='#d4d4d4',
                              activebackground='#3e3e42', activeforeground='#ffffff')
        menubar.add_cascade(label="Capture", menu=capture_menu)
        capture_menu.add_command(label="Start Capture", command=self.start_capture)
        capture_menu.add_command(label="Stop Capture", command=self.stop_capture)
        
        view_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d30', fg='#d4d4d4',
                           activebackground='#3e3e42', activeforeground='#ffffff')
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Zoom In (Ctrl+Plus)", command=self.zoom_in)
        view_menu.add_command(label="Zoom Out (Ctrl+Minus)", command=self.zoom_out)
        view_menu.add_command(label="Reset Zoom (Ctrl+0)", command=self.zoom_reset)
        
        help_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d30', fg='#d4d4d4',
                           activebackground='#3e3e42', activeforeground='#ffffff')
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def create_toolbar(self):
        toolbar_frame = ttk.Frame(self.root)
        toolbar_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        self.start_btn = ttk.Button(toolbar_frame, text="▶ Start Capture", 
                                    command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(toolbar_frame, text="⏹ Stop Capture", 
                                   command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, text="🗑 Clear Packets", 
                  command=self.clear_packets).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, text="🔍+", 
                  command=self.zoom_in).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="🔍-", 
                  command=self.zoom_out).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="🔍Reset", 
                  command=self.zoom_reset).pack(side=tk.LEFT, padx=2)
        
        self.status_label = ttk.Label(toolbar_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=20, fill=tk.X, expand=True)

    def create_main_layout(self):
        # Main container with 3 panes
        main_container = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top pane - Packet list
        self.create_packet_list_pane(main_container)
        
        # Middle pane - Credentials monitor
        self.create_credentials_pane(main_container)
        
        # Bottom pane - Packet details
        self.create_packet_details_pane(main_container)

    def create_packet_list_pane(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, weight=2)
        
        self.packet_list_header = ttk.Label(frame, text="Packet List", font=("Arial", 10, "bold"))
        self.packet_list_header.pack(anchor=tk.W, pady=5)
        
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(tree_frame, columns=columns, height=15, 
                                       show='headings')
        
        self.column_widths = {
            "No.": 50,
            "Time": 100,
            "Source": 120,
            "Destination": 120,
            "Protocol": 80,
            "Length": 70,
            "Info": 700
        }
        
        for col in columns:
            self.packet_tree.heading(col, text=col)
            self.packet_tree.column(col, width=self.column_widths[col])
        
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)

    def create_credentials_pane(self, parent):
        """Create credentials monitoring pane"""
        frame = ttk.Frame(parent)
        parent.add(frame, weight=1)
        
        # Warning header
        header_frame = ttk.Frame(frame)
        header_frame.pack(fill=tk.X, pady=5)
        
        warning_label = ttk.Label(header_frame, 
                                 text="⚠️ HTTP CREDENTIALS DETECTED (PLAIN TEXT)", 
                                 style='Warning.TLabel')
        warning_label.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(header_frame, text="Clear", 
                  command=self.clear_credentials).pack(side=tk.RIGHT, padx=5)
        ttk.Button(header_frame, text="Export", 
                  command=self.export_credentials).pack(side=tk.RIGHT, padx=5)
        
        # Credentials display
        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.credentials_text = tk.Text(text_frame, height=8, font=("Courier", 10),
                                       yscrollcommand=scrollbar.set, wrap=tk.WORD,
                                       bg='#1a1a1a', fg='#ff6b6b',
                                       insertbackground='#ff6b6b',
                                       selectbackground='#4a1a1a')
        self.credentials_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scrollbar.config(command=self.credentials_text.yview)
        
        # Configure tags
        self.credentials_text.tag_config('timestamp', foreground='#888888', font=("Courier", 9))
        self.credentials_text.tag_config('url', foreground='#4ec9b0', font=("Courier", 10, 'bold'))
        self.credentials_text.tag_config('field', foreground='#ffaa00', font=("Courier", 10))
        self.credentials_text.tag_config('value', foreground='#ff6b6b', font=("Courier", 10, 'bold'))

    def create_packet_details_pane(self, parent):
        frame = ttk.Frame(parent)
        parent.add(frame, weight=1)
        
        self.packet_details_header = ttk.Label(frame, text="Packet Details", font=("Arial", 10, "bold"))
        self.packet_details_header.pack(anchor=tk.W, pady=5)
        
        text_frame = ttk.Frame(frame)
        text_frame.pack(fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.details_text = tk.Text(text_frame, height=10, font=("Courier", 9),
                                   yscrollcommand=scrollbar.set, wrap=tk.NONE,
                                   bg='#1e1e1e', fg='#d4d4d4', 
                                   insertbackground='#d4d4d4',
                                   selectbackground='#264f78')
        self.details_text.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        scrollbar.config(command=self.details_text.yview)
        
        self.details_text.tag_config('label', foreground='#4ec9b0', 
                                    font=("Courier", 9, "bold"))
        self.details_text.tag_config('value', foreground='#d4d4d4')
        self.details_text.tag_config('header', foreground='#569cd6', 
                                    font=("Courier", 9, "bold"))
        self.details_text.tag_config('credential', foreground='#ff6b6b',
                                    font=("Courier", 9, "bold"))

    def create_statusbar(self):
        statusbar_frame = ttk.Frame(self.root, height=20)
        statusbar_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.packet_count_label = ttk.Label(statusbar_frame, text="Packets: 0")
        self.packet_count_label.pack(side=tk.LEFT, padx=10, pady=2)
        
        self.cred_count_label = ttk.Label(statusbar_frame, text="Credentials: 0", 
                                         foreground='#ff6b6b')
        self.cred_count_label.pack(side=tk.LEFT, padx=10, pady=2)

    def extract_http_credentials(self, packet):
        """Extract credentials from HTTP POST requests"""
        if not packet.haslayer(TCP) or not packet.haslayer(Raw):
            return None
        
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            
            # Check if it's an HTTP POST request
            if 'POST' not in payload[:20]:
                return None
            
            credentials = {
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'src_ip': packet[IP].src if packet.haslayer(IP) else 'Unknown',
                'dst_ip': packet[IP].dst if packet.haslayer(IP) else 'Unknown',
                'method': 'POST',
                'url': '',
                'username': None,
                'password': None,
                'raw_data': {}
            }
            
            # Extract URL from Host and path
            host_match = re.search(r'Host:\s*([^\r\n]+)', payload, re.IGNORECASE)
            path_match = re.search(r'POST\s+([^\s]+)', payload)
            
            if host_match and path_match:
                credentials['url'] = f"http://{host_match.group(1)}{path_match.group(1)}"
            
            # Split headers and body
            if '\r\n\r\n' in payload:
                headers, body = payload.split('\r\n\r\n', 1)
            else:
                body = payload
            
            # Common username/password field patterns
            username_patterns = [
                r'(?:username|user|login|email|account|id)=([^&\r\n]+)',
                r'"(?:username|user|login|email|account|id)"\s*:\s*"([^"]+)"'
            ]
            
            password_patterns = [
                r'(?:password|passwd|pass|pwd)=([^&\r\n]+)',
                r'"(?:password|passwd|pass|pwd)"\s*:\s*"([^"]+)"'
            ]
            
            # Search for username
            for pattern in username_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    credentials['username'] = match.group(1)
                    break
            
            # Search for password
            for pattern in password_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    credentials['password'] = match.group(1)
                    break
            
            # Extract all form data
            form_data = re.findall(r'([^&=]+)=([^&\r\n]+)', body)
            for key, value in form_data:
                credentials['raw_data'][key] = value
            
            # Also try JSON format
            json_match = re.search(r'\{[^}]+\}', body)
            if json_match:
                try:
                    import json
                    json_data = json.loads(json_match.group(0))
                    credentials['raw_data'].update(json_data)
                    
                    # Try to find username/password in JSON
                    for key in json_data:
                        if key.lower() in ['username', 'user', 'login', 'email']:
                            credentials['username'] = json_data[key]
                        elif key.lower() in ['password', 'passwd', 'pass', 'pwd']:
                            credentials['password'] = json_data[key]
                except Exception:
                    pass
            
            # Only return if we found at least username or password
            if credentials['username'] or credentials['password']:
                return credentials
            
        except Exception as e:
            pass
        
        return None

    def display_credentials(self, creds):
        """Display captured credentials"""
        global credentials_list
        credentials_list.append(creds)
        
        self.credentials_text.config(state=tk.NORMAL)
        
        # Add separator
        self.credentials_text.insert(tk.END, "\n" + "="*80 + "\n")
        
        # Timestamp
        self.credentials_text.insert(tk.END, f"[{creds['timestamp']}] ", 'timestamp')
        
        # URL
        self.credentials_text.insert(tk.END, f"\n🌐 URL: {creds['url']}\n", 'url')
        
        # Source/Destination
        self.credentials_text.insert(tk.END, f"📡 {creds['src_ip']} → {creds['dst_ip']}\n\n")
        
        # Username
        if creds['username']:
            self.credentials_text.insert(tk.END, "👤 Username: ", 'field')
            self.credentials_text.insert(tk.END, f"{creds['username']}\n", 'value')
        
        # Password
        if creds['password']:
            self.credentials_text.insert(tk.END, "🔑 Password: ", 'field')
            self.credentials_text.insert(tk.END, f"{creds['password']}\n", 'value')
        
        # Additional fields
        if creds['raw_data']:
            self.credentials_text.insert(tk.END, "\n📋 Additional Data:\n", 'field')
            for key, value in creds['raw_data'].items():
                if key not in ['username', 'user', 'login', 'password', 'passwd', 'pass']:
                    self.credentials_text.insert(tk.END, f"   {key}: {value}\n")
        
        self.credentials_text.insert(tk.END, "\n")
        self.credentials_text.config(state=tk.DISABLED)
        self.credentials_text.see(tk.END)
        
        # Update count
        self.cred_count_label.config(text=f"Credentials: {len(credentials_list)}")
        
        # Flash warning
        self.root.bell()

    def analyze_packet(self, packet):
        global packet_count
        packet_count += 1
        
        packet_info = {
            'no': packet_count,
            'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'src': 'Unknown',
            'dst': 'Unknown',
            'protocol': 'Other',
            'length': len(packet),
            'info': '',
            'raw_packet': packet,
            'has_credentials': False
        }
        
        try:
            # Check for credentials first
            credentials = self.extract_http_credentials(packet)
            if credentials:
                packet_info['has_credentials'] = True
                self.root.after(0, self.display_credentials, credentials)
            
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info['src'] = ip_layer.src
                packet_info['dst'] = ip_layer.dst
                
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    packet_info['protocol'] = 'TCP'
                    packet_info['info'] = f"Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}"
                    
                    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                        packet_info['protocol'] = 'HTTP'
                        if packet_info['has_credentials']:
                            packet_info['info'] += " [CREDENTIALS DETECTED]"
                    elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        packet_info['protocol'] = 'HTTPS'
                
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    packet_info['protocol'] = 'UDP'
                    packet_info['info'] = f"Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}"
                    
                    if udp_layer.dport == 53 or udp_layer.sport == 53:
                        packet_info['protocol'] = 'DNS'
                
                elif packet.haslayer(ICMP):
                    packet_info['protocol'] = 'ICMP'
                    icmp_layer = packet[ICMP]
                    packet_info['info'] = f"Type: {icmp_layer.type}, Code: {icmp_layer.code}"
            
            elif packet.haslayer(IPv6):
                packet_info['protocol'] = 'IPv6'
                packet_info['info'] = "IPv6 packet"
            
            elif packet.haslayer(ARP):
                packet_info['protocol'] = 'ARP'
                arp_layer = packet[ARP]
                packet_info['src'] = arp_layer.psrc
                packet_info['dst'] = arp_layer.pdst
                packet_info['info'] = f"{arp_layer.op} - Who has {arp_layer.pdst}?"
        
        except Exception as e:
            packet_info['info'] = f"Error: {str(e)}"
        
        return packet_info

    def get_protocol_color(self, protocol_name):
        return PROTOCOL_COLORS.get(protocol_name, PROTOCOL_COLORS['Other'])

    def get_protocol_text_color(self, protocol_name):
        return PROTOCOL_TEXT_COLORS.get(protocol_name, PROTOCOL_TEXT_COLORS['Other'])

    def add_packet_to_list(self, packet_info):
        packet_list.append(packet_info)
        
        item_id = self.packet_tree.insert('', 'end', values=(
            packet_info['no'],
            packet_info['time'],
            packet_info['src'][:20],
            packet_info['dst'][:20],
            packet_info['protocol'],
            packet_info['length'],
            packet_info['info'][:80]
        ))
        
        # Highlight packets with credentials
        if packet_info['has_credentials']:
            self.packet_tree.item(item_id, tags=('credentials',))
            self.packet_tree.tag_configure('credentials', 
                                          background='#4a1a1a', foreground='#ff6b6b')
        else:
            color = self.get_protocol_color(packet_info['protocol'])
            text_color = self.get_protocol_text_color(packet_info['protocol'])
            self.packet_tree.item(item_id, tags=(packet_info['protocol'],))
            self.packet_tree.tag_configure(packet_info['protocol'], 
                                          background=color, foreground=text_color)
        
        self.packet_count_label.config(text=f"Packets: {packet_count}")
        self.packet_tree.see(item_id)

    def on_packet_select(self, event):
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        item = selection[0]
        index = list(self.packet_tree.get_children()).index(item)
        
        if index < len(packet_list):
            packet_info = packet_list[index]
            self.display_packet_details(packet_info)

    def display_packet_details(self, packet_info):
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        packet = packet_info['raw_packet']
        
        details = f"Frame {packet_info['no']}: {packet_info['length']} bytes\n"
        details += f"Captured at: {packet_info['time']}\n"
        if packet_info['has_credentials']:
            self.details_text.insert(tk.END, details, 'header')
            self.details_text.insert(tk.END, "\n⚠️ THIS PACKET CONTAINS CREDENTIALS ⚠️\n\n", 'credential')
        else:
            self.details_text.insert(tk.END, details + "\n", 'header')
        
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            details = f"\nInternet Protocol Version 4 (IPv4)\n"
            details += f"  Source IP: {ip_layer.src}\n"
            details += f"  Destination IP: {ip_layer.dst}\n"
            details += f"  Time to Live (TTL): {ip_layer.ttl}\n"
            details += f"  Protocol: {ip_layer.proto}\n"
            self.details_text.insert(tk.END, details)
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            details = f"\nTransmission Control Protocol (TCP)\n"
            details += f"  Source Port: {tcp_layer.sport}\n"
            details += f"  Destination Port: {tcp_layer.dport}\n"
            details += f"  Sequence Number: {tcp_layer.seq}\n"
            details += f"  Acknowledgment Number: {tcp_layer.ack}\n"
            details += f"  Flags: {tcp_layer.flags}\n"
            details += f"  Window Size: {tcp_layer.window}\n"
            self.details_text.insert(tk.END, details)
        
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            details = f"\nUser Datagram Protocol (UDP)\n"
            details += f"  Source Port: {udp_layer.sport}\n"
            details += f"  Destination Port: {udp_layer.dport}\n"
            details += f"  Length: {udp_layer.len}\n"
            details += f"  Checksum: {udp_layer.chksum}\n"
            self.details_text.insert(tk.END, details)
        
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            details = f"\nInternet Control Message Protocol (ICMP)\n"
            details += f"  Type: {icmp_layer.type}\n"
            details += f"  Code: {icmp_layer.code}\n"
            details += f"  Checksum: {icmp_layer.chksum}\n"
            self.details_text.insert(tk.END, details)
        
        # Show HTTP payload if present
        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode('utf-8', errors='ignore')
                if 'HTTP' in payload[:50] or 'POST' in payload[:50] or 'GET' in payload[:50]:
                    details = f"\n\nHTTP Payload:\n"
                    details += "=" * 60 + "\n"
                    details += payload[:1000]  # Show first 1000 chars
                    if len(payload) > 1000:
                        details += "\n... (truncated)"
                    if packet_info['has_credentials']:
                        self.details_text.insert(tk.END, details, 'credential')
                    else:
                        self.details_text.insert(tk.END, details)
            except Exception:
                pass
        
        self.details_text.config(state=tk.DISABLED)

    def clear_packets(self):
        global packet_count, packet_list
        packet_count = 0
        packet_list.clear()
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.packet_count_label.config(text="Packets: 0")
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)

    def clear_credentials(self):
        global credentials_list
        credentials_list.clear()
        self.credentials_text.config(state=tk.NORMAL)
        self.credentials_text.delete(1.0, tk.END)
        self.credentials_text.config(state=tk.DISABLED)
        self.cred_count_label.config(text="Credentials: 0")

    def export_credentials(self):
        if not credentials_list:
            messagebox.showinfo("Export", "No credentials to export.")
            return
        
        try:
            from tkinter import filedialog
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
                title="Save Credentials"
            )
            if filename:
                with open(filename, 'w') as f:
                    for cred in credentials_list:
                        f.write(f"[{cred['timestamp']}]\n")
                        f.write(f"URL: {cred['url']}\n")
                        f.write(f"Source: {cred['src_ip']} -> Destination: {cred['dst_ip']}\n")
                        if cred['username']:
                            f.write(f"Username: {cred['username']}\n")
                        if cred['password']:
                            f.write(f"Password: {cred['password']}\n")
                        if cred['raw_data']:
                            f.write("Additional Data:\n")
                            for k, v in cred['raw_data'].items():
                                f.write(f"  {k}: {v}\n")
                        f.write("\n" + "="*60 + "\n\n")
                messagebox.showinfo("Export", f"Credentials saved to {filename}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export: {str(e)}")

    def start_capture(self):
        global is_capturing, capture_thread
        if is_capturing:
            return
        
        is_capturing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Capturing...")
        
        def capture_worker():
            try:
                sniff(prn=self.packet_callback, store=False, stop_filter=lambda x: not is_capturing)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Capture Error", f"Failed to start capture:\n{str(e)}"))
                self.root.after(0, self.stop_capture)
        
        capture_thread = threading.Thread(target=capture_worker, daemon=True)
        capture_thread.start()

    def stop_capture(self):
        global is_capturing
        is_capturing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Stopped")

    def packet_callback(self, packet):
        if not is_capturing:
            return
        packet_info = self.analyze_packet(packet)
        self.root.after(0, self.add_packet_to_list, packet_info)

    def zoom_in(self, event=None):
        self.zoom_level = min(self.zoom_level + 0.1, 2.0)
        self.apply_zoom()

    def zoom_out(self, event=None):
        self.zoom_level = max(self.zoom_level - 0.1, 0.5)
        self.apply_zoom()

    def zoom_reset(self, event=None):
        self.zoom_level = 1.0
        self.apply_zoom()

    def apply_zoom(self):
        new_font_size = int(self.base_font_size * self.zoom_level)
        new_tree_font_size = int(self.base_treeview_font_size * self.zoom_level)
        new_heading_font_size = int(self.base_heading_font_size * self.zoom_level)
        
        self.credentials_text.config(font=("Courier", max(8, new_font_size)))
        self.details_text.config(font=("Courier", max(8, new_font_size)))
        
        style = ttk.Style()
        style.configure('Treeview', font=("Arial", max(8, new_tree_font_size)), rowheight=max(20, int(20 * self.zoom_level)))
        style.configure('Treeview.Heading', font=("Arial", max(8, new_heading_font_size), "bold"))

    def show_about(self):
        messagebox.showinfo("About", 
            "Network Packet Sniffer GUI\n"
            "Detects HTTP credentials in plain text.\n\n"
            "⚠️ For educational and authorized security testing only.\n"
            "Unauthorized interception of network traffic is illegal.")

def main():
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()

if __name__ == "__main__":
    # Check for root privileges (required for raw packet capture)
    if os.geteuid() != 0:
        print("This program requires root privileges to capture packets.")
        print("Please run with sudo:")
        print(f"  sudo {sys.executable} {os.path.basename(__file__)}")
        sys.exit(1)
    
    main()
