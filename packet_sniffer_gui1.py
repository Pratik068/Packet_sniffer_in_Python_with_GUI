#!/usr/bin/env python3
"""
Network Packet Sniffer GUI - Python Implementation for Linux
Advanced packet capture and analysis with Tkinter GUI similar to Wireshark
"""

import sys
import os
import threading
from datetime import datetime
from collections import deque

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, IPv6
    import tkinter as tk
    from tkinter import ttk, messagebox
except ImportError as e:
    print(f"Error: Required module not installed - {e}")
    print("Install with: pip install scapy")
    sys.exit(1)

# Global variables
packet_count = 0
packet_list = deque(maxlen=1000)  # Store last 1000 packets
is_capturing = False
capture_thread = None

# Color scheme for different protocols - Dark theme
PROTOCOL_COLORS = {
    'TCP': '#1a3a4a',      # Dark blue-gray
    'UDP': '#2a2a3a',      # Dark purple-gray
    'ICMP': '#3a2a3a',     # Dark purple
    'ARP': '#3a3a2a',      # Dark yellow-gray
    'IPv6': '#2a3a2a',     # Dark green-gray
    'DNS': '#3a2a2a',      # Dark red-gray
    'HTTP': '#3a2a1a',     # Dark orange-gray
    'HTTPS': '#2a1a3a',    # Dark purple
    'Other': '#2a2a2a'     # Dark gray
}

# Protocol text colors
PROTOCOL_TEXT_COLORS = {
    'TCP': '#5eb3e0',      # Light blue
    'UDP': '#9a9ad4',      # Light purple
    'ICMP': '#d49ad4',     # Light pink
    'ARP': '#d4d49a',      # Light yellow
    'IPv6': '#9ad49a',     # Light green
    'DNS': '#d4a09a',      # Light coral
    'HTTP': '#d4b09a',     # Light orange
    'HTTPS': '#b09ad4',    # Light purple
    'Other': '#aaaaaa'     # Light gray
}

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Sniffer - Wireshark Style")
        self.root.geometry("1400x800")
        self.root.minsize(1000, 600)
        
        # Set dark background
        self.root.configure(bg='#1e1e1e')
        
        # Zoom level tracking
        self.zoom_level = 1.0
        self.base_font_size = 9
        self.base_treeview_font_size = 10
        self.base_heading_font_size = 9
        
        # Set style with dark theme
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure dark theme colors
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='#d4d4d4')
        style.configure('TButton', background='#2d2d30', foreground='#d4d4d4')
        style.map('TButton', background=[('active', '#3e3e42')])
        style.configure('Treeview', background='#252526', foreground='#d4d4d4', 
                       fieldbackground='#252526', borderwidth=0, rowheight=20)
        style.configure('Treeview.Heading', background='#2d2d30', foreground='#d4d4d4')
        style.map('Treeview.Heading', background=[('active', '#3e3e42')])
        
        # Store style reference for zoom updates
        self.style = style
        
        self.create_menu_bar()
        self.create_toolbar()
        self.create_main_layout()
        self.create_statusbar()
        
        # Bind zoom shortcuts
        self.root.bind('<Control-plus>', self.zoom_in)
        self.root.bind('<Control-equal>', self.zoom_in)  # For keyboards without numpad
        self.root.bind('<Control-minus>', self.zoom_out)
        self.root.bind('<Control-0>', self.zoom_reset)
        
        global packet_count
        packet_count = 0

    def create_menu_bar(self):
        """Create menu bar"""
        menubar = tk.Menu(self.root, bg='#2d2d30', fg='#d4d4d4', 
                         activebackground='#3e3e42', activeforeground='#ffffff')
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d30', fg='#d4d4d4',
                           activebackground='#3e3e42', activeforeground='#ffffff')
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Clear Packets", command=self.clear_packets)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Capture menu
        capture_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d30', fg='#d4d4d4',
                              activebackground='#3e3e42', activeforeground='#ffffff')
        menubar.add_cascade(label="Capture", menu=capture_menu)
        capture_menu.add_command(label="Start Capture", command=self.start_capture)
        capture_menu.add_command(label="Stop Capture", command=self.stop_capture)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d30', fg='#d4d4d4',
                           activebackground='#3e3e42', activeforeground='#ffffff')
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0, bg='#2d2d30', fg='#d4d4d4',
                           activebackground='#3e3e42', activeforeground='#ffffff')
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="Zoom In (Ctrl+Plus)", command=self.zoom_in)
        view_menu.add_command(label="Zoom Out (Ctrl+Minus)", command=self.zoom_out)
        view_menu.add_command(label="Reset Zoom (Ctrl+0)", command=self.zoom_reset)

    def create_toolbar(self):
        """Create toolbar with buttons"""
        toolbar_frame = ttk.Frame(self.root)
        toolbar_frame.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        self.start_btn = ttk.Button(toolbar_frame, text="▶ Start Capture", 
                                    command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(toolbar_frame, text="⏹ Stop Capture", 
                                   command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(toolbar_frame, text="🗑 Clear", 
                  command=self.clear_packets).pack(side=tk.LEFT, padx=5)
        
        # Zoom buttons
        ttk.Button(toolbar_frame, text="🔍+", 
                  command=self.zoom_in).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="🔍-", 
                  command=self.zoom_out).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar_frame, text="🔍Reset", 
                  command=self.zoom_reset).pack(side=tk.LEFT, padx=2)
        
        # Status label
        self.status_label = ttk.Label(toolbar_frame, text="Ready")
        self.status_label.pack(side=tk.LEFT, padx=20, fill=tk.X, expand=True)

    def create_main_layout(self):
        """Create main layout with packet list and details"""
        # Main container
        main_container = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Top pane - Packet list
        self.create_packet_list_pane(main_container)
        
        # Bottom pane - Packet details
        self.create_packet_details_pane(main_container)

    def create_packet_list_pane(self, parent):
        """Create packet list with columns"""
        frame = ttk.Frame(parent)
        parent.add(frame, weight=2)
        
        # Header
        self.packet_list_header = ttk.Label(frame, text="Packet List", font=("Arial", 10, "bold"))
        self.packet_list_header.pack(anchor=tk.W, pady=5)
        
        # Create frame for treeview and scrollbars
        tree_frame = ttk.Frame(frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview columns
        columns = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
        self.packet_tree = ttk.Treeview(tree_frame, columns=columns, height=15, 
                                       show='headings')
        
        # Define columns
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
        
        # Add scrollbars
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, 
                           command=self.packet_tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, 
                           command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Pack layout
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind selection
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)

    def create_packet_details_pane(self, parent):
        """Create packet details display"""
        frame = ttk.Frame(parent)
        parent.add(frame, weight=1)
        
        # Header
        self.packet_details_header = ttk.Label(frame, text="Packet Details", font=("Arial", 10, "bold"))
        self.packet_details_header.pack(anchor=tk.W, pady=5)
        
        # Text widget with scrollbar
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
        
        # Store reference to update font on zoom
        self.details_font = ("Courier", 9)
        
        # Configure text tags for colors
        self.details_text.tag_config('label', foreground='#4ec9b0', 
                                    font=("Courier", 9, "bold"))
        self.details_text.tag_config('value', foreground='#d4d4d4')
        self.details_text.tag_config('header', foreground='#569cd6', 
                                    font=("Courier", 9, "bold"))

    def create_statusbar(self):
        """Create status bar"""
        statusbar_frame = ttk.Frame(self.root, height=20)
        statusbar_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.packet_count_label = ttk.Label(statusbar_frame, text="Packets: 0")
        self.packet_count_label.pack(side=tk.LEFT, padx=10, pady=2)

    def get_protocol_color(self, protocol_name):
        """Get color for protocol"""
        return PROTOCOL_COLORS.get(protocol_name, PROTOCOL_COLORS['Other'])

    def get_protocol_text_color(self, protocol_name):
        """Get text color for protocol"""
        return PROTOCOL_TEXT_COLORS.get(protocol_name, PROTOCOL_TEXT_COLORS['Other'])

    def analyze_packet(self, packet):
        """Analyze packet and extract information"""
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
            'raw_packet': packet
        }
        
        try:
            # Check for IP layer
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                packet_info['src'] = ip_layer.src
                packet_info['dst'] = ip_layer.dst
                
                # Check for TCP
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    packet_info['protocol'] = 'TCP'
                    packet_info['info'] = f"Src Port: {tcp_layer.sport}, Dst Port: {tcp_layer.dport}"
                    
                    # Check for HTTP
                    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                        packet_info['protocol'] = 'HTTP'
                    # Check for HTTPS
                    elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        packet_info['protocol'] = 'HTTPS'
                
                # Check for UDP
                elif packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    packet_info['protocol'] = 'UDP'
                    packet_info['info'] = f"Src Port: {udp_layer.sport}, Dst Port: {udp_layer.dport}"
                    
                    # Check for DNS
                    if udp_layer.dport == 53 or udp_layer.sport == 53:
                        packet_info['protocol'] = 'DNS'
                
                # Check for ICMP
                elif packet.haslayer(ICMP):
                    packet_info['protocol'] = 'ICMP'
                    icmp_layer = packet[ICMP]
                    packet_info['info'] = f"Type: {icmp_layer.type}, Code: {icmp_layer.code}"
            
            # Check for IPv6
            elif packet.haslayer(IPv6):
                packet_info['protocol'] = 'IPv6'
                packet_info['info'] = "IPv6 packet"
            
            # Check for ARP
            elif packet.haslayer(ARP):
                packet_info['protocol'] = 'ARP'
                arp_layer = packet[ARP]
                packet_info['src'] = arp_layer.psrc
                packet_info['dst'] = arp_layer.pdst
                packet_info['info'] = f"{arp_layer.op} - Who has {arp_layer.pdst}?"
        
        except Exception as e:
            packet_info['info'] = f"Error: {str(e)}"
        
        return packet_info

    def add_packet_to_list(self, packet_info):
        """Add packet to the list display"""
        packet_list.append(packet_info)
        
        # Insert into treeview
        item_id = self.packet_tree.insert('', 'end', values=(
            packet_info['no'],
            packet_info['time'],
            packet_info['src'][:20],
            packet_info['dst'][:20],
            packet_info['protocol'],
            packet_info['length'],
            packet_info['info'][:80]
        ))
        
        # Set row color
        color = self.get_protocol_color(packet_info['protocol'])
        text_color = self.get_protocol_text_color(packet_info['protocol'])
        self.packet_tree.item(item_id, tags=(packet_info['protocol'],))
        self.packet_tree.tag_configure(packet_info['protocol'], 
                                      background=color, foreground=text_color)
        
        # Update packet count
        self.packet_count_label.config(text=f"Packets: {packet_count}")
        
        # Auto-scroll to latest packet
        self.packet_tree.see(item_id)

    def on_packet_select(self, event):
        """Display packet details when selected"""
        selection = self.packet_tree.selection()
        if not selection:
            return
        
        # Get selected item index
        item = selection[0]
        index = list(self.packet_tree.get_children()).index(item)
        
        if index < len(packet_list):
            packet_info = packet_list[index]
            self.display_packet_details(packet_info)

    def display_packet_details(self, packet_info):
        """Display detailed packet information"""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        packet = packet_info['raw_packet']
        
        # Header info
        details = f"Frame {packet_info['no']}: {packet_info['length']} bytes\n"
        details += f"Captured at: {packet_info['time']}\n\n"
        self.details_text.insert(tk.END, details, 'header')
        
        # IP Layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            details = f"\nInternet Protocol Version 4 (IPv4)\n"
            details += f"  Source IP: {ip_layer.src}\n"
            details += f"  Destination IP: {ip_layer.dst}\n"
            details += f"  Time to Live (TTL): {ip_layer.ttl}\n"
            details += f"  Protocol: {ip_layer.proto}\n"
            self.details_text.insert(tk.END, details)
        
        # TCP Layer
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
        
        # UDP Layer
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            details = f"\nUser Datagram Protocol (UDP)\n"
            details += f"  Source Port: {udp_layer.sport}\n"
            details += f"  Destination Port: {udp_layer.dport}\n"
            details += f"  Length: {udp_layer.len}\n"
            details += f"  Checksum: {udp_layer.chksum}\n"
            self.details_text.insert(tk.END, details)
        
        # ICMP Layer
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            details = f"\nInternet Control Message Protocol (ICMP)\n"
            details += f"  Type: {icmp_layer.type}\n"
            details += f"  Code: {icmp_layer.code}\n"
            details += f"  Checksum: {icmp_layer.chksum}\n"
            self.details_text.insert(tk.END, details)
        
        # Raw bytes
        details = f"\n\nPacket Bytes (first 128):\n"
        raw_bytes = bytes(packet)[:128]
        hex_str = ' '.join(f'{b:02x}' for b in raw_bytes)
        details += hex_str
        self.details_text.insert(tk.END, details)
        
        self.details_text.config(state=tk.DISABLED)

    def packet_callback(self, packet):
        """Callback function for packet sniffer"""
        if not is_capturing:
            return False
        
        packet_info = self.analyze_packet(packet)
        self.root.after(0, self.add_packet_to_list, packet_info)

    def start_capture(self):
        """Start packet capture in a separate thread"""
        global is_capturing, capture_thread
        
        if is_capturing:
            messagebox.showwarning("Warning", "Capture already running!")
            return
        
        is_capturing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_label.config(text="Capturing packets...")
        
        # Start capture in separate thread
        capture_thread = threading.Thread(target=self._capture_packets, daemon=True)
        capture_thread.start()

    def _capture_packets(self):
        """Packet capture thread"""
        global is_capturing
        try:
            # Sniff packets
            sniff(prn=self.packet_callback, store=False, 
                  stop_filter=lambda x: not is_capturing)
        except PermissionError:
            self.root.after(0, lambda: messagebox.showerror("Error", 
                "This program requires root privileges!\nRun with: sudo python3 packet_sniffer_gui.py"))
            is_capturing = False
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", 
                f"Capture error: {str(e)}"))
            is_capturing = False

    def stop_capture(self):
        """Stop packet capture"""
        global is_capturing
        is_capturing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Capture stopped")

    def clear_packets(self):
        """Clear all packets from the list"""
        global packet_count
        
        packet_list.clear()
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        packet_count = 0
        self.packet_count_label.config(text="Packets: 0")
        
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        self.details_text.config(state=tk.DISABLED)

    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo("About", 
            "Network Packet Sniffer v1.0\n\n"
            "A Wireshark-style packet analyzer using Scapy\n\n"
            "Made for Linux with Tkinter")
    
    def zoom_in(self, event=None):
        """Increase zoom level"""
        self.zoom_level = min(self.zoom_level + 0.1, 2.0)  # Max 200%
        self.apply_zoom()
    
    def zoom_out(self, event=None):
        """Decrease zoom level"""
        self.zoom_level = max(self.zoom_level - 0.1, 0.5)  # Min 50%
        self.apply_zoom()
    
    def zoom_reset(self, event=None):
        """Reset zoom to 100%"""
        self.zoom_level = 1.0
        self.apply_zoom()
    
    def apply_zoom(self):
        """Apply zoom level to all text elements"""
        # Calculate new font sizes
        new_font_size = int(self.base_font_size * self.zoom_level)
        new_treeview_font_size = int(self.base_treeview_font_size * self.zoom_level)
        new_heading_font_size = int(self.base_heading_font_size * self.zoom_level)
        new_rowheight = int(20 * self.zoom_level)
        
        # Update treeview font and row height
        self.style.configure('Treeview', 
                           background='#252526', 
                           foreground='#d4d4d4',
                           fieldbackground='#252526', 
                           borderwidth=0, 
                           rowheight=new_rowheight,
                           font=('TkDefaultFont', new_treeview_font_size))
        
        self.style.configure('Treeview.Heading', 
                           background='#2d2d30', 
                           foreground='#d4d4d4',
                           font=('TkDefaultFont', new_heading_font_size, 'bold'))
        
        # Update column widths proportionally
        for col in self.packet_tree['columns']:
            base_width = self.column_widths[col]
            new_width = int(base_width * self.zoom_level)
            self.packet_tree.column(col, width=new_width)
        
        # Update header labels
        header_font_size = int(10 * self.zoom_level)
        self.packet_list_header.config(font=("Arial", header_font_size, "bold"))
        self.packet_details_header.config(font=("Arial", header_font_size, "bold"))
        
        # Update details text font
        self.details_text.config(font=("Courier", new_font_size))
        
        # Update text tags with new font size
        self.details_text.tag_config('label', foreground='#4ec9b0', 
                                    font=("Courier", new_font_size, "bold"))
        self.details_text.tag_config('value', foreground='#d4d4d4',
                                    font=("Courier", new_font_size))
        self.details_text.tag_config('header', foreground='#569cd6', 
                                    font=("Courier", new_font_size, "bold"))
        
        # Update status to show zoom level
        zoom_percent = int(self.zoom_level * 100)
        current_status = self.status_label.cget("text")
        if "Zoom:" in current_status:
            base_status = current_status.split(" | ")[0]
        else:
            base_status = current_status
        self.status_label.config(text=f"{base_status} | Zoom: {zoom_percent}%")


def main():
    """Main function"""
    # Check for root privileges
    if os.getuid() != 0:
        print("Error: This program requires root privileges.")
        print("Please run with: sudo python3 packet_sniffer_gui.py")
        sys.exit(1)
    
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
