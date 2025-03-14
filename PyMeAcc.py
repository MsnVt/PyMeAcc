import sys
import os
import re
import argparse
import pyshark
import struct
from collections import defaultdict, deque
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import threading
import json
import binascii

class MemoryStructureInspector:

    def __init__(self, master):
        self.master = master
        self.master.title("Wireshark Memory Structure Inspector")
        self.master.geometry("1200x800")
        
        # Initialize variables
        self.capture = None
        self.structures = {}
        self.current_packets = []
        self.known_patterns = {}
        self.search_results = []
        
        self.create_gui()
        self.load_known_patterns()
    
    def create_gui(self):
        # Create main frame with left and right panes
        main_frame = ttk.PanedWindow(self.master, orient=tk.HORIZONTAL)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left frame for controls
        left_frame = ttk.Frame(main_frame)
        main_frame.add(left_frame, weight=1)
        
        # Right frame for results
        right_frame = ttk.Frame(main_frame)
        main_frame.add(right_frame, weight=2)
        
        # ===== Control Panel =====
        control_frame = ttk.LabelFrame(left_frame, text="Controls")
        control_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # File selection
        file_frame = ttk.Frame(control_frame)
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(file_frame, text="Capture File:").pack(side=tk.LEFT, padx=5)
        self.file_var = tk.StringVar()
        ttk.Entry(file_frame, textvariable=self.file_var, width=30).pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        ttk.Button(file_frame, text="Browse", command=self.browse_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_frame, text="Load", command=self.load_capture).pack(side=tk.LEFT, padx=5)
        
        # Structure definition
        struct_frame = ttk.LabelFrame(control_frame, text="Structure Definition")
        struct_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(struct_frame, text="Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.struct_name_var = tk.StringVar()
        ttk.Entry(struct_frame, textvariable=self.struct_name_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(struct_frame, text="Structure Format:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.struct_format_var = tk.StringVar()
        struct_format_entry = ttk.Entry(struct_frame, textvariable=self.struct_format_var)
        struct_format_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(struct_frame, text="Format Help:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        format_help = "i: int, f: float, s: string, 4s: 4-byte string, H: unsigned short"
        ttk.Label(struct_frame, text=format_help).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Button(struct_frame, text="Add Structure", command=self.add_structure).grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        
        # Known structures
        known_frame = ttk.LabelFrame(control_frame, text="Known Structures")
        known_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.struct_listbox = tk.Listbox(known_frame, height=5)
        self.struct_listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.struct_listbox.bind('<<ListboxSelect>>', self.select_structure)
        
        # Search controls
        search_frame = ttk.LabelFrame(control_frame, text="Search")
        search_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        ttk.Label(search_frame, text="Protocol:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.protocol_var = tk.StringVar()
        protocols = ["Any", "TCP", "UDP", "HTTP", "DNS", "ICMP"]
        ttk.Combobox(search_frame, textvariable=self.protocol_var, values=protocols).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        self.protocol_var.set("Any")
        
        ttk.Label(search_frame, text="Filter:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.filter_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.filter_var).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(search_frame, text="Search Algorithm:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.algorithm_var = tk.StringVar()
        algorithms = ["Boyer-Moore", "KMP", "Regex", "Binary Pattern"]
        ttk.Combobox(search_frame, textvariable=self.algorithm_var, values=algorithms).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        self.algorithm_var.set("Boyer-Moore")
        
        ttk.Button(search_frame, text="Search", command=self.search_structures).grid(row=3, column=0, columnspan=2, padx=5, pady=5)
        
        # ===== Results Panel =====
        result_notebook = ttk.Notebook(right_frame)
        result_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packet list tab
        packet_frame = ttk.Frame(result_notebook)
        result_notebook.add(packet_frame, text="Packet List")
        
        self.packet_tree = ttk.Treeview(packet_frame, columns=("no", "time", "source", "destination", "protocol", "length", "info"))
        self.packet_tree.heading("no", text="No.")
        self.packet_tree.heading("time", text="Time")
        self.packet_tree.heading("source", text="Source")
        self.packet_tree.heading("destination", text="Destination")
        self.packet_tree.heading("protocol", text="Protocol")
        self.packet_tree.heading("length", text="Length")
        self.packet_tree.heading("info", text="Info")
        self.packet_tree.column("#0", width=0, stretch=tk.NO)
        self.packet_tree.column("no", width=50, anchor=tk.W)
        self.packet_tree.column("time", width=100, anchor=tk.W)
        self.packet_tree.column("source", width=150, anchor=tk.W)
        self.packet_tree.column("destination", width=150, anchor=tk.W)
        self.packet_tree.column("protocol", width=70, anchor=tk.W)
        self.packet_tree.column("length", width=70, anchor=tk.W)
        self.packet_tree.column("info", width=300, anchor=tk.W)
        
        packet_scrollbar = ttk.Scrollbar(packet_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scrollbar.set)
        
        packet_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.packet_tree.bind("<<TreeviewSelect>>", self.select_packet)
        
        # Structure view tab
        structure_frame = ttk.Frame(result_notebook)
        result_notebook.add(structure_frame, text="Structure View")
        
        self.structure_text = tk.Text(structure_frame, wrap=tk.WORD)
        structure_scrollbar = ttk.Scrollbar(structure_frame, orient=tk.VERTICAL, command=self.structure_text.yview)
        self.structure_text.configure(yscrollcommand=structure_scrollbar.set)
        
        structure_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.structure_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Hex view tab
        hex_frame = ttk.Frame(result_notebook)
        result_notebook.add(hex_frame, text="Hex View")
        
        self.hex_text = tk.Text(hex_frame, font=("Courier", 10))
        hex_scrollbar = ttk.Scrollbar(hex_frame, orient=tk.VERTICAL, command=self.hex_text.yview)
        self.hex_text.configure(yscrollcommand=hex_scrollbar.set)
        
        hex_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.hex_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def browse_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap"), ("PCAPNG files", "*.pcapng"), ("All files", "*.*")])
        if file_path:
            self.file_var.set(file_path)
    
    def load_capture(self):
        filename = self.file_var.get()
        if not filename:
            messagebox.showerror("Error", "Please select a capture file first")
            return
            
        if not os.path.exists(filename):
            messagebox.showerror("Error", f"File {filename} does not exist")
            return
            
        self.status_var.set(f"Loading capture file {os.path.basename(filename)}...")
        self.master.update_idletasks()
        
        # Load in a separate thread to keep UI responsive
        def load_thread():
            try:
                self.capture = pyshark.FileCapture(filename)
                self.current_packets = []
                
                # Clear existing data
                for item in self.packet_tree.get_children():
                    self.packet_tree.delete(item)
                
                # Load first 1000 packets (to avoid freezing for large captures)
                max_packets = 1000
                for i, packet in enumerate(self.capture):
                    if i >= max_packets:
                        break
                        
                    self.current_packets.append(packet)
                    try:
                        no = packet.number
                        time = packet.sniff_time.strftime('%H:%M:%S.%f')[:-3]
                        source = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                        dest = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                        protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else packet.highest_layer
                        length = packet.length
                        info = f"{packet.highest_layer} Packet"
                        
                        self.packet_tree.insert("", "end", values=(no, time, source, dest, protocol, length, info))
                    except Exception as e:
                        print(f"Error processing packet {i}: {e}")
                
                self.status_var.set(f"Loaded {len(self.current_packets)} packets from {os.path.basename(filename)}")
            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
                messagebox.showerror("Error", f"Failed to load capture file: {str(e)}")
        
        threading.Thread(target=load_thread, daemon=True).start()
    
    def add_structure(self):
        name = self.struct_name_var.get()
        fmt = self.struct_format_var.get()
        
        if not name or not fmt:
            messagebox.showerror("Error", "Both name and format are required")
            return
            
        try:
            # Test if format is valid
            struct.calcsize(fmt)
            self.structures[name] = fmt
            self.update_structure_list()
            self.save_known_patterns()
            
            # Clear fields
            self.struct_name_var.set("")
            self.struct_format_var.set("")
            
            messagebox.showinfo("Success", f"Structure '{name}' added successfully")
        except struct.error as e:
            messagebox.showerror("Error", f"Invalid structure format: {str(e)}")
    
    def update_structure_list(self):
        self.struct_listbox.delete(0, tk.END)
        for name in sorted(self.structures.keys()):
            self.struct_listbox.insert(tk.END, f"{name}: {self.structures[name]}")
    
    def select_structure(self, event):
        if not self.struct_listbox.curselection():
            return
            
        selected = self.struct_listbox.get(self.struct_listbox.curselection())
        name = selected.split(":")[0].strip()
        
        self.struct_name_var.set(name)
        self.struct_format_var.set(self.structures[name])
    
    def select_packet(self, event):
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return
            
        item = selected_items[0]
        packet_number = int(self.packet_tree.item(item, "values")[0])
        
        # Find the corresponding packet
        packet = None
        for p in self.current_packets:
            if int(p.number) == packet_number:
                packet = p
                break
                
        if not packet:
            return
            
        # Display hex view
        self.display_hex_view(packet)
        
        # Try to find structures in the packet data
        self.find_structures_in_packet(packet)
    
    def display_hex_view(self, packet):
        self.hex_text.delete(1.0, tk.END)
        
        # Get raw packet data
        if hasattr(packet, 'binary_data'):
            data = packet.binary_data
        else:
            self.hex_text.insert(tk.END, "Binary data not available for this packet")
            return
        
        # Format as hex dump with both hex and ASCII representation
        offset = 0
        while offset < len(data):
            # Line address
            line = f"{offset:08x}  "
            
            # Hex bytes
            chunk = data[offset:offset+16]
            hex_values = [f"{b:02x}" for b in chunk]
            
            # Format in groups of 8
            if len(hex_values) > 8:
                hex_part = " ".join(hex_values[:8]) + "  " + " ".join(hex_values[8:])
            else:
                hex_part = " ".join(hex_values)
            
            # Padding for alignment if line is short
            hex_part = hex_part.ljust(49)
            line += hex_part + " |"
            
            # ASCII representation
            for b in chunk:
                if 32 <= b <= 126:  # Printable ASCII
                    line += chr(b)
                else:
                    line += "."
            
            line += "|\n"
            self.hex_text.insert(tk.END, line)
            offset += 16
    
    def find_structures_in_packet(self, packet):
        self.structure_text.delete(1.0, tk.END)
        
        if not hasattr(packet, 'binary_data'):
            self.structure_text.insert(tk.END, "Binary data not available for this packet")
            return
        
        data = packet.binary_data
        results = []
        
        # Try each known structure
        for name, fmt in self.structures.items():
            struct_size = struct.calcsize(fmt)
            
            # Try all possible offsets
            for offset in range(len(data) - struct_size + 1):
                try:
                    chunk = data[offset:offset+struct_size]
                    values = struct.unpack(fmt, chunk)
                    
                    # Check if values look reasonable (non-random)
                    # This is a simple heuristic - we're looking for printable strings and reasonable numeric values
                    reasonable = False
                    for v in values:
                        if isinstance(v, bytes) and all(32 <= b <= 126 for b in v if b != 0):
                            reasonable = True
                            break
                        elif isinstance(v, int) and -10000000 < v < 10000000:
                            reasonable = True
                            
                    if reasonable:
                        results.append((name, offset, fmt, values))
                except:
                    # Skip errors (invalid data for the format)
                    continue
        
        # Display results
        if results:
            for name, offset, fmt, values in results:
                self.structure_text.insert(tk.END, f"=== {name} at offset 0x{offset:x} ===\n")
                
                # Format unpacked values
                formatted_values = []
                for v in values:
                    if isinstance(v, bytes):
                        try:
                            s = v.decode('utf-8').rstrip('\x00')
                            formatted_values.append(f"'{s}'")
                        except:
                            formatted_values.append(f"0x{v.hex()}")
                    else:
                        formatted_values.append(str(v))
                
                self.structure_text.insert(tk.END, f"Format: {fmt}\n")
                self.structure_text.insert(tk.END, f"Values: {', '.join(formatted_values)}\n\n")
        else:
            self.structure_text.insert(tk.END, "No known structures found in this packet.\n")
            self.structure_text.insert(tk.END, "Try defining a structure or using a different search algorithm.")
    
    def search_structures(self):
        if not self.capture:
            messagebox.showerror("Error", "Please load a capture file first")
            return
        
        protocol_filter = self.protocol_var.get()
        custom_filter = self.filter_var.get()
        algorithm = self.algorithm_var.get()
        
        if not self.structures:
            messagebox.showerror("Error", "Please define at least one structure first")
            return
        
        self.status_var.set("Searching for structures...")
        self.master.update_idletasks()
        
        # Clear packet list
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Search in a separate thread
        def search_thread():
            try:
                self.search_results = []
                
                # Apply basic filters
                filtered_packets = self.current_packets
                if protocol_filter != "Any":
                    filtered_packets = [p for p in filtered_packets if hasattr(p, 'transport_layer') and p.transport_layer == protocol_filter]
                
                if custom_filter:
                    # This is a simple filter implementation - in a real tool, you'd want more sophisticated parsing
                    filtered_packets = [p for p in filtered_packets if self.matches_filter(p, custom_filter)]
                
                # Apply search algorithm to find structures
                for packet in filtered_packets:
                    if hasattr(packet, 'binary_data'):
                        data = packet.binary_data
                        
                        for name, fmt in self.structures.items():
                            # Search for structure using selected algorithm
                            if algorithm == "Boyer-Moore":
                                matches = self.boyer_moore_search(data, fmt, name)
                            elif algorithm == "KMP":
                                matches = self.kmp_search(data, fmt, name)
                            elif algorithm == "Regex":
                                matches = self.regex_search(data, fmt, name)
                            else:  # Binary Pattern
                                matches = self.binary_pattern_search(data, fmt, name)
                            
                            if matches:
                                self.search_results.append((packet, matches))
                                break  # Found at least one match in this packet
                
                # Update UI with results
                self.master.after(0, self.update_search_results)
                
            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
                messagebox.showerror("Error", f"Search failed: {str(e)}")
        
        threading.Thread(target=search_thread, daemon=True).start()
    
    def update_search_results(self):
        # Clear and populate packet list with search results
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        for packet, matches in self.search_results:
            try:
                no = packet.number
                time = packet.sniff_time.strftime('%H:%M:%S.%f')[:-3]
                source = packet.ip.src if hasattr(packet, 'ip') else "N/A"
                dest = packet.ip.dst if hasattr(packet, 'ip') else "N/A"
                protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else packet.highest_layer
                length = packet.length
                
                # Create info with match details
                match_info = ", ".join([f"{name} at 0x{offset:x}" for name, offset, _ in matches])
                info = f"Found: {match_info}"
                
                self.packet_tree.insert("", "end", values=(no, time, source, dest, protocol, length, info))
            except Exception as e:
                print(f"Error adding search result: {e}")
        
        self.status_var.set(f"Found {len(self.search_results)} packets with matching structures")
    
    def matches_filter(self, packet, filter_text):
        """Simple filter implementation"""
        filter_parts = filter_text.lower().split()
        
        # Convert packet to string for simple text search
        packet_str = str(packet).lower()
        
        # All parts must match
        for part in filter_parts:
            if part not in packet_str:
                return False
        return True
    
    # Search algorithm implementations
    def boyer_moore_search(self, data, fmt, name):
        """Boyer-Moore string search algorithm adapted for structure detection"""
        results = []
        struct_size = struct.calcsize(fmt)
        
        # For simplicity, search for patterns of printable strings in the format
        # In a real implementation, we would use actual Boyer-Moore for better performance
        for offset in range(len(data) - struct_size + 1):
            try:
                chunk = data[offset:offset+struct_size]
                values = struct.unpack(fmt, chunk)
                
                # Check for valid/reasonable values
                for v in values:
                    if isinstance(v, bytes) and all(32 <= b <= 126 for b in v if b != 0):
                        results.append((name, offset, values))
                        break
                    elif isinstance(v, int) and -10000000 < v < 10000000:
                        results.append((name, offset, values))
                        break
            except:
                continue
        
        return results
    
    def kmp_search(self, data, fmt, name):
        """Knuth-Morris-Pratt algorithm for structure detection"""
        # For simplicity, we'll reuse the Boyer-Moore implementation
        # In a real tool, this would be a proper KMP implementation
        return self.boyer_moore_search(data, fmt, name)
    
    def regex_search(self, data, fmt, name):
        """Regular expression-based search"""
        results = []
        struct_size = struct.calcsize(fmt)
        
        # Convert format to a regex pattern (simplified approach)
        # In a real tool, this would be more sophisticated
        for offset in range(len(data) - struct_size + 1):
            try:
                chunk = data[offset:offset+struct_size]
                values = struct.unpack(fmt, chunk)
                
                # Look for strings that match common patterns
                for v in values:
                    if isinstance(v, bytes):
                        # Look for printable strings, IP addresses, etc.
                        try:
                            s = v.decode('utf-8').rstrip('\x00')
                            if re.match(r'^[\w\-\.]+$', s) and len(s) > 3:
                                results.append((name, offset, values))
                                break
                        except:
                            pass
            except:
                continue
        
        return results
    
    def binary_pattern_search(self, data, fmt, name):
        """Binary pattern matching for structures"""
        results = []
        struct_size = struct.calcsize(fmt)
        
        # A more direct approach - look for specific binary patterns
        # For demo purposes, we'll use common headers or magic numbers
        # In a real tool, this would be customizable
        
        # Check if any known binary patterns exist for this structure
        if name in self.known_patterns:
            pattern = self.known_patterns[name].get('binary_pattern')
            if pattern:
                # Convert hex string to bytes
                try:
                    pattern_bytes = bytes.fromhex(pattern.replace(' ', ''))
                    
                    # Find all occurrences
                    idx = 0
                    while idx < len(data) - len(pattern_bytes) + 1:
                        if data[idx:idx+len(pattern_bytes)] == pattern_bytes:
                            # Try to unpack the full structure
                            try:
                                values = struct.unpack(fmt, data[idx:idx+struct_size])
                                results.append((name, idx, values))
                            except:
                                pass
                        idx += 1
                except:
                    pass
        
        # If no pattern defined or no matches, fall back to general search
        if not results:
            return self.boyer_moore_search(data, fmt, name)
        
        return results
    
    def load_known_patterns(self):
        """Load known patterns from config file"""
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "structure_patterns.json")
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    self.structures = config.get('structures', {})
                    self.known_patterns = config.get('patterns', {})
                    self.update_structure_list()
            except Exception as e:
                print(f"Error loading patterns: {e}")
                # Initialize with some common structures
                self.initialize_default_structures()
        else:
            self.initialize_default_structures()
    
    def initialize_default_structures(self):
        """Initialize with default common structures"""
        self.structures = {
            "IPv4_Header": "!BBHHHBBH4s4s",
            "TCP_Header": "!HHLLBBHHH",
            "UDP_Header": "!HHHH",
            "Ethernet_Header": "!6s6sH",
            "HTTP_Request": "4s60s8s",
        }
        
        self.known_patterns = {
            "IPv4_Header": {
                "binary_pattern": "45 00",  # Common IPv4 version and header length
                "description": "IPv4 Packet Header"
            },
            "HTTP_Request": {
                "binary_pattern": "47 45 54 20",  # "GET "
                "description": "HTTP GET Request"
            }
        }
        
        self.update_structure_list()
    
    def save_known_patterns(self):
        """Save patterns to config file"""
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "structure_patterns.json")
        
        config = {
            'structures': self.structures,
            'patterns': self.known_patterns
        }
        
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Error saving patterns: {e}")

def main():
    root = tk.Tk()
    app = MemoryStructureInspector(root)
    root.mainloop()

if __name__ == "__main__":
    main()