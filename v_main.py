import os
import sys
import struct
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import pyshark
from collections import defaultdict
import threading

class StructurePatternAnalyzer:
    def __init__(self, master):
        self.master = master
        self.master.title("Memory Structure Pattern Analyzer")
        self.master.geometry("1200x800")
        
        # Initialize variables
        self.capture_files = []
        self.structures = {}
        self.patterns = {}
        self.structure_instances = defaultdict(list)
        self.correlations = {}
        
        # Load known structures from shared config
        self.load_known_structures()
        
        # Create GUI
        self.create_gui()
    
    def create_gui(self):
        # Create main layout
        main_pane = ttk.PanedWindow(self.master, orient=tk.HORIZONTAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left panel - Controls
        control_frame = ttk.Frame(main_pane)
        main_pane.add(control_frame, weight=1)
        
        # Right panel - Results
        results_frame = ttk.Frame(main_pane)
        main_pane.add(results_frame, weight=2)
        
        # ===== Control Panel =====
        file_frame = ttk.LabelFrame(control_frame, text="PCAP Files")
        file_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.file_listbox = tk.Listbox(file_frame, height=5)
        self.file_listbox.pack(fill=tk.X, padx=5, pady=5)
        
        file_buttons = ttk.Frame(file_frame)
        file_buttons.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Button(file_buttons, text="Add File", command=self.add_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_buttons, text="Remove File", command=self.remove_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(file_buttons, text="Clear All", command=self.clear_files).pack(side=tk.LEFT, padx=5)
        
        # Structures frame
        struct_frame = ttk.LabelFrame(control_frame, text="Structure Definitions")
        struct_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.struct_tree = ttk.Treeview(struct_frame, columns=("name", "format"), show="headings")
        self.struct_tree.heading("name", text="Name")
        self.struct_tree.heading("format", text="Format")
        self.struct_tree.column("name", width=120, anchor=tk.W)
        self.struct_tree.column("format", width=200, anchor=tk.W)
        
        struct_scrollbar = ttk.Scrollbar(struct_frame, orient=tk.VERTICAL, command=self.struct_tree.yview)
        self.struct_tree.configure(yscrollcommand=struct_scrollbar.set)
        
        struct_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.struct_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Structure edit frame
        edit_frame = ttk.LabelFrame(control_frame, text="Edit Structure")
        edit_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(edit_frame, text="Name:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.struct_name_var = tk.StringVar()
        ttk.Entry(edit_frame, textvariable=self.struct_name_var).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(edit_frame, text="Format:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.struct_format_var = tk.StringVar()
        ttk.Entry(edit_frame, textvariable=self.struct_format_var).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        
        ttk.Label(edit_frame, text="Signature Pattern:").grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)
        self.signature_var = tk.StringVar()
        ttk.Entry(edit_frame, textvariable=self.signature_var).grid(row=2, column=1, padx=5, pady=5, sticky=tk.W+tk.E)
        ttk.Label(edit_frame, text="(hex bytes, e.g. 'FF EE DD')").grid(row=2, column=2, padx=5, pady=5, sticky=tk.W)
        
        button_frame = ttk.Frame(edit_frame)
        button_frame.grid(row=3, column=0, columnspan=3, padx=5, pady=5)
        
        ttk.Button(button_frame, text="Add/Update Structure", command=self.add_update_structure).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Structure", command=self.delete_structure).pack(side=tk.LEFT, padx=5)
        
        # Analysis controls
        analysis_frame = ttk.LabelFrame(control_frame, text="Analysis Controls")
        analysis_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(analysis_frame, text="Sample Size:").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        self.sample_var = tk.StringVar(value="1000")
        ttk.Entry(analysis_frame, textvariable=self.sample_var, width=10).grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        
        ttk.Label(analysis_frame, text="Min Confidence:").grid(row=1, column=0, padx=5, pady=5, sticky=tk.W)
        self.confidence_var = tk.StringVar(value="80")
        ttk.Entry(analysis_frame, textvariable=self.confidence_var, width=10).grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)
        ttk.Label(analysis_frame, text="%").grid(row=1, column=2, sticky=tk.W)
        
        ttk.Button(analysis_frame, text="Analyze Patterns", command=self.analyze_patterns).grid(row=2, column=0, columnspan=3, padx=5, pady=5)
        
        # ===== Results Panel =====
        results_notebook = ttk.Notebook(results_frame)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Patterns tab
        patterns_frame = ttk.Frame(results_notebook)
        results_notebook.add(patterns_frame, text="Structure Patterns")
        
        self.patterns_text = tk.Text(patterns_frame, wrap=tk.WORD)
        patterns_scrollbar = ttk.Scrollbar(patterns_frame, orient=tk.VERTICAL, command=self.patterns_text.yview)
        self.patterns_text.configure(yscrollcommand=patterns_scrollbar.set)
        
        patterns_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.patterns_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Correlation tab
        correlation_frame = ttk.Frame(results_notebook)
        results_notebook.add(correlation_frame, text="Structure Correlations")
        
        # We'll add a matplotlib figure for visualizing correlations
        self.correlation_figure = plt.Figure(figsize=(6, 5), dpi=100)
        self.correlation_canvas = FigureCanvasTkAgg(self.correlation_figure, correlation_frame)
        self.correlation_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Statistics tab
        stats_frame = ttk.Frame(results_notebook)
        results_notebook.add(stats_frame, text="Statistics")
        
        self.stats_tree = ttk.Treeview(stats_frame, columns=("structure", "count", "avg_offset", "correlation"), show="headings")
        self.stats_tree.heading("structure", text="Structure")
        self.stats_tree.heading("count", text="Instances")
        self.stats_tree.heading("avg_offset", text="Avg Offset")
        self.stats_tree.heading("correlation", text="Correlation Score")
        
        stats_scrollbar = ttk.Scrollbar(stats_frame, orient=tk.VERTICAL, command=self.stats_tree.yview)
        self.stats_tree.configure(yscrollcommand=stats_scrollbar.set)
        
        stats_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.stats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Initialize structure tree
        self.update_structure_tree()
        
        # Bind selection event
        self.struct_tree.bind("<<TreeviewSelect>>", self.on_structure_select)
    
    def load_known_structures(self):
        """Load structures from shared config file"""
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "structure_patterns.json")
        
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    self.structures = config.get('structures', {})
                    self.patterns = config.get('patterns', {})
            except Exception as e:
                print(f"Error loading structures: {e}")
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
        
        self.patterns = {
            "IPv4_Header": {
                "binary_pattern": "45 00",
                "description": "IPv4 Packet Header"
            },
            "HTTP_Request": {
                "binary_pattern": "47 45 54 20",
                "description": "HTTP GET Request"
            }
        }
    
    def save_structures(self):
        """Save structures to shared config file"""
        config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "structure_patterns.json")
        
        config = {
            'structures': self.structures,
            'patterns': self.patterns
        }
        
        try:
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Error saving structures: {e}")
            messagebox.showerror("Error", f"Failed to save structures: {str(e)}")
    
    def update_structure_tree(self):
        """Update the structure treeview with current structures"""
        # Clear tree
        for item in self.struct_tree.get_children():
            self.struct_tree.delete(item)
        
        # Add structures
        for name, fmt in self.structures.items():
            self.struct_tree.insert("", "end", values=(name, fmt))
    
    def on_structure_select(self, event):
        """Handle structure selection"""
        selected_items = self.struct_tree.selection()
        if not selected_items:
            return
        
        item = selected_items[0]
        name = self.struct_tree.item(item, "values")[0]
        fmt = self.struct_tree.item(item, "values")[1]
        
        self.struct_name_var.set(name)
        self.struct_format_var.set(fmt)
        
        # Set pattern if exists
        if name in self.patterns:
            self.signature_var.set(self.patterns[name].get('binary_pattern', ''))
        else:
            self.signature_var.set('')
    
    def add_file(self):
        """Add PCAP file to analysis"""
        file_paths = filedialog.askopenfilenames(filetypes=[("PCAP files", "*.pcap"), ("PCAPNG files", "*.pcapng"), ("All files", "*.*")])
        
        if not file_paths:
            return
        
        for file_path in file_paths:
            if file_path not in self.capture_files:
                self.capture_files.append(file_path)
                self.file_listbox.insert(tk.END, os.path.basename(file_path))
    
    def remove_file(self):
        """Remove selected file from analysis"""
        selection = self.file_listbox.curselection()
        if not selection:
            return
        
        index = selection[0]
        del self.capture_files[index]
        self.file_listbox.delete(index)
    
    def clear_files(self):
        """Clear all files"""
        self.capture_files = []
        self.file_listbox.delete(0, tk.END)
    
    def add_update_structure(self):
        """Add or update structure definition"""
        name = self.struct_name_var.get()
        fmt = self.struct_format_var.get()
        pattern = self.signature_var.get()
        
        if not name or not fmt:
            messagebox.showerror("Error", "Structure name and format are required")
            return
        
        # Validate format
        try:
            struct.calcsize(fmt)
        except struct.error as e:
            messagebox.showerror("Error", f"Invalid structure format: {str(e)}")
            return
        
        # Add/update structure
        self.structures[name] = fmt
        
        # Add/update pattern if provided
        if pattern:
            if name not in self.patterns:
                self.patterns[name] = {}
            self.patterns[name]['binary_pattern'] = pattern
        
        # Update UI
        self.update_structure_tree()
        
        # Save to config
        self.save_structures()
        
        # Clear form
        self.struct_name_var.set("")
        self.struct_format_var.set("")
        self.signature_var.set("")
        
        messagebox.showinfo("Success", f"Structure '{name}' saved successfully")
    
    def delete_structure(self):
        """Delete selected structure"""
        name = self.struct_name_var.get()
        
        if not name or name not in self.structures:
            messagebox.showerror("Error", "Please select a valid structure")
            return
        
        # Remove structure
        del self.structures[name]
        if name in self.patterns:
            del self.patterns[name]
        
        # Update UI
        self.update_structure_tree()
        
        # Save to config
        self.save_structures()
        
        # Clear form
        self.struct_name_var.set("")
        self.struct_format_var.set("")
        self.signature_var.set("")
        
        messagebox.showinfo("Success", f"Structure '{name}' deleted successfully")
    
    def analyze_patterns(self):
        """Analyze structure patterns across capture files"""
        if not self.capture_files:
            messagebox.showerror("Error", "Please add at least one capture file")
            return
        
        if not self.structures:
            messagebox.showerror("Error", "Please define at least one structure")
            return
        
        # Get analysis parameters
        try:
            sample_size = int(self.sample_var.get())
            min_confidence = float(self.confidence_var.get()) / 100.0
        except ValueError:
            messagebox.showerror("Error", "Invalid sample size or confidence value")
            return
        
        # Clear previous results
        self.structure_instances.clear()
        self.correlations.clear()
        
        # Update status
        self.status_var.set("Analyzing packets...")
        self.master.update_idletasks()
        
        # Analyze in a separate thread
        def analyze_thread():
            try:
                total_packets = 0
                
                # Process each file
                for file_path in self.capture_files:
                    try:
                        # Load capture
                        capture = pyshark.FileCapture(file_path)
                        
                        # Process packets
                        for i, packet in enumerate(capture):
                            if i >= sample_size // len(self.capture_files):
                                break
                            
                            total_packets += 1
                            self.process_packet(packet)
                    except Exception as e:
                        print(f"Error processing {file_path}: {e}")
                        continue
                
                # Calculate correlations
                self.calculate_correlations()
                
                # Update UI with results
                self.master.after(0, self.update_analysis_results)
                
            except Exception as e:
                self.status_var.set(f"Error: {str(e)}")
                messagebox.showerror("Error", f"Analysis failed: {str(e)}")
        
        threading.Thread(target=analyze_thread, daemon=True).start()
    
    def process_packet(self, packet):
        """Process a single packet for structure analysis"""
        if not hasattr(packet, 'binary_data'):
            return
        
        data = packet.binary_data
        found_structures = []
        
        # Search for known structures
        for name, fmt in self.structures.items():
            struct_size = struct.calcsize(fmt)
            
            # First, check for pattern signature if available
            pattern_found = False
            pattern_offset = -1
            
            if name in self.patterns and 'binary_pattern' in self.patterns[name]:
                try:
                    pattern = self.patterns[name]['binary_pattern']
                    pattern_bytes = bytes.fromhex(pattern.replace(' ', ''))
                    
                    # Search for pattern
                    for offset in range(len(data) - len(pattern_bytes) + 1):
                        if data[offset:offset+len(pattern_bytes)] == pattern_bytes:
                            pattern_found = True
                            pattern_offset = offset
                            break
                except Exception as e:
                    print(f"Error processing pattern for {name}: {e}")
            
            # If pattern found, try to parse structure at that offset
            if pattern_found and pattern_offset >= 0:
                if pattern_offset + struct_size <= len(data):
                    try:
                        values = struct.unpack(fmt, data[pattern_offset:pattern_offset+struct_size])
                        # Store for analysis
                        self.structure_instances[name].append({
                            'offset': pattern_offset,
                            'values': values,
                            'packet_id': getattr(packet, 'number', 0)
                        })
                        found_structures.append((name, pattern_offset))
                    except:
                        pass
            else:
                # No pattern or pattern not found - try scanning
                for offset in range(0, len(data) - struct_size + 1, 8):  # Step by 8 bytes for better performance
                    try:
                        chunk = data[offset:offset+struct_size]
                        values = struct.unpack(fmt, chunk)
                        
                        # Check for reasonable values
                        reasonable = False
                        for v in values:
                            if isinstance(v, bytes) and all(32 <= b <= 126 for b in v if b != 0):
                                reasonable = True
                                break
                            elif isinstance(v, int) and -10000000 < v < 10000000:
                                reasonable = True
                        
                        if reasonable:
                            # Store for analysis
                            self.structure_instances[name].append({
                                'offset': offset,
                                'values': values,
                                'packet_id': getattr(packet, 'number', 0)
                            })
                            found_structures.append((name, offset))
                            break  # Only store first occurrence per packet
                    except:
                        continue
        
        # Store structure co-occurrences for correlation analysis
        for i, (struct1, offset1) in enumerate(found_structures):
            for j, (struct2, offset2) in enumerate(found_structures):
                if i < j:  # Only process unique pairs
                    key = f"{struct1}__{struct2}"
                    if key not in self.correlations:
                        self.correlations[key] = {
                            'count': 0,
                            'offset_diff_sum': 0,
                            'offset_diff_count': 0
                        }
                    
                    self.correlations[key]['count'] += 1
                    offset_diff = abs(offset2 - offset1)
                    self.correlations[key]['offset_diff_sum'] += offset_diff
                    self.correlations[key]['offset_diff_count'] += 1
    
    def calculate_correlations(self):
        """Calculate correlation statistics"""
        # Calculate average offset differences
        for key in self.correlations:
            if self.correlations[key]['offset_diff_count'] > 0:
                self.correlations[key]['avg_offset_diff'] = self.correlations[key]['offset_diff_sum'] / self.correlations[key]['offset_diff_count']
            else:
                self.correlations[key]['avg_offset_diff'] = 0
    
    def update_analysis_results(self):
        """Update UI with analysis results"""
        # Clear existing results
        self.patterns_text.delete(1.0, tk.END)
        
        for item in self.stats_tree.get_children():
            self.stats_tree.delete(item)
        
        # Update patterns text
        self.patterns_text.insert(tk.END, "=== Structure Patterns Analysis ===\n\n")
        
        for name, instances in self.structure_instances.items():
            if not instances:
                continue
                
            self.patterns_text.insert(tk.END, f"Structure: {name} ({self.structures[name]})\n")
            self.patterns_text.insert(tk.END, f"Instances found: {len(instances)}\n")
            
            # Calculate average offset
            avg_offset = sum(instance['offset'] for instance in instances) / len(instances)
            self.patterns_text.insert(tk.END, f"Average offset: {avg_offset:.2f} bytes\n")
            
            # Analyze common offset patterns
            offset_counts = defaultdict(int)
            for instance in instances:
                offset_counts[instance['offset']] += 1
            
            # Show most common offsets
            common_offsets = sorted(offset_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            if common_offsets:
                self.patterns_text.insert(tk.END, "Common offsets:\n")
                for offset, count in common_offsets:
                    percentage = (count / len(instances)) * 100
                    self.patterns_text.insert(tk.END, f"  - Offset 0x{offset:x}: {count} instances ({percentage:.1f}%)\n")
            
            # Field value analysis for first few instances
            if instances:
                self.patterns_text.insert(tk.END, "\nSample values:\n")
                for i, instance in enumerate(instances[:3]):
                    self.patterns_text.insert(tk.END, f"  Instance {i+1} at offset 0x{instance['offset']:x}:\n")
                    
                    # Format values
                    for j, value in enumerate(instance['values']):
                        if isinstance(value, bytes):
                            try:
                                s = value.decode('utf-8').rstrip('\x00')
                                if s and all(32 <= ord(c) <= 126 for c in s):
                                    self.patterns_text.insert(tk.END, f"    Field {j}: '{s}'\n")
                                else:
                                    self.patterns_text.insert(tk.END, f"    Field {j}: 0x{value.hex()}\n")
                            except:
                                self.patterns_text.insert(tk.END, f"    Field {j}: 0x{value.hex()}\n")
                        else:
                            self.patterns_text.insert(tk.END, f"    Field {j}: {value}\n")
            
            self.patterns_text.insert(tk.END, "\n" + "-"*50 + "\n\n")
            
            # Add to statistics tree
            correlation_score = 0
            for key in self.correlations:
                if key.startswith(f"{name}__") or key.endswith(f"__{name}"):
                    correlation_score += self.correlations[key]['count']
            
            self.stats_tree.insert("", "end", values=(
                name, 
                len(instances), 
                f"{avg_offset:.2f}", 
                correlation_score
            ))
        
        # Draw correlation matrix
        self.draw_correlation_matrix()
        
        # Update status
        self.status_var.set(f"Analysis complete. Found {sum(len(instances) for instances in self.structure_instances.values())} structure instances.")
    
    def draw_correlation_matrix(self):
        """Draw correlation matrix visualization"""
        # Get unique structure names
        struct_names = list(self.structure_instances.keys())
        if not struct_names:
            return
        
        # Clear figure
        self.correlation_figure.clear()
        ax = self.correlation_figure.add_subplot(111)
        
        # Create correlation matrix
        n = len(struct_names)
        matrix = np.zeros((n, n))
        
        # Fill matrix with correlation counts
        for i, struct1 in enumerate(struct_names):
            for j, struct2 in enumerate(struct_names):
                if i == j:
                    # Self-correlation is the number of instances
                    matrix[i, j] = len(self.structure_instances[struct1])
                else:
                    # Check both directions
                    key1 = f"{struct1}__{struct2}"
                    key2 = f"{struct2}__{struct1}"
                    count = 0
                    if key1 in self.correlations:
                        count = self.correlations[key1]['count']
                    elif key2 in self.correlations:
                        count = self.correlations[key2]['count']
                    matrix[i, j] = count
        
        # Normalize matrix for better visualization
        max_val = matrix.max()
        if max_val > 0:
            norm_matrix = matrix / max_val
        else:
            norm_matrix = matrix
        
        # Create heatmap
        cax = ax.matshow(norm_matrix, cmap='Blues')
        self.correlation_figure.colorbar(cax)
        
        # Add structure names as labels
        ax.set_xticks(np.arange(n))
        ax.set_yticks(np.arange(n))
        ax.set_xticklabels(struct_names, rotation=45, ha="left")
        ax.set_yticklabels(struct_names)
        
        # Add correlation values
        for i in range(n):
            for j in range(n):
                if norm_matrix[i, j] > 0.5:
                    text_color = "white"
                else:
                    text_color = "black"
                ax.text(j, i, f"{int(matrix[i, j])}", ha="center", va="center", color=text_color)
        
        ax.set_title("Structure Correlation Matrix")
        
        # Redraw canvas
        self.correlation_figure.tight_layout()
        self.correlation_canvas.draw()

def main():
    root = tk.Tk()
    app = StructurePatternAnalyzer(root)
    root.mainloop()

if __name__ == "__main__":
    main()