# Memory Structure Inspector
## Advanced Network Binary Structure Analysis Tool

*Version 1.0*

---

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Core Concepts](#core-concepts)
4. [User Interface](#user-interface)
5. [Working with Captures](#working-with-captures)
6. [Defining Structures](#defining-structures)
7. [Search Capabilities](#search-capabilities)
8. [Structure Analysis](#structure-analysis)
9. [Advanced Usage](#advanced-usage)
10. [Troubleshooting](#troubleshooting)
11. [Reference](#reference)

---

## Introduction

The Memory Structure Inspector is a forensic analysis tool designed for network analysts, security researchers, and protocol developers. It enables deep inspection of binary data structures within network traffic, allowing users to define, detect, and analyze custom binary formats across packet captures.

### Key Features

- Load and analyze PCAP/PCAPNG network capture files
- Define and detect custom binary structures using Python's struct format
- Multiple search algorithms for finding structures in packet payloads
- Visual packet inspection with both hex and structure views
- Protocol filtering and custom search expressions
- Save and manage known structure patterns for reuse

### Use Cases

- Reverse engineering proprietary network protocols
- Detecting malformed packets or protocol anomalies
- Identifying data structures in network traffic
- Validating protocol implementations
- Forensic analysis of network captures

---

## Installation

### Prerequisites

- Python 3.6 or higher
- Tkinter (usually included with Python)
- pyshark

### Required Packages

```
pip install pyshark
```

Note: pyshark requires Wireshark to be installed on your system.

### Starting the Application

Run the application by executing the script inside its directory:

```
python PyMeAcc.py
```

---

## Core Concepts

### Binary Structures

The tool uses Python's `struct` module to define binary data structures. These structures are patterns of bytes that follow specific formats, such as network protocol headers, data records, or custom application-specific formats.

### Structure Formats

Structure formats use the same notation as Python's `struct` module:

| Format | C Type | Python Type | Size (bytes) |
|--------|--------|-------------|--------------|
| `B` | unsigned char | integer | 1 |
| `H` | unsigned short | integer | 2 |
| `I` | unsigned int | integer | 4 |
| `L` | unsigned long | integer | 4 |
| `Q` | unsigned long long | integer | 8 |
| `f` | float | float | 4 |
| `d` | double | float | 8 |
| `s` | char[] | bytes | 1 per char |
| `4s` | char[4] | bytes (length 4) | 4 |

Prefix with numbers to indicate array size (e.g., `4s` for a 4-byte string).
Prefix with `!` for network byte order (big-endian).

### Search Algorithms

The tool supports multiple algorithms for locating structures in binary data:

- **Boyer-Moore**: Efficient string matching algorithm, good for general use
- **KMP (Knuth-Morris-Pratt)**: String searching algorithm optimized for repeated pattern matching
- **Regex**: Pattern matching using regular expressions for more complex patterns
- **Binary Pattern**: Direct binary pattern matching for specific byte sequences

---

## User Interface

The Memory Structure Inspector UI is divided into two main panes:

### Left Pane (Controls)

- **File Selection**: Load capture files
- **Structure Definition**: Define binary structures
- **Known Structures**: View and select saved structures
- **Search Controls**: Filter and search for structures

### Right Pane (Results)

- **Packet List**: Display filtered packets
- **Structure View**: Show detected structures
- **Hex View**: Display raw packet bytes

---

## Working with Captures

### Loading a Capture File

1. Click the **Browse** button in the Controls panel
2. Select a PCAP or PCAPNG file
3. Click **Load** to process the file

The tool will load up to 1000 packets from the capture file to maintain performance. For larger files, you may need to use filters to focus on specific traffic of interest.

### Navigating Packets

- Click on a packet in the Packet List to select it
- The Structure View and Hex View will update to show the selected packet
- Scroll through the packet list to browse available packets

### Filtering Packets

Use the **Protocol** dropdown and **Filter** field to narrow down packets:

- Select a protocol (TCP, UDP, HTTP, etc.)
- Enter filter text to match packet content
- Click **Search** to apply filters

---

## Defining Structures

### Creating a New Structure

1. Enter a descriptive **Name**
2. Specify the **Structure Format** using struct notation
3. Click **Add Structure**

Example formats:
- IPv4 Header: `!BBHHHBBH4s4s`
- TCP Header: `!HHLLBBHHH`
- UDP Header: `!HHHH`

### Format Syntax Guide

- `!` - Use network byte order (big-endian)
- `B` - Unsigned byte (8 bits)
- `H` - Unsigned short (16 bits)
- `L` - Unsigned long (32 bits)
- `Q` - Unsigned long long (64 bits)
- `f` - Float (32 bits)
- `d` - Double (64 bits)
- `4s` - 4-byte string
- `s` - Single character string

### Managing Structures

- Select a structure from the **Known Structures** list to edit it
- Structures are automatically saved to a configuration file
- Default structures include common network protocols

---

## Search Capabilities

### Search Algorithms

The tool provides four search algorithms, each with different strengths:

1. **Boyer-Moore**
   - Fast general-purpose algorithm
   - Good for most structure searches
   - Default choice for performance

2. **Knuth-Morris-Pratt (KMP)**
   - Optimized for patterns with repeated elements
   - More efficient for certain structure types

3. **Regex**
   - Pattern matching using regular expressions
   - Useful for complex or flexible patterns
   - Can match structures that have variable components

4. **Binary Pattern**
   - Direct binary pattern matching
   - Most precise when exact byte patterns are known
   - Uses known patterns from the configuration

### Performing a Search

1. Select the desired **Protocol** filter
2. Enter optional custom **Filter** text
3. Choose a **Search Algorithm**
4. Click **Search**

The tool will scan all loaded packets for the defined structures and display matching packets in the Packet List.

### Working with Binary Patterns

For the Binary Pattern algorithm, you can define known patterns in the `structure_patterns.json` configuration file:

```json
{
  "IPv4_Header": {
    "binary_pattern": "45 00",
    "description": "IPv4 Packet Header"
  }
}
```

This tells the tool to look for the hex pattern `45 00` (IPv4 version 4, header length 5 words) when searching for IPv4 headers.

---

## Structure Analysis

### Viewing Detected Structures

1. Select a packet from the Packet List
2. Navigate to the **Structure View** tab
3. Detected structures will be displayed with:
   - Structure name
   - Offset in the packet
   - Format specification
   - Decoded values

### Interpreting Structure Data

For each detected structure, the tool shows:

- **Name and offset**: Where in the packet the structure was found
- **Format**: The struct format string used
- **Values**: Decoded values, with strings shown in quotes

Example output:
```
=== IPv4_Header at offset 0x0e ===
Format: !BBHHHBBH4s4s
Values: 69, 0, 1500, 23567, 0, 64, 6, 30912, b'192.168.1.1', b'10.0.0.1'
```

### Hex View Analysis

The Hex View tab shows the raw packet bytes with:

- Offset address (left column)
- Hexadecimal byte values (middle columns)
- ASCII representation (right column)

This allows you to correlate structure fields with their raw binary representation.

---

## Advanced Usage

### Custom Filtering

The filter field supports simple text matching across packet attributes. For more complex filtering:

- Combine multiple terms (space-separated)
- All terms must match for a packet to be included
- Terms are case-insensitive

### Binary Pattern Definition

To improve structure detection, define binary patterns that identify your structures:

1. Create or modify `structure_patterns.json`
2. Add entries with structure name, binary pattern (hex), and description
3. Use spaces between bytes for readability (`"45 00 00 34"`)

### Working with Large Captures

For captures with more than 1000 packets:

1. Use Wireshark to pre-filter the capture and save a smaller file
2. Apply specific protocol filters when loading
3. Use the custom filter to narrow down packets of interest

---

## Troubleshooting

### Common Issues

**Problem**: Structure not detected in packets
**Solution**: 
- Verify the structure format is correct
- Check packet offset (header structures may start after Ethernet frame)
- Try a different search algorithm
- Define a binary pattern for more precise detection

**Problem**: Application crashes when loading large files
**Solution**:
- Pre-filter captures in Wireshark
- Increase system memory
- Split capture into smaller files

**Problem**: Invalid structure format error
**Solution**:
- Ensure format string follows struct module syntax
- Check that total structure size doesn't exceed packet size
- Verify endianness (use ! for network byte order)

---

## Reference

### Default Structures

| Name | Format | Description |
|------|--------|-------------|
| IPv4_Header | !BBHHHBBH4s4s | IPv4 packet header |
| TCP_Header | !HHLLBBHHH | TCP segment header |
| UDP_Header | !HHHH | UDP datagram header |
| Ethernet_Header | !6s6sH | Ethernet frame header |
| HTTP_Request | 4s60s8s | Simple HTTP request pattern |

### Format Characters

| Format | C Type | Python Type | Size |
|--------|--------|-------------|------|
| x | pad byte | no value | 1 |
| c | char | bytes (length 1) | 1 |
| b | signed char | integer | 1 |
| B | unsigned char | integer | 1 |
| ? | _Bool | bool | 1 |
| h | short | integer | 2 |
| H | unsigned short | integer | 2 |
| i | int | integer | 4 |
| I | unsigned int | integer | 4 |
| l | long | integer | 4 |
| L | unsigned long | integer | 4 |
| q | long long | integer | 8 |
| Q | unsigned long long | integer | 8 |
| n | ssize_t | integer | size |
| N | size_t | integer | size |
| e | | float | 2 |
| f | float | float | 4 |
| d | double | float | 8 |
| s | char[] | bytes | |
| p | char[] | bytes | |
| P | void * | integer | size |

### Search Algorithm Selection Guide

| Algorithm | Best For | Limitations |
|-----------|----------|-------------|
| Boyer-Moore | General searching, good performance | Less precise without patterns |
| KMP | Repeated patterns, consistent structures | Similar limitations to Boyer-Moore |
| Regex | Complex patterns, text-based structures | Slower performance |
| Binary Pattern | Known byte sequences, precise matching | Requires pattern definition |
