# PCAP to NetFlow v5 Exporter

This repository contains a **PCAP to NetFlow v5 Exporter** application, which reads packets from a PCAP file, aggregates them into flows, and exports the resulting flow records to a specified NetFlow collector. The exporter supports active and inactive timeouts to manage flow lifecycle and is implemented in C++ using the **libpcap** library for packet parsing and BSD sockets for sending NetFlow records over UDP.

## Features

- **PCAP Parsing**: Reads raw packets from `.pcap` or `.pcapng` files using libpcap.
- **Flow Aggregation**: Groups packets into flows based on the standard 5-tuple (source IP, destination IP, source port, destination port, protocol).
- **NetFlow v5 Export**: Formats aggregated flow data into NetFlow v5 records and exports them via UDP.
- **Timeout Management**: Implements active and inactive timeouts for flow expiration.
- **Customizable**: Supports command-line parameters for specifying timeouts, collector IP/port, and the input PCAP file.

## Getting Started

### Prerequisites

1. **C++ Compiler**: A C++11-compatible compiler such as `g++`.
2. **libpcap**: Required for reading packets from `.pcap` or `.pcapng` files.
3. **Make** (optional): If you use the provided Makefile to compile.

### Installation

1. **Clone or Download** this repository.
2. **Build** using the provided Makefile:
```make```
This command compiles the exporter and creates an executable named `p2nprobe`.  
*(If you also want to build a simple test UDP server, run `make all`.)*

## Usage
```./p2nprobe <collector_ip>:<collector_port> <pcap_file> [-a <active_timeout> -i <inactive_timeout>]```

- `<collector_ip>:<collector_port>`: IP address and port number of the NetFlow collector.
- `<pcap_file>`: Path to the PCAP or PCAPNG file containing the captured network traffic.
- `-a <active_timeout>`: (Optional) Active timeout in seconds (default: 60).
- `-i <inactive_timeout>`: (Optional) Inactive timeout in seconds (default: 60).

### Example
Exporting flows from example.pcap to a local NetFlow collector listening on 2055
```./p2nprobe 127.0.0.1:2055 example.pcap -a 15 -i 15```

## Usage Scenarios

Below are two example scenarios using `.pcapng` files from [Wireshark Sample Captures](https://wiki.wireshark.org/SampleCaptures).

### 1. `200722_win_scale_examples_anon.pcapng`

**Command**:```./p2nprobe 127.0.0.1:2055 200722_win_scale_examples_anon.pcapng -a 10 -i 5```
**Explanation**:
- **`127.0.0.1:2055`**: Sends NetFlow data to a local collector on port `2055`.
- **`200722_win_scale_examples_anon.pcapng`**: Input file containing window scaling traffic.
- **`-a 10 -i 5`**: Sets active and inactive timeouts for flow expiration.

**Expected Outcome**:
- The NetFlow collector should receive records showing TCP flows with varying TCP window sizes.
- Verify that each flow’s packet count and byte count align with the traffic seen in the pcap.

### 2. `chargen-tcp.pcap`
**Command**:```./p2nprobe 127.0.0.1:2055 chargen-tcp.pcap -a 20 -i 10```

**Explanation**:
- **`127.0.0.1:2055`**: Same local collector setup on port `2055`.
- **`chargen-tcp.pcap`**: Input file with chargen TCP traffic.
- **`-a 20 -i 10`**: Slightly longer active/inactive timeouts to account for the stream-based nature of chargen traffic.

**Expected Outcome**:
- Flows with a repetitive pattern of bytes corresponding to the chargen service.
- Consistent flow records in the collector showing total bytes and packets increasing steadily.

## Testing

### 1. Simple UDP Server (Optional)

A simple `udp_server` can be compiled (via `make all`) and run to see if your NetFlow packets arrive: ```./udp_server```
It listens on port `2055` by default and prints the size of received packets. This helps confirm that **p2nprobe** is sending data, does not parse the NetFlow protocol.

### 2. Using `nfcapd` from NFDUMP

For a full-featured test, run a NetFlow collector      :  `nfcapd -p 2055 -l /tmp/netflow`
Use `nfdump` to analyze the collected NetFlow records  :  `nfdump -r /tmp/netflow/nfcapd.current`

## Contact

- **Author**: Patrik Kiseda
- **Email**: patokiseda@gmail.com
- **GitHub**: PatrikKiseda
