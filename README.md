# MACsec Packet Reordering Application

## Overview

This DPDK application uses exactly two network interfaces in a bidirectional forwarding configuration. Packets received on one interface are forwarded to the opposite interface. For MACsec-encapsulated packets, the application detects out-of-order packets by checking packet numbers in the MACsec header, buffers them, and reorders them before transmission.

## Features

- Bidirectional packet forwarding between two interfaces
- Packets received on interface 1 → transmitted on interface 2
- Packets received on interface 2 → transmitted on interface 1
- Detects MACsec-encapsulated packets (ethertype 0x88E5)
- Extracts packet numbers from MACsec SecTAG headers
- Buffers and reorders out-of-order MACsec packets per direction
- Transmits packets in correct order
- Forwards non-MACsec packets immediately without reordering
- Provides statistics on packet processing

## Building

### Using Make (standalone build)

```bash
cd examples/macsec-reorder
make
```

The binary will be created in `build/macsec-reorder`.

### Using Meson (as part of DPDK build)

The application is automatically built when building DPDK with meson.

## Running

The application requires exactly 2 network ports for bidirectional forwarding.

### Basic Usage

```bash
sudo ./build/macsec-reorder -l 0-2 -n 4 -- -p 0x3
```

Where:
- `-l 0-2`: Use cores 0-2
- `-n 4`: Use 4 memory channels
- `-p 0x3`: Port mask (ports 0 and 1 enabled)
  - Port 0: Receives packets → forwards to Port 1
  - Port 1: Receives packets → forwards to Port 0

### Options

- `-p PORTMASK`: Hexadecimal bitmask of ports to configure (must include at least 3 ports)
- `-P`: Enable promiscuous mode on RX ports
- `-T PERIOD`: Statistics refresh period in seconds (0 to disable, default 10)

### Example

```bash
sudo ./build/macsec-reorder -l 0-2 -n 4 -- -p 0x3 -P -T 5
```

This will:
- Use ports 0 and 1 for bidirectional forwarding
- Enable promiscuous mode
- Print statistics every 5 seconds

## How It Works

1. **Bidirectional Packet Reception**: The application reads packets from both ports simultaneously.

2. **Forwarding Logic**:
   - Packets received on Port 1 → forwarded to Port 2
   - Packets received on Port 2 → forwarded to Port 1

3. **MACsec Detection**: Each packet is checked for MACsec encapsulation by examining the ethertype field (0x88E5).

4. **Packet Number Extraction**: For MACsec packets, the application parses the SecTAG header to extract the 32-bit packet number (PN).

5. **Reordering**: MACsec packets are inserted into direction-specific reorder buffers:
   - Port 1 → Port 2: Uses `reorder_buffer_port1_to_port2`
   - Port 2 → Port 1: Uses `reorder_buffer_port2_to_port1`
   - The packet number is used as the sequence number for reordering

6. **Transmission**: 
   - Reordered MACsec packets are drained from the appropriate buffer and transmitted in order
   - Non-MACsec packets are forwarded immediately without reordering
   - Packets that arrive too early (outside the reorder window) are dropped

## MACsec Header Structure

The application supports standard MACsec SecTAG format (IEEE 802.1AE):

```
+-------------------+
| TCI + AN (1 byte) |
+-------------------+
| Short Length (1)  |
+-------------------+
| Packet Number (4) |
+-------------------+
| SCI (8 bytes)     |
| (optional)        |
+-------------------+
```

The packet number is extracted from bytes 2-5 of the SecTAG (after TCI+AN and Short Length).

## Statistics

The application provides the following statistics:

- **RX Port 1 packets**: Total packets received on port 1
- **RX Port 2 packets**: Total packets received on port 2
- **TX Port 1 packets**: Total packets transmitted on port 1
- **TX Port 2 packets**: Total packets transmitted on port 2
- **MACsec packets**: Number of MACsec-encapsulated packets detected
- **Non-MACsec packets**: Number of non-MACsec packets
- **Out-of-order packets**: Packets that arrived too early (outside reorder window)
- **Reordered packets**: Packets successfully reordered and transmitted
- **Dropped packets**: Packets dropped due to errors or buffer full

## Limitations

- Currently supports standard 32-bit packet numbers (XPN/64-bit not fully implemented)
- Early packets (outside reorder window) are dropped rather than buffered
- Reorder buffer size is fixed at 8192 packets per direction
- Single-threaded processing (runs on one lcore)
- Requires exactly 2 ports (not configurable)

## Notes

- The application uses DPDK's experimental reorder API (`rte_reorder_seqn`)
- Requires DPDK with reorder library support
- MACsec packets must have valid SecTAG headers for proper operation
- Non-MACsec packets bypass the reordering mechanism

## Troubleshooting

1. **No packets received**: Check that exactly 2 ports are enabled in portmask and links are up
2. **Packets dropped**: Increase reorder buffer size or check for early packet arrivals
3. **Compilation errors**: Ensure DPDK is properly installed and `pkg-config` can find it
4. **Wrong port count**: The application requires exactly 2 ports. Use portmask like `0x3` (ports 0 and 1) or `0x6` (ports 1 and 2)

