# MACsec Packet Reordering Application - Architecture Guide

## Overview

This application reorders out-of-order MACsec packets based on their Packet Number (PN) from the MACsec SecTAG header. It operates as a transparent "bump-in-the-wire" between two network segments.

## Use Case

MACsec (IEEE 802.1AE) encrypts Ethernet frames and includes anti-replay protection using a Packet Number (PN). Receivers typically reject packets that arrive out of order. This application solves the problem when network paths cause packet reordering, allowing MACsec to work over such links.

## Architecture Diagram

```
                        DIRECTION: Port 1 → Port 2
    ┌─────────────────────────────────────────────────────────────────┐
    │                                                                 │
    │   Port 1 (RX)                                     Port 2 (TX)   │
    │       │                                                ▲        │
    │       ▼                                                │        │
    │   ┌─────────┐      ┌──────────────┐      ┌──────────┐ │        │
    │   │ Worker  │─────▶│ Reorder Ring │─────▶│ Reorder  │─┼────┐   │
    │   │ Thread  │      └──────────────┘      │ Thread   │ │    │   │
    │   │ (lcore) │                            │ (lcore)  │ │    │   │
    │   └─────────┘                            └──────────┘ │    │   │
    │       │                                       │       │    │   │
    │       │ (non-MACsec)                         │       │    │   │
    │       ▼                                       ▼       │    │   │
    │   ┌──────────┐                          ┌──────────┐ │    │   │
    │   │ TX Ring  │─────────────────────────▶│ TX Thread│─┘    │   │
    │   │ (Port 2) │                          │ (lcore)  │      │   │
    │   └──────────┘                          └──────────┘      │   │
    │                                                            │   │
    └────────────────────────────────────────────────────────────┼───┘
                                                                 │
                        DIRECTION: Port 2 → Port 1               │
    ┌────────────────────────────────────────────────────────────┼───┐
    │                                                            │   │
    │   Port 2 (RX)                                     Port 1 (TX)  │
    │       │                                                ▲   │   │
    │       ▼                                                │   │   │
    │   ┌─────────┐      ┌──────────────┐      ┌──────────┐ │   │   │
    │   │ Worker  │─────▶│ Reorder Ring │─────▶│ Reorder  │─┼───┘   │
    │   │ Thread  │      └──────────────┘      │ Thread   │ │       │
    │   │ (lcore) │                            │ (lcore)  │ │       │
    │   └─────────┘                            └──────────┘ │       │
    │       │                                       │       │       │
    │       │ (non-MACsec)                         │       │       │
    │       ▼                                       ▼       │       │
    │   ┌──────────┐                          ┌──────────┐ │       │
    │   │ TX Ring  │─────────────────────────▶│ TX Thread│─┘       │
    │   │ (Port 1) │                          │ (lcore)  │         │
    │   └──────────┘                          └──────────┘         │
    │                                                               │
    └───────────────────────────────────────────────────────────────┘
```

## Thread Model

The application uses a multi-threaded pipeline with each thread type running on dedicated CPU cores:

### 1. Worker Threads
- **Role**: Receive packets from NIC, classify, and route
- **Count**: One per RX queue per port (configurable via `-q`)
- **Actions**:
  - Poll NIC RX queue using `rte_eth_rx_burst()`
  - Check if packet is MACsec (ethertype 0x88E5)
  - Extract Packet Number (PN) from MACsec SecTAG
  - Send MACsec packets to reorder ring
  - Send non-MACsec packets directly to TX ring

### 2. Reorder Threads
- **Role**: Reorder MACsec packets by sequence number
- **Count**: One per direction (2 total)
- **Actions**:
  - Receive packets from reorder ring
  - Insert into `rte_reorder` buffer with packet's PN
  - Drain packets in correct order
  - Handle timeout for lost packets
  - Send reordered packets to TX ring

### 3. TX Threads
- **Role**: Transmit packets on NIC
- **Count**: One per port (2 total)
- **Actions**:
  - Receive packets from TX ring
  - Buffer packets using `rte_eth_tx_buffer()`
  - Periodically flush buffer to NIC

### 4. Stats Thread (Optional)
- **Role**: Display statistics periodically
- **Count**: 1 (can be disabled with `-S`)

## Key Data Structures

### rte_reorder_buffer
DPDK's built-in packet reordering library. Key concepts:
- **min_seqn**: Next expected sequence number
- **insert()**: Adds packet to buffer
- **drain()**: Returns packets in order starting from min_seqn

### rte_ring
Lock-free FIFO queues for inter-thread communication:
- `tx_ring_port1/2`: Carry packets to TX threads
- `reorder_ring_p1_p2/p2_p1`: Carry MACsec packets to reorder threads

### expected_seq
Atomic counter tracking the next expected MACsec PN for each direction.

## MACsec Packet Format

```
┌──────────────────┬───────────────────┬─────────────────┐
│ Ethernet Header  │ MACsec SecTAG     │ Encrypted Data  │
│ (14 bytes)       │ (8-16 bytes)      │ (variable)      │
└──────────────────┴───────────────────┴─────────────────┘
                   │
                   ▼
          ┌────────────────────────────────┐
          │ TCI+AN (1B) │ SL (1B) │ PN (4B)│
          │             │         │ ◄───── │ ← We use this!
          │ SCI (8B, optional)             │
          └────────────────────────────────┘
```

The **Packet Number (PN)** is a 32-bit counter that increments with each MACsec packet. This is what we use for reordering.

## Packet Flow

### Normal MACsec Packet (In Order)
1. Worker receives packet from NIC
2. Extracts PN, stores in mbuf metadata
3. Sends to reorder ring
4. Reorder thread inserts into buffer
5. Buffer auto-drains (PN matches expected)
6. Packet sent to TX ring
7. TX thread sends to NIC

### Out-of-Order Packet
1. Packet arrives with PN > expected
2. Inserted into reorder buffer (buffered, not drained)
3. When missing packet arrives, buffer drains in order

### Lost Packet (Timeout)
1. Buffer waiting for PN=100, has PN=101, 102, 103...
2. After 2 seconds, timeout triggers
3. Skip to minimum buffered PN (101)
4. Drain 101, 102, 103...

## Configuration Parameters

### Compile-Time (main.c)
| Parameter | Default | Description |
|-----------|---------|-------------|
| `MAX_PKT_BURST` | 64 | Packets processed per burst |
| `REORDER_BUFFER_SIZE` | 8192 | Max packets in reorder buffer |
| `RING_SIZE` | 16384 | Size of inter-thread rings |
| `REORDER_TIMEOUT_US` | 2000000 | Timeout for lost packets (2 sec) |

### Run-Time (Command Line)
| Option | Description |
|--------|-------------|
| `-p PORTMASK` | Which ports to use (hex, must be exactly 2) |
| `-P` | Enable promiscuous mode |
| `-T PERIOD` | Stats refresh interval (seconds) |
| `-S` | Disable stats thread |
| `-D` | Enable debug logging |
| `-F` | Passthrough mode (no reordering) |
| `-q QUEUES` | RX queues per port |

## Example Usage

```bash
# Basic usage with ports 0 and 1
sudo ./build/macsec-reorder -l 0-9 -n 4 -- -p 0x3 -P

# With debug output
sudo ./build/macsec-reorder -l 0-9 -n 4 -- -p 0x3 -P -D -T 5

# Passthrough mode (for testing delays)
sudo ./build/macsec-reorder -l 0-9 -n 4 -- -p 0x3 -P -F

# 4 RX queues per port
sudo ./build/macsec-reorder -l 0-15 -n 4 -- -p 0x3 -P -q 4
```

## Tuning for Your Environment

### Timeout Value (`REORDER_TIMEOUT_US`)
- Default: 2 seconds (2,000,000 µs)
- Increase if your network has longer delays
- Decrease for faster detection of truly lost packets

### Buffer Size (`REORDER_BUFFER_SIZE`)
- Default: 8192 packets
- Increase if you see "buffer full" warnings
- Must accommodate max expected out-of-order gap

### RX Queues
- More queues = more parallelism
- Requires more CPU cores
- Diminishing returns beyond ~4-8 queues typically

## Troubleshooting

### "Timeout flushes" keeps increasing
- Packets are being lost or delayed beyond timeout
- Check network path for packet loss
- Consider increasing `REORDER_TIMEOUT_US`

### "INSERT FAILED: seq out of range"
- Packet PN is too far from expected
- May indicate sequence number wraparound issues
- Check if MACsec session was reset

### "INSERT FAILED: buffer full"
- Too many packets buffered waiting for missing ones
- Increase `REORDER_BUFFER_SIZE`
- Or investigate why packets are consistently lost

### High "Dropped packets"
- Rings are full (workers producing faster than consumers)
- Increase `RING_SIZE`
- Add more worker threads

## Extending the Code

### Adding Metrics
Statistics are tracked in `struct lcore_stats`. Add new counters there and update `print_stats()`.

### Changing Reorder Algorithm
The `reorder_thread()` function handles all sequencing logic. The timeout skip behavior is controlled there.

### Supporting More Ports
Currently hardcoded to 2 ports. Would need to:
1. Update `parse_args()` to accept more ports
2. Create additional rings and reorder buffers per port pair
3. Launch additional threads

## Dependencies

- DPDK 24.11 or compatible version
- Libraries used:
  - `rte_reorder` - Packet reordering
  - `rte_ring` - Lock-free queues
  - `rte_ethdev` - NIC access
  - `rte_mbuf` - Packet buffers

