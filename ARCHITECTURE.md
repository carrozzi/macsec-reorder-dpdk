# MACsec Packet Reordering Application - Architecture Guide

## Overview

This application reorders out-of-order MACsec packets based on their Packet Number (PN) from the MACsec SecTAG header. It operates as a transparent "bump-in-the-wire" between two network segments.

## Use Case

MACsec (IEEE 802.1AE) encrypts Ethernet frames and includes anti-replay protection using a Packet Number (PN). Receivers typically reject packets that arrive out of order. This application solves the problem when network paths cause packet reordering, allowing MACsec to work over such links.

### Typical Deployment Scenarios

1. **Multi-path routing**: ECMP or load-balanced links that cause packet reordering
2. **Network devices with buffering**: Switches/routers that may delay certain packets
3. **Asymmetric links**: Traffic taking different paths in each direction
4. **WAN optimization devices**: Devices that may reorder packets during optimization

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
2. After timeout (default 500ms), timeout triggers
3. Skip to minimum buffered PN (101)
4. Drain 101, 102, 103...

## Configuration Parameters

### Compile-Time (main.c)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `MAX_PKT_BURST` | 64 | Packets processed per burst |
| `REORDER_BUFFER_SIZE` | 65536 | Max packets in reorder buffer |
| `RING_SIZE` | 131072 | Size of inter-thread rings |
| `REORDER_TIMEOUT_US` | 500000 | Timeout for lost packets (500ms) |

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

## Tuning Guide

### Understanding the Key Parameters

The three most important parameters to tune are:

1. **REORDER_TIMEOUT_US** - How long to wait for delayed packets
2. **REORDER_BUFFER_SIZE** - How many packets can be buffered
3. **RING_SIZE** - Inter-thread communication capacity

### When to Adjust REORDER_TIMEOUT_US

**Current default: 500,000 µs (500ms)**

| Scenario | Recommended Value |
|----------|-------------------|
| Delays up to 200ms | 300,000 (300ms) |
| Delays up to 400ms | 500,000 (500ms) - default |
| Delays 350-500ms | 600,000-700,000 (600-700ms) |
| Delays up to 1 second | 1,200,000 (1.2s) |

**Signs you need to INCREASE timeout:**
- High "Timeout flushes" counter in stats
- Packets are arriving but being skipped as "lost"
- You know your network has delays longer than current timeout

**Signs you can DECREASE timeout:**
- Very fast network with minimal delay variation
- You want faster recovery from truly lost packets
- Timeout flushes counter stays at 0

### When to Adjust REORDER_BUFFER_SIZE

**Current default: 65,536 packets (64K)**

**Formula for minimum size:**
```
buffer_size > packet_rate × max_delay × delay_percentage
```

**Examples:**
| Packet Rate | Delay | Delay % | Minimum Buffer |
|-------------|-------|---------|----------------|
| 50K pps | 200ms | 5% | 500 packets |
| 50K pps | 500ms | 10% | 2,500 packets |
| 100K pps | 500ms | 10% | 5,000 packets |
| 200K pps | 500ms | 30% | 30,000 packets |

**Signs you need to INCREASE buffer:**
- "INSERT FAILED: buffer full" in debug logs
- High dropped packet count
- Very high packet rates with long delays

**Signs you can DECREASE buffer:**
- Memory constrained system
- Low packet rates
- Short delays
- Low delay percentage

**Memory usage:** ~200 bytes per slot
- 8K buffer = ~1.6MB per direction
- 64K buffer = ~13MB per direction
- 256K buffer = ~52MB per direction

### When to Adjust RING_SIZE

**Current default: 131,072 (128K)**

**Rule of thumb:** At least 2× REORDER_BUFFER_SIZE

**Signs you need to INCREASE:**
- "Enqueue failed" counter increasing in stats
- Bursty traffic patterns causing drops

### Delay Rate Limits

The relationship between delay rate and achievable throughput:

| Delay Rate | Expected Behavior |
|------------|-------------------|
| 1-5% | Full throughput achievable |
| 5-10% | Full throughput, some timeout overhead |
| 10-20% | May see minor throughput reduction |
| 20-30% | Noticeable throughput reduction |
| >30% | Significant throughput impact |

**Why high delay rates cause problems:**

With each timeout event (every ~50ms of blocked progress), we can only skip one gap. With 30% delay rate at 50K pps, there are ~15,000 gaps per second, but we can only handle ~20 gaps per second through timeouts.

## Important: Downstream MACsec Anti-Replay

**Even when this application correctly reorders packets, you may still see packet loss at the receiving MACsec endpoint.**

### Why This Happens

MACsec receivers maintain an **anti-replay window** - a range of acceptable packet numbers. When packets arrive:

1. PN within window → Accepted
2. PN below window → Rejected (too old)
3. PN above window → Accepted, window advances

### The Problem

Even if we reorder packets perfectly:

1. Source sends PN 1000, 1001, 1002, 1003...
2. PN 1001 is delayed by 200ms
3. Our app receives: 1000, 1002, 1003, 1004... (holding, waiting for 1001)
4. After delay, 1001 arrives, we release: 1000, 1001, 1002, 1003, 1004...
5. MACsec receiver gets packets in order ✓

But if the delay mechanism is **before** MACsec encryption (not our case) or if there's **additional delay after our app**, the receiver's window may have advanced.

### Testing Observation

In testing with 2 Gbps UDP traffic and 5% delay at 200ms:
- **Our app**: 21M packets in, 21M packets out, 0 drops
- **iperf receiver**: 5.5% loss

The loss matched the delay rate, indicating the receiving MACsec implementation (Linux software MACsec) was rejecting packets despite correct ordering.

### Solutions

1. **Use hardware MACsec** - Switches with hardware MACsec typically have larger/configurable replay windows
2. **Check receiver replay window** - Some implementations allow configuring the window size
3. **Reduce delay percentage** - Lower delay rates cause fewer issues
4. **Accept some loss** - For some applications, small loss is acceptable

## Troubleshooting

### "Timeout flushes" keeps increasing
- Packets are being lost or delayed beyond timeout
- Check network path for packet loss
- Consider increasing `REORDER_TIMEOUT_US`

### "INSERT FAILED: seq out of range"
- Packet PN is too far from expected
- May indicate sequence number wraparound issues
- Check if MACsec session was reset
- Consider increasing `REORDER_BUFFER_SIZE`

### "INSERT FAILED: buffer full"
- Too many packets buffered waiting for missing ones
- Increase `REORDER_BUFFER_SIZE`
- Or investigate why packets are consistently lost

### High "Dropped packets"
- Rings are full (workers producing faster than consumers)
- Increase `RING_SIZE`
- Add more worker threads

### Loss at receiver matches delay percentage
- Downstream MACsec anti-replay is rejecting packets
- Check receiver's replay window configuration
- Consider hardware MACsec with larger windows

### Application exits unexpectedly
- Check for SIGINT/SIGTERM signals
- Verify no other process is killing it
- Check system logs for OOM killer activity

## Performance Considerations

### CPU Core Assignment

Recommended minimum cores:
- 2 worker threads (1 per port)
- 2 reorder threads (1 per direction)
- 2 TX threads (1 per port)
- 1 stats thread (optional)
- **Total: 6-7 cores minimum**

For higher throughput:
- Add more worker threads per port (with multiple RX queues)
- Use NUMA-aware core assignment

### Memory Requirements

| Component | Size |
|-----------|------|
| Reorder buffers (2×) | ~26 MB (at 64K default) |
| Rings (4×) | ~4 MB (at 128K default) |
| Packet pool | ~1.5 GB (at default size) |
| **Total** | ~1.6 GB |

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
