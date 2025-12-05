/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 *
 * MACsec Packet Reordering Application
 * =====================================
 * 
 * PURPOSE:
 * This application reorders out-of-order MACsec packets based on their
 * Packet Number (PN) from the MACsec SecTAG header. It acts as a transparent
 * bump-in-the-wire between two network segments.
 *
 * USE CASE:
 * When MACsec packets traverse network paths that may cause reordering (e.g.,
 * multi-path routing, asymmetric links, or network devices that buffer/delay
 * packets), the receiving MACsec endpoint may reject packets due to anti-replay
 * protection. This application sits inline and reorders packets before they
 * reach the MACsec receiver, ensuring packets arrive in sequence order.
 *
 * ARCHITECTURE OVERVIEW:
 * 
 *   Port 1 (RX)                                              Port 2 (TX)
 *       |                                                        ^
 *       v                                                        |
 *   [Worker Threads] ---> [Reorder Ring] ---> [Reorder Thread] --+
 *       |                                          |             |
 *       +---> [TX Ring] --------------------------+              |
 *                                                                |
 *   Port 2 (RX)                                              Port 1 (TX)
 *       |                                                        ^
 *       v                                                        |
 *   [Worker Threads] ---> [Reorder Ring] ---> [Reorder Thread] --+
 *       |                                          |             |
 *       +---> [TX Ring] --------------------------+              |
 *
 * THREAD MODEL:
 * - Worker Threads: Poll NIC RX queues, extract MACsec PN, send to reorder
 * - Reorder Threads: Collect packets, reorder by PN, send to TX
 * - TX Threads: Batch packets and transmit on NIC
 * - Stats Thread: Periodically print statistics (optional)
 *
 * KEY DATA STRUCTURES:
 * - rte_reorder_buffer: DPDK's built-in packet reordering library
 * - rte_ring: Lock-free FIFO queues for inter-thread communication
 * - expected_seq: Tracks the next expected sequence number per direction
 *
 * IMPORTANT NOTES ON DOWNSTREAM MACSEC:
 * Even when this application correctly reorders packets, you may still see
 * packet loss at the receiving MACsec endpoint. This can happen if:
 * 
 * 1. The MACsec receiver has a small anti-replay window that has already
 *    advanced past delayed packets by the time they arrive (even reordered).
 * 
 * 2. Software MACsec implementations (e.g., Linux macsec) often have fixed,
 *    small replay windows. Hardware MACsec on network switches typically
 *    handles this better with larger/configurable windows.
 * 
 * 3. If you see loss matching your delay rate (e.g., 5% delay = ~5% loss),
 *    check the receiving MACsec device's replay window configuration.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_reorder.h>
#include <rte_ring.h>
#include <rte_atomic.h>

/* Custom log type for this application */
#define RTE_LOGTYPE_MACSEC_REORDER RTE_LOGTYPE_USER1

/*
 * =============================================================================
 * CONSTANTS AND CONFIGURATION
 * =============================================================================
 * 
 * TUNING GUIDE:
 * The parameters below control the reordering behavior. Adjust them based on
 * your network characteristics:
 * 
 * 1. REORDER_BUFFER_SIZE - How many packets can be held waiting for reordering
 *    - Increase if: High packet rates AND long delays (e.g., 100K+ pps with 500ms delay)
 *    - Formula: buffer_size > packet_rate * max_delay * delay_percentage
 *    - Example: 50K pps * 0.5s * 0.30 = 7,500 packets minimum for 30% delay
 *    - Current: 64K packets (handles ~100K pps with 500ms delay at 10% rate)
 * 
 * 2. REORDER_TIMEOUT_US - How long to wait for a missing packet before skipping
 *    - Must be LONGER than your maximum expected packet delay
 *    - Too short: Packets arrive after timeout, get dropped as "late"
 *    - Too long: Throughput suffers when packets are truly lost
 *    - Current: 500ms (works for delays up to ~400ms)
 *    - For 350-500ms delays, increase to 600,000-700,000 (600-700ms)
 * 
 * 3. RING_SIZE - Inter-thread communication buffer size
 *    - Should be at least 2x REORDER_BUFFER_SIZE
 *    - Increase if you see "Enqueue failed" in stats
 * 
 * 4. Delay Rate vs Throughput:
 *    - Low delay rates (1-10%): Full throughput achievable
 *    - High delay rates (>20%): Throughput limited by timeout cycles
 *    - At 30%+ delay rate with high packet rates, expect reduced throughput
 */

/* MACsec ethertype (IEEE 802.1AE) - identifies MACsec-encapsulated frames */
#ifndef RTE_ETHER_TYPE_MACSEC
#define RTE_ETHER_TYPE_MACSEC 0x88E5
#endif

/* Packet processing parameters */
#define MAX_PKT_BURST 64           /* Max packets to process in one burst */
#define BURST_TX_DRAIN_US 100      /* TX buffer drain interval (microseconds) */
#define MEMPOOL_CACHE_SIZE 256     /* Per-core mbuf cache size */

/*
 * REORDER_BUFFER_SIZE: Maximum packets the reorder buffer can hold.
 * 
 * This determines how many "out-of-order" packets can be buffered while
 * waiting for missing packets to arrive. The buffer uses a sliding window
 * based on sequence numbers.
 * 
 * WHEN TO INCREASE:
 * - High packet rates (>50K pps) combined with long delays (>200ms)
 * - Seeing "INSERT FAILED: buffer full" in debug logs
 * - High percentage of delayed packets (>10%)
 * 
 * WHEN TO DECREASE:
 * - Memory constrained systems
 * - Low packet rates or short delays
 * 
 * Memory usage: ~200 bytes per slot (pointers + metadata)
 * Current 64K = ~13MB per reorder buffer (2 buffers total = ~26MB)
 */
#define REORDER_BUFFER_SIZE 65536

/*
 * RING_SIZE: Size of inter-thread communication rings.
 * 
 * Rings connect workers to reorder threads and reorder threads to TX threads.
 * Should be large enough to handle burst traffic without blocking.
 * 
 * WHEN TO INCREASE:
 * - Seeing "Enqueue failed" counter increasing in stats
 * - Very bursty traffic patterns
 * 
 * Rule of thumb: At least 2x REORDER_BUFFER_SIZE
 */
#define RING_SIZE 131072

#define MAX_RX_QUEUES_PER_PORT 8   /* Maximum RX queues per port */

/* 
 * REORDER_TIMEOUT_US: Timeout for lost packets (microseconds).
 * 
 * If a packet hasn't arrived after this time, assume it's lost and skip it.
 * This allows the reorder buffer to make progress when packets are truly lost.
 * 
 * CRITICAL: Must be LONGER than your maximum expected packet delay!
 * 
 * WHEN TO INCREASE:
 * - Packet delays longer than current timeout
 * - Seeing high "Timeout flushes" with packets that should have arrived
 * - For 350-500ms delays, use 600,000-700,000 (600-700ms)
 * 
 * WHEN TO DECREASE:
 * - Delays are shorter and you want faster recovery from true packet loss
 * - Network has minimal delay variation
 * 
 * Current: 500ms (500,000 us) - works for delays up to ~400ms
 */
#define REORDER_TIMEOUT_US 500000

/* NIC descriptor ring sizes */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* Number of RX queues per port (set based on available workers) */
static uint16_t nb_rx_queues = 1;

/*
 * =============================================================================
 * MACSEC HEADER STRUCTURES
 * =============================================================================
 * 
 * MACsec frame format (IEEE 802.1AE):
 * 
 *   +----------------+----------------+------------------+
 *   | Ethernet Hdr   | SecTAG         | Encrypted Data   |
 *   | (14 bytes)     | (8-16 bytes)   | (variable)       |
 *   +----------------+----------------+------------------+
 *                    ^
 *                    |
 *   SecTAG contains the Packet Number (PN) we use for reordering
 */

/* MACsec SecTAG structure (IEEE 802.1AE) */
struct macsec_sectag {
	uint8_t tci_an;    /* TCI (Tag Control Info) + AN (Association Number) */
	uint8_t sl;        /* Short Length field */
	uint32_t pn;       /* Packet Number - THIS IS WHAT WE USE FOR REORDERING */
	uint8_t sci[8];    /* Secure Channel Identifier (optional, depends on TCI) */
} __rte_packed;

/* MACsec TCI flags - used to parse SecTAG correctly */
#define MACSEC_TCI_ES    0x20    /* End Station bit */
#define MACSEC_TCI_SC    0x10    /* Secure Channel bit (SCI present if set) */
#define MACSEC_TCI_SCB   0x08    /* Single Copy Broadcast bit */
#define MACSEC_TCI_E     0x04    /* Encryption bit */
#define MACSEC_TCI_C     0x02    /* Changed Text bit */
#define MACSEC_AN_MASK   0x03    /* Association Number mask */

/*
 * =============================================================================
 * GLOBAL STATE
 * =============================================================================
 */

/* Port IDs - which physical ports to use */
static uint16_t port1 = 0;  /* Traffic Port 1 <-> Port 2 */
static uint16_t port2 = 1;

/* Signal for graceful shutdown */
static volatile bool force_quit;

/* Configuration flags (set via command line) */
static uint64_t timer_period = 10;     /* Stats refresh interval (seconds) */
static int promiscuous_on = 0;         /* Enable promiscuous mode on ports */
static int stats_thread_enabled = 1;   /* Enable statistics thread */
static int debug_mode = 0;             /* Enable verbose debug logging */
static int passthrough_mode = 0;       /* Bypass reordering (for testing) */

/* Memory pool for packet buffers */
static struct rte_mempool *mbuf_pool;

/* 
 * Reorder buffers - one for each traffic direction.
 * The rte_reorder library maintains packets in sequence order and
 * releases them when all preceding packets have arrived.
 */
static struct rte_reorder_buffer *reorder_buffer_port1_to_port2;
static struct rte_reorder_buffer *reorder_buffer_port2_to_port1;

/* TX buffers for packet batching before transmission */
static struct rte_eth_dev_tx_buffer *tx_buffer_port1;
static struct rte_eth_dev_tx_buffer *tx_buffer_port2;

/* 
 * Expected sequence numbers for each direction.
 * Atomic because multiple worker threads may read/update these.
 * 
 * When a packet arrives:
 * - If seq == expected: packet is in order
 * - If seq > expected: packet arrived early (future packet)
 * - If seq < expected: packet arrived late (may have been delayed)
 */
static rte_atomic32_t expected_seq_port1_to_port2 = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t expected_seq_port2_to_port1 = RTE_ATOMIC32_INIT(0);

/* 
 * Flags indicating if expected_seq has been initialized.
 * We initialize expected_seq from the first MACsec packet we see,
 * since we don't know the starting sequence number in advance.
 */
static rte_atomic32_t first_pkt_init_p1_p2 = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t first_pkt_init_p2_p1 = RTE_ATOMIC32_INIT(0);

/*
 * Inter-thread communication rings:
 * - TX rings: carry packets ready for transmission
 * - Reorder rings: carry MACsec packets needing reordering
 */
static struct rte_ring *tx_ring_port1;
static struct rte_ring *tx_ring_port2;
static struct rte_ring *reorder_ring_port1_to_port2;
static struct rte_ring *reorder_ring_port2_to_port1;

/*
 * =============================================================================
 * THREAD ARGUMENT STRUCTURES
 * =============================================================================
 * Each thread type receives a struct with the resources it needs.
 */

/* Arguments passed to each worker thread */
struct worker_thread_args {
	uint16_t port_id;               /* Port to receive from */
	uint16_t dst_port;              /* Destination port (for reference) */
	uint16_t queue_id;              /* Which RX queue to poll */
	struct rte_ring *tx_ring;       /* Ring for non-MACsec or passthrough packets */
	struct rte_ring *reorder_ring;  /* Ring for MACsec packets needing reorder */
	rte_atomic32_t *expected_seq;   /* Shared expected sequence for this direction */
	rte_atomic32_t *first_pkt_init; /* Flag: has expected_seq been initialized? */
	const char *dir_str;            /* "P1->P2" or "P2->P1" for logging */
};

/* Arguments passed to each reorder thread */
struct reorder_thread_args {
	uint16_t dst_port;                      /* Destination port ID */
	struct rte_ring *ring_in;               /* Ring to receive packets from workers */
	struct rte_ring *tx_ring;               /* Ring to send reordered packets to TX */
	struct rte_reorder_buffer *reorder_buf; /* The actual reorder buffer */
	rte_atomic32_t *expected_seq;           /* Shared expected sequence */
	rte_atomic32_t *first_pkt_init;         /* First packet init flag */
	const char *dir_str;                    /* Direction string for logging */
};

/* Arguments passed to each TX thread */
struct tx_thread_args {
	uint16_t port_id;                       /* Port to transmit on */
	struct rte_ring *ring_in;               /* Ring to receive packets from */
	struct rte_eth_dev_tx_buffer *tx_buf;   /* TX buffer for batching */
};

/*
 * =============================================================================
 * STATISTICS
 * =============================================================================
 * Per-lcore statistics, cache-aligned to prevent false sharing.
 */
struct __rte_cache_aligned lcore_stats {
	uint64_t rx_pkts;          /* Total packets received */
	uint64_t tx_pkts;          /* Total packets transmitted */
	uint64_t macsec_pkts;      /* MACsec packets processed */
	uint64_t non_macsec_pkts;  /* Non-MACsec packets (forwarded directly) */
	uint64_t in_order_pkts;    /* Packets that were already in order (fast path) */
	uint64_t out_of_order_pkts;/* Packets that arrived out of order */
	uint64_t dropped_pkts;     /* Packets dropped (queue full, etc.) */
	uint64_t reordered_pkts;   /* Packets successfully reordered and sent */
	uint64_t enqueue_failed;   /* Failed to enqueue to ring */
	uint64_t late_pkts;        /* Packets that arrived after their slot */
	uint64_t timeout_flushed;  /* Packets skipped due to timeout */
	uint64_t cas_retries;      /* Atomic CAS operation retries */
};
static struct lcore_stats lcore_stats_array[RTE_MAX_LCORE];

/*
 * =============================================================================
 * PORT CONFIGURATION
 * =============================================================================
 * RSS (Receive Side Scaling) distributes incoming packets across multiple
 * RX queues based on packet header fields. This enables parallel processing
 * by multiple worker threads.
 */
static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_RSS,  /* Enable RSS for multi-queue RX */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,  /* Use default RSS key */
			.rss_hf = 0,      /* RSS hash functions - set per device */
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE, /* Single TX queue is sufficient */
	},
};

/*
 * =============================================================================
 * PACKET INSPECTION FUNCTIONS
 * =============================================================================
 */

/**
 * Check if a packet is MACsec encapsulated.
 * 
 * MACsec packets have ethertype 0x88E5 in the Ethernet header.
 * 
 * @param m  The packet mbuf to check
 * @return   true if MACsec, false otherwise
 */
static inline bool
is_macsec_packet(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;

	/* Sanity check: packet must be at least Ethernet header size */
	if (unlikely(m->data_len < sizeof(struct rte_ether_hdr)))
		return false;

	/* Get pointer to Ethernet header at start of packet data */
	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	
	/* Check if ethertype matches MACsec (0x88E5) */
	return (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_MACSEC));
}

/**
 * Extract the Packet Number (PN) from a MACsec SecTAG.
 * 
 * The PN is a 32-bit counter that increments with each packet sent.
 * It's used for:
 * 1. Replay protection (receiver rejects old PNs)
 * 2. Our use case: reordering out-of-order packets
 * 
 * @param m   The MACsec packet mbuf
 * @param pn  Output: the extracted packet number
 * @return    true on success, false if packet is malformed
 */
static inline bool
extract_macsec_pn(struct rte_mbuf *m, uint64_t *pn)
{
	struct rte_ether_hdr *eth_hdr;
	struct macsec_sectag *sectag;
	uint16_t ether_type;
	uint32_t offset = sizeof(struct rte_ether_hdr);

	/* Check minimum packet size */
	if (unlikely(m->data_len < offset + sizeof(struct macsec_sectag)))
		return false;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

	/* Handle VLAN-tagged frames: skip 4-byte VLAN tag */
	if (ether_type == RTE_ETHER_TYPE_VLAN) {
		offset += 4;
		if (unlikely(m->data_len < offset + sizeof(struct macsec_sectag)))
			return false;
	}

	/* Get pointer to SecTAG following Ethernet header */
	sectag = (struct macsec_sectag *)((uint8_t *)eth_hdr + offset);
	
	/* Extract and convert PN from network byte order */
	*pn = (uint64_t)rte_be_to_cpu_32(sectag->pn);
	return true;
}

/**
 * Atomically initialize expected_seq with the first packet's sequence number.
 * 
 * Multiple threads may see the first packet simultaneously, so we use
 * atomic compare-and-swap (CAS) to ensure only one thread wins.
 * 
 * @param first_pkt_init  Atomic flag (0 = not initialized, 1 = initialized)
 * @param expected_seq    The expected sequence counter to initialize
 * @param seq             Sequence number from first packet
 * @param dir_str         Direction string for logging
 * @return                true if this thread won the race and initialized
 */
static inline bool
try_init_expected_seq(rte_atomic32_t *first_pkt_init, rte_atomic32_t *expected_seq,
		      uint32_t seq, const char *dir_str)
{
	/* Atomic CAS: try to change first_pkt_init from 0 to 1 */
	if (rte_atomic32_cmpset((volatile uint32_t *)&first_pkt_init->cnt, 0, 1)) {
		/* We won the race - initialize expected_seq to this packet's PN */
		rte_atomic32_set(expected_seq, seq);
		RTE_LOG(INFO, MACSEC_REORDER,
			"[%s] First MACsec pkt: initializing expected_seq to %u\n",
			dir_str, seq);
		return true;
	}
	return false;
}

/*
 * =============================================================================
 * WORKER THREAD
 * =============================================================================
 * Worker threads are the first stage of packet processing:
 * 1. Poll packets from NIC RX queue
 * 2. Classify as MACsec or non-MACsec
 * 3. For MACsec: extract PN and send to reorder buffer
 * 4. For non-MACsec: send directly to TX
 */

/**
 * Worker thread main loop.
 * 
 * Each worker handles one RX queue from one port. Multiple workers can
 * process different queues in parallel. RSS distributes packets across
 * queues to enable this parallelism.
 * 
 * PACKET FLOW:
 *   NIC RX Queue --> Worker --> Reorder Ring (MACsec)
 *                          \--> TX Ring (non-MACsec)
 */
static int
worker_thread(void *arg)
{
	struct worker_thread_args *args = (struct worker_thread_args *)arg;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	uint16_t nb_rx;
	unsigned int lcore_id = rte_lcore_id();
	struct lcore_stats *lcore_stat = &lcore_stats_array[lcore_id];
	uint16_t i;
	uint64_t pn;
	uint32_t seq, expected, new_expected;
	int cas_success;

	RTE_LOG(INFO, MACSEC_REORDER,
		"Worker thread started on lcore %u for port %u queue %u (%s)\n",
		lcore_id, args->port_id, args->queue_id, args->dir_str);

	while (!force_quit) {
		/* 
		 * Poll packets directly from NIC RX queue.
		 * rte_eth_rx_burst is non-blocking - returns 0 if no packets.
		 */
		nb_rx = rte_eth_rx_burst(args->port_id, args->queue_id,
					 pkts, MAX_PKT_BURST);
		if (nb_rx == 0)
			continue;

		lcore_stat->rx_pkts += nb_rx;

		/* Process each received packet */
		for (i = 0; i < nb_rx; i++) {
			struct rte_mbuf *pkt = pkts[i];

			/*
			 * PASSTHROUGH MODE: Forward all packets without reordering.
			 * Useful for debugging to verify the delay mechanism works.
			 */
			if (passthrough_mode) {
				if (is_macsec_packet(pkt)) {
					lcore_stat->macsec_pkts++;
					if (debug_mode && extract_macsec_pn(pkt, &pn)) {
						RTE_LOG(INFO, MACSEC_REORDER,
							"[%s] PASSTHROUGH MACsec seq=%u\n",
							args->dir_str, (uint32_t)pn);
					}
				} else {
					lcore_stat->non_macsec_pkts++;
				}
				/* Send directly to TX ring */
				if (rte_ring_enqueue(args->tx_ring, pkt) != 0) {
					rte_pktmbuf_free(pkt);
					lcore_stat->enqueue_failed++;
					lcore_stat->dropped_pkts++;
				}
				continue;
			}

			/*
			 * NORMAL MODE: Reorder MACsec packets by PN
			 */
			if (is_macsec_packet(pkt)) {
				lcore_stat->macsec_pkts++;

				if (extract_macsec_pn(pkt, &pn)) {
					seq = (uint32_t)pn;
					
					/* 
					 * Store sequence number in mbuf metadata.
					 * rte_reorder uses this to know packet ordering.
					 */
					*rte_reorder_seqn(pkt) = seq;

					/* Initialize expected_seq on first MACsec packet */
					if (rte_atomic32_read(args->first_pkt_init) == 0) {
						try_init_expected_seq(args->first_pkt_init,
								      args->expected_seq,
								      seq, args->dir_str);
					}

					/* Get current expected sequence (for logging) */
					expected = rte_atomic32_read(args->expected_seq);

					if (debug_mode) {
						RTE_LOG(INFO, MACSEC_REORDER,
							"[%s] MACsec pkt: seq=%u, expected=%u, diff=%d\n",
							args->dir_str, seq, expected,
							(int32_t)(seq - expected));
					}

					/*
					 * Send ALL MACsec packets through reorder buffer.
					 * 
					 * Why not use a "fast path" for in-order packets?
					 * - Race condition: if we forward in-order packets directly,
					 *   delayed packets may arrive and be classified as "late"
					 *   because expected_seq raced ahead of them.
					 * - By sending everything through the reorder buffer, we let
					 *   the buffer handle sequencing correctly.
					 */
					if (rte_ring_enqueue(args->reorder_ring, pkt) != 0) {
						rte_pktmbuf_free(pkt);
						lcore_stat->enqueue_failed++;
						lcore_stat->dropped_pkts++;
					}
				} else {
					/* Failed to extract PN - treat as non-MACsec */
					lcore_stat->non_macsec_pkts++;
					if (rte_ring_enqueue(args->tx_ring, pkt) != 0) {
						rte_pktmbuf_free(pkt);
						lcore_stat->enqueue_failed++;
						lcore_stat->dropped_pkts++;
					}
				}
			} else {
				/* Non-MACsec packet - forward directly to TX */
				lcore_stat->non_macsec_pkts++;
				if (rte_ring_enqueue(args->tx_ring, pkt) != 0) {
					rte_pktmbuf_free(pkt);
					lcore_stat->enqueue_failed++;
					lcore_stat->dropped_pkts++;
				}
			}
		}
	}

	return 0;
}

/*
 * =============================================================================
 * REORDER THREAD
 * =============================================================================
 * The reorder thread is responsible for:
 * 1. Receiving MACsec packets from workers via ring
 * 2. Inserting them into the rte_reorder buffer
 * 3. Draining packets in correct sequence order
 * 4. Handling timeouts for lost packets
 * 
 * HOW rte_reorder WORKS:
 * - Maintains min_seqn: the next sequence number to release
 * - insert(): adds packet to internal buffer
 * - drain(): returns packets with seq >= min_seqn in order
 *   - If packet at min_seqn exists, returns it and advances min_seqn
 *   - Continues until a gap is found
 * - min_seqn_set(): manually advance min_seqn (for timeout handling)
 */

/**
 * Reorder thread main loop with timeout handling.
 * 
 * PACKET FLOW:
 *   Reorder Ring --> Insert to rte_reorder --> Drain in order --> TX Ring
 * 
 * TIMEOUT MECHANISM:
 * If no packets drain for REORDER_TIMEOUT_US, we assume a packet is lost
 * and skip ahead to the next available packet in the buffer.
 */
static int
reorder_thread(void *arg)
{
	struct reorder_thread_args *args = (struct reorder_thread_args *)arg;
	struct rte_mbuf *pkts_in[MAX_PKT_BURST];
	struct rte_mbuf *pkts_drained[MAX_PKT_BURST];
	unsigned int nb_deq, nb_drained;
	unsigned int i;
	int ret;
	uint32_t seq, drained_seq, expected_seq;
	unsigned int lcore_id = rte_lcore_id();
	struct lcore_stats *lcore_stat = &lcore_stats_array[lcore_id];
	uint64_t last_progress_tsc, cur_tsc;
	const uint64_t timeout_tsc = (rte_get_tsc_hz() * REORDER_TIMEOUT_US) / 1000000;
	uint32_t last_expected = 0;
	bool has_buffered_pkts = false;
	bool reorder_buf_initialized = false;

	/* 
	 * Track minimum sequence number in the buffer.
	 * Used for "smart skip" on timeout - jump to next available packet
	 * instead of incrementing by 1.
	 */
	uint32_t min_buffered_seq = UINT32_MAX;
	
	RTE_LOG(INFO, MACSEC_REORDER,
		"Reorder thread started on lcore %u for %s (timeout=%u us)\n",
		lcore_id, args->dir_str, REORDER_TIMEOUT_US);

	last_progress_tsc = rte_rdtsc();

	while (!force_quit) {
		/*
		 * Initialize reorder buffer's min_seqn once we know the starting
		 * sequence number (from first packet).
		 */
		if (!reorder_buf_initialized && rte_atomic32_read(args->first_pkt_init) != 0) {
			expected_seq = rte_atomic32_read(args->expected_seq);
			rte_reorder_min_seqn_set(args->reorder_buf,
				(rte_reorder_seqn_t)expected_seq);
			reorder_buf_initialized = true;
			last_expected = expected_seq;
			RTE_LOG(INFO, MACSEC_REORDER,
				"[%s] Reorder buffer initialized with min_seqn=%u\n",
				args->dir_str, expected_seq);
		}
		
		cur_tsc = rte_rdtsc();

		/*
		 * STEP 1: Dequeue packets from workers
		 */
		nb_deq = rte_ring_dequeue_burst(args->ring_in, (void *)pkts_in,
						MAX_PKT_BURST, NULL);

		if (nb_deq > 0) {
			has_buffered_pkts = true;
			
			/* Insert each packet into the reorder buffer */
			for (i = 0; i < nb_deq; i++) {
				struct rte_mbuf *pkt = pkts_in[i];
				seq = *rte_reorder_seqn(pkt);
				expected_seq = rte_atomic32_read(args->expected_seq);

				if (debug_mode) {
					RTE_LOG(INFO, MACSEC_REORDER,
						"[%s] REORDER INSERT: seq=%u, expected=%u\n",
						args->dir_str, seq, expected_seq);
				}

				/*
				 * rte_reorder_insert returns:
				 * 0 on success
				 * -1 on error (ERANGE: out of buffer range, ENOSPC: buffer full)
				 */
				ret = rte_reorder_insert(args->reorder_buf, pkt);
				if (ret == -1) {
					if (rte_errno == ERANGE) {
						RTE_LOG(WARNING, MACSEC_REORDER,
							"[%s] INSERT FAILED: seq=%u out of range\n",
							args->dir_str, seq);
					} else if (rte_errno == ENOSPC) {
						RTE_LOG(WARNING, MACSEC_REORDER,
							"[%s] INSERT FAILED: buffer full\n",
							args->dir_str);
					}
					rte_pktmbuf_free(pkt);
					lcore_stat->dropped_pkts++;
				} else {
					/* Track minimum seq for smart timeout skip */
					if (seq < min_buffered_seq)
						min_buffered_seq = seq;
				}
			}
		}

		/*
		 * STEP 2: Try to drain packets in order
		 * 
		 * rte_reorder_drain returns packets starting from min_seqn,
		 * continuing while consecutive packets are available.
		 */
		nb_drained = rte_reorder_drain(args->reorder_buf, pkts_drained,
					       MAX_PKT_BURST);
		if (nb_drained > 0) {
			lcore_stat->reordered_pkts += nb_drained;
			last_progress_tsc = cur_tsc;  /* Reset timeout timer */
			min_buffered_seq = UINT32_MAX;  /* Reset min tracking */

			if (debug_mode) {
				RTE_LOG(INFO, MACSEC_REORDER,
					"[%s] DRAINED: %u packets\n",
					args->dir_str, nb_drained);
			}

			/* Forward drained packets to TX ring */
			for (i = 0; i < nb_drained; i++) {
				drained_seq = *rte_reorder_seqn(pkts_drained[i]);
				if (rte_ring_enqueue(args->tx_ring, pkts_drained[i]) != 0) {
					rte_pktmbuf_free(pkts_drained[i]);
					lcore_stat->enqueue_failed++;
					lcore_stat->dropped_pkts++;
				}
				/* Update expected_seq to track our progress */
				rte_atomic32_set(args->expected_seq, drained_seq + 1);
			}
			/* Check if there might be more packets */
			has_buffered_pkts = (nb_drained == MAX_PKT_BURST);
		}

		/*
		 * STEP 3: Handle timeout - skip lost packets
		 * 
		 * If we have packets buffered but can't drain (waiting for a
		 * missing packet), and timeout expires, assume packet is lost.
		 * 
		 * CONSERVATIVE SKIP: Only skip to min_buffered_seq (a packet we
		 * KNOW is in the buffer). If we don't have min_buffered_seq,
		 * skip just one packet. Never overshoot beyond known packets.
		 */
		expected_seq = rte_atomic32_read(args->expected_seq);
		if (has_buffered_pkts && (cur_tsc - last_progress_tsc > timeout_tsc)) {
			/* Only timeout if we're actually stuck (expected_seq unchanged) */
			if (expected_seq == last_expected && rte_atomic32_read(args->first_pkt_init) != 0) {
				uint32_t new_expected;
				uint32_t skipped;
				
				/*
				 * Skip to min_buffered_seq if we have it - this is a packet
				 * we KNOW exists in the buffer. Otherwise, skip just 1.
				 */
				if (min_buffered_seq != UINT32_MAX && min_buffered_seq > expected_seq) {
					new_expected = min_buffered_seq;
					skipped = new_expected - expected_seq;
				} else {
					/* Fallback: skip just 1 packet */
					new_expected = expected_seq + 1;
					skipped = 1;
				}
				
				/* Advance reorder buffer */
				rte_reorder_min_seqn_set(args->reorder_buf,
					(rte_reorder_seqn_t)new_expected);
				rte_atomic32_set(args->expected_seq, new_expected);
				lcore_stat->timeout_flushed += skipped;
				
				if (debug_mode) {
					RTE_LOG(WARNING, MACSEC_REORDER,
						"[%s] TIMEOUT: skipping %u packets (%u -> %u), min_buf=%u\n",
						args->dir_str, skipped, expected_seq, new_expected,
						min_buffered_seq);
				}
				
				/* Reset ONLY after using */
				min_buffered_seq = UINT32_MAX;
				
				/* Drain all available packets after skip */
				bool drained_any = false;
				nb_drained = rte_reorder_drain(args->reorder_buf,
					pkts_drained, MAX_PKT_BURST);
				while (nb_drained > 0) {
					drained_any = true;
					lcore_stat->reordered_pkts += nb_drained;
					for (i = 0; i < nb_drained; i++) {
						drained_seq = *rte_reorder_seqn(pkts_drained[i]);
						if (rte_ring_enqueue(args->tx_ring, pkts_drained[i]) != 0) {
							rte_pktmbuf_free(pkts_drained[i]);
							lcore_stat->enqueue_failed++;
							lcore_stat->dropped_pkts++;
						}
						rte_atomic32_set(args->expected_seq, drained_seq + 1);
					}
					nb_drained = rte_reorder_drain(args->reorder_buf,
						pkts_drained, MAX_PKT_BURST);
				}
				
				/* 
				 * Reset timeout timer. If we drained packets, reset normally.
				 * If we didn't drain, add a small delay (1/10 of timeout)
				 * before trying again to allow delayed packets to arrive.
				 */
				if (drained_any) {
					last_progress_tsc = cur_tsc;
				} else {
					/* Didn't drain - wait a fraction of timeout before retry */
					last_progress_tsc = cur_tsc - (timeout_tsc * 9 / 10);
				}
			}
		}
		last_expected = expected_seq;

		/* CPU-friendly pause when idle */
		if (nb_deq == 0 && nb_drained == 0)
			rte_pause();
	}

	return 0;
}

/*
 * =============================================================================
 * TX THREAD
 * =============================================================================
 * TX threads handle the final stage: transmitting packets on the NIC.
 * 
 * Uses buffered TX for efficiency:
 * - Packets are batched in a buffer
 * - Buffer is flushed periodically or when full
 * - Batch transmission is more efficient than per-packet TX
 */

/**
 * TX thread main loop.
 * 
 * PACKET FLOW:
 *   TX Ring --> TX Buffer --> NIC TX Queue
 */
static int
tx_thread(void *arg)
{
	struct tx_thread_args *args = (struct tx_thread_args *)arg;
	uint16_t port_id = args->port_id;
	struct rte_ring *ring_in = args->ring_in;
	struct rte_eth_dev_tx_buffer *tx_buf = args->tx_buf;
	struct rte_mbuf *pkts_ring[MAX_PKT_BURST];
	unsigned int nb_deq;
	unsigned int i;
	int sent;
	uint64_t prev_tsc, cur_tsc, diff_tsc;
	/* Calculate cycles for TX drain interval */
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	unsigned int lcore_id = rte_lcore_id();
	struct lcore_stats *lcore_stat = &lcore_stats_array[lcore_id];

	prev_tsc = rte_rdtsc();

	RTE_LOG(INFO, MACSEC_REORDER, "TX thread started on lcore %u for port %u\n",
		lcore_id, port_id);

	while (!force_quit) {
		cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;

		/* Periodically flush TX buffer to avoid latency */
		if (unlikely(diff_tsc > drain_tsc)) {
			sent = rte_eth_tx_buffer_flush(port_id, 0, tx_buf);
			if (sent)
				lcore_stat->tx_pkts += sent;
			prev_tsc = cur_tsc;
		}

		/* Dequeue packets from ring */
		nb_deq = rte_ring_dequeue_burst(ring_in, (void *)pkts_ring,
						MAX_PKT_BURST, NULL);

		if (nb_deq > 0) {
			/* Add packets to TX buffer (may trigger transmission) */
			for (i = 0; i < nb_deq; i++) {
				sent = rte_eth_tx_buffer(port_id, 0, tx_buf, pkts_ring[i]);
				if (sent)
					lcore_stat->tx_pkts += sent;
			}
		}
	}

	return 0;
}

/*
 * =============================================================================
 * STATISTICS THREAD
 * =============================================================================
 */

static void print_stats(void);

/**
 * Statistics thread - periodically prints statistics to console.
 */
static int
stats_thread(__rte_unused void *arg)
{
	uint64_t prev_tsc, cur_tsc, timer_tsc;
	uint64_t timer_period_cycles = timer_period * rte_get_timer_hz();

	prev_tsc = rte_rdtsc();
	timer_tsc = 0;

	RTE_LOG(INFO, MACSEC_REORDER, "Stats thread started on lcore %u\n",
		rte_lcore_id());

	while (!force_quit) {
		cur_tsc = rte_rdtsc();
		uint64_t diff_tsc = cur_tsc - prev_tsc;

		timer_tsc += diff_tsc;
		if (unlikely(timer_tsc >= timer_period_cycles)) {
			print_stats();
			timer_tsc = 0;
		}

		prev_tsc = cur_tsc;
		rte_delay_us_sleep(100000);  /* Sleep 100ms between checks */
	}

	return 0;
}

/**
 * Print aggregated statistics from all lcores.
 */
static void
print_stats(void)
{
	const char clr[] = { 27, '[', '2', 'J', '\0' };       /* Clear screen */
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' }; /* Cursor home */
	uint64_t total_rx = 0, total_tx = 0;
	uint64_t total_macsec = 0, total_non_macsec = 0;
	uint64_t total_in_order = 0, total_out_of_order = 0;
	uint64_t total_dropped = 0, total_reordered = 0;
	uint64_t total_enq_failed = 0, total_late_pkts = 0;
	uint64_t total_timeout = 0, total_cas_retries = 0;
	unsigned int lcore_id;

	/* Aggregate statistics from all lcores */
	RTE_LCORE_FOREACH(lcore_id) {
		struct lcore_stats *stat = &lcore_stats_array[lcore_id];
		total_rx += stat->rx_pkts;
		total_tx += stat->tx_pkts;
		total_macsec += stat->macsec_pkts;
		total_non_macsec += stat->non_macsec_pkts;
		total_in_order += stat->in_order_pkts;
		total_out_of_order += stat->out_of_order_pkts;
		total_dropped += stat->dropped_pkts;
		total_reordered += stat->reordered_pkts;
		total_enq_failed += stat->enqueue_failed;
		total_late_pkts += stat->late_pkts;
		total_timeout += stat->timeout_flushed;
		total_cas_retries += stat->cas_retries;
	}

	/* Get current expected sequence numbers */
	uint32_t exp_seq_p1_p2 = rte_atomic32_read(&expected_seq_port1_to_port2);
	uint32_t exp_seq_p2_p1 = rte_atomic32_read(&expected_seq_port2_to_port1);
	int init_p1_p2 = rte_atomic32_read(&first_pkt_init_p1_p2);
	int init_p2_p1 = rte_atomic32_read(&first_pkt_init_p2_p1);

	printf("%s%s", clr, topLeft);

	printf("\n============== MACsec Reorder Statistics ==============\n");
	printf("RX queues per port:        %20u\n", nb_rx_queues);
	printf("Total RX packets:          %20" PRIu64 "\n", total_rx);
	printf("Total TX packets:          %20" PRIu64 "\n", total_tx);
	printf("MACsec packets:            %20" PRIu64 "\n", total_macsec);
	printf("Non-MACsec packets:        %20" PRIu64 "\n", total_non_macsec);
	printf("In-order packets (fast):   %20" PRIu64 "\n", total_in_order);
	printf("Out-of-order packets:      %20" PRIu64 "\n", total_out_of_order);
	printf("Reordered packets:         %20" PRIu64 "\n", total_reordered);
	printf("Late packets (dropped):    %20" PRIu64 "\n", total_late_pkts);
	printf("Timeout flushes:           %20" PRIu64 "\n", total_timeout);
	printf("Dropped packets (total):   %20" PRIu64 "\n", total_dropped);
	printf("Enqueue failed:            %20" PRIu64 "\n", total_enq_failed);
	printf("CAS retries:               %20" PRIu64 "\n", total_cas_retries);
	printf("--------------------------------------------------------\n");
	printf("Expected seq P1->P2:       %20u%s\n", exp_seq_p1_p2,
		init_p1_p2 ? "" : " (not initialized)");
	printf("Expected seq P2->P1:       %20u%s\n", exp_seq_p2_p1,
		init_p2_p1 ? "" : " (not initialized)");
	printf("========================================================\n");

	fflush(stdout);
}

/*
 * =============================================================================
 * SIGNAL HANDLING
 * =============================================================================
 */

static void
signal_handler(int signum)
{
	if (signum == SIGUSR1) {
		/* SIGUSR1: Print stats on demand */
		print_stats();
	} else if (signum == SIGINT || signum == SIGTERM) {
		/* Ctrl+C or kill: Graceful shutdown */
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

/*
 * =============================================================================
 * COMMAND LINE PARSING
 * =============================================================================
 */

static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-P] [-T PERIOD] [-S] [-D] [-F] [-q QUEUES]\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"              (must include exactly 2 ports)\n"
		"  -P: Enable promiscuous mode\n"
		"  -T PERIOD: statistics refresh period in seconds (0 to disable, default 10)\n"
		"  -S: Disable statistics thread\n"
		"  -D: Enable debug mode (verbose packet sequence logging)\n"
		"  -F: Passthrough mode (forward all packets without reordering)\n"
		"  -q QUEUES: Number of RX queues per port (default: auto based on cores)\n",
		prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

static int
parse_args(int argc, char **argv)
{
	int opt;
	char **argvopt;
	char *prgname = argv[0];
	uint32_t portmask = 0;
	int queues_specified = 0;

	argvopt = argv;

	while ((opt = getopt(argc, argvopt, "p:PT:SDFq:")) != EOF) {
		switch (opt) {
		case 'p':
			portmask = parse_portmask(optarg);
			if (portmask == 0) {
				printf("invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case 'P':
			promiscuous_on = 1;
			break;
		case 'T': {
			unsigned long tmp = strtoul(optarg, NULL, 10);
			if (tmp > 86400) {
				printf("invalid timer period (max 86400)\n");
				return -1;
			}
			timer_period = tmp;
			break;
		}
		case 'S':
			stats_thread_enabled = 0;
			break;
		case 'D':
			debug_mode = 1;
			break;
		case 'F':
			passthrough_mode = 1;
			break;
		case 'q': {
			unsigned long tmp = strtoul(optarg, NULL, 10);
			if (tmp < 1 || tmp > MAX_RX_QUEUES_PER_PORT) {
				printf("invalid queue count (1-%d)\n", MAX_RX_QUEUES_PER_PORT);
				return -1;
			}
			nb_rx_queues = tmp;
			queues_specified = 1;
			break;
		}
		default:
			print_usage(prgname);
			return -1;
		}
	}

	/* Count and validate ports in mask */
	uint32_t port_count = 0;
	uint16_t portid;

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		if ((portmask & (1 << portid)) != 0)
			port_count++;
	}

	if (port_count != 2) {
		printf("Error: Need exactly 2 ports in portmask (found %u)\n", port_count);
		print_usage(prgname);
		return -1;
	}

	/* Extract port1 and port2 from mask */
	port_count = 0;
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		if ((portmask & (1 << portid)) != 0) {
			if (port_count == 0)
				port1 = portid;
			else if (port_count == 1) {
				port2 = portid;
				break;
			}
			port_count++;
		}
	}

	/* Validate ports exist */
	if (!rte_eth_dev_is_valid_port(port1)) {
		printf("Error: Port %u is not available\n", port1);
		return -1;
	}
	if (!rte_eth_dev_is_valid_port(port2)) {
		printf("Error: Port %u is not available\n", port2);
		return -1;
	}

	/* Auto-calculate RX queues if not specified */
	if (!queues_specified) {
		unsigned int nb_lcores = rte_lcore_count();
		/* Reserve cores: 1 main + 2 reorder + 2 TX + 1 stats (optional) */
		unsigned int reserved = 1 + 2 + 2 + (stats_thread_enabled ? 1 : 0);
		if (nb_lcores > reserved) {
			unsigned int workers_per_port = (nb_lcores - reserved) / 2;
			if (workers_per_port > MAX_RX_QUEUES_PER_PORT)
				workers_per_port = MAX_RX_QUEUES_PER_PORT;
			if (workers_per_port < 1)
				workers_per_port = 1;
			nb_rx_queues = workers_per_port;
		}
	}

	printf("Configuration:\n");
	printf("  Port 1: %u (receives -> forwards to Port 2)\n", port1);
	printf("  Port 2: %u (receives -> forwards to Port 1)\n", port2);
	printf("  RX queues per port: %u\n", nb_rx_queues);
	printf("  Promiscuous mode: %s\n", promiscuous_on ? "enabled" : "disabled");
	printf("  Stats thread: %s\n", stats_thread_enabled ? "enabled" : "disabled");
	printf("  Debug mode: %s\n", debug_mode ? "enabled" : "disabled");
	printf("  Passthrough mode: %s\n", passthrough_mode ? "enabled (NO REORDERING)" : "disabled");

	return optind - 1;
}

/*
 * =============================================================================
 * LINK STATUS CHECK
 * =============================================================================
 */

static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100
#define MAX_CHECK_TIME 90
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
	char link_status_text[RTE_ETH_LINK_MAX_STR_LEN];

	printf("\nChecking link status");
	fflush(stdout);

	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;

		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;

			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					printf("Port %u link get failed: %s\n",
						portid, rte_strerror(-ret));
				continue;
			}

			if (print_flag == 1) {
				rte_eth_link_to_str(link_status_text,
					sizeof(link_status_text), &link);
				printf("Port %d %s\n", portid, link_status_text);
				continue;
			}

			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}

		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

/*
 * =============================================================================
 * MAIN FUNCTION
 * =============================================================================
 * Initialization sequence:
 * 1. Initialize DPDK EAL
 * 2. Parse command line arguments
 * 3. Create memory pool for packets
 * 4. Create reorder buffers
 * 5. Configure and start ports
 * 6. Create inter-thread rings
 * 7. Launch worker, reorder, TX, and stats threads
 * 8. Wait for threads to complete (on shutdown)
 * 9. Cleanup and exit
 */

int
main(int argc, char **argv)
{
	int ret;
	uint16_t nb_ports;
	uint16_t portid, queueid;
	unsigned int nb_mbufs;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf local_port_conf;

	/* Initialize DPDK EAL (Environment Abstraction Layer) */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* Setup signal handlers */
	force_quit = false;
	signal(SIGINT, signal_handler);   /* Ctrl+C */
	signal(SIGTERM, signal_handler);  /* kill */
	signal(SIGUSR1, signal_handler);  /* Manual stats request */

	/* Parse application-specific arguments */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");

	/* Check available ports */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* 
	 * Create packet memory pool.
	 * Size accounts for RX/TX descriptors, burst buffers, and cache.
	 */
	nb_mbufs = nb_rx_queues * 2 * (nb_rxd + nb_txd + MAX_PKT_BURST + MEMPOOL_CACHE_SIZE);
	nb_mbufs = RTE_MAX(nb_mbufs, 8192U);

	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Create reorder buffers - one per traffic direction */
	reorder_buffer_port1_to_port2 = rte_reorder_create("reorder_p1_p2",
		rte_socket_id(), REORDER_BUFFER_SIZE);
	if (reorder_buffer_port1_to_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reorder buffer P1->P2: %s\n",
			rte_strerror(rte_errno));

	reorder_buffer_port2_to_port1 = rte_reorder_create("reorder_p2_p1",
		rte_socket_id(), REORDER_BUFFER_SIZE);
	if (reorder_buffer_port2_to_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reorder buffer P2->P1: %s\n",
			rte_strerror(rte_errno));

	/* Initialize ports with multiple RX queues */
	RTE_ETH_FOREACH_DEV(portid) {
		if (portid != port1 && portid != port2)
			continue;

		printf("Initializing port %u with %u RX queues... ", portid, nb_rx_queues);
		fflush(stdout);

		/* Get device capabilities */
		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error getting device info for port %u: %s\n",
				portid, strerror(-ret));

		/* Limit queues to device capability */
		if (nb_rx_queues > dev_info.max_rx_queues) {
			printf("\nWarning: Reducing RX queues from %u to %u (device limit)\n",
				nb_rx_queues, dev_info.max_rx_queues);
			nb_rx_queues = dev_info.max_rx_queues;
		}

		local_port_conf = port_conf;

		/* Configure RSS based on device capabilities */
		if (nb_rx_queues > 1) {
			uint64_t rss_hf_want = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
			uint64_t rss_hf_supported = dev_info.flow_type_rss_offloads;
			
			local_port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf_want & rss_hf_supported;
			
			if (local_port_conf.rx_adv_conf.rss_conf.rss_hf == 0) {
				printf("\nWarning: RSS not supported, using single queue\n");
				nb_rx_queues = 1;
				local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
			} else {
				printf("RSS hash functions: 0x%" PRIx64 "\n",
					local_port_conf.rx_adv_conf.rss_conf.rss_hf);
			}
		} else {
			local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
		}

		/* Enable fast mbuf free if supported */
		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		/* Configure the port */
		ret = rte_eth_dev_configure(portid, nb_rx_queues, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure port %u: err=%d\n",
				portid, ret);

		/* Adjust descriptor counts if needed */
		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"Cannot adjust descriptors for port %u: err=%d\n",
				portid, ret);

		/* Setup RX queues */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		for (queueid = 0; queueid < nb_rx_queues; queueid++) {
			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
				rte_eth_dev_socket_id(portid), &rxq_conf, mbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					"RX queue setup failed for port %u queue %u: err=%d\n",
					portid, queueid, ret);
		}

		/* Setup TX queue (single queue is sufficient) */
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
			rte_eth_dev_socket_id(portid), &txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"TX queue setup failed for port %u: err=%d\n",
				portid, ret);

		/* Start the port */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot start port %u: err=%d\n",
				portid, ret);

		/* Enable promiscuous mode if requested */
		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Cannot enable promiscuous on port %u: %s\n",
					portid, rte_strerror(-ret));
		}

		printf("done\n");
	}

	/* Initialize TX buffers for packet batching */
	tx_buffer_port1 = rte_zmalloc_socket("tx_buffer_port1",
		RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
		rte_eth_dev_socket_id(port1));
	if (tx_buffer_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate TX buffer for port %u\n", port1);
	rte_eth_tx_buffer_init(tx_buffer_port1, MAX_PKT_BURST);

	tx_buffer_port2 = rte_zmalloc_socket("tx_buffer_port2",
		RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
		rte_eth_dev_socket_id(port2));
	if (tx_buffer_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate TX buffer for port %u\n", port2);
	rte_eth_tx_buffer_init(tx_buffer_port2, MAX_PKT_BURST);

	/* Wait for link up on both ports */
	check_all_ports_link_status((1 << port1) | (1 << port2));

	/* 
	 * Create inter-thread rings.
	 * RING_F_SC_DEQ: Single-consumer dequeue (only one thread reads).
	 * Default is multi-producer (multiple workers can write).
	 */
	tx_ring_port1 = rte_ring_create("tx_ring_p1", RING_SIZE, rte_socket_id(),
		RING_F_SC_DEQ);
	if (tx_ring_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create TX ring for port1: %s\n",
			rte_strerror(rte_errno));

	tx_ring_port2 = rte_ring_create("tx_ring_p2", RING_SIZE, rte_socket_id(),
		RING_F_SC_DEQ);
	if (tx_ring_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create TX ring for port2: %s\n",
			rte_strerror(rte_errno));

	reorder_ring_port1_to_port2 = rte_ring_create("reorder_ring_p1_p2", RING_SIZE,
		rte_socket_id(), RING_F_SC_DEQ);
	if (reorder_ring_port1_to_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reorder ring P1->P2: %s\n",
			rte_strerror(rte_errno));

	reorder_ring_port2_to_port1 = rte_ring_create("reorder_ring_p2_p1", RING_SIZE,
		rte_socket_id(), RING_F_SC_DEQ);
	if (reorder_ring_port2_to_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reorder ring P2->P1: %s\n",
			rte_strerror(rte_errno));

	/* Calculate core requirements */
	unsigned int nb_lcores = rte_lcore_count();
	unsigned int fixed_cores = 2 + 2 + (stats_thread_enabled ? 1 : 0);
	unsigned int worker_cores_needed = nb_rx_queues * 2;
	unsigned int total_needed = 1 + fixed_cores + worker_cores_needed;

	if (nb_lcores < total_needed) {
		rte_exit(EXIT_FAILURE,
			"Need at least %u cores (found %u)\n"
			"  1 main + %u workers (%u queues x 2 ports) + 2 reorder + 2 TX%s\n",
			total_needed, nb_lcores, worker_cores_needed, nb_rx_queues,
			stats_thread_enabled ? " + 1 stats" : "");
	}

	/* Allocate and setup worker thread arguments */
	struct worker_thread_args *worker_args = rte_zmalloc("worker_args",
		sizeof(struct worker_thread_args) * worker_cores_needed, 0);
	if (worker_args == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate worker args\n");

	/* Setup workers for P1->P2 direction */
	for (queueid = 0; queueid < nb_rx_queues; queueid++) {
		worker_args[queueid].port_id = port1;
		worker_args[queueid].dst_port = port2;
		worker_args[queueid].queue_id = queueid;
		worker_args[queueid].tx_ring = tx_ring_port2;
		worker_args[queueid].reorder_ring = reorder_ring_port1_to_port2;
		worker_args[queueid].expected_seq = &expected_seq_port1_to_port2;
		worker_args[queueid].first_pkt_init = &first_pkt_init_p1_p2;
		worker_args[queueid].dir_str = "P1->P2";
	}

	/* Setup workers for P2->P1 direction */
	for (queueid = 0; queueid < nb_rx_queues; queueid++) {
		unsigned int idx = nb_rx_queues + queueid;
		worker_args[idx].port_id = port2;
		worker_args[idx].dst_port = port1;
		worker_args[idx].queue_id = queueid;
		worker_args[idx].tx_ring = tx_ring_port1;
		worker_args[idx].reorder_ring = reorder_ring_port2_to_port1;
		worker_args[idx].expected_seq = &expected_seq_port2_to_port1;
		worker_args[idx].first_pkt_init = &first_pkt_init_p2_p1;
		worker_args[idx].dir_str = "P2->P1";
	}

	/* Setup reorder thread arguments */
	struct reorder_thread_args reorder_args_p1_p2 = {
		.dst_port = port2,
		.ring_in = reorder_ring_port1_to_port2,
		.tx_ring = tx_ring_port2,
		.reorder_buf = reorder_buffer_port1_to_port2,
		.expected_seq = &expected_seq_port1_to_port2,
		.first_pkt_init = &first_pkt_init_p1_p2,
		.dir_str = "P1->P2",
	};

	struct reorder_thread_args reorder_args_p2_p1 = {
		.dst_port = port1,
		.ring_in = reorder_ring_port2_to_port1,
		.tx_ring = tx_ring_port1,
		.reorder_buf = reorder_buffer_port2_to_port1,
		.expected_seq = &expected_seq_port2_to_port1,
		.first_pkt_init = &first_pkt_init_p2_p1,
		.dir_str = "P2->P1",
	};

	/* Setup TX thread arguments */
	struct tx_thread_args tx_args_port1 = {
		.port_id = port1,
		.ring_in = tx_ring_port1,
		.tx_buf = tx_buffer_port1,
	};

	struct tx_thread_args tx_args_port2 = {
		.port_id = port2,
		.ring_in = tx_ring_port2,
		.tx_buf = tx_buffer_port2,
	};

	/* Launch threads on available lcores */
	unsigned int lcore_id;
	unsigned int lcore_idx = 0;
	unsigned int worker_idx = 0;
	unsigned int reorder_lcore_p1_p2 = 0, reorder_lcore_p2_p1 = 0;
	unsigned int tx_lcore_port1 = 0, tx_lcore_port2 = 0;
	unsigned int stats_lcore = 0;

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (worker_idx < worker_cores_needed) {
			/* Launch worker threads first */
			printf("Launching worker for port %u queue %u on lcore %u (%s)\n",
				worker_args[worker_idx].port_id,
				worker_args[worker_idx].queue_id,
				lcore_id, worker_args[worker_idx].dir_str);
			rte_eal_remote_launch(worker_thread, &worker_args[worker_idx], lcore_id);
			worker_idx++;
		} else if (reorder_lcore_p1_p2 == 0) {
			reorder_lcore_p1_p2 = lcore_id;
			printf("Launching reorder thread P1->P2 on lcore %u\n", lcore_id);
			rte_eal_remote_launch(reorder_thread, &reorder_args_p1_p2, lcore_id);
		} else if (reorder_lcore_p2_p1 == 0) {
			reorder_lcore_p2_p1 = lcore_id;
			printf("Launching reorder thread P2->P1 on lcore %u\n", lcore_id);
			rte_eal_remote_launch(reorder_thread, &reorder_args_p2_p1, lcore_id);
		} else if (tx_lcore_port1 == 0) {
			tx_lcore_port1 = lcore_id;
			printf("Launching TX thread for port %u on lcore %u\n", port1, lcore_id);
			rte_eal_remote_launch(tx_thread, &tx_args_port1, lcore_id);
		} else if (tx_lcore_port2 == 0) {
			tx_lcore_port2 = lcore_id;
			printf("Launching TX thread for port %u on lcore %u\n", port2, lcore_id);
			rte_eal_remote_launch(tx_thread, &tx_args_port2, lcore_id);
		} else if (stats_thread_enabled && stats_lcore == 0) {
			stats_lcore = lcore_id;
			printf("Launching stats thread on lcore %u\n", lcore_id);
			rte_eal_remote_launch(stats_thread, NULL, lcore_id);
		}
		lcore_idx++;
	}

	printf("\nAll threads launched. Processing packets...\n");

	/* Wait for all threads to complete (on shutdown signal) */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			ret = -1;
	}

	/* Print final statistics */
	print_stats();

	/* Stop and close ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (portid != port1 && portid != port2)
			continue;
		printf("Closing port %d...", portid);
		ret = rte_eth_dev_stop(portid);
		if (ret != 0)
			printf("rte_eth_dev_stop: err=%d, port=%d\n", ret, portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* Cleanup */
	rte_free(worker_args);
	rte_eal_cleanup();
	printf("Bye...\n");

	return 0;
}
