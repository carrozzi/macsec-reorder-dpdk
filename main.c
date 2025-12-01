/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024
 *
 * MACsec packet reordering application
 * Reads packets from two interfaces, reorders out-of-order MACsec packets,
 * and transmits them out of another interface.
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

#define RTE_LOGTYPE_MACSEC_REORDER RTE_LOGTYPE_USER1

/* MACsec ethertype (IEEE 802.1AE) */
#ifndef RTE_ETHER_TYPE_MACSEC
#define RTE_ETHER_TYPE_MACSEC 0x88E5
#endif

#define MAX_PKT_BURST 64  /* Increased for 100Gbps */
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256
#define REORDER_BUFFER_SIZE 8192
#define RING_SIZE 16384  /* Size of rings for inter-thread communication */

/* Configurable number of RX/TX ring descriptors */
#define RX_DESC_DEFAULT 1024
#define TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RX_DESC_DEFAULT;
static uint16_t nb_txd = TX_DESC_DEFAULT;

/* MACsec SecTAG structure (IEEE 802.1AE) */
struct macsec_sectag {
	uint8_t tci_an;      /* TCI (6 bits) + AN (2 bits) */
	uint8_t sl;          /* Short Length (8 bits) */
	uint32_t pn;         /* Packet Number (32 bits, network byte order) */
	uint8_t sci[8];      /* SCI (Secure Channel Identifier, optional) */
} __rte_packed;

/* MACsec SecTAG with Extended Packet Number (XPN) */
struct macsec_sectag_xpn {
	uint8_t tci_an;      /* TCI (6 bits) + AN (2 bits) */
	uint8_t sl;          /* Short Length (8 bits) */
	uint64_t pn;         /* Extended Packet Number (64 bits, network byte order) */
	uint8_t sci[8];      /* SCI (Secure Channel Identifier, optional) */
} __rte_packed;

/* MACsec flags */
#define MACSEC_TCI_ES    0x20  /* End Station */
#define MACSEC_TCI_SC    0x10  /* SCI present */
#define MACSEC_TCI_SCB   0x08  /* SCB */
#define MACSEC_TCI_E     0x04  /* Encryption */
#define MACSEC_TCI_C     0x02  /* Changed */
#define MACSEC_AN_MASK   0x03  /* Association Number mask */

/* Port configuration */
static uint16_t port1 = 0;
static uint16_t port2 = 1;

static volatile bool force_quit;

/* Timer period for statistics (in seconds) */
static uint64_t timer_period = 10;

/* Promiscuous mode flag */
static int promiscuous_on = 0;

/* Mempool for mbufs */
static struct rte_mempool *mbuf_pool;

/* Reorder buffers - one for each direction */
static struct rte_reorder_buffer *reorder_buffer_port1_to_port2;
static struct rte_reorder_buffer *reorder_buffer_port2_to_port1;

/* TX buffers */
static struct rte_eth_dev_tx_buffer *tx_buffer_port1;
static struct rte_eth_dev_tx_buffer *tx_buffer_port2;

/* Expected sequence numbers for each direction (for fast-path optimization)
 * Using atomic operations for thread-safe access */
static rte_atomic32_t expected_seq_port1_to_port2 = RTE_ATOMIC32_INIT(0);
static rte_atomic32_t expected_seq_port2_to_port1 = RTE_ATOMIC32_INIT(0);

/* Rings for inter-thread communication */
static struct rte_ring *rx_ring_port1;  /* RX port1 -> workers */
static struct rte_ring *rx_ring_port2;  /* RX port2 -> workers */
static struct rte_ring *tx_ring_port1;  /* Workers/reorder -> TX port1 */
static struct rte_ring *tx_ring_port2;  /* Workers/reorder -> TX port2 */
static struct rte_ring *reorder_ring_port1_to_port2;  /* Workers -> reorder thread (out-of-order) */
static struct rte_ring *reorder_ring_port2_to_port1;  /* Workers -> reorder thread (out-of-order) */

/* Thread arguments */
struct rx_thread_args {
	uint16_t port_id;
	uint16_t dst_port;
	struct rte_ring *ring_out;
};

struct worker_thread_args {
	struct rte_ring *rx_ring_port1;
	struct rte_ring *rx_ring_port2;
	struct rte_ring *tx_ring_port1;
	struct rte_ring *tx_ring_port2;
	struct rte_ring *reorder_ring_p1_p2;  /* For out-of-order packets port1->port2 */
	struct rte_ring *reorder_ring_p2_p1;  /* For out-of-order packets port2->port1 */
};

struct reorder_thread_args {
	uint16_t dst_port;
	struct rte_ring *ring_in;  /* Receives out-of-order packets from workers */
	struct rte_ring *tx_ring;  /* Sends reordered packets to TX thread */
	struct rte_reorder_buffer *reorder_buf;
	rte_atomic32_t *expected_seq;
};

struct tx_thread_args {
	uint16_t port_id;
	struct rte_ring *ring_in;
	struct rte_eth_dev_tx_buffer *tx_buf;
};

/* Per-lcore statistics */
struct __rte_cache_aligned lcore_stats {
	uint64_t rx_pkts;
	uint64_t tx_pkts;
	uint64_t macsec_pkts;
	uint64_t non_macsec_pkts;
	uint64_t in_order_pkts;
	uint64_t out_of_order_pkts;
	uint64_t dropped_pkts;
	uint64_t reordered_pkts;
	uint64_t enqueue_failed;
	uint64_t dequeue_failed;
};
static struct lcore_stats lcore_stats_array[RTE_MAX_LCORE];

/* Port configuration */
static struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

/**
 * Check if packet is MACsec encapsulated
 * MACsec packets have ethertype 0x88E5
 */
static inline bool
is_macsec_packet(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth_hdr;

	if (unlikely(m->data_len < sizeof(struct rte_ether_hdr)))
		return false;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	return (eth_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_MACSEC));
}

/**
 * Extract packet number from MACsec SecTAG
 * Returns true if successful, false otherwise
 */
static inline bool
extract_macsec_pn(struct rte_mbuf *m, uint64_t *pn)
{
	struct rte_ether_hdr *eth_hdr;
	struct macsec_sectag *sectag;
	struct macsec_sectag_xpn *sectag_xpn;
	uint8_t tci_an;
	uint16_t ether_type;
	uint32_t offset = sizeof(struct rte_ether_hdr);

	/* Check minimum packet size */
	if (unlikely(m->data_len < offset + sizeof(struct macsec_sectag)))
		return false;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);

	/* Check for VLAN tag */
	if (ether_type == RTE_ETHER_TYPE_VLAN) {
		offset += 4; /* VLAN header size */
		if (unlikely(m->data_len < offset + sizeof(struct macsec_sectag)))
			return false;
	}

	/* Get SecTAG */
	sectag = (struct macsec_sectag *)((uint8_t *)eth_hdr + offset);
	tci_an = sectag->tci_an;

	/* Check if XPN (Extended Packet Number) is used */
	/* For simplicity, we check the TCI field - in real implementation,
	 * you might need to check SA configuration */
	if (tci_an & MACSEC_TCI_E) {
		/* Check if XPN format (64-bit PN) */
		/* For now, we'll use standard 32-bit PN */
		*pn = (uint64_t)rte_be_to_cpu_32(sectag->pn);
		return true;
	}

	/* Standard 32-bit packet number */
	*pn = (uint64_t)rte_be_to_cpu_32(sectag->pn);
	return true;
}

/**
 * RX thread - reads packets from a port and enqueues to ring
 */
static int
rx_thread(void *arg)
{
	struct rx_thread_args *args = (struct rx_thread_args *)arg;
	uint16_t port_id = args->port_id;
	struct rte_ring *ring_out = args->ring_out;
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	uint16_t nb_rx;
	unsigned int lcore_id = rte_lcore_id();
	struct lcore_stats *lcore_stat = &lcore_stats_array[lcore_id];

	RTE_LOG(INFO, MACSEC_REORDER, "RX thread started on lcore %u for port %u\n",
		lcore_id, port_id);

	while (!force_quit) {
		/* Read packets from port */
		nb_rx = rte_eth_rx_burst(port_id, 0, pkts, MAX_PKT_BURST);
		if (likely(nb_rx > 0)) {
			lcore_stat->rx_pkts += nb_rx;

			/* Enqueue to ring */
			unsigned int nb_enq = rte_ring_enqueue_burst(ring_out,
				(void *)pkts, nb_rx, NULL);
			if (unlikely(nb_enq < nb_rx)) {
				/* Free packets that couldn't be enqueued */
				unsigned int i;
				for (i = nb_enq; i < nb_rx; i++)
					rte_pktmbuf_free(pkts[i]);
				lcore_stat->enqueue_failed += (nb_rx - nb_enq);
				lcore_stat->dropped_pkts += (nb_rx - nb_enq);
			}
		}
	}

	return 0;
}

/**
 * Worker thread - processes packets from RX rings (fast path only)
 * Multiple worker threads can run in parallel
 */
static int
worker_thread(void *arg)
{
	struct worker_thread_args *args = (struct worker_thread_args *)arg;
	struct rte_mbuf *pkts_rx1[MAX_PKT_BURST];
	struct rte_mbuf *pkts_rx2[MAX_PKT_BURST];
	unsigned int nb_deq1, nb_deq2;
	unsigned int lcore_id = rte_lcore_id();
	struct lcore_stats *lcore_stat = &lcore_stats_array[lcore_id];
	uint16_t i;
	uint64_t pn;
	uint32_t seq;
	uint32_t expected_seq_p1_p2, expected_seq_p2_p1;

	RTE_LOG(INFO, MACSEC_REORDER, "Worker thread started on lcore %u\n", lcore_id);

	while (!force_quit) {
		/* Dequeue packets from RX rings */
		nb_deq1 = rte_ring_dequeue_burst(args->rx_ring_port1,
			(void *)pkts_rx1, MAX_PKT_BURST, NULL);
		nb_deq2 = rte_ring_dequeue_burst(args->rx_ring_port2,
			(void *)pkts_rx2, MAX_PKT_BURST, NULL);

		if (nb_deq1 == 0 && nb_deq2 == 0)
			continue;

		/* Process packets from port1 -> port2 */
		for (i = 0; i < nb_deq1; i++) {
			struct rte_mbuf *pkt = pkts_rx1[i];

			if (is_macsec_packet(pkt)) {
				lcore_stat->macsec_pkts++;

				if (extract_macsec_pn(pkt, &pn)) {
					seq = (uint32_t)pn;
					*rte_reorder_seqn(pkt) = seq;

					/* Get current expected sequence (atomic read) */
					expected_seq_p1_p2 = rte_atomic32_read(&expected_seq_port1_to_port2);

					/* Fast path: Check if packet is in-order */
					if (seq == expected_seq_p1_p2) {
						lcore_stat->in_order_pkts++;
						/* Update expected sequence (atomic) */
						rte_atomic32_set(&expected_seq_port1_to_port2, seq + 1);
						/* Enqueue directly to TX ring (bypass reorder buffer) */
						if (rte_ring_enqueue(args->tx_ring_port2, pkt) != 0) {
							rte_pktmbuf_free(pkt);
							lcore_stat->enqueue_failed++;
							lcore_stat->dropped_pkts++;
						}
					} else if (seq > expected_seq_p1_p2) {
						/* Out-of-order (future packet) - send to reorder thread */
						lcore_stat->out_of_order_pkts++;
						if (rte_ring_enqueue(args->reorder_ring_p1_p2, pkt) != 0) {
							rte_pktmbuf_free(pkt);
							lcore_stat->enqueue_failed++;
							lcore_stat->dropped_pkts++;
						}
					} else {
						/* Packet too early (seq < expected) - drop it */
						RTE_LOG(DEBUG, MACSEC_REORDER,
							"Packet with seq %u too early (expected %u), dropping\n",
							seq, expected_seq_p1_p2);
						rte_pktmbuf_free(pkt);
						lcore_stat->dropped_pkts++;
					}
				} else {
					/* Failed to extract PN - forward as non-MACsec */
					lcore_stat->non_macsec_pkts++;
					if (rte_ring_enqueue(args->tx_ring_port2, pkt) != 0) {
						rte_pktmbuf_free(pkt);
						lcore_stat->enqueue_failed++;
						lcore_stat->dropped_pkts++;
					}
				}
			} else {
				/* Non-MACsec packet - forward immediately */
				lcore_stat->non_macsec_pkts++;
				if (rte_ring_enqueue(args->tx_ring_port2, pkt) != 0) {
					rte_pktmbuf_free(pkt);
					lcore_stat->enqueue_failed++;
					lcore_stat->dropped_pkts++;
				}
			}
		}

		/* Process packets from port2 -> port1 */
		for (i = 0; i < nb_deq2; i++) {
			struct rte_mbuf *pkt = pkts_rx2[i];

			if (is_macsec_packet(pkt)) {
				lcore_stat->macsec_pkts++;

				if (extract_macsec_pn(pkt, &pn)) {
					seq = (uint32_t)pn;
					*rte_reorder_seqn(pkt) = seq;

					/* Get current expected sequence (atomic read) */
					expected_seq_p2_p1 = rte_atomic32_read(&expected_seq_port2_to_port1);

					/* Fast path: Check if packet is in-order */
					if (seq == expected_seq_p2_p1) {
						lcore_stat->in_order_pkts++;
						/* Update expected sequence (atomic) */
						rte_atomic32_set(&expected_seq_port2_to_port1, seq + 1);
						/* Enqueue directly to TX ring (bypass reorder buffer) */
						if (rte_ring_enqueue(args->tx_ring_port1, pkt) != 0) {
							rte_pktmbuf_free(pkt);
							lcore_stat->enqueue_failed++;
							lcore_stat->dropped_pkts++;
						}
					} else if (seq > expected_seq_p2_p1) {
						/* Out-of-order (future packet) - send to reorder thread */
						lcore_stat->out_of_order_pkts++;
						if (rte_ring_enqueue(args->reorder_ring_p2_p1, pkt) != 0) {
							rte_pktmbuf_free(pkt);
							lcore_stat->enqueue_failed++;
							lcore_stat->dropped_pkts++;
						}
					} else {
						/* Packet too early (seq < expected) - drop it */
						RTE_LOG(DEBUG, MACSEC_REORDER,
							"Packet with seq %u too early (expected %u), dropping\n",
							seq, expected_seq_p2_p1);
						rte_pktmbuf_free(pkt);
						lcore_stat->dropped_pkts++;
					}
				} else {
					/* Failed to extract PN - forward as non-MACsec */
					lcore_stat->non_macsec_pkts++;
					if (rte_ring_enqueue(args->tx_ring_port1, pkt) != 0) {
						rte_pktmbuf_free(pkt);
						lcore_stat->enqueue_failed++;
						lcore_stat->dropped_pkts++;
					}
				}
			} else {
				/* Non-MACsec packet - forward immediately */
				lcore_stat->non_macsec_pkts++;
				if (rte_ring_enqueue(args->tx_ring_port1, pkt) != 0) {
					rte_pktmbuf_free(pkt);
					lcore_stat->enqueue_failed++;
					lcore_stat->dropped_pkts++;
				}
			}
		}
	}

	return 0;
}

/**
 * Reorder thread - handles out-of-order packets and reorder buffer operations
 * One thread per direction (required for thread-safe reorder buffer access)
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
	uint32_t seq, drained_seq;
	unsigned int lcore_id = rte_lcore_id();
	struct lcore_stats *lcore_stat = &lcore_stats_array[lcore_id];
	uint32_t expected_seq;

	RTE_LOG(INFO, MACSEC_REORDER, "Reorder thread started on lcore %u for port %u\n",
		lcore_id, args->dst_port);

	while (!force_quit) {
		/* Dequeue out-of-order packets from workers (non-blocking) */
		nb_deq = rte_ring_dequeue_burst(args->ring_in, (void *)pkts_in,
			MAX_PKT_BURST, NULL);

		if (nb_deq > 0) {
			for (i = 0; i < nb_deq; i++) {
				struct rte_mbuf *pkt = pkts_in[i];
				seq = *rte_reorder_seqn(pkt);

				/* Insert into reorder buffer */
				ret = rte_reorder_insert(args->reorder_buf, pkt);
				if (ret == -1) {
					if (rte_errno == ERANGE || rte_errno == ENOSPC) {
						rte_pktmbuf_free(pkt);
						lcore_stat->dropped_pkts++;
					} else {
						RTE_LOG(ERR, MACSEC_REORDER,
							"Error inserting packet: %s\n",
							rte_strerror(rte_errno));
						rte_pktmbuf_free(pkt);
						lcore_stat->dropped_pkts++;
					}
				}
			}
		}

		/* Always try to drain packets from reorder buffer
		 * (expected_seq may have been updated by worker threads) */
		nb_drained = rte_reorder_drain(args->reorder_buf, pkts_drained, MAX_PKT_BURST);
		if (nb_drained > 0) {
			lcore_stat->reordered_pkts += nb_drained;
			for (i = 0; i < nb_drained; i++) {
				drained_seq = *rte_reorder_seqn(pkts_drained[i]);
				if (rte_ring_enqueue(args->tx_ring, pkts_drained[i]) != 0) {
					rte_pktmbuf_free(pkts_drained[i]);
					lcore_stat->enqueue_failed++;
					lcore_stat->dropped_pkts++;
				}
				/* Update expected sequence (atomic) */
				rte_atomic32_set(args->expected_seq, drained_seq + 1);
			}
		}

		/* If no packets to process, yield to avoid busy-waiting */
		if (nb_deq == 0 && nb_drained == 0)
			rte_pause();
	}

	return 0;
}

/**
 * TX thread - drains reorder buffer and transmits packets
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

		/* Drain TX buffer periodically */
		if (unlikely(diff_tsc > drain_tsc)) {
			sent = rte_eth_tx_buffer_flush(port_id, 0, tx_buf);
			if (sent) {
				lcore_stat->tx_pkts += sent;
			}
			prev_tsc = cur_tsc;
		}

			/* Dequeue packets from ring */
		nb_deq = rte_ring_dequeue_burst(ring_in, (void *)pkts_ring,
			MAX_PKT_BURST, NULL);

		if (nb_deq > 0) {
			/* Transmit packets */
			for (i = 0; i < nb_deq; i++) {
				sent = rte_eth_tx_buffer(port_id, 0, tx_buf, pkts_ring[i]);
				if (sent)
					lcore_stat->tx_pkts += sent;
			}
		}
	}

	return 0;
}

/**
 * Print statistics
 */
static void print_stats(void);

/**
 * Statistics thread - aggregates and prints statistics
 */
static int
stats_thread(__rte_unused void *arg)
{
	uint64_t prev_tsc, cur_tsc, timer_tsc;
	uint64_t timer_period_cycles = timer_period * rte_get_timer_hz();
	unsigned int lcore_id;

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
		rte_delay_us_sleep(100000); /* Sleep 100ms */
	}

	return 0;
}

/**
 * Print statistics - aggregates from all lcores
 */
static void
print_stats(void)
{
	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
	uint64_t total_rx = 0, total_tx = 0;
	uint64_t total_macsec = 0, total_non_macsec = 0;
	uint64_t total_in_order = 0, total_out_of_order = 0;
	uint64_t total_dropped = 0, total_reordered = 0;
	uint64_t total_enq_failed = 0;
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
	}

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\n============== MACsec Reorder Statistics ==============\n");
	printf("Total RX packets:          %20" PRIu64 "\n", total_rx);
	printf("Total TX packets:          %20" PRIu64 "\n", total_tx);
	printf("MACsec packets:            %20" PRIu64 "\n", total_macsec);
	printf("Non-MACsec packets:        %20" PRIu64 "\n", total_non_macsec);
	printf("In-order packets (fast):   %20" PRIu64 "\n", total_in_order);
	printf("Out-of-order packets:      %20" PRIu64 "\n", total_out_of_order);
	printf("Reordered packets:         %20" PRIu64 "\n", total_reordered);
	printf("Dropped packets:           %20" PRIu64 "\n", total_dropped);
	printf("Enqueue failed:            %20" PRIu64 "\n", total_enq_failed);
	printf("========================================================\n");

	fflush(stdout);
}

/**
 * Signal handler
 */
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

/**
 * Display usage
 */
static void
print_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-P] [-T PERIOD]\n"
		"  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
		"              (must include exactly 2 ports)\n"
		"  -P: Enable promiscuous mode\n"
		"  -T PERIOD: statistics refresh period in seconds (0 to disable, default 10)\n",
		prgname);
}

/**
 * Parse portmask
 */
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

/**
 * Parse arguments
 */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	uint32_t portmask = 0;

	argvopt = argv;

	while ((opt = getopt(argc, argvopt, "p:PT:")) != EOF) {
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
		default:
			print_usage(prgname);
			return -1;
		}
	}

	/* Count number of bits set in portmask */
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

	/* Find the two enabled ports */
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

	/* Verify both ports are available */
	if (!rte_eth_dev_is_valid_port(port1)) {
		printf("Error: Port %u is not available\n", port1);
		return -1;
	}
	if (!rte_eth_dev_is_valid_port(port2)) {
		printf("Error: Port %u is not available\n", port2);
		return -1;
	}

	printf("Configuration:\n");
	printf("  Port 1: %u (receives -> forwards to Port 2)\n", port1);
	printf("  Port 2: %u (receives -> forwards to Port 1)\n", port2);
	printf("  Promiscuous mode: %s\n", promiscuous_on ? "enabled" : "disabled");

	return optind - 1;
}

/**
 * Check link status
 */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) */
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

/**
 * Main function
 */
int
main(int argc, char **argv)
{
	int ret;
	uint16_t nb_ports;
	uint16_t portid;
	unsigned int nb_mbufs;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_txconf txq_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_conf local_port_conf;

	/* Initialize EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Parse application arguments */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid arguments\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/* Calculate number of mbufs needed */
	nb_mbufs = 2 * (nb_rxd + nb_txd + MAX_PKT_BURST + MEMPOOL_CACHE_SIZE);

	/* Create mbuf pool */
	mbuf_pool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	/* Create reorder buffers for both directions */
	reorder_buffer_port1_to_port2 = rte_reorder_create("macsec_reorder_p1_p2", rte_socket_id(),
		REORDER_BUFFER_SIZE);
	if (reorder_buffer_port1_to_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reorder buffer port1->port2: %s\n",
			rte_strerror(rte_errno));

	reorder_buffer_port2_to_port1 = rte_reorder_create("macsec_reorder_p2_p1", rte_socket_id(),
		REORDER_BUFFER_SIZE);
	if (reorder_buffer_port2_to_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reorder buffer port2->port1: %s\n",
			rte_strerror(rte_errno));

	/* Initialize ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if (portid != port1 && portid != port2)
			continue;

		printf("Initializing port %u... ", portid);
		fflush(stdout);

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));

		local_port_conf = port_conf;
		if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

		/* Configure port */
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"Cannot adjust number of descriptors: err=%d, port=%u\n",
				ret, portid);

		/* Setup RX queue */
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd,
			rte_eth_dev_socket_id(portid), &rxq_conf, mbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d, port=%u\n",
				ret, portid);

		/* Setup TX queue */
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd,
			rte_eth_dev_socket_id(portid), &txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err=%d, port=%u\n",
				ret, portid);

		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%u\n",
				ret, portid);

		/* Enable promiscuous mode if requested */
		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_promiscuous_enable: err=%s, port=%u\n",
					rte_strerror(-ret), portid);
		}

		printf("done\n");
	}

	/* Initialize TX buffers */
	tx_buffer_port1 = rte_zmalloc_socket("tx_buffer_port1",
		RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
		rte_eth_dev_socket_id(port1));
	if (tx_buffer_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
			port1);
	rte_eth_tx_buffer_init(tx_buffer_port1, MAX_PKT_BURST);

	tx_buffer_port2 = rte_zmalloc_socket("tx_buffer_port2",
		RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0,
		rte_eth_dev_socket_id(port2));
	if (tx_buffer_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n",
			port2);
	rte_eth_tx_buffer_init(tx_buffer_port2, MAX_PKT_BURST);

	/* Check link status */
	uint32_t port_mask = (1 << port1) | (1 << port2);
	check_all_ports_link_status(port_mask);

	/* Create rings for inter-thread communication */
	rx_ring_port1 = rte_ring_create("rx_ring_port1", RING_SIZE, rte_socket_id(),
		RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (rx_ring_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create RX ring for port1: %s\n",
			rte_strerror(rte_errno));

	rx_ring_port2 = rte_ring_create("rx_ring_port2", RING_SIZE, rte_socket_id(),
		RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (rx_ring_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create RX ring for port2: %s\n",
			rte_strerror(rte_errno));

	tx_ring_port1 = rte_ring_create("tx_ring_port1", RING_SIZE, rte_socket_id(),
		RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (tx_ring_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create TX ring for port1: %s\n",
			rte_strerror(rte_errno));

	tx_ring_port2 = rte_ring_create("tx_ring_port2", RING_SIZE, rte_socket_id(),
		RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (tx_ring_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create TX ring for port2: %s\n",
			rte_strerror(rte_errno));

	/* Create reorder rings for out-of-order packets */
	reorder_ring_port1_to_port2 = rte_ring_create("reorder_ring_p1_p2", RING_SIZE,
		rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (reorder_ring_port1_to_port2 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reorder ring port1->port2: %s\n",
			rte_strerror(rte_errno));

	reorder_ring_port2_to_port1 = rte_ring_create("reorder_ring_p2_p1", RING_SIZE,
		rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (reorder_ring_port2_to_port1 == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create reorder ring port2->port1: %s\n",
			rte_strerror(rte_errno));

	/* Check if we have enough cores */
	unsigned int nb_lcores = rte_lcore_count();
	unsigned int required_cores = 9; /* 1 main + 2 RX + 1 worker + 2 reorder + 2 TX + 1 stats */
	unsigned int nb_worker_cores_available = 0;
	
	if (nb_lcores >= required_cores) {
		/* Calculate available worker cores (total - main - 7 fixed cores) */
		nb_worker_cores_available = nb_lcores - 1 - 7; /* -1 for main, -7 for fixed */
	} else {
		rte_exit(EXIT_FAILURE,
			"Error: Need at least %u cores total (found %u)\n"
			"  Breakdown:\n"
			"  - 1 core for main thread\n"
			"  - 2 cores for RX threads (one per port)\n"
			"  - 2 cores for reorder threads (one per direction)\n"
			"  - 2 cores for TX threads (one per port)\n"
			"  - 1 core for stats thread\n"
			"  - 1+ cores for worker threads (scales with available cores)\n"
			"  = %u cores minimum\n",
			required_cores, nb_lcores, required_cores);
	}
	
	if (nb_worker_cores_available == 0) {
		rte_exit(EXIT_FAILURE,
			"Error: No cores available for worker threads.\n"
			"  With %u cores total, all worker cores are used for fixed threads.\n"
			"  Need at least %u cores total to have worker threads.\n",
			nb_lcores, required_cores);
	}

	/* Initialize thread arguments */
	struct rx_thread_args rx_args_port1 = {
		.port_id = port1,
		.dst_port = port2,
		.ring_out = rx_ring_port1,
	};

	struct rx_thread_args rx_args_port2 = {
		.port_id = port2,
		.dst_port = port1,
		.ring_out = rx_ring_port2,
	};

	struct worker_thread_args worker_args = {
		.rx_ring_port1 = rx_ring_port1,
		.rx_ring_port2 = rx_ring_port2,
		.tx_ring_port1 = tx_ring_port1,
		.tx_ring_port2 = tx_ring_port2,
		.reorder_ring_p1_p2 = reorder_ring_port1_to_port2,
		.reorder_ring_p2_p1 = reorder_ring_port2_to_port1,
	};

	struct reorder_thread_args reorder_args_p1_p2 = {
		.dst_port = port2,
		.ring_in = reorder_ring_port1_to_port2,
		.tx_ring = tx_ring_port2,
		.reorder_buf = reorder_buffer_port1_to_port2,
		.expected_seq = &expected_seq_port1_to_port2,
	};

	struct reorder_thread_args reorder_args_p2_p1 = {
		.dst_port = port1,
		.ring_in = reorder_ring_port2_to_port1,
		.tx_ring = tx_ring_port1,
		.reorder_buf = reorder_buffer_port2_to_port1,
		.expected_seq = &expected_seq_port2_to_port1,
	};

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
	unsigned int rx_lcore_port1 = 0, rx_lcore_port2 = 0;
	unsigned int reorder_lcore_p1_p2 = 0, reorder_lcore_p2_p1 = 0;
	unsigned int tx_lcore_port1 = 0, tx_lcore_port2 = 0;
	unsigned int stats_lcore = 0;
	unsigned int lcore_idx = 0;
	unsigned int worker_lcores[RTE_MAX_LCORE];
	unsigned int nb_workers_launched = 0;

	/* Assign fixed lcores - skip main lcore
	 * We need: 2 RX + 2 reorder + 2 TX + 1 stats = 7 fixed cores
	 * Remaining cores go to worker threads (need at least 1) */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (lcore_idx < 7) {
			/* Assign fixed function cores */
			switch (lcore_idx) {
			case 0:
				rx_lcore_port1 = lcore_id;
				break;
			case 1:
				rx_lcore_port2 = lcore_id;
				break;
			case 2:
				reorder_lcore_p1_p2 = lcore_id;
				break;
			case 3:
				reorder_lcore_p2_p1 = lcore_id;
				break;
			case 4:
				tx_lcore_port1 = lcore_id;
				break;
			case 5:
				tx_lcore_port2 = lcore_id;
				break;
			case 6:
				stats_lcore = lcore_id;
				break;
			}
		} else {
			/* Remaining cores are for worker threads */
			if (nb_workers_launched < RTE_MAX_LCORE) {
				worker_lcores[nb_workers_launched++] = lcore_id;
			}
		}
		lcore_idx++;
	}

	/* Launch RX thread for port1 */
	if (rx_lcore_port1 > 0) {
		printf("Launching RX thread for port %u on lcore %u\n",
			port1, rx_lcore_port1);
		rte_eal_remote_launch(rx_thread, &rx_args_port1, rx_lcore_port1);
	}

	/* Launch RX thread for port2 */
	if (rx_lcore_port2 > 0) {
		printf("Launching RX thread for port %u on lcore %u\n",
			port2, rx_lcore_port2);
		rte_eal_remote_launch(rx_thread, &rx_args_port2, rx_lcore_port2);
	}

	/* Launch multiple worker threads */
	if (nb_workers_launched == 0) {
		/* If no worker cores were assigned (shouldn't happen with 7+ cores),
		 * we need at least one worker thread. Use the stats core if needed. */
		rte_exit(EXIT_FAILURE,
			"Error: No worker threads available. Need at least 7 cores.\n");
	}
	printf("Launching %u worker thread(s):\n", nb_workers_launched);
	for (unsigned int i = 0; i < nb_workers_launched; i++) {
		printf("  Worker thread %u on lcore %u\n", i, worker_lcores[i]);
		rte_eal_remote_launch(worker_thread, &worker_args, worker_lcores[i]);
	}

	/* Launch reorder thread for port1->port2 */
	if (reorder_lcore_p1_p2 > 0) {
		printf("Launching reorder thread for port %u->%u on lcore %u\n",
			port1, port2, reorder_lcore_p1_p2);
		rte_eal_remote_launch(reorder_thread, &reorder_args_p1_p2, reorder_lcore_p1_p2);
	}

	/* Launch reorder thread for port2->port1 */
	if (reorder_lcore_p2_p1 > 0) {
		printf("Launching reorder thread for port %u->%u on lcore %u\n",
			port2, port1, reorder_lcore_p2_p1);
		rte_eal_remote_launch(reorder_thread, &reorder_args_p2_p1, reorder_lcore_p2_p1);
	}

	/* Launch TX thread for port1 */
	if (tx_lcore_port1 > 0) {
		printf("Launching TX thread for port %u on lcore %u\n",
			port1, tx_lcore_port1);
		rte_eal_remote_launch(tx_thread, &tx_args_port1, tx_lcore_port1);
	}

	/* Launch TX thread for port2 */
	if (tx_lcore_port2 > 0) {
		printf("Launching TX thread for port %u on lcore %u\n",
			port2, tx_lcore_port2);
		rte_eal_remote_launch(tx_thread, &tx_args_port2, tx_lcore_port2);
	}

	/* Launch stats thread */
	if (stats_lcore > 0) {
		printf("Launching stats thread on lcore %u\n", stats_lcore);
		rte_eal_remote_launch(stats_thread, NULL, stats_lcore);
	}

	printf("\nAll threads launched. Starting packet processing...\n");

	/* Wait for all worker threads */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			ret = -1;
	}

	/* Print final statistics */
	print_stats();

	/* Cleanup */
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

	rte_eal_cleanup();
	printf("Bye...\n");

	return 0;
}

