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

#define RTE_LOGTYPE_MACSEC_REORDER RTE_LOGTYPE_USER1

/* MACsec ethertype (IEEE 802.1AE) */
#ifndef RTE_ETHER_TYPE_MACSEC
#define RTE_ETHER_TYPE_MACSEC 0x88E5
#endif

#define MAX_PKT_BURST 32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256
#define REORDER_BUFFER_SIZE 8192

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

/* Expected sequence numbers for each direction (for fast-path optimization) */
static uint32_t expected_seq_port1_to_port2 = 0;
static uint32_t expected_seq_port2_to_port1 = 0;

/* Statistics */
struct __rte_cache_aligned app_stats {
	uint64_t rx_port1_pkts;
	uint64_t rx_port2_pkts;
	uint64_t tx_port1_pkts;
	uint64_t tx_port2_pkts;
	uint64_t macsec_pkts;
	uint64_t non_macsec_pkts;
	uint64_t in_order_pkts;      /* Packets transmitted via fast path */
	uint64_t out_of_order_pkts;
	uint64_t dropped_pkts;
	uint64_t reordered_pkts;
};
static struct app_stats stats;

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
 * Process received packets and insert into reorder buffer
 * port_id: port where packet was received
 * dst_port: port where packet should be transmitted
 */
static void
process_rx_packets(struct rte_mbuf **pkts, uint16_t nb_rx, uint16_t port_id, uint16_t dst_port)
{
	uint16_t i;
	uint64_t pn;
	uint32_t seq;
	int ret;
	struct rte_reorder_buffer *reorder_buf;
	struct rte_eth_dev_tx_buffer *tx_buf;
	uint32_t *expected_seq;

	/* Select appropriate reorder buffer, TX buffer, and expected sequence based on direction */
	if (port_id == port1) {
		reorder_buf = reorder_buffer_port1_to_port2;
		tx_buf = tx_buffer_port2;
		expected_seq = &expected_seq_port1_to_port2;
	} else {
		reorder_buf = reorder_buffer_port2_to_port1;
		tx_buf = tx_buffer_port1;
		expected_seq = &expected_seq_port2_to_port1;
	}

	for (i = 0; i < nb_rx; i++) {
		struct rte_mbuf *pkt = pkts[i];

		/* Check if MACsec packet */
		if (is_macsec_packet(pkt)) {
			stats.macsec_pkts++;

			/* Extract packet number */
			if (extract_macsec_pn(pkt, &pn)) {
				seq = (uint32_t)pn;
				*rte_reorder_seqn(pkt) = seq;

				/* Fast path: Check if packet is in-order */
				if (seq == *expected_seq) {
					/* Packet is in-order - transmit directly (fast path) */
					stats.in_order_pkts++;
					ret = rte_eth_tx_buffer(dst_port, 0, tx_buf, pkt);
					if (ret) {
						if (dst_port == port1)
							stats.tx_port1_pkts += ret;
						else
							stats.tx_port2_pkts += ret;
					}
					/* Update expected sequence number */
					(*expected_seq)++;

					/* Try to drain any buffered packets that are now ready */
					struct rte_mbuf *drained_pkts[MAX_PKT_BURST];
					unsigned int nb_drained = rte_reorder_drain(reorder_buf, drained_pkts, MAX_PKT_BURST);
					if (nb_drained > 0) {
						stats.reordered_pkts += nb_drained;
						unsigned int j;
						for (j = 0; j < nb_drained; j++) {
							uint32_t drained_seq = *rte_reorder_seqn(drained_pkts[j]);
							ret = rte_eth_tx_buffer(dst_port, 0, tx_buf, drained_pkts[j]);
							if (ret) {
								if (dst_port == port1)
									stats.tx_port1_pkts += ret;
								else
									stats.tx_port2_pkts += ret;
							}
							/* Update expected sequence to the last drained packet + 1 */
							*expected_seq = drained_seq + 1;
						}
					}
				} else {
					/* Packet is out-of-order - use reorder buffer (slow path) */
					stats.out_of_order_pkts++;
					ret = rte_reorder_insert(reorder_buf, pkt);
					if (ret == -1) {
						if (rte_errno == ERANGE) {
							/* Packet too early - drop it */
							RTE_LOG(DEBUG, MACSEC_REORDER,
								"Packet with PN %" PRIu64 " too early (expected %u)\n",
								pn, *expected_seq);
							rte_pktmbuf_free(pkt);
							stats.dropped_pkts++;
						} else if (rte_errno == ENOSPC) {
							/* Buffer full - drop packet */
							RTE_LOG(DEBUG, MACSEC_REORDER,
								"Reorder buffer full, dropping packet\n");
							rte_pktmbuf_free(pkt);
							stats.dropped_pkts++;
						} else {
							/* Other error */
							RTE_LOG(ERR, MACSEC_REORDER,
								"Error inserting packet into reorder buffer: %s\n",
								rte_strerror(rte_errno));
							rte_pktmbuf_free(pkt);
							stats.dropped_pkts++;
						}
					}
				}
			} else {
				/* Failed to extract PN - treat as non-MACsec */
				RTE_LOG(DEBUG, MACSEC_REORDER,
					"Failed to extract PN from MACsec packet\n");
				stats.non_macsec_pkts++;
				/* Forward immediately without reordering */
				ret = rte_eth_tx_buffer(dst_port, 0, tx_buf, pkt);
				if (ret) {
					if (dst_port == port1)
						stats.tx_port1_pkts += ret;
					else
						stats.tx_port2_pkts += ret;
				}
			}
		} else {
			/* Non-MACsec packet - forward immediately */
			stats.non_macsec_pkts++;
			ret = rte_eth_tx_buffer(dst_port, 0, tx_buf, pkt);
			if (ret) {
				if (dst_port == port1)
					stats.tx_port1_pkts += ret;
				else
					stats.tx_port2_pkts += ret;
			}
		}
	}
}

/**
 * Print statistics
 */
static void print_stats(void);

/**
 * Drain reorder buffer and transmit packets
 * This is called periodically to drain any buffered packets that became ready
 */
static void
drain_and_transmit(void)
{
	struct rte_mbuf *pkts[MAX_PKT_BURST];
	unsigned int nb_drained;
	unsigned int i;
	int sent;
	uint32_t seq;

	/* Drain reordered packets from port1->port2 direction */
	nb_drained = rte_reorder_drain(reorder_buffer_port1_to_port2, pkts, MAX_PKT_BURST);
	if (nb_drained > 0) {
		stats.reordered_pkts += nb_drained;
		for (i = 0; i < nb_drained; i++) {
			seq = *rte_reorder_seqn(pkts[i]);
			sent = rte_eth_tx_buffer(port2, 0, tx_buffer_port2, pkts[i]);
			if (sent)
				stats.tx_port2_pkts += sent;
			/* Update expected sequence to the last drained packet + 1 */
			expected_seq_port1_to_port2 = seq + 1;
		}
	}

	/* Drain reordered packets from port2->port1 direction */
	nb_drained = rte_reorder_drain(reorder_buffer_port2_to_port1, pkts, MAX_PKT_BURST);
	if (nb_drained > 0) {
		stats.reordered_pkts += nb_drained;
		for (i = 0; i < nb_drained; i++) {
			seq = *rte_reorder_seqn(pkts[i]);
			sent = rte_eth_tx_buffer(port1, 0, tx_buffer_port1, pkts[i]);
			if (sent)
				stats.tx_port1_pkts += sent;
			/* Update expected sequence to the last drained packet + 1 */
			expected_seq_port2_to_port1 = seq + 1;
		}
	}
}

/**
 * Main processing loop
 */
static void
main_loop(void)
{
	struct rte_mbuf *pkts_burst1[MAX_PKT_BURST];
	struct rte_mbuf *pkts_burst2[MAX_PKT_BURST];
	uint16_t nb_rx1, nb_rx2;
	uint64_t prev_tsc, cur_tsc, diff_tsc, timer_tsc;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S *
			BURST_TX_DRAIN_US;
	uint64_t timer_period_cycles = timer_period * rte_get_timer_hz();

	prev_tsc = rte_rdtsc();
	timer_tsc = 0;

	RTE_LOG(INFO, MACSEC_REORDER, "Entering main loop on lcore %u\n",
		rte_lcore_id());
	RTE_LOG(INFO, MACSEC_REORDER, "Port 1: %u, Port 2: %u\n",
		port1, port2);

	while (!force_quit) {
		cur_tsc = rte_rdtsc();

		/* Drain TX buffers periodically */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			int sent1 = rte_eth_tx_buffer_flush(port1, 0, tx_buffer_port1);
			if (sent1)
				stats.tx_port1_pkts += sent1;

			int sent2 = rte_eth_tx_buffer_flush(port2, 0, tx_buffer_port2);
			if (sent2)
				stats.tx_port2_pkts += sent2;

			/* Print statistics periodically */
			timer_tsc += diff_tsc;
			if (unlikely(timer_tsc >= timer_period_cycles)) {
				print_stats();
				timer_tsc = 0;
			}

			prev_tsc = cur_tsc;
		}

		/* Read packets from port 1 -> forward to port 2 */
		nb_rx1 = rte_eth_rx_burst(port1, 0, pkts_burst1, MAX_PKT_BURST);
		if (likely(nb_rx1 > 0)) {
			stats.rx_port1_pkts += nb_rx1;
			process_rx_packets(pkts_burst1, nb_rx1, port1, port2);
		}

		/* Read packets from port 2 -> forward to port 1 */
		nb_rx2 = rte_eth_rx_burst(port2, 0, pkts_burst2, MAX_PKT_BURST);
		if (likely(nb_rx2 > 0)) {
			stats.rx_port2_pkts += nb_rx2;
			process_rx_packets(pkts_burst2, nb_rx2, port2, port1);
		}

		/* Drain reorder buffers and transmit */
		drain_and_transmit();
	}
}

/**
 * Print statistics
 */
static void
print_stats(void)
{
	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\n============== MACsec Reorder Statistics ==============\n");
	printf("RX Port 1 packets:        %20" PRIu64 "\n", stats.rx_port1_pkts);
	printf("RX Port 2 packets:        %20" PRIu64 "\n", stats.rx_port2_pkts);
	printf("TX Port 1 packets:        %20" PRIu64 "\n", stats.tx_port1_pkts);
	printf("TX Port 2 packets:        %20" PRIu64 "\n", stats.tx_port2_pkts);
	printf("MACsec packets:           %20" PRIu64 "\n", stats.macsec_pkts);
	printf("Non-MACsec packets:       %20" PRIu64 "\n", stats.non_macsec_pkts);
	printf("In-order packets (fast):  %20" PRIu64 "\n", stats.in_order_pkts);
	printf("Out-of-order packets:     %20" PRIu64 "\n", stats.out_of_order_pkts);
	printf("Reordered packets:        %20" PRIu64 "\n", stats.reordered_pkts);
	printf("Dropped packets:          %20" PRIu64 "\n", stats.dropped_pkts);
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

	/* Main loop */
	printf("\nStarting packet processing...\n");

	/* Run main loop directly - it has its own while loop */
	main_loop();

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

