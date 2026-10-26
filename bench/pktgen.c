// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define NSEC_PER_SEC 1000000000ULL

struct ethhdr_min {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t proto;
} __attribute__((packed));

struct iphdr_min {
	uint8_t vihl;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag_off;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t check;
	uint32_t saddr;
	uint32_t daddr;
} __attribute__((packed));

struct udphdr_min {
	uint16_t sport;
	uint16_t dport;
	uint16_t len;
	uint16_t check;
} __attribute__((packed));

struct ring {
	int fd;
	uint8_t *map;
	size_t map_size;
	unsigned block_size;
	unsigned block_nr;
	unsigned frame_size;
	unsigned frame_nr;
	unsigned frame_idx;
	struct tpacket_hdr **frames;
};

static uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

static void sleep_until(uint64_t deadline)
{
	struct timespec ts = {
		.tv_sec = (time_t)(deadline / NSEC_PER_SEC),
		.tv_nsec = (long)(deadline % NSEC_PER_SEC),
	};

	while (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL) ==
	       EINTR)
		;
}

static uint16_t ipv4_csum(const void *data, size_t len)
{
	const uint16_t *p = data;
	uint32_t sum = 0;

	for (size_t i = 0; i < len / 2; i++)
		sum += ntohs(p[i]);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return htons((uint16_t)~sum);
}

static int parse_mac(const char *str, uint8_t mac[6])
{
	unsigned int v[6];

	if (sscanf(str, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3],
		   &v[4], &v[5]) != 6)
		return -EINVAL;
	for (int i = 0; i < 6; i++)
		mac[i] = (uint8_t)v[i];
	return 0;
}

static int ring_setup(struct ring *r, const char *iface, unsigned block_nr,
		      unsigned frame_size, unsigned block_size)
{
	struct sockaddr_ll sll = {
		.sll_family = AF_PACKET,
		.sll_protocol = htons(ETH_P_ALL),
	};
	struct tpacket_req req;
	int ver = TPACKET_V1;
	int one = 1;

	memset(r, 0, sizeof(*r));
	r->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (r->fd < 0)
		return -errno;

	setsockopt(r->fd, SOL_SOCKET, SO_PRIORITY, &(int){6}, sizeof(int));
	setsockopt(r->fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver));
	setsockopt(r->fd, SOL_PACKET, PACKET_QDISC_BYPASS, &one, sizeof(one));

	sll.sll_ifindex = (int)if_nametoindex(iface);
	if (!sll.sll_ifindex) {
		close(r->fd);
		return -ENODEV;
	}
	if (bind(r->fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		int err = -errno;

		close(r->fd);
		return err;
	}

	r->block_size = block_size;
	r->block_nr = block_nr;
	r->frame_size = frame_size;
	req.tp_block_size = block_size;
	req.tp_block_nr = block_nr;
	req.tp_frame_size = frame_size;
	req.tp_frame_nr = (block_size / frame_size) * block_nr;
	if (setsockopt(r->fd, SOL_PACKET, PACKET_TX_RING, &req, sizeof(req)) < 0) {
		int err = -errno;

		close(r->fd);
		return err;
	}

	r->frame_nr = req.tp_frame_nr;
	r->map_size = (size_t)block_size * block_nr;
	r->map = mmap(NULL, r->map_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		      r->fd, 0);
	if (r->map == MAP_FAILED) {
		int err = -errno;

		close(r->fd);
		return err;
	}

	r->frames = calloc(r->frame_nr, sizeof(*r->frames));
	if (!r->frames) {
		munmap(r->map, r->map_size);
		close(r->fd);
		return -ENOMEM;
	}
	unsigned per_block = r->block_size / r->frame_size;
	for (unsigned i = 0; i < r->frame_nr; i++) {
		unsigned block = i / per_block;
		unsigned off = (i % per_block) * r->frame_size;

		r->frames[i] = (struct tpacket_hdr *)(r->map +
			(size_t)block * r->block_size + off);
	}
	return 0;
}

#define TPACKET_TX_HDRLEN TPACKET_ALIGN(sizeof(struct tpacket_hdr))

static void ring_close(struct ring *r)
{
	free(r->frames);
	if (r->map && r->map != MAP_FAILED)
		munmap(r->map, r->map_size);
	if (r->fd >= 0)
		close(r->fd);
}

static int ring_kick(struct ring *r)
{
	if (sendto(r->fd, NULL, 0, 0, NULL, 0) < 0 && errno != EAGAIN)
		return -errno;
	return 0;
}

static int ring_wait_available(struct ring *r, struct tpacket_hdr *h,
			       unsigned int *errors)
{
	uint64_t spins = 0;

	for (;;) {
		if (h->tp_status == TP_STATUS_AVAILABLE)
			return 0;
		if (h->tp_status & TP_STATUS_WRONG_FORMAT) {
			(*errors)++;
			h->tp_status = TP_STATUS_AVAILABLE;
			return 0;
		}
		if ((spins++ & 0x3ff) == 0)
			ring_kick(r);
		if ((spins & 0xffff) == 0)
			sched_yield();
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s --iface IF [options]\n"
		"  --src-mac MAC       default 02:00:00:00:00:01\n"
		"  --dst-mac MAC       default 02:00:00:00:00:02\n"
		"  --src-ip IP         default 10.10.0.1\n"
		"  --dst-ip IP         default 10.10.0.2\n"
		"  --src-ip-count N    default 1 (round-robin from src-ip)\n"
		"  --src-port N        default 40000\n"
		"  --dst-port N        default 9999\n"
		"  --payload N         default 64\n"
		"  --count N           default 0 (unlimited)\n"
		"  --duration SEC      default 0 (use count)\n"
		"  --pps N             default 0 (as fast as possible)\n"
		"  --cpu N             pin sender to CPU N\n"
		"  --batch N           packets per kick (default 1024)\n"
		"  --ring-frames N     TX ring frames (default 8192)\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *iface = NULL;
	uint8_t src_mac[6] = { 0x02, 0, 0, 0, 0, 1 };
	uint8_t dst_mac[6] = { 0x02, 0, 0, 0, 0, 2 };
	char src_ip[64] = "10.10.0.1";
	char dst_ip[64] = "10.10.0.2";
	unsigned src_ip_count = 1;
	unsigned src_port = 40000;
	unsigned dst_port = 9999;
	unsigned payload_len = 64;
	uint64_t count = 0;
	double duration = 0;
	double pps = 0;
	int cpu = -1;
	unsigned batch = 1024;
	unsigned ring_frames = 8192;
	struct ring ring;
	struct rusage ru0, ru1;
	uint64_t start, end, sent = 0, next_deadline;
	uint32_t src_base, dst_addr;
	unsigned errors = 0;
	int opt, ret;

	static const struct option long_opts[] = {
		{ "iface", required_argument, NULL, 'i' },
		{ "src-mac", required_argument, NULL, 'S' },
		{ "dst-mac", required_argument, NULL, 'D' },
		{ "src-ip", required_argument, NULL, 's' },
		{ "dst-ip", required_argument, NULL, 'd' },
		{ "src-ip-count", required_argument, NULL, 'n' },
		{ "src-port", required_argument, NULL, 'p' },
		{ "dst-port", required_argument, NULL, 'P' },
		{ "payload", required_argument, NULL, 'l' },
		{ "count", required_argument, NULL, 'c' },
		{ "duration", required_argument, NULL, 't' },
		{ "pps", required_argument, NULL, 'r' },
		{ "cpu", required_argument, NULL, 'C' },
		{ "batch", required_argument, NULL, 'b' },
		{ "ring-frames", required_argument, NULL, 'R' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "hi:S:D:s:d:n:p:P:l:c:t:r:C:b:R:",
				  long_opts, NULL)) != -1) {
		switch (opt) {
		case 'i':
			iface = optarg;
			break;
		case 'S':
			if (parse_mac(optarg, src_mac)) {
				fprintf(stderr, "bad src-mac\n");
				return 1;
			}
			break;
		case 'D':
			if (parse_mac(optarg, dst_mac)) {
				fprintf(stderr, "bad dst-mac\n");
				return 1;
			}
			break;
		case 's':
			snprintf(src_ip, sizeof(src_ip), "%s", optarg);
			break;
		case 'd':
			snprintf(dst_ip, sizeof(dst_ip), "%s", optarg);
			break;
		case 'n':
			src_ip_count = strtoul(optarg, NULL, 10);
			break;
		case 'p':
			src_port = strtoul(optarg, NULL, 10);
			break;
		case 'P':
			dst_port = strtoul(optarg, NULL, 10);
			break;
		case 'l':
			payload_len = strtoul(optarg, NULL, 10);
			break;
		case 'c':
			count = strtoull(optarg, NULL, 10);
			break;
		case 't':
			duration = strtod(optarg, NULL);
			break;
		case 'r':
			pps = strtod(optarg, NULL);
			break;
		case 'C':
			cpu = atoi(optarg);
			break;
		case 'b':
			batch = strtoul(optarg, NULL, 10);
			break;
		case 'R':
			ring_frames = strtoul(optarg, NULL, 10);
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (!iface || (!count && duration <= 0) || !src_ip_count || !batch) {
		usage(argv[0]);
		return 1;
	}
	if (payload_len > 1400) {
		fprintf(stderr, "payload too large (max 1400)\n");
		return 1;
	}
	if (inet_pton(AF_INET, src_ip, &src_base) != 1 ||
	    inet_pton(AF_INET, dst_ip, &dst_addr) != 1) {
		fprintf(stderr, "bad IPv4 address\n");
		return 1;
	}
	src_base = ntohl(src_base);
	dst_addr = ntohl(dst_addr);

	if (cpu >= 0) {
		cpu_set_t set;

		CPU_ZERO(&set);
		CPU_SET(cpu, &set);
		if (sched_setaffinity(0, sizeof(set), &set) < 0) {
			fprintf(stderr, "sched_setaffinity(%d): %s\n", cpu,
				strerror(errno));
			return 1;
		}
	}

	unsigned block_size = 1u << 20;
	unsigned frame_size = 2048;
	unsigned block_nr = ring_frames / (block_size / frame_size);
	if (!block_nr)
		block_nr = 1;

	ret = ring_setup(&ring, iface, block_nr, frame_size, block_size);
	if (ret) {
		fprintf(stderr, "ring_setup(%s): %s\n", iface, strerror(-ret));
		return 1;
	}

	size_t frame_len = sizeof(struct ethhdr_min) + sizeof(struct iphdr_min) +
			   sizeof(struct udphdr_min) + payload_len;
	uint8_t *frame = calloc(1, frame_len);
	if (!frame)
		return 1;

	struct ethhdr_min *eth = (void *)frame;
	memcpy(eth->dst, dst_mac, 6);
	memcpy(eth->src, src_mac, 6);
	eth->proto = htons(ETH_P_IP);

	struct iphdr_min *ip = (void *)(frame + sizeof(*eth));
	ip->vihl = 0x45;
	ip->tos = 0;
	ip->tot_len = htons(sizeof(*ip) + sizeof(struct udphdr_min) +
			    payload_len);
	ip->id = 0;
	ip->frag_off = 0;
	ip->ttl = 64;
	ip->protocol = 17;
	ip->daddr = htonl(dst_addr);

	struct udphdr_min *udp = (void *)(ip + 1);
	udp->sport = htons(src_port);
	udp->dport = htons(dst_port);
	udp->len = htons(sizeof(*udp) + payload_len);
	udp->check = 0;

	memset(udp + 1, 0x41, payload_len);
	ip->saddr = htonl(src_base);
	ip->check = 0;
	ip->check = ipv4_csum(ip, sizeof(*ip));

	getrusage(RUSAGE_SELF, &ru0);
	start = now_ns();
	next_deadline = start;
	uint64_t end_ns = duration > 0 ? start + (uint64_t)(duration * NSEC_PER_SEC) : 0;
	unsigned batch_target = batch;
	if (pps > 0) {
		double per_ms = pps / 1000.0;

		if (per_ms < 1)
			per_ms = 1;
		batch_target = (unsigned)per_ms;
		if (batch_target > ring.frame_nr / 2)
			batch_target = ring.frame_nr / 2;
	}

	unsigned src_idx = 0;

	for (;;) {
		unsigned in_batch = 0;
		uint64_t now;

		if (end_ns) {
			now = now_ns();
			if (now >= end_ns)
				break;
		}
		if (count && sent >= count)
			break;

		while (in_batch < batch_target) {
			struct tpacket_hdr *h = ring.frames[ring.frame_idx];
			void *data;

			if (count && sent >= count)
				break;

			ring_wait_available(&ring, h, &errors);

			if (src_ip_count > 1) {
				uint32_t src = src_base +
					(uint32_t)(src_idx % src_ip_count);

				ip->saddr = htonl(src);
				ip->check = 0;
				ip->check = ipv4_csum(ip, sizeof(*ip));
				src_idx++;
			}

			data = (uint8_t *)h + TPACKET_TX_HDRLEN;
			memcpy(data, frame, frame_len);
			h->tp_len = frame_len;
			h->tp_snaplen = frame_len;
			h->tp_mac = TPACKET_TX_HDRLEN;
			h->tp_net = TPACKET_TX_HDRLEN + sizeof(struct ethhdr_min);
			__sync_synchronize();
			h->tp_status = TP_STATUS_SEND_REQUEST;

			ring.frame_idx++;
			if (ring.frame_idx == ring.frame_nr)
				ring.frame_idx = 0;
			sent++;
			in_batch++;
		}

		ring_kick(&ring);
		if (pps > 0) {
			next_deadline += (uint64_t)(in_batch / pps * NSEC_PER_SEC);
			if (now_ns() < next_deadline)
				sleep_until(next_deadline);
		}
		if (!in_batch) {
			if (end_ns && now_ns() >= end_ns)
				break;
			sched_yield();
		}
	}

	for (unsigned i = 0; i < ring.frame_nr; i++)
		ring_wait_available(&ring, ring.frames[i], &errors);
	ring_kick(&ring);
	end = now_ns();
	getrusage(RUSAGE_SELF, &ru1);

	double elapsed = (double)(end - start) / NSEC_PER_SEC;
	double user_ms = (ru1.ru_utime.tv_sec - ru0.ru_utime.tv_sec) * 1000.0 +
			 (ru1.ru_utime.tv_usec - ru0.ru_utime.tv_usec) / 1000.0;
	double sys_ms = (ru1.ru_stime.tv_sec - ru0.ru_stime.tv_sec) * 1000.0 +
			(ru1.ru_stime.tv_usec - ru0.ru_stime.tv_usec) / 1000.0;

	printf("sent=%llu elapsed_s=%.6f offered_pps=%.1f errors=%u "
	       "cpu_user_ms=%.3f cpu_sys_ms=%.3f\n",
	       (unsigned long long)sent, elapsed,
	       elapsed > 0 ? sent / elapsed : 0.0, errors, user_ms, sys_ms);

	free(frame);
	ring_close(&ring);
	return 0;
}
