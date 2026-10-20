// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "xdp_ratelimit.h"

#define NSEC_PER_SEC	1000000000ULL

struct bucket {
	__u64 tokens_ns;	/* remaining budget in nanoseconds */
	__u64 last_ns;		/* last update (bpf_ktime_get_ns) */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, RATELIMIT_BUCKET_MAX_ENTRIES);
	__type(key, __u32);	/* IPv4 source address (network order) */
	__type(value, struct bucket);
} buckets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, RATELIMIT_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

/* Filled by the loader before load; avoids divisions in the fast path. */
const volatile __u64 rate_pps = RATELIMIT_DEFAULT_RATE_PPS;
const volatile __u64 burst = RATELIMIT_DEFAULT_BURST;
const volatile __u64 cost_ns = NSEC_PER_SEC / RATELIMIT_DEFAULT_RATE_PPS;
const volatile __u64 capacity_ns =
	(NSEC_PER_SEC / RATELIMIT_DEFAULT_RATE_PPS) * RATELIMIT_DEFAULT_BURST;

struct iphdr_min {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	__u8 ihl:4, version:4;
#else
	__u8 version:4, ihl:4;
#endif
	__u8 tos;
	__be16 tot_len;
	__be16 id;
	__be16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__sum16 check;
	__be32 saddr;
	__be32 daddr;
} __attribute__((packed));

static __always_inline void count_packet(__u32 idx)
{
	__u64 *value = bpf_map_lookup_elem(&stats, &idx);

	if (value)
		*value += 1;
}

SEC("xdp")
int xdp_ratelimit(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data;
	struct iphdr_min *ip;
	struct bucket *bucket;
	__u64 now, tokens, last, delta;
	__u32 key, ihl_bytes;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->version != 4)
		return XDP_PASS;
	ihl_bytes = (__u32)ip->ihl * 4;
	if (ip->ihl < 5 || bpf_ntohs(ip->tot_len) < ihl_bytes)
		return XDP_PASS;

	key = ip->saddr;
	now = bpf_ktime_get_ns();
	bucket = bpf_map_lookup_elem(&buckets, &key);
	if (!bucket) {
		struct bucket new_bucket = {
			.tokens_ns = capacity_ns,
			.last_ns = now,
		};

		bpf_map_update_elem(&buckets, &key, &new_bucket, BPF_NOEXIST);
		bucket = bpf_map_lookup_elem(&buckets, &key);
		if (!bucket) {
			/* fail-open on map pressure */
			count_packet(RATELIMIT_STAT_PASS);
			return XDP_PASS;
		}
	}

	tokens = bucket->tokens_ns;
	last = bucket->last_ns;
	if (now > last) {
		delta = now - last;
		tokens += delta;
		if (tokens > capacity_ns)
			tokens = capacity_ns;
	}

	if (tokens >= cost_ns) {
		bucket->tokens_ns = tokens - cost_ns;
		bucket->last_ns = now;
		count_packet(RATELIMIT_STAT_PASS);
		return XDP_PASS;
	}

	bucket->tokens_ns = tokens;
	bucket->last_ns = now;
	count_packet(RATELIMIT_STAT_DROP);
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
