/* SPDX-License-Identifier: GPL-2.0 */
#ifndef XDP_RATELIMIT_H
#define XDP_RATELIMIT_H

#define RATELIMIT_DEFAULT_RATE_PPS	1000ULL
#define RATELIMIT_DEFAULT_BURST	2000ULL

/* bucket map capacity (LRU eviction above this) */
#define RATELIMIT_BUCKET_MAX_ENTRIES	(1u << 18)

enum ratelimit_stat {
	RATELIMIT_STAT_PASS = 0,
	RATELIMIT_STAT_DROP = 1,
	RATELIMIT_STAT_MAX = 2,
};

#define RATELIMIT_PIN_ROOT	"/sys/fs/bpf/xdp-ratelimit"
#define RATELIMIT_RUN_ROOT	"/run/xdp-ratelimit"

#endif /* XDP_RATELIMIT_H */
