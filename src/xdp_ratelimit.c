// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <sched.h>
#include <linux/sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_ratelimit.h"
#include "xdp_ratelimit.skel.h"

#define NSEC_PER_SEC 1000000000ULL

enum xdp_mode {
	MODE_AUTO,
	MODE_NATIVE,
	MODE_GENERIC,
};

static bool valid_ifname(const char *iface)
{
	size_t len = strlen(iface);

	if (!len || len >= IFNAMSIZ)
		return false;
	if (!strcmp(iface, ".") || !strcmp(iface, ".."))
		return false;
	for (size_t i = 0; i < len; i++) {
		unsigned char c = iface[i];

		if (c == '/' || isspace(c))
			return false;
	}
	return true;
}

static bool valid_netns_name(const char *name)
{
	size_t len = strlen(name);

	if (!len || len >= NAME_MAX)
		return false;
	if (!strcmp(name, ".") || !strcmp(name, ".."))
		return false;
	return !strchr(name, '/');
}

/*
 * Enter only the network namespace. Do not touch the mount namespace:
 * `ip netns exec` remounts /sys and hides the host bpffs, which breaks
 * map pinning. setns(CLONE_NEWNET) alone keeps /sys/fs/bpf visible while
 * making ifindex lookups and XDP attach happen in the target netns.
 */
static int enter_netns(const char *name)
{
	char path[PATH_MAX];
	int fd, err;

	snprintf(path, sizeof(path), "/var/run/netns/%s", name);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;
	if (setns(fd, CLONE_NEWNET) < 0) {
		err = -errno;
		close(fd);
		return err;
	}
	close(fd);
	return 0;
}

static int make_dirs(const char *path)
{
	char tmp[PATH_MAX];
	char *p;

	if (strlen(path) >= sizeof(tmp))
		return -ENAMETOOLONG;
	strcpy(tmp, path);

	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, 0700) && errno != EEXIST)
			return -errno;
		*p = '/';
	}
	if (mkdir(tmp, 0700) && errno != EEXIST)
		return -errno;
	return 0;
}

static const char *mode_name(enum xdp_mode mode)
{
	switch (mode) {
	case MODE_NATIVE:
		return "native";
	case MODE_GENERIC:
		return "generic";
	default:
		return "auto";
	}
}

static int mode_from_name(const char *name, enum xdp_mode *mode)
{
	if (!strcmp(name, "auto"))
		*mode = MODE_AUTO;
	else if (!strcmp(name, "native") || !strcmp(name, "driver"))
		*mode = MODE_NATIVE;
	else if (!strcmp(name, "generic") || !strcmp(name, "skb"))
		*mode = MODE_GENERIC;
	else
		return -EINVAL;
	return 0;
}

static void map_paths(const char *iface, char *dir, size_t dir_len,
		      char *buckets, size_t buckets_len,
		      char *stats, size_t stats_len)
{
	snprintf(dir, dir_len, "%s/%s", RATELIMIT_PIN_ROOT, iface);
	snprintf(buckets, buckets_len, "%s/buckets", dir);
	snprintf(stats, stats_len, "%s/stats", dir);
}

static void conf_path(const char *iface, char *path, size_t len)
{
	snprintf(path, len, "%s/%s.conf", RATELIMIT_RUN_ROOT, iface);
}

static int xdp_detach_any(int ifindex)
{
	const __u32 modes[] = {
		XDP_FLAGS_DRV_MODE,
		XDP_FLAGS_SKB_MODE,
		0,
	};
	int last = -ENOENT;

	for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		int err = bpf_xdp_detach(ifindex, modes[i], NULL);

		if (!err)
			return 0;
		last = err;
	}
	return last;
}

static int xdp_detach_mode(int ifindex, enum xdp_mode mode)
{
	switch (mode) {
	case MODE_GENERIC:
		return bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
	case MODE_NATIVE:
		return bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
	default:
		return xdp_detach_any(ifindex);
	}
}

static int xdp_attach_mode(int ifindex, int prog_fd, enum xdp_mode mode,
			   bool force, enum xdp_mode *used)
{
	__u32 primary;
	int err;

	if (mode == MODE_GENERIC) {
		primary = XDP_FLAGS_SKB_MODE;
	} else {
		primary = XDP_FLAGS_DRV_MODE;
	}

	if (force)
		xdp_detach_any(ifindex);

	err = bpf_xdp_attach(ifindex, prog_fd,
			     primary | XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
	if (!err) {
		*used = (primary == XDP_FLAGS_SKB_MODE) ?
			MODE_GENERIC : MODE_NATIVE;
		return 0;
	}
	if (mode != MODE_AUTO)
		return err;

	err = bpf_xdp_attach(ifindex, prog_fd,
			     XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST,
			     NULL);
	if (!err) {
		*used = MODE_GENERIC;
		return 0;
	}
	return err;
}

static int write_conf(const char *iface, enum xdp_mode mode, __u64 rate,
		      __u64 burst)
{
	char path[PATH_MAX];
	FILE *fp;
	int err;

	err = make_dirs(RATELIMIT_RUN_ROOT);
	if (err)
		return err;

	conf_path(iface, path, sizeof(path));
	fp = fopen(path, "w");
	if (!fp)
		return -errno;

	fprintf(fp, "mode=%s\nrate_pps=%llu\nburst=%llu\n",
		mode_name(mode), (unsigned long long)rate,
		(unsigned long long)burst);
	if (fclose(fp))
		return -errno;
	return 0;
}

static int read_conf_mode(const char *iface, enum xdp_mode *mode)
{
	char path[PATH_MAX], line[128], modebuf[16];
	FILE *fp;

	conf_path(iface, path, sizeof(path));
	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "mode=%15s", modebuf) == 1) {
			int err = mode_from_name(modebuf, mode);

			fclose(fp);
			return err;
		}
	}
	fclose(fp);
	return -ENOENT;
}

static int cmd_load(const char *iface, __u64 rate, __u64 burst,
		    enum xdp_mode mode, bool force)
{
	struct xdp_ratelimit_bpf *skel = NULL;
	char dir[PATH_MAX], buckets[PATH_MAX], stats[PATH_MAX], conf[PATH_MAX];
	enum xdp_mode used = mode;
	unsigned int ifindex;
	__u64 cost_ns, capacity_ns;
	__u32 current_prog = 0;
	bool replaced = false;
	int err, conf_err;

	ifindex = if_nametoindex(iface);
	if (!ifindex) {
		fprintf(stderr, "interface not found: %s\n", iface);
		return 1;
	}
	if (!rate || rate > NSEC_PER_SEC) {
		fprintf(stderr, "rate must be 1..1000000000 pps\n");
		return 1;
	}
	if (!burst) {
		fprintf(stderr, "burst must be > 0\n");
		return 1;
	}

	cost_ns = NSEC_PER_SEC / rate;
	if (!cost_ns)
		cost_ns = 1;
	if (burst > UINT64_MAX / cost_ns) {
		fprintf(stderr, "burst * cost_ns overflows\n");
		return 1;
	}
	capacity_ns = cost_ns * burst;
	map_paths(iface, dir, sizeof(dir), buckets, sizeof(buckets),
		  stats, sizeof(stats));
	conf_path(iface, conf, sizeof(conf));

	/* Refuse to disturb an existing program unless --force is given. */
	if (!bpf_xdp_query_id(ifindex, 0, &current_prog) && current_prog) {
		if (!force) {
			fprintf(stderr, "%s already has an XDP program attached "
				"(use --force to replace it)\n", iface);
			return 1;
		}
		err = xdp_detach_any(ifindex);
		if (err) {
			fprintf(stderr, "failed to detach existing XDP program "
				"from %s: %s\n", iface, strerror(-err));
			return 1;
		}
		replaced = true;
	}

	skel = xdp_ratelimit_bpf__open();
	if (!skel) {
		fprintf(stderr, "failed to open BPF skeleton\n");
		return 1;
	}

	skel->rodata->rate_pps = rate;
	skel->rodata->burst = burst;
	skel->rodata->cost_ns = cost_ns;
	skel->rodata->capacity_ns = capacity_ns;

	err = xdp_ratelimit_bpf__load(skel);
	if (err) {
		fprintf(stderr, "failed to load BPF program: %s\n",
			strerror(-err));
		goto out;
	}

	/* Attach before touching pins: a failed attach must not break the
	 * control plane of a program that is already running.
	 */
	err = xdp_attach_mode(ifindex, bpf_program__fd(skel->progs.xdp_ratelimit),
			      mode, false, &used);
	if (err) {
		fprintf(stderr, "failed to attach XDP to %s: %s\n", iface,
			strerror(-err));
		if (replaced) {
			unlink(buckets);
			unlink(stats);
			rmdir(dir);
			unlink(conf);
		}
		goto out;
	}

	err = make_dirs(RATELIMIT_PIN_ROOT);
	if (err) {
		fprintf(stderr, "failed to create %s: %s\n",
			RATELIMIT_PIN_ROOT, strerror(-err));
		goto detach;
	}
	err = make_dirs(dir);
	if (err) {
		fprintf(stderr, "failed to create %s: %s\n", dir, strerror(-err));
		goto detach;
	}
	unlink(buckets);
	unlink(stats);
	err = bpf_map__pin(skel->maps.buckets, buckets);
	if (err) {
		fprintf(stderr, "failed to pin buckets map: %s\n",
			strerror(-err));
		goto detach;
	}
	err = bpf_map__pin(skel->maps.stats, stats);
	if (err) {
		fprintf(stderr, "failed to pin stats map: %s\n",
			strerror(-err));
		goto detach;
	}

	conf_err = write_conf(iface, used, rate, burst);
	if (conf_err)
		fprintf(stderr, "warning: failed to write conf: %s\n",
			strerror(-conf_err));

	printf("attached xdp_ratelimit to %s (ifindex=%u)\n", iface, ifindex);
	printf("mode=%s rate_pps=%llu burst=%llu cost_ns=%llu capacity_ns=%llu\n",
	       mode_name(used), (unsigned long long)rate,
	       (unsigned long long)burst, (unsigned long long)cost_ns,
	       (unsigned long long)capacity_ns);
	printf("buckets_map=%s\nstats_map=%s\n", buckets, stats);

out:
	xdp_ratelimit_bpf__destroy(skel);
	return err ? 1 : 0;

detach:
	(void)xdp_detach_mode(ifindex, used);
	unlink(buckets);
	unlink(stats);
	rmdir(dir);
	unlink(conf);
	goto out;
}

static int cmd_detach(const char *iface)
{
	char dir[PATH_MAX], buckets[PATH_MAX], stats[PATH_MAX], conf[PATH_MAX];
	enum xdp_mode mode = MODE_AUTO;
	unsigned int ifindex;
	int err;

	map_paths(iface, dir, sizeof(dir), buckets, sizeof(buckets),
		  stats, sizeof(stats));
	conf_path(iface, conf, sizeof(conf));

	ifindex = if_nametoindex(iface);
	if (ifindex) {
		(void)read_conf_mode(iface, &mode);
		if (mode == MODE_NATIVE)
			err = bpf_xdp_detach(ifindex, XDP_FLAGS_DRV_MODE, NULL);
		else if (mode == MODE_GENERIC)
			err = bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
		else
			err = xdp_detach_any(ifindex);
		if (err && err != -ENOENT)
			fprintf(stderr, "warning: XDP detach failed: %s\n",
				strerror(-err));
	} else {
		fprintf(stderr, "interface not found: %s (cleanup maps only)\n",
			iface);
	}

	unlink(buckets);
	unlink(stats);
	rmdir(dir);
	unlink(conf);
	printf("detached %s (if present) and cleaned pins\n", iface);
	return 0;
}

static int read_u64_map(int fd, __u32 key, __u64 *total, int ncpus)
{
	__u64 *values;
	int err;

	values = calloc((size_t)ncpus, sizeof(*values));
	if (!values)
		return -ENOMEM;

	err = bpf_map_lookup_elem(fd, &key, values);
	if (!err) {
		*total = 0;
		for (int i = 0; i < ncpus; i++)
			*total += values[i];
	}
	free(values);
	return err;
}

static int cmd_stats(const char *iface)
{
	char dir[PATH_MAX], buckets[PATH_MAX], stats[PATH_MAX];
	__u64 pass = 0, drop = 0;
	int fd, ncpus, err;

	map_paths(iface, dir, sizeof(dir), buckets, sizeof(buckets),
		  stats, sizeof(stats));

	fd = bpf_obj_get(stats);
	if (fd < 0) {
		fprintf(stderr, "stats map not found at %s: %s\n", stats,
			strerror(errno));
		return 1;
	}

	ncpus = libbpf_num_possible_cpus();
	if (ncpus <= 0) {
		fprintf(stderr, "failed to get possible CPU count\n");
		close(fd);
		return 1;
	}

	err = read_u64_map(fd, RATELIMIT_STAT_PASS, &pass, ncpus);
	if (err) {
		fprintf(stderr, "failed to read pass stat: %s\n", strerror(-err));
		close(fd);
		return 1;
	}
	err = read_u64_map(fd, RATELIMIT_STAT_DROP, &drop, ncpus);
	if (err) {
		fprintf(stderr, "failed to read drop stat: %s\n", strerror(-err));
		close(fd);
		return 1;
	}
	close(fd);

	printf("iface: %s\n", iface);
	printf("pass_packets: %llu\n", (unsigned long long)pass);
	printf("drop_packets: %llu\n", (unsigned long long)drop);
	printf("total_packets: %llu\n", (unsigned long long)(pass + drop));
	return 0;
}

static int cmd_status(const char *iface)
{
	char path[PATH_MAX], line[128];
	FILE *fp;

	conf_path(iface, path, sizeof(path));
	fp = fopen(path, "r");
	if (!fp) {
		fprintf(stderr, "%s is not loaded (no %s)\n", iface, path);
		return 1;
	}
	printf("iface: %s\n", iface);
	while (fgets(line, sizeof(line), fp))
		fputs(line, stdout);
	fclose(fp);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s <command> [options]\n"
		"\n"
		"commands:\n"
		"  load    --iface IF [--rate PPS] [--burst N] [--mode auto|native|generic] [--force]\n"
		"  detach  --iface IF\n"
		"  stats   --iface IF\n"
		"  status  --iface IF\n"
		"\n"
		"common options:\n"
		"  --netns NAME   enter only the network namespace (keeps bpffs visible)\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *iface = NULL;
	const char *netns = NULL;
	enum xdp_mode mode = MODE_AUTO;
	__u64 rate = RATELIMIT_DEFAULT_RATE_PPS;
	__u64 burst = RATELIMIT_DEFAULT_BURST;
	bool force = false;
	const char *cmd;
	int opt, err;

	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}
	cmd = argv[1];

	static const struct option long_opts[] = {
		{ "iface", required_argument, NULL, 'i' },
		{ "rate", required_argument, NULL, 'r' },
		{ "burst", required_argument, NULL, 'b' },
		{ "mode", required_argument, NULL, 'm' },
		{ "netns", required_argument, NULL, 'n' },
		{ "force", no_argument, NULL, 'f' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	optind = 2;
	while ((opt = getopt_long(argc, argv, "i:r:b:m:n:fh", long_opts,
				  NULL)) != -1) {
		switch (opt) {
		case 'i':
			iface = optarg;
			break;
		case 'n':
			netns = optarg;
			break;
		case 'r':
			rate = strtoull(optarg, NULL, 10);
			break;
		case 'b':
			burst = strtoull(optarg, NULL, 10);
			break;
		case 'm':
			if (mode_from_name(optarg, &mode)) {
				fprintf(stderr, "invalid mode: %s\n", optarg);
				return 1;
			}
			break;
		case 'f':
			force = true;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (iface && !valid_ifname(iface)) {
		fprintf(stderr, "invalid interface name: %s\n", iface);
		return 1;
	}
	if (netns && !valid_netns_name(netns)) {
		fprintf(stderr, "invalid netns name: %s\n", netns);
		return 1;
	}

	if (netns) {
		err = enter_netns(netns);
		if (err) {
			fprintf(stderr, "failed to enter netns %s: %s\n", netns,
				strerror(-err));
			return 1;
		}
	}

	if (!strcmp(cmd, "load")) {
		if (!iface) {
			usage(argv[0]);
			return 1;
		}
		return cmd_load(iface, rate, burst, mode, force);
	}
	if (!strcmp(cmd, "detach")) {
		if (!iface) {
			usage(argv[0]);
			return 1;
		}
		return cmd_detach(iface);
	}
	if (!strcmp(cmd, "stats")) {
		if (!iface) {
			usage(argv[0]);
			return 1;
		}
		return cmd_stats(iface);
	}
	if (!strcmp(cmd, "status")) {
		if (!iface) {
			usage(argv[0]);
			return 1;
		}
		return cmd_status(iface);
	}

	usage(argv[0]);
	return 1;
}
