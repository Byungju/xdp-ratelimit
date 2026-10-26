// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE 33
#endif

#define BATCH 64
#define BUFSZ 2048

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [--bind ADDR] [--port N] [--timeout SEC] "
		"[--rcvbuf BYTES] [--cpu N]\n", prog);
}

int main(int argc, char **argv)
{
	const char *bind_addr = "0.0.0.0";
	unsigned port = 9999;
	double timeout = 1.0;
	int rcvbuf = 64 << 20;
	int cpu = -1;
	int opt;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
	};
	struct timeval tv;
	struct rusage ru0, ru1;
	uint64_t packets = 0, bytes = 0;

	static const struct option long_opts[] = {
		{ "bind", required_argument, NULL, 'b' },
		{ "port", required_argument, NULL, 'p' },
		{ "timeout", required_argument, NULL, 't' },
		{ "rcvbuf", required_argument, NULL, 'r' },
		{ "cpu", required_argument, NULL, 'c' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	while ((opt = getopt_long(argc, argv, "b:p:t:r:c:h", long_opts,
				  NULL)) != -1) {
		switch (opt) {
		case 'b':
			bind_addr = optarg;
			break;
		case 'p':
			port = strtoul(optarg, NULL, 10);
			break;
		case 't':
			timeout = strtod(optarg, NULL);
			break;
		case 'r':
			rcvbuf = atoi(optarg);
			break;
		case 'c':
			cpu = atoi(optarg);
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
		fprintf(stderr, "bad bind address\n");
		return 1;
	}
	addr.sin_port = htons(port);

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

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf,
		       sizeof(rcvbuf)) < 0)
		setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		perror("bind");
		return 1;
	}

	tv.tv_sec = (time_t)timeout;
	tv.tv_usec = (suseconds_t)((timeout - tv.tv_sec) * 1000000);
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	struct mmsghdr msgs[BATCH];
	struct iovec iov[BATCH];
	char bufs[BATCH][BUFSZ];

	getrusage(RUSAGE_SELF, &ru0);
	for (;;) {
		memset(msgs, 0, sizeof(msgs));
		for (int i = 0; i < BATCH; i++) {
			iov[i].iov_base = bufs[i];
			iov[i].iov_len = sizeof(bufs[i]);
			msgs[i].msg_hdr.msg_iov = &iov[i];
			msgs[i].msg_hdr.msg_iovlen = 1;
		}
		int n = recvmmsg(fd, msgs, BATCH, MSG_WAITFORONE, NULL);
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			if (errno == EINTR)
				continue;
			perror("recvmmsg");
			break;
		}
		for (int i = 0; i < n; i++) {
			packets++;
			bytes += msgs[i].msg_len;
		}
	}
	getrusage(RUSAGE_SELF, &ru1);

	double user_ms = (ru1.ru_utime.tv_sec - ru0.ru_utime.tv_sec) * 1000.0 +
			 (ru1.ru_utime.tv_usec - ru0.ru_utime.tv_usec) / 1000.0;
	double sys_ms = (ru1.ru_stime.tv_sec - ru0.ru_stime.tv_sec) * 1000.0 +
			(ru1.ru_stime.tv_usec - ru0.ru_stime.tv_usec) / 1000.0;

	printf("received_packets=%llu\n", (unsigned long long)packets);
	printf("received_bytes=%llu\n", (unsigned long long)bytes);
	printf("cpu_user_ms=%.3f\n", user_ms);
	printf("cpu_sys_ms=%.3f\n", sys_ms);
	close(fd);
	return 0;
}
