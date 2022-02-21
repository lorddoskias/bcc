// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2022 SUSE Linux Products GmbH. All Rights Reserved.
//
// Based on tcpaccept(8) from BCC by Brendan Gregg
#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include "maps.bpf.h"
#include "tcpaccept.h"

SEC(".rodata") int filter_ports[MAX_PORTS];
const volatile int filter_ports_len = 0;
const volatile uid_t filter_uid = -1;
const volatile pid_t filter_pid = 0;

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv4_flow_key);
	__type(value, u64);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ipv4_count SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline bool filter_port(__u16 port)
{
	int i;

	if (filter_ports_len == 0)
		return false;

	for (i = 0; i < filter_ports_len; i++) {
		if (port == filter_ports[i])
			return false;
	}
	return true;
}

static __always_inline bool filter_uid_pid(u32 pid)
{
    __u32 uid;

    if (filter_pid && pid != filter_pid)
        return true;

    uid = bpf_get_current_uid_gid();
    if (filter_uid != (uid_t) -1 && uid != filter_uid)
        return true;

    return false;
}

static __always_inline int
bpf__inet_csk_accept(struct pt_regs *ctx, int ret)
{
	struct sock *sk;
	u16 protocol;
	__u16 rport, lport, family;
	struct event event = {};
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	sk = (struct sock *)PT_REGS_RC(ctx);
	if (!sk)
		return 0;

	lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	if (filter_port(lport) || filter_uid_pid(pid))
		return 0;

	rport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);

	if (protocol != IPPROTO_TCP)
		return 0;

	event.pid = pid;
	event.uid = bpf_get_current_uid_gid();
	event.ts_us = bpf_ktime_get_ns() / 1000;
	event.rport = rport;
	event.lport = lport;
	bpf_get_current_comm(event.task, sizeof(event.task));

	if (family == AF_INET) {
		event.af = AF_INET;
		BPF_CORE_READ_INTO(&event.daddr_v4, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&event.saddr_v4, sk, __sk_common.skc_daddr);
	} else if (family == AF_INET6) {
		BPF_CORE_READ_INTO(&event.saddr_v6, sk,
				__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&event.daddr_v6, sk,
				__sk_common.skc_v6_daddr.in6_u.u6_addr32);
	}

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
			&event, sizeof(event));

	return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_retprobe, int ret)
{
	return bpf__inet_csk_accept(ctx, ret);
}

char LICENSE[] SEC("license") = "GPL";
