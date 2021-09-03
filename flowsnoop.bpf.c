// Copyright 2021 Google LLC

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <vmlinux.h>           /* all kernel types */
#include <bpf/bpf_core_read.h> /* for BPF CO-RE helpers */
#include <bpf/bpf_helpers.h> /* most used helpers: SEC, __always_inline, etc */
#include <bpf/bpf_tracing.h> /* for getting kprobe arguments */
#include <bpf/bpf_endian.h>


#ifndef BPF_NOEXIST
#define BPF_NOEXIST 1
#endif

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86DD
#endif

#define TP_DATA_LOC_READ_CONST(dst, field, length)                             \
  do {                                                                         \
    unsigned short __offset = ctx->__data_loc_##field & 0xFFFF;                \
    bpf_probe_read((void *)dst, length, (char *)ctx + __offset);               \
  } while (0);

const volatile char targ_iface[16] = {
    0,
};
volatile int use_map = 0;

#define BUCKETS 10240

struct conn_s {
  u32 src_ip;
  u32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
};

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
} events SEC(".maps");



// used for config setup
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 128);
    __type(key, u32);
    __type(value, u32);
} config_map SEC(".maps");


struct connections_s {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BUCKETS);
  __type(key, struct conn_s);
  __type(value, u64);
} connections SEC(".maps"), bconnections SEC(".maps");

struct conn6_s {
  u8 src_ip[16];
  u8 dst_ip[16];
  u16 src_port;
  u16 dst_port;
  u8 protocol;
};
struct connections6_s {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, BUCKETS);
  __type(key, struct conn6_s);
  __type(value, u64);
} connections6 SEC(".maps"), bconnections6 SEC(".maps");

static int is_equal(char *got, const volatile char *want, int n) {
  int i;
  if (want[0] == '\0')
    return 1;
  for (i = 0; i < n; i++) {
    if (got[i] != want[i])
      return 0;
    if (got[i] == '\0')
      return 1;
  }
  return 0;
}


// assume we now only filter on source ip
static __always_inline int get_config(u32 key)
{
    u32 *config = bpf_map_lookup_elem(&config_map, &key);
    if (config == NULL)
        return 0;
    return *config;
}


static __always_inline bool source_ip_match(u32 value) {
    u32 filter = get_config(1);
    return filter == value;
}


static inline struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
  return (struct tcphdr *)(BPF_CORE_READ(skb, head) +
                           BPF_CORE_READ(skb, transport_header));
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
  return (struct iphdr *)(BPF_CORE_READ(skb, head) +
                          BPF_CORE_READ(skb, network_header));
}

static inline struct ipv6hdr *skb_to_ipv6hdr(const struct sk_buff *skb) {
  return (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                            BPF_CORE_READ(skb, network_header));
}

static inline struct ethhdr *skb_to_ethhdr(const struct sk_buff *skb) {
  return (struct ethhdr *)(BPF_CORE_READ(skb, head) +
                            BPF_CORE_READ(skb, mac_header));
}

static int do_count4(void *ctx, struct sk_buff *skb, int len) {
  struct iphdr *ip = skb_to_iphdr(skb);
  struct conn_s conn = {};
  u64 *oval = 0;
  u8 version;
  struct connections_s *conn_table = &connections;
  bpf_probe_read(&version, 1, ip);
  if ((version & 0xf0) != 0x40) /* IPv4 only */
    return -1;
  BPF_CORE_READ_INTO(&conn.protocol, ip, protocol);
  BPF_CORE_READ_INTO(&conn.src_ip, ip, saddr);
  BPF_CORE_READ_INTO(&conn.dst_ip, ip, daddr);
  if ((conn.protocol == 6 || conn.protocol == 17) &&
      BPF_CORE_READ(skb, transport_header) != 0) {
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    BPF_CORE_READ_INTO(&conn.src_port, tcp, source);
    BPF_CORE_READ_INTO(&conn.dst_port, tcp, dest);
  }

  if (!source_ip_match(conn.src_ip)) {
          return -1;
  }


  if (use_map)
    conn_table = &bconnections;
  oval = bpf_map_lookup_elem(conn_table, &conn);
  if (oval) {
    __sync_fetch_and_add(oval, len);
  } else {
    u64 nval = len;
    if (bpf_map_update_elem(conn_table, &conn, &nval, BPF_NOEXIST) == -1) {
      oval = bpf_map_lookup_elem(conn_table, &conn);
      if (oval)
        __sync_fetch_and_add(oval, len);
    }
  }


  bpf_perf_event_output(ctx, &events, 0, &conn, sizeof(conn));

  return 0;
}

static int do_count6(struct sk_buff *skb, int len) {
  struct ipv6hdr *ip = skb_to_ipv6hdr(skb);
  struct conn6_s conn = {};
  u64 *oval = 0;
  u64 nval = 0;
  u8 version;
  struct connections6_s *conn_table = &connections6;
  bpf_probe_read(&version, 1, ip);
  if ((version & 0xf0) != 0x60) /* IPv6 only */
    return -1;
  /* TODO: check this, it is not correct in all cases. */
  BPF_CORE_READ_INTO(&conn.protocol, ip, nexthdr);
  bpf_probe_read(conn.src_ip, 16, &ip->saddr);
  bpf_probe_read(conn.dst_ip, 16, &ip->daddr);
  if ((conn.protocol == 6 || conn.protocol == 17) &&
      BPF_CORE_READ(skb, transport_header) != 0) {
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    BPF_CORE_READ_INTO(&conn.src_port, tcp, source);
    BPF_CORE_READ_INTO(&conn.dst_port, tcp, dest);
  }
  if (use_map)
    conn_table = &bconnections6;
  oval = bpf_map_lookup_elem(conn_table, &conn);
  if (oval) {
    __sync_fetch_and_add(oval, len);
  } else {
    u64 nval = len;
    if (bpf_map_update_elem(conn_table, &conn, &nval, BPF_NOEXIST) == -1) {
      oval = bpf_map_lookup_elem(conn_table, &conn);
      if (oval)
        __sync_fetch_and_add(oval, len);
    }
  }
  return 0;
}

static __always_inline void do_count(void *ctx, struct sk_buff *skb, int len, char *dev) {
  struct ethhdr *hdr = skb_to_ethhdr(skb);
  u16 prot = BPF_CORE_READ(hdr, h_proto);
  if (!is_equal(dev, targ_iface, 16))
    return;
  if (BPF_CORE_READ(skb, network_header) == 0)
    return;
  if (prot == bpf_htons(ETH_P_IP))
      do_count4(ctx, skb, len);
  if (prot == bpf_htons(ETH_P_IPV6))
      do_count6(skb, len);
  return;
}

SEC("tracepoint/net/netif_receive_skb")
int tracepoint__net_netif_receive_skb(
  struct trace_event_raw_net_dev_template *ctx) {
  char dev[16] = {
      0,
  };
  struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
  TP_DATA_LOC_READ_CONST(dev, name, 16);
  do_count(ctx, skb, ctx->len, dev);
  return 0;
}

SEC("tracepoint/net/net_dev_start_xmit")
int tracepoint__net_net_dev_start_xmit(
    struct trace_event_raw_net_dev_start_xmit *ctx) {
  char dev[16] = {
      0,
  };
  struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;
  TP_DATA_LOC_READ_CONST(dev, name, 16);
  do_count(ctx, skb, ctx->len - ctx->network_offset, dev);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
