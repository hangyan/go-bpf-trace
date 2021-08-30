#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>




#include <trace.bpf.h>

#define TASK_COMM_LEN 16
#define	IFNAMSIZ      16
#define         XT_TABLE_MAXNAMELEN   32

#define ROUTE_EVT_IF 1
#define ROUTE_EVT_IPTABLE 2
#define FUNNAMESIZE 30



#define MAC_HEADER_SIZE 14;
#define member_address(source_struct, source_member)            \
    ({                                                          \
        void* __ret;                                            \
        __ret = (void*) (((char*)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                  \
    })
#define member_read(destination, source_struct, source_member)  \
  do{                                                           \
    bpf_probe_read(                                             \
      destination,                                              \
      sizeof(source_struct->source_member),                     \
      member_address(source_struct, source_member)              \
    );                                                          \
  } while(0)



// Event structure
struct route_evt_t {
    /* Content flags */
    u64 flags;

    char comm[TASK_COMM_LEN];

    /* Routing information */
    char ifname[IFNAMSIZ];
    u64 netns;

    /* Packet type (IPv4 or IPv6) and address */
    u64 ip_version; // familiy (IPv4 or IPv6)
    u64 icmptype;
    u64 icmpid;     // In practice, this is the PID of the ping process (see "ident" field in https://github.com/iputils/iputils/blob/master/ping_common.c)
    u64 icmpseq;    // Sequence number
    u64 saddr[2];   // Source address. IPv4: store in saddr[0]
    u64 daddr[2];   // Dest   address. IPv4: store in daddr[0]

    /* Iptables trace */
    u64 hook;
    u64 verdict;
    char tablename[XT_TABLE_MAXNAMELEN];

    u64 ts;
    char funcname[FUNNAMESIZE];
};


struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
        __uint(key_size, sizeof(u32));
        __uint(value_size, sizeof(u32));
} events SEC(".maps");



/**
  * Common tracepoint handler. Detect IPv4/IPv6 ICMP echo request and replies and
  * emit event with address, interface and namespace.
  */
static inline int do_trace_skb(struct route_evt_t *evt, void *ctx,
                               struct sk_buff *skb) {
    // Prepare event for userland
    evt->flags |= ROUTE_EVT_IF;

    // command name
    bpf_get_current_comm(evt->comm, TASK_COMM_LEN);

    evt->ts = bpf_ktime_get_ns();

    // Compute MAC header address
    char *head;
    u16 mac_header;
    u16 network_header;

    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);

    if (network_header == 0) {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

    // Compute IP Header address
    char *ip_header_address = head + network_header;

    // Abstract IPv4 / IPv6
    u8 proto_icmp;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;
    u8 icmp_offset_from_ip_header;
    u8 l4proto;

    // Load IP protocol version
    bpf_probe_read(&evt->ip_version, sizeof(u8), ip_header_address);
    evt->ip_version = evt->ip_version >> 4 & 0xf;

    // Filter IP packets
    if (evt->ip_version == 4) {
        // Load IP Header
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), ip_header_address);

        // Load protocol and address
        icmp_offset_from_ip_header = iphdr.ihl * 4;
        l4proto = iphdr.protocol;
        evt->saddr[0] = iphdr.saddr;
        evt->daddr[0] = iphdr.daddr;

        // Load constants
        proto_icmp = IPPROTO_ICMP;
        proto_icmp_echo_request = ICMP_ECHO;
        proto_icmp_echo_reply = ICMP_ECHOREPLY;
    } else if (evt->ip_version == 6) {
        // Assume no option header --> fixed size header
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)ip_header_address;
        icmp_offset_from_ip_header = sizeof(*ipv6hdr);

        // Load protocol and address
        bpf_probe_read(&l4proto, sizeof(ipv6hdr->nexthdr),
                       (char *)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(evt->saddr, sizeof(ipv6hdr->saddr),
                       (char *)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(evt->daddr, sizeof(ipv6hdr->daddr),
                       (char *)ipv6hdr + offsetof(struct ipv6hdr, daddr));

        // Load constants
        proto_icmp = IPPROTO_ICMPV6;
        proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
        proto_icmp_echo_reply = ICMPV6_ECHO_REPLY;
    } else {
        return 0;
    }

    // Filter ICMP packets
    if (l4proto != proto_icmp) {
        return 0;
    }

    // Compute ICMP header address and load ICMP header
    char *icmp_header_address = ip_header_address + icmp_offset_from_ip_header;
    struct icmphdr icmphdr;
    bpf_probe_read(&icmphdr, sizeof(icmphdr), icmp_header_address);

    // filter ICMP echo request and echo reply
    if (icmphdr.type != proto_icmp_echo_request &&
        icmphdr.type != proto_icmp_echo_reply) {
        return 0;
    }

    // Get ICMP info
    evt->icmptype = icmphdr.type;
    evt->icmpid = icmphdr.un.echo.id;
    evt->icmpseq = icmphdr.un.echo.sequence;

    // Fix endian
    // evt->icmpid = evt->icmpid;
    //evt->icmpseq = evt->icmpseq;

    // Get device pointer, we'll need it to get the name and network namespace
    struct net_device *dev;
    member_read(&dev, skb, dev);

    // Load interface name
    bpf_probe_read(&evt->ifname, IFNAMSIZ, dev->name);

#ifdef CONFIG_NET_NS
    struct net *net;

    // Get netns id. The code below is equivalent to: evt->netns =
    // dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common *ns = member_address(net, ns);
    member_read(&evt->netns, ns, inum);
#endif

    return 0;
}


static __always_inline int do_trace(void *ctx, struct sk_buff *skb, char* fnname)
{
    // Prepare event for userland
    struct route_evt_t evt = {};

    //strcpy(evt.funcname, fnname);
    // bpf_probe_read_str(evt.funcname,sizeof(fnname), fnname);


    // Process packet
    int ret = do_trace_skb(&evt, ctx, skb);

    // Send event
    bpf_perf_event_output(ctx, &events, 0, &evt, sizeof(evt));
     //route_evt.perf_submit(ctx, &evt, sizeof(evt));

    // Return
    return ret;
}





SEC("tracepoint/net/netif_rx")
int tracepoint__net__netif_rx(struct trace_event_raw_net_dev_template* ctx) {
    return do_trace(ctx, (struct sk_buff*)ctx->skbaddr, "net:netif_rx");
}

SEC("tracepoint/net/net_dev_queue")
int tracepoint__net__net_dev_queue(struct trace_event_raw_net_dev_template* ctx) {
    return do_trace(ctx, (struct sk_buff*)ctx->skbaddr, "net:net_dev_queue");
}

SEC("tracepoint/net/napi_gro_receive_entry")
int tracepoint__net__napi_gro_receive_entry(struct trace_event_raw_net_dev_template* ctx) {
    return do_trace(ctx, (struct sk_buff*)ctx->skbaddr, "net:napi_gro_receive_entry");
}

SEC("tracepoint/net/netif_receive_skb_entry")
int tracepoint__net__netif_receive_skb_entry(struct trace_event_raw_net_dev_template* ctx) {
    return do_trace(ctx, (struct sk_buff*)ctx->skbaddr, "net:netif_receive_skb_entry");
}



// Some eBPF programs must be GPL licensed. This depends on program types,
// eBPF helpers used and among other things. As this eBPF program is
// integrating with tracepoints, it must be GPL.
char _license[] SEC("license") = "GPL";
