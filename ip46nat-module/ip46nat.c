/*
 * ip46nat.c - kernel module for performing IPv4-IPv6 NAT
 *
 * author: Tomasz Mrugalski <thomson@klub.com.pl>
 *
 * released under GNU GPLv2 license.
 *
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in6.h>
#include <net/route.h>
#include <net/ip6_route.h>

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>

#include <linux/icmp.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Tomasz Mrugalski");
MODULE_DESCRIPTION("IPv4-IPv6 translator");
#define MODULE_VERS "2012-09-25"
#define MODULE_NAME "ip46nat"

#define V6PREFIX_MAX_LEN 64
#define V4ADDR_MAX_LEN 32

#define DEBUG_NONE    0
#define DEBUG_MATCHED 1
#define DEBUG_ALL     2

static char prefixlan_str[V6PREFIX_MAX_LEN];
static char prefixwan_str[V6PREFIX_MAX_LEN];
static char v4addr_str[V4ADDR_MAX_LEN];

  /* used as a src/dst "filler" during IPv4->IPv6 address expansion */
  // static char prefixlan[16]; /* src prefix for outgoing traffic */
  // static char prefixwan[16]; /* dst prefix for outgoing traffic */
  // static int v6prefix_length = 64;

  /* used to match source address in incoming IPv4 packets */
  // __u32 v4addr;
  //static int v4masklen;

/* module parameters */
static char  cfg_prefixlan[16]; /* src prefix */
static char  cfg_prefixwan[16]; /* dst prefix */
static int   cfg_v6prefix_length = 128;

static short cfg_v4offset = 96; /* specified in bits */
static __u32 cfg_v4addr; /* v4 prefix */
static short cfg_v4masklen = 24;

static short cfg_debug = DEBUG_NONE;

static int   cfg_offset; /* not set directly, but calculated based on offset (specified in bytes) */
static __u32 cfg_v4mask; /* not set directly, but calculated based on v4masklen */

/* end of module parameters */

module_param_string(prefixlan, prefixlan_str, V6PREFIX_MAX_LEN,   0);
module_param_string(prefixwan, prefixwan_str, V6PREFIX_MAX_LEN,   0);
module_param_string(v4addr,    v4addr_str, V4ADDR_MAX_LEN, 0);
module_param_named(v4offset,   cfg_v4offset, short, 0);
module_param_named(debug,      cfg_debug, short, 0);
module_param_named(v4masklen,  cfg_v4masklen, short, 0);
module_param_named(v6prefixlen, cfg_v6prefix_length, short, 0);

struct packet_type ipv4_pkt;
struct packet_type ipv6_pkt;

/* procfs data */
static struct proc_dir_entry *procfs_dir, *procfs_stats_file, *procfs_params_file;

/* stats */
static int cnt4to6          = 0; /* IPv4 to IPv6 nated */
static int cnt6to4          = 0; /* IPv6 to IPv4 nated */
static int cnt4rcv          = 0; /* IPv4 received */
static int cnt4snd          = 0; /* IPv4 sent */
static int cnt6rcv          = 0; /* IPv6 received */
static int cnt6snd          = 0; /* IPv6 sent */
static int cnt4drop_mtu     = 0; /* IPv4 dropped due to too big size */
static int cnt4drop_route   = 0; /* IPv4 dropped due to missing route */
static int cnt6drop_route   = 0; /* IPv6 dropped due to missing route */
static int cnt4xmit_errors  = 0; /* IPv4 transmission errors */
static int cnt6xmit_errors  = 0; /* IPv6 transmission errors */

static int procfs_init(void);
static void procfs_exit(void);


/* ******************************************************************************** */
/* *** utility functions ********************************************************** */
/* ******************************************************************************** */

void in4_ntop(char * buf, int addr)
{
    sprintf(buf, "%d.%d.%d.%d", addr&0xff, (addr>>8)&0xff, (addr>>16)&0xff, (addr>>24)&0xff);
}

void in6_ntop(char * dst, const unsigned char * src)
{
    const int NS_IN6ADDRSZ = 16;
    const int NS_INT16SZ = 2;

    char tmp[40], *tp; // 40 - maximum size of expanded (no ::) IPv6 address
    struct { int base, len; } best, cur;
    u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
    int i;

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
	 */
	memset(words, '\0', sizeof words);
	for (i = 0; i < NS_IN6ADDRSZ; i += 2)
		words[i / 2] = (src[i] << 8) | src[i + 1];
	best.base = -1;
	cur.base = -1;
	cur.len = 1;
	best.len = 1;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		if (words[i] == 0) {
			if (cur.base == -1)
				cur.base = i, cur.len = 1;
			else
				cur.len++;
		} else {
			if (cur.base != -1) {
				if (best.base == -1 || cur.len > best.len)
					best = cur;
				cur.base = -1;
			}
		}
	}
	if (cur.base != -1) {
		if (best.base == -1 || cur.len > best.len)
			best = cur;
	}
	if (best.base != -1 && best.len < 2)
		best.base = -1;

	/*
	 * Format the result.
	 */
	tp = tmp;
	for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
		/* Are we inside the best run of 0x00's? */
		if (best.base != -1 && i >= best.base &&
		    i < (best.base + best.len)) {
			if (i == best.base)
				*tp++ = ':';
			continue;
		}
		/* Are we following an initial run of 0x00s or any real hex? */
		if (i != 0)
			*tp++ = ':';
		tp += sprintf(tp, "%x", words[i]);
	}
	/* Was it a trailing run of 0x00's? */
	if (best.base != -1 && (best.base + best.len) ==
	    (NS_IN6ADDRSZ / NS_INT16SZ))
		*tp++ = ':';
	*tp++ = '\0';
	strcpy(dst, tmp);
}

void in6_ntop2(char * buf, const struct in6_addr * addr)
{
    in6_ntop(buf, (char *)&addr->s6_addr);
}

/* ******************************************************************************** */
/* *** IPv4 -> IPv6 functions ***************************************************** */
/* ******************************************************************************** */
void ip6_update_csum(struct sk_buff * skb, struct ipv6hdr * ip6hdr)
{
    __wsum sum1=0;
    __sum16 sum2=0;
    __sum16 oldsum = 0;

    switch (ip6hdr->nexthdr)
    {
    case IPPROTO_TCP:
    {
	struct tcphdr *th = tcp_hdr(skb);
	unsigned tcplen = 0;
	oldsum = th->check;
	tcplen = ntohs(ip6hdr->payload_len); /* TCP header + payload */

	th->check = 0;
	sum1 = csum_partial((char*)th, tcplen, 0); /* calculate checksum for TCP hdr+payload */
	sum2 = csum_ipv6_magic(&ip6hdr->saddr, &ip6hdr->daddr, tcplen, ip6hdr->nexthdr, sum1); /* add pseudoheader */

	if (cfg_debug>=DEBUG_MATCHED)
	    printk(KERN_ALERT " Updating TCP (over IPv6) checksum to %x (old=%x)\n", htons(sum2), htons(oldsum) );
	th->check = sum2;
	break;
    }
    case IPPROTO_UDP:
    {
	struct udphdr *udp = udp_hdr(skb);
	unsigned udplen = ntohs(ip6hdr->payload_len); /* UDP hdr + payload */

	oldsum = udp->check;
	udp->check = 0;

	sum1 = csum_partial((char*)udp, udplen, 0); /* calculate checksum for UDP hdr+payload */
	sum2 = csum_ipv6_magic(&ip6hdr->saddr, &ip6hdr->daddr, udplen, ip6hdr->nexthdr, sum1); /* add pseudoheader */

	if (cfg_debug>=DEBUG_MATCHED)
	    printk(KERN_ALERT " Updating UDP (over IPv6) checksum to %x (old=%x)\n", htons(sum2), htons(oldsum) );
	udp->check = sum2;

	break;
    }

    case IPPROTO_ICMP:
	break;
    }
}

static int ipv4_send_as_ipv6(struct sk_buff * skb)
{
    char buf1[32], buf2[32], buf3[64], buf4[64];
    char v6saddr[16], v6daddr[16];
    int err = -1;
    int tclass = 0;
    int flowlabel = 0;
    int len;

    struct ipv6hdr * hdr6;
    struct iphdr * hdr4 = ip_hdr(skb);
    struct sk_buff * copy = 0;

    memcpy(v6saddr, cfg_prefixlan, 16);
    memcpy(v6daddr, cfg_prefixwan, 16);
    memcpy(v6saddr+cfg_offset, &hdr4->saddr, 4);
    memcpy(v6daddr+cfg_offset, &hdr4->daddr, 4);

    if (cfg_debug>=DEBUG_MATCHED)
    {
	in4_ntop(buf1, ntohl(hdr4->saddr));
	in4_ntop(buf2, ntohl(hdr4->daddr));
	in6_ntop(buf3, v6saddr);
	in6_ntop(buf4, v6daddr);

	printk(KERN_ALERT " IPv4(src=%s, dst=%s)->IPv6(src=%s,dst=%s)\n", buf1, buf2,buf3,buf4);
    }

    if (ntohs(hdr4->tot_len) > 1480) {
	if (cfg_debug>DEBUG_NONE)
	    printk(KERN_ALERT "#Too large IPv4 (len=%d) received, dropped. %d such errors so far.\n",
		   ntohs(hdr4->tot_len), ++cnt4drop_mtu);
	return -1;
    }

    len = skb->tail - skb->data;

    /* create new skb */
    copy = skb_copy(skb, GFP_ATOMIC); // other possible option: GFP_ATOMIC

    /* Remove any debris in the socket control block */
    memset(IPCB(copy), 0, sizeof(struct inet_skb_parm));

    /* expand header (add 20 extra bytes at the beginning of sk_buff) */
    pskb_expand_head(copy, 20, 0, GFP_ATOMIC);

    skb_push(copy, sizeof(struct ipv6hdr) - sizeof(struct iphdr)); /* push boundary by extra 20 bytes */

    skb_reset_network_header(copy);
    skb_set_transport_header(copy,40); /* transport (TCP/UDP/ICMP/...) header starts after 40 bytes */

    /* printk(KERN_ALERT "#### skb->len=%d len=%d copy->len=%d\n", skb->len, len, copy->len); */

    hdr6 = ipv6_hdr(copy);

    /* build IPv6 header */
    tclass = 0; /* traffic class */
    *(__be32 *)hdr6 = htonl(0x60000000 | (tclass << 20)) | flowlabel; /* version, priority, flowlabel */
    hdr6->payload_len = htons(ntohs(hdr4->tot_len)
			      - sizeof(struct iphdr)); /* IPv6 length is a payload length, IPv4 is hdr+payload */
    hdr6->nexthdr     = hdr4->protocol;
    hdr6->hop_limit   = hdr4->ttl;
    memcpy(&hdr6->saddr, v6saddr, 16);
    memcpy(&hdr6->daddr, v6daddr, 16);

    copy->priority = skb->priority;
    copy->mark     = skb->mark;
    copy->protocol = htons(ETH_P_IPV6);

    ip6_update_csum(copy, hdr6);

    ip6_route_input(copy);
    if (skb_dst(copy) == NULL) {
	if (cfg_debug>=DEBUG_MATCHED)
	    printk(KERN_ALERT "#Unable to find route, IPv6 packet not sent (%d IPv6 route errors so far)\n",
		   ++cnt6drop_route);
	return -1;
    }

    if (dst_mtu(skb_dst(copy))==0) {
	if (cfg_debug>=DEBUG_MATCHED)
	    printk(KERN_ALERT "#Route with mtu=0 found, IPv6 packet not sent (%d IPv6 route errors so far).\n",
		   ++cnt6drop_route);
	return -1;
    }

    err = ip6_forward(copy);
    if (err==0) {
	/* packet sent successfully */
	cnt6snd++;
	cnt4to6++;
    } else {
	if (cfg_debug>=DEBUG_MATCHED)
	    printk(KERN_ALERT "#IPv4->IPv6: Packet transmission (ip6_forward()) failed. Errors so far: %d\n",
		   ++cnt6xmit_errors);
    }

    /* should skb be released here? No, it shouldn't */

    return 0;
}

static int ipv4_handler(struct sk_buff *skb,struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    struct iphdr * hdr = ip_hdr(skb);
    static char buf1[32], buf2[32], buf3[32];

    int process = 0;
    int mcast = 0;

    cnt4rcv++;

    in4_ntop(buf1, ntohl(hdr->saddr));
    in4_ntop(buf2, ntohl(hdr->daddr));
    in4_ntop(buf3, (cfg_v4addr & cfg_v4mask) );

    /* IPv4 address pattern checking */
    if ( (hdr->saddr & cfg_v4mask) == (cfg_v4addr & cfg_v4mask) )
	process = 1;

    if ((hdr->daddr >> 24) >= 224)
	 mcast = 1; /* that's multicast */

    if ( (process && (cfg_debug>=DEBUG_MATCHED)) || (cfg_debug>=DEBUG_ALL) ) {
	printk(KERN_ALERT "#IPv4 rcvd (rcvd so far: %d) [src=%s, dst=%s,looking for %s/%d]%s\n", cnt4rcv, buf1, buf2,
	       buf3, cfg_v4masklen, process?(mcast?"M":"*"):"");
    }

    if (process && !mcast)
	ipv4_send_as_ipv6(skb);

    kfree_skb(skb);
    return 1;
}

/* ******************************************************************************** */
/* *** IPv6 -> IPv4 functions ***************************************************** */
/* ******************************************************************************** */
void ipv4_update_csum(struct sk_buff * skb, struct iphdr *iph)
{
    __wsum sum1=0;
    __sum16 sum2=0;
    __sum16 oldsum=0;

    int iphdrlen = ip_hdrlen(skb);

    switch (iph->protocol)
    {
    case IPPROTO_TCP:
    {
	/* ripped from tcp_v4_send_check fro tcp_ipv4.c */
	struct tcphdr *th = tcp_hdr(skb);
	unsigned tcplen = 0;

	/* printk(KERN_ALERT "iph=%p th=%p copy->len=%d, th->check=%x iphdrlen=%d thlen=%d\n",
	   iph, th, skb->len, ntohs(th->check), iphdrlen, thlen); */

	skb->csum = 0;
	skb->ip_summed = CHECKSUM_COMPLETE;

	// calculate payload
	oldsum = th->check;
	th->check = 0;
	tcplen = ntohs(iph->tot_len) - iphdrlen; /* skb->len - iphdrlen; (may cause trouble due to padding) */
	sum1 = csum_partial((char*)th, tcplen, 0); /* calculate checksum for TCP hdr+payload */
	sum2 = csum_tcpudp_magic(iph->saddr, iph->daddr, tcplen, iph->protocol, sum1); /* add pseudoheader */
	if (cfg_debug>=DEBUG_MATCHED)
	    printk(KERN_ALERT " Updating TCP (over IPv4) checksum to %04x (oldsum=%04x)\n", htons(sum2), htons(oldsum));

	th->check = sum2;

	break;
    }
    case IPPROTO_UDP:
    {
	struct udphdr *udp = udp_hdr(skb);
	unsigned udplen = 0;


	oldsum = udp->check;
	udp->check = 0;
	udplen = ntohs(iph->tot_len) - iphdrlen;

	sum1 = csum_partial((char*)udp, udplen, 0);
	sum2 = csum_tcpudp_magic(iph->saddr, iph->daddr, udplen, iph->protocol, sum1);
	udp->check = sum2;
	printk(KERN_ALERT " Updating UDP (over IPv4) checksum to %04x (oldsum=%04x)\n", htons(sum2), htons(oldsum) );

	break;
    }
    case IPPROTO_ICMP:
    {
	/* do nothing here. ICMP does not use pseudoheaders for checksum calculation. */
	break;
    }
    default:
	break;
    }
}

static int ipv6_send_as_ipv4(struct sk_buff * skb)
{
    struct ipv6hdr * hdr = ipv6_hdr(skb);
    struct iphdr   * iph;
    char buf1[64], buf2[64], buf3[64], buf4[64];
    __u32 v4saddr, v4daddr;
    struct sk_buff * copy = 0;
    int err = -1;
    int truncSize = 0;


    v4saddr = *( (__u32*)&(hdr->saddr.s6_addr[cfg_offset]) );
    v4daddr = *( (__u32*)&(hdr->daddr.s6_addr[cfg_offset]) );

    if (cfg_debug>DEBUG_NONE)
    {
	in6_ntop2(buf1,&hdr->saddr);
	in6_ntop2(buf2,&hdr->daddr);
	in4_ntop(buf3, v4saddr);
	in4_ntop(buf4, v4daddr);

	printk(KERN_ALERT " IPv6(src=%s,dst=%s)->IPv4(src=%s,dst=%s)\n", buf1, buf2, buf3, buf4);
    }

    copy = skb_copy(skb, GFP_ATOMIC); // other possible option: GFP_ATOMIC

    /* Remove any debris in the socket control block */
    memset(IPCB(copy), 0, sizeof(struct inet_skb_parm));

    /* modify packet: actual IPv6->IPv4 transformation */
    truncSize = sizeof(struct ipv6hdr) - sizeof(struct iphdr); /* chop first 20 bytes */
    skb_pull(copy, truncSize);
    skb_reset_network_header(copy);
    skb_set_transport_header(copy,20); /* transport (TCP/UDP/ICMP/...) header starts after 20 bytes */

    /* build IPv4 header */
    iph = ip_hdr(copy);
    iph->ttl      = hdr->hop_limit;
    iph->saddr    = v4saddr;
    iph->daddr    = v4daddr;
    iph->protocol = hdr->nexthdr;
    *((__be16 *)iph) = htons((4 << 12) | (5 << 8) | (0x00/*tos*/ & 0xff));
    iph->frag_off = htons(IP_DF);
    /* iph->tot_len  = htons(copy->len); // almost good, but it may cause troubles with sizeof(IPv6 pkt)<64 (padding issue) */
    iph->tot_len  = htons(  ntohs(hdr->payload_len)+ 20 /*sizeof(ipv4hdr)*/ );
    iph->check    = 0;
    iph->check    = ip_fast_csum((unsigned char *)iph, iph->ihl);
    copy->protocol = htons(ETH_P_IP);

    ipv4_update_csum(copy, iph); /* update L4 (TCP/UDP/ICMP) checksum */

    /* try to find route for this packet */
    err = ip_route_input(copy, v4daddr, v4saddr, 0, copy->dev);

    if (err==0) {
	err = ip_forward(copy);
	if (err == 0) {
	    cnt6to4++;
	    cnt4snd++;
	} else {
	    printk(KERN_ALERT "#IPv6->IPv4: Unable to send packet (ip_forward failed). %d such errors so far.\n", ++cnt4xmit_errors);
	}
    } else {
	printk(KERN_ALERT "# Unable to find route, packet dropped. (%d failed routes for IPv4 so far)\n", ++cnt4drop_route);
    }

    /* TBD: should copy be released here? */

    return 1;
}

static int ipv6_handler(struct sk_buff *skb,struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    struct ipv6hdr * hdr = ipv6_hdr(skb);
    char buf1[64], buf2[64], buf3[64], buf4[64];
    int process = 0;

    cnt6rcv++;

    if (!memcmp(cfg_prefixwan, hdr->saddr.s6_addr, cfg_v6prefix_length/8) &&
	!memcmp(cfg_prefixlan, hdr->daddr.s6_addr, cfg_v6prefix_length/8) )
    {
	process = 1;
    }

    if ( (cfg_debug>=DEBUG_ALL) || ( process && (cfg_debug>=DEBUG_MATCHED) ) )
    {
	in6_ntop2(buf1, &hdr->saddr); /* received src */
	in6_ntop2(buf2, &hdr->daddr); /* received dst */
	in6_ntop(buf3, cfg_prefixwan);    /* expected src */
	in6_ntop(buf4, cfg_prefixlan);    /* expected dst */
	printk(KERN_ALERT "#IPv6 rcvd (rcvd so far: %d) [src=%s dst=%s, looking for %s/%d->%s/%d] %s\n",
	       cnt6rcv, buf1, buf2, buf3, cfg_v6prefix_length, buf4, cfg_v6prefix_length, process?"*":"");
    }

    if (process) {
	ipv6_send_as_ipv4(skb);
    }

    kfree_skb(skb);
    return 1;
}


/* ******************************************************************************** */
/* *** kernel interface functions ************************************************* */
/* ******************************************************************************** */

int check_init_params(void)
{
    const char * end;
    int status = 0;

    if (!in6_pton(prefixlan_str, V6PREFIX_MAX_LEN, cfg_prefixlan, '\0', &end)) {
	printk(KERN_ALERT "Unable to process prefixlan parameter(%s). Please define v6prefix (e.g. prefixlan=2000::123)\n", prefixlan_str);
	status = -1; // initialization failed
    }

    if (!in6_pton(prefixwan_str, V6PREFIX_MAX_LEN, cfg_prefixwan, '\0', &end)) {
	printk(KERN_ALERT "Unable to process prefixwan parameter (%s). Please define v6prefix (e.g. prefixwan=2000::123)\n", prefixwan_str);
	status = -1; // initialization failed
    }

    if (!in4_pton(v4addr_str, V4ADDR_MAX_LEN, (u8 *)&(cfg_v4addr), '\0', &end)) {
	printk(KERN_ALERT "Unable to process v4addr parameter(%s). Please define v4addr (e.g. v4addr=1.2.3.4).\n", v4addr_str);
	status = -1;
    }

    if (cfg_v4offset < 0 || cfg_v4offset > 96) {
	printk(KERN_ALERT "Invalid IPv4 offset. Values expected: [0..95>\n");
	status = -1;
    }

    cfg_offset = cfg_v4offset / 8; /* bit -> byte conversion */

    return status;
}

void register_handlers(void)
{
    memset(&ipv4_pkt, sizeof(ipv4_pkt), 0);
    memset(&ipv6_pkt, sizeof(ipv6_pkt), 0);

    /* register IPv4 packet handler */
    ipv4_pkt.type = htons(ETH_P_IP);
    ipv4_pkt.dev = NULL;
    ipv4_pkt.func = ipv4_handler;
    dev_add_pack(&ipv4_pkt);

    /* register IPv6 packet handler */
    ipv6_pkt.type = htons(ETH_P_IPV6);
    ipv6_pkt.dev = NULL;
    ipv6_pkt.func = ipv6_handler;
    dev_add_pack(&ipv6_pkt);
    printk("Handlers for IPv4 and IPv6 installed.\n");
}

void unregister_handlers(void)
{
    dev_remove_pack(&ipv4_pkt);
    dev_remove_pack(&ipv6_pkt);
    printk("Handlers for IPv4 and IPv6 removed.\n");
}

/*
 * hello_init  the init function, called when the module is loaded.
 * Returns zero if successfully loaded, nonzero otherwise.
 */
static int __init hello_init(void)
{
    int err = 0;
    printk("ip46nat module: version %s\n", MODULE_VERS);

    if (check_init_params() < 0 ) {
	    printk(KERN_ALERT "Invalid parameters specified (prefixlan, prefixwan and v4addr is required).\n");
	err = -1;
    }

    if (err < 0) {
	printk(KERN_ALERT "IPv4-IPv6 NAT module loading failed.\n");
	return -1;
    }

    printk(KERN_ALERT "IPv4-IPv6 NAT module loaded: prefixlan: %s/%d, prefixwan: %s/%d, v4addr: %s/%d\n",
	   prefixlan_str, cfg_v6prefix_length, prefixwan_str, cfg_v6prefix_length, v4addr_str, cfg_v4masklen);
    printk(KERN_ALERT "IPv4-IPv6 NAT module loaded: offset: %d debug: %d\n",
	   cfg_offset, cfg_debug);

    register_handlers();
    err = procfs_init();
    if (err)
    {
	printk(KERN_ALERT "Unable to create /proc entries.\n");
	return err;
    }

    switch (cfg_v4masklen) {
    case 32:
    {
	cfg_v4mask = htonl(0xffffffff); /* v4 addrs are stored in network byte order */
	break;
    }
    case 24:
    {
	cfg_v4mask = htonl(0x00ffffff);
	break;
    }
    case 16:
    {
	cfg_v4mask = htonl(0x0000ffff);
	break;
    }
    case 8:
    {
	cfg_v4mask = htonl(0x000000ff);
	break;
    }
    default:
	printk(KERN_ALERT "Unsupposted mask length: %d. Module loading failed.\n", cfg_v4masklen);
	return -1;
    }

    return 0;
}

/*
 * hello_exit  the exit function, called when the module is removed.
 */
static void __exit hello_exit(void)
{
    unregister_handlers();
    procfs_exit();

    printk(KERN_ALERT "---IPv4-IPv6 NAT statistics-------------------\n");
    printk(KERN_ALERT "IPv4-to-IPv6 packets: %d\n", cnt4to6);
    printk(KERN_ALERT "IPv6-to-IPv4 packets: %d\n", cnt6to4);
    printk(KERN_ALERT "IPv4 rcvd: %d, sent: %d\n", cnt4rcv, cnt4snd);
    printk(KERN_ALERT "IPv6 rcvd: %d, sent: %d\n", cnt6rcv, cnt6snd);
    printk(KERN_ALERT "IPv4 dropped (too large): %d\n", cnt4drop_mtu);
    printk(KERN_ALERT "IPv4 dropped (no route): %d\n", cnt4drop_route);
    printk(KERN_ALERT "IPv6 dropped (no route): %d\n", cnt6drop_route);
    printk(KERN_ALERT "IPv4 dropped (transmission failed): %d\n", cnt4xmit_errors);
    printk(KERN_ALERT "IPv6 dropped (transmission failed): %d\n", cnt6xmit_errors);
    printk(KERN_ALERT "----------------------------------------------\n");
    printk(KERN_ALERT "IPv4-IPv6 NAT module unloaded.\n");
}

static int procfs_read_stats(char *page, char **start,
			     off_t off, int count,
			     int *eof, void *data)
{
    int len;

    len  = sprintf(page,     "IPv4 received = %d, sent = %d\n", cnt4rcv, cnt4snd);
    len += sprintf(page+len, "IPv6 received = %d, sent = %d\n", cnt6rcv, cnt6snd);
    len += sprintf(page+len, "IPv4-to-IPv6 packets= %d\n", cnt4to6);
    len += sprintf(page+len, "IPv6-to-IPv4 packets: %d\n", cnt6to4);
    len += sprintf(page+len, "IPv4 dropped (too large): %d\n", cnt4drop_mtu);
    len += sprintf(page+len, "IPv4 dropped (no route): %d\n", cnt4drop_route);
    len += sprintf(page+len, "IPv6 dropped (no route): %d\n", cnt6drop_route);
    len += sprintf(page+len, "IPv4 dropped (transmission failed): %d\n", cnt4xmit_errors);
    len += sprintf(page+len, "IPv6 dropped (transmission failed): %d\n", cnt6xmit_errors);

    return len;
}

static int procfs_read_params(char *page, char **start,
			      off_t off, int count,
			      int *eof, void *data)
{
	int len;

	char plain_lan[32], plain_wan[32], plain_v4[64];
	in6_ntop(plain_lan, cfg_prefixlan);
	in6_ntop(plain_wan, cfg_prefixwan);
	in4_ntop(plain_v4, cfg_v4addr);

	len  = sprintf(page, "prefixlan= %s\n", plain_lan);
	len += sprintf(page+len, "prefixwan= %s\n", plain_wan);
	len += sprintf(page+len, "v6prefix_length= %d\n", cfg_v6prefix_length);
	len += sprintf(page+len,"\n");
	len += sprintf(page+len, "v4addr= %s\n", plain_v4);
	len += sprintf(page+len, "v4masklen = %d\n", cfg_v4masklen);
	len += sprintf(page+len, "v4offset = %d bits (%d bytes)\n", cfg_v4offset, cfg_offset);
	len += sprintf(page+len, "\n");
	len += sprintf(page+len, "debug=%d", (cfg_debug?1:0) );

	return len;
}

static int procfs_write_params(struct file *file,
			       const char *buffer,
			       unsigned long count,
			       void *data)
{
	int len = 0;
	// struct cfg_t *cfg = (struct cfg_t *)data;

	/* TODO: Implement parameter modification */
	/* if(copy_from_user(cfg->value, buffer, len))
	   return -EFAULT; */

	return len;
}

static int  procfs_init(void)
{
    procfs_dir = proc_mkdir(MODULE_NAME, NULL);
    if (!procfs_dir)
    {
	printk (KERN_ERR "Cannot create /proc/%s\n", MODULE_NAME);
	return -ENOMEM;
    }

    procfs_stats_file = create_proc_read_entry("stats",
					       0444, procfs_dir,
					       procfs_read_stats,
					       NULL);
    if (!procfs_stats_file)
    {
	printk (KERN_ERR "cannot create /proc/%s/stats\n",MODULE_NAME);
	remove_proc_entry(MODULE_NAME, 0);
	return -ENOMEM;
    }

    procfs_params_file = create_proc_entry("params", 0644, procfs_dir);
    if(procfs_params_file == NULL) {
	remove_proc_entry(MODULE_NAME, 0);
	return -ENOMEM;
    }
    procfs_params_file->data = 0; // &cfg;
    procfs_params_file->read_proc  = procfs_read_params;
    procfs_params_file->write_proc = procfs_write_params;

    return 0;
}

static void  procfs_exit(void)
{
    remove_proc_entry("params", procfs_dir);
    remove_proc_entry("stats", procfs_dir);
    remove_proc_entry(MODULE_NAME, NULL);
}

module_init(hello_init);
module_exit(hello_exit);
