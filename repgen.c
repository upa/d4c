
/* DNS Response Generator */

#include <stdio.h>
#include <search.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pthread.h>


#include "patricia.h"


#define NM_BURST_MAX	1024

#define ADDR4COPY(s, d) *(((u_int32_t *)(d))) = *(((u_int32_t *)(s)))
#define ADDRCMP(s, d) (*(((u_int32_t *)(d))) == *(((u_int32_t *)(s))))


int verbose = 0;
int vale_rings = 0;


struct repgen {
	char * intf;
	char * qname;
};

struct repgen repgen;

struct vnfapp {
	pthread_t tid;

	int rx_fd, tx_fd;
	int rx_q, tx_q;
	char * rx_if, * tx_if;
	struct netmap_ring * rx_ring, * tx_ring;

	void * data;
};


/* DNS related codes */
struct dns_hdr {
	u_int16_t	id;
	u_int16_t	flag;
	u_int16_t	qn_count;
	u_int16_t	an_count;
	u_int16_t	ns_count;
	u_int16_t	ar_count;

	char qname[0];
} __attribute__ ((__packed__));
#define DNS_FLAG_QR		0x8000
#define DNS_FLAG_OP		0x1800
#define DNS_FLAG_OP_STANDARD	0x0000
#define DNS_FLAG_OP_INVERSE	0x0800
#define DNS_FLAG_OP_STATUS	0x1000
#define DNS_FLAG_AA		0x0400
#define DNS_FLAG_TC		0x0200
#define DNS_FLAG_RD		0x0100
#define DNS_FLAG_RA		0x0080
#define DNS_FLAG_RC		0x000F
#define DNS_FLAG_RC_NOERR	0x0000
#define DNS_FLAG_RC_FMTERR	0x0001
#define DNS_FLAG_RC_SRVERR	0x0002
#define DNS_FLAG_RC_NMERR	0x0003
#define DNS_FLAG_RC_NOIMPL	0x0004
#define DNS_FLAG_RC_DENIED	0x0005

#define DNS_IS_QUERY(d)	(!(ntohs ((d)->flag) & DNS_FLAG_QR))
#define DNS_IS_RESPONSE(d) ((ntohs ((d)->flag) & DNS_FLAG_QR))
#define DNS_IS_AUTHORITATIVE(d) (ntohs ((d)->flag) & DNS_FLAG_AA)


/* DNS  Queries related codes */

struct dns_qname_ftr {
	u_int16_t	rep_type;
	u_int16_t	rep_class;
} __attribute__ ((__packed__));
#define DNS_REP_TYPE_A		1
#define DNS_REP_TYPE_NS		2
#define DNS_REP_TYPE_CNAME	5
#define DNS_REP_TYPE_PTR	12
#define DNS_REP_TYPE_MX		15
#define DNS_REP_TYPE_AAAA	28
#define DNS_REP_TYPE_ANY	255

#define DNS_REP_CLASS_INTERNET	1


static uint16_t
checksum(const void * data, uint16_t len, uint32_t sum)
{
        const uint8_t *addr = data;
        uint32_t i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (len & ~1U); i += 2) {
                sum += (u_int16_t)ntohs(*((u_int16_t *)(addr + i)));
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }
        /*
         * If there's a single byte left over, checksum it, too.
         * Network byte order is big-endian, so the remaining byte is
         * the high byte.
         */

        if (i < len) {
                sum += addr[i] << 8;
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }

        return sum;
}

static u_int16_t
wrapsum(u_int32_t sum)
{
        sum = ~sum & 0xFFFF;
        return (htons(sum));
}


void
set_ether_header (struct ether_header * eth, __u8 * dst_mac, __u8 * src_mac)
{
        memcpy (eth->ether_dhost, dst_mac, ETH_ALEN);
        memcpy (eth->ether_shost, src_mac, ETH_ALEN);
        eth->ether_type = htons (ETHERTYPE_IP);

        return;
}

void
set_ip_header (struct ip * ip, struct in_addr * dst_addr,
               struct in_addr * src_addr, size_t len)
{

        ip->ip_v = IPVERSION;
        ip->ip_hl = 5;
        ip->ip_id = 0;
        ip->ip_tos = IPTOS_LOWDELAY;
        ip->ip_len = htons (len);
        ip->ip_id = 0;
        ip->ip_off = htons (IP_DF);
        ip->ip_ttl = 16;
        ip->ip_p = IPPROTO_UDP;
        ip->ip_dst = *dst_addr;
        ip->ip_src = *src_addr;
        ip->ip_sum = 0;
        ip->ip_sum = wrapsum (checksum (ip, sizeof (*ip), 0));

        return;
}

void
set_udp_header (struct udphdr * udp, size_t len)
{

        udp->uh_sport = htons (53);
        udp->uh_dport = htons (53);

        udp->uh_ulen = htons (len);

        udp->uh_sum = 0;        /* no udp checksum */

        return;
}


u_int
xmit (struct vnfapp * va)
{
	int len;
	u_int burst, m, k;
	
	struct netmap_slot * ts;
	struct ether_header * eth;
	struct ip * ip;
	struct udphdr * udp;
	struct dns_hdr * dns;
	struct dns_qname_ftr * ftr;

	__u8 smac[ETH_ALEN] = { 0x01, 0x01, 0x01, 0x02, 0x02, 0x02 };
	__u8 dmac[ETH_ALEN] = { 0x01, 0x01, 0x01, 0x03, 0x03, 0x03 };
	struct in_addr saddr = { 0x0100000A };
	struct in_addr daddr = { 0x0200000A };	


	burst = NM_BURST_MAX;

	m = nm_ring_space (va->tx_ring);
	if (m < burst)
		burst = m;

	m = burst;


	len = 	sizeof (struct ether_header) + 
		sizeof (struct ip) + 
		sizeof (struct udphdr) +
		sizeof (struct dns_hdr) +
		14 + sizeof (struct dns_qname_ftr);


	while (burst-- > 0) {

		ts = &va->tx_ring->slot[k];

		eth = (struct ether_header *)
			NETMAP_BUF (va->tx_ring, ts->buf_idx);

		set_ether_header (eth, dmac, smac);

		ip = (struct ip *) (eth + 1);
		set_ip_header (ip, &daddr, &saddr,
			       len - sizeof (struct ether_header));

		udp = (struct udphdr *) (((char *) ip) + (ip->ip_hl * 4));
		set_udp_header (udp, len - sizeof (struct ether_header) -
				sizeof (struct ip));

		dns = (struct dns_hdr *) (udp + 1);

		dns->id = 0x0002;
		dns->flag = htons (0x0100);
		dns->qn_count = htons (1);
		dns->an_count = 0;
		dns->ns_count = 0;
		dns->ar_count = 0;
		dns->qname[0] = 0x03;
		dns->qname[1] = 'w';
		dns->qname[2] = 'w';
		dns->qname[3] = 'w';
		dns->qname[4] = 0x04;
		dns->qname[5] = 'k';
		dns->qname[6] = 'a';
		dns->qname[7] = 'm';
		dns->qname[8] = 'e';
		dns->qname[9] = 0x03;
		dns->qname[10] = 'n';
		dns->qname[11] = 'e';
		dns->qname[12] = 't';
		dns->qname[13] = 0x00;

		ftr = (struct dns_qname_ftr *)(&dns->qname[14]);
		ftr->rep_type  = htons (DNS_REP_TYPE_A);
		ftr->rep_class = htons (DNS_REP_CLASS_INTERNET);

		ts->len = len;

		k = nm_ring_next (va->tx_ring, k);

	}

	va->tx_ring->head = va->tx_ring->cur = k;

	return m;
}

void * 
processing_thread (void * param)
{
	struct vnfapp * va = param;

	D ("rxfd=%d, txfd=%d, rxq=%d, txq=%d, rxif=%s, txif=%s, "
           "rxring=%p, txring=%p",
           va->rx_fd, va->tx_fd, va->rx_q, va->tx_q, va->rx_if, va->tx_if,
           va->rx_ring, va->tx_ring);

	pthread_detach (pthread_self ());

	while (1) {

		xmit (va);

		ioctl (va->tx_fd, NIOCTXSYNC, va->rx_q);
	}

	return NULL;
}


int
nm_get_ring_num (char * ifname, int direct)
{
	int fd;
	struct nmreq nmr;

	fd = open ("/dev/netmap", O_RDWR);
	if (fd < 0) {
		D ("Unable to open /dev/netmap");
		perror ("open");
		return -1;
	}

	memset (&nmr, 0, sizeof (nmr));
	nmr.nr_version = NETMAP_API;
	strncpy (nmr.nr_name, ifname, IFNAMSIZ - 1);

	if (vale_rings && strncmp (ifname, "vale", 4) == 0) {
		nmr.nr_rx_rings = vale_rings;
		nmr.nr_tx_rings = vale_rings;
	}

	if (ioctl (fd, NIOCGINFO, &nmr)) {
		D ("unable to get interface info for %s", ifname);
		return -1;
	}

	close (fd);

	if (direct == 0)
		return nmr.nr_tx_rings;

	if (direct == 1)
		return nmr.nr_rx_rings;

	return -1;
}
#define nm_get_tx_ring_num(intf) nm_get_ring_num (intf, 0)
#define nm_get_rx_ring_num(intf) nm_get_ring_num (intf, 1)

int
nm_ring (char * ifname, int q, struct netmap_ring ** ring,  int x, int w)
{
	int fd;
	char * mem;
	struct nmreq nmr;
	struct netmap_if * nifp;

	/* open netmap for  ring */

	fd = open ("/dev/netmap", O_RDWR);
	if (fd < 0) {
		D ("unable to open /dev/netmap");
		return -1;
	}

	memset (&nmr, 0, sizeof (nmr));
	strcpy (nmr.nr_name, ifname);
	nmr.nr_version = NETMAP_API;
	nmr.nr_ringid = q;

	if (w)
		nmr.nr_flags |= NR_REG_ONE_NIC;
	else
		nmr.nr_flags |= NR_REG_ALL_NIC;

	if (ioctl (fd, NIOCREGIF, &nmr) < 0) {
		D ("unable to register interface %s", ifname);
		return -1;
	}

	if (vale_rings && strncmp (ifname, "vale", 4) == 0) {
		nmr.nr_rx_rings = vale_rings;
		nmr.nr_tx_rings = vale_rings;
	}

	mem = mmap (NULL, nmr.nr_memsize,
		    PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		D ("unable to mmap");
		return -1;
	}

	nifp = NETMAP_IF (mem, nmr.nr_offset);

	if (x > 0)
		*ring = NETMAP_TXRING (nifp, q);
	else
		*ring = NETMAP_RXRING (nifp, q);

	return fd;
}
#define nm_hw_tx_ring(i, q, r) nm_ring (i, q, r, 1, NETMAP_HW_RING)
#define nm_hw_rx_ring(i, q, r) nm_ring (i, q, r, 0, NETMAP_HW_RING)
#define nm_sw_tx_ring(i, q, r) nm_ring (i, q, r, 1, NETMAP_SW_RING)
#define nm_sw_rx_ring(i, q, r) nm_ring (i, q, r, 0, NETMAP_SW_RING)
#define nm_vl_tx_ring(i, q, r) nm_ring (i, q, r, 1, 0)
#define nm_vl_rx_ring(i, q, r) nm_ring (i, q, r, 0, 0)


void
usage (void)
{
	printf ("Usage of repgen\n"
		"\t" "-i : Interface name\n"
		"\t" "-q : Query name\n"
		"\t" "-e : Number of Rings of a vale port\n"
		"\t" "-f : Daemon mode\n"
		"\t" "-v : Verbose mode\n"
		"\t" "-h : Print this help\n"
		"");
		

	return;
}

int
main (int argc, char ** argv)
{
	int n, q, ch, f_flag = 0;

	repgen.intf = NULL;
	repgen.qname = NULL;

	while ((ch = getopt (argc, argv, "i:e:s:fvh")) != -1) {
		switch (ch) {
		case 'i' :
			repgen.intf = optarg;
			break;
		case 'e' :
			vale_rings = atoi (optarg);
			if (vale_rings > 4) {
				D ("Max of number of vale rings is 4.");
				return -1;
			}
			break;
		case 'f' :
			f_flag = 1;
			break;
		case 'v' :
			verbose = 1;
			break;
		case 'h' :
		default :
			usage ();
			return -1;
		}
	}
	if (!repgen.intf) {
		D ("interface is not specified");
		return -1;
	}

	q = nm_get_rx_ring_num (repgen.intf);

	if (f_flag) {
		daemon (0, 0);
	}

	/* Assign threads for each RX rings of Right interface */
	for (n = 0; n < q; n++) {
		struct vnfapp * va;
		va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		va->rx_q = n;
		va->tx_q = n % q;
		va->rx_if = repgen.intf;
		va->tx_if = repgen.intf;
		va->rx_fd = nm_vl_rx_ring(repgen.intf, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring(repgen.intf, va->tx_q, &va->tx_ring);

		pthread_create (&va->tid, NULL, processing_thread, va);
	}
	

	while (1) {
		/* controlling module will be implemented here */
		sleep (100);
	}

	return 0;
}
