
/* D4C: Dirty Deeds Done Dirt Cheap */

#include <stdio.h>

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



struct d4c {
	patricia_tree_t * dst_table;
	patricia_tree_t * src_table;
};

struct d4c d4c;



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
	u_int16_t	qd_count;
	u_int16_t	an_count;
	u_int16_t	ns_count;
	u_int16_t	ar_count;
};
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



static inline void
dst2prefix (void * addr, u_int16_t len, prefix_t * prefix)
{
	prefix->family = AF_INET;
	prefix->bitlen = len;
	prefix->ref_count = 1;

	ADDR4COPY (addr, &prefix->add);

	return;
}

static inline void *
find_patricia_entry (patricia_tree_t * tree, void * addr, u_int16_t len)
{
	prefix_t prefix;
	patricia_node_t * pn;

	dst2prefix (addr, len, &prefix);

	pn = patricia_search_best (tree, &prefix);

	if (pn)
		return pn->data;

	return NULL;
}

static inline void
add_patricia_entry (patricia_tree_t * tree, void * addr, u_int16_t len,
		    void * data)
{
	prefix_t * prefix;
	patricia_node_t * pn;

	prefix = (prefix_t *) malloc (sizeof (prefix_t));

	dst2prefix (addr, len, prefix);

	pn = patricia_lookup (tree, prefix);

	pn->data = data;

	return;
}

int
split_prefixlen (char * str, void * prefix, int * len)
{
	int n, l, c = 0;
	char * p, * args[2];

	/* PREIFX/LEN */

	p = str;
	args[c++] = str;
	l = strlen (str);

	for (n = 0; n < l; n++) {
		if (*(p + n) == '_' || *(p + n) == '/' ||
		    *(p + n) == ':' || *(p + n) == '-') {
			*(p + n) = '\0';
			args[c++] = (p + n + 1);
		}
	}

	*len = atoi (args[1]);

	return inet_pton (AF_INET, args[0], prefix);
}


u_int
move (struct vnfapp * va)
{
	u_int burst, m, j, k;
	
	struct netmap_slot * rs, * ts;
	struct ether_header * eth;
	struct ip * ip;
	struct udphdr * udp;
	struct dns_hdr * dns;

#define ZEROCOPY
#ifdef	ZEROCOPY
	u_int idx;
#else
	char * spkt;
	char * dpkt;
#endif

	j = va->rx_ring->cur;
	k = va->rx_ring->cur;
	burst = NM_BURST_MAX;

	m = nm_ring_space (va->rx_ring);
	if (m < burst)
		burst = m;

	m = nm_ring_space (va->tx_ring);
	if (m < burst)
		burst = m;

	m = burst;

	while (burst-- > 0) {
		rs = &va->rx_ring->slot[j];
		ts = &va->tx_ring->slot[k];

		if (ts->buf_idx < 2 || rs->buf_idx < 2) {
			D ("wrong index rx[%d] = %d -> tx[%d] = %d",
			   j, rs->buf_idx, k, ts->buf_idx);
			sleep (2);
		}

		eth = (struct ether_header *)
			NETMAP_BUF (va->rx_ring, rs->buf_idx);
		ip = (struct ip *) (eth + 1);

		/* is DNS packet ? */
		if (ip->ip_p != IPPROTO_UDP)
			goto packet_forward;
		
		udp = (struct udphdr *) (((char *) ip) + (ip->ip_hl * 4));

		if (udp->source != htons (53))
			goto packet_forward;


		dns = (struct dns_hdr *) (udp + 1);

		/* If dns packet is query and not authoritative, 
		 * the dns packet comes from a resolver server on 
		 * other AS !! It is DDoS packet !! Drop !!
		 */

		if (DNS_IS_RESPONSE (dns) && !DNS_IS_AUTHORITATIVE (dns) &&
		    find_patricia_entry (d4c.dst_table, &ip->ip_dst, 32) &&
		    !find_patricia_entry (d4c.src_table, &ip->ip_src, 32)) {
			if (verbose) {
				D ("drop pkt to %s", inet_ntoa (ip->ip_dst));
			}
			goto packet_drop;
		}
		

	packet_forward:


#ifdef	ZEROCOPY
		idx = ts->buf_idx;
		ts->buf_idx = rs->buf_idx;
		rs->buf_idx = idx;
		ts->flags |= NS_BUF_CHANGED;
		rs->flags |= NS_BUF_CHANGED;
		ts->len = rs->len;
#else
		spkt = NETMAP_BUF (va->rx_ring, rs->buf_idx);
		dpkt = NETMAP_BUF (va->tx_ring, ts->buf_idx);
		nm_pkt_copy (spkt, dpkt, rs->len);
		ts->len = rs->len;
#endif
		
	packet_drop:
		j = nm_ring_next (va->rx_ring, j);
		k = nm_ring_next (va->tx_ring, k);
	}

	va->rx_ring->head = va->rx_ring->cur = j;
	va->tx_ring->head = va->tx_ring->cur = j;

	if (verbose)
		D ("swap %d packets", m);

	return m;
}

void * 
processing_thread (void * param)
{
	struct pollfd x[1];
	struct vnfapp * va = param;

	D ("rxfd=%d, txfd=%d, rxq=%d, txq=%d, rxif=%s, txif=%s, "
           "rxring=%p, txring=%p",
           va->rx_fd, va->tx_fd, va->rx_q, va->tx_q, va->rx_if, va->tx_if,
           va->rx_ring, va->tx_ring);

	pthread_detach (pthread_self ());
	
	x[0].fd = va->rx_fd;
	x[0].events = POLLIN;

	while (1) {

		poll (x, 1, -1);

		ioctl (va->rx_fd, NIOCRXSYNC, va->rx_q);

		move (va);

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
	printf ("Usage of d4c\n"
		"\t" "-r : Right interface name\n"
		"\t" "-l : Left interface name\n"
		"\t" "-q : Max number of threads for interface\n"
		"\t" "-d : Prefixes of filtered destination of DNS response\n"
		"\t" "-s : Prefixes that is NOT filtered DNS responses\n"
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
	struct in_addr prefix;
	int ret, q, rq, lq, n, len, ch, f_flag = 0;
	char * rif, * lif;
	
	q = 256;

	memset (&d4c, 0, sizeof (d4c));
	d4c.dst_table = New_Patricia (32);
	d4c.src_table = New_Patricia (32);


	while ((ch = getopt (argc, argv, "r:l:q:e:d:s:fvh")) != -1) {
		switch (ch) {
		case 'r' :
			rif = optarg;
			break;
		case 'l' :
			lif = optarg;
			break;
		case 'q' :
			q = atoi (optarg);
			if (q < 1) {
				D ("Invalid -q argument.");
				return -1;
			}
			break;
		case 'e' :
			vale_rings = atoi (optarg);
			if (vale_rings > 4) {
				D ("Max of number of vale rings is 4.");
				return -1;
			}
			break;
		case 'd' :
			D ("Insert mitigated destination prefix %s", optarg);
			ret = split_prefixlen (optarg, &prefix, &len);
			if (ret < 0 || len < 0 || 32 < len) {
				D ("Invalid prefix %s", optarg);
				return -1;
			}
			
			/* main is dummy to avoid NULL */
			add_patricia_entry (d4c.dst_table, &prefix, len, main);
			break;
		case 's' :
			D ("Insert unfiltered source prefix %s", optarg);
			ret = split_prefixlen (optarg, &prefix, &len);
			if (ret < 1 || len < 0 || 32 < len) {
				D ("Invalid prefix %s", optarg);
				return -1;
			}
			
			/* main is dummy to avoid NULL */
			add_patricia_entry (d4c.src_table, &prefix, len, main);
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
	
	if (rif == NULL || lif == NULL) {
		usage ();
		return -1;
	}
	
	rq = nm_get_rx_ring_num (rif);
	lq = nm_get_rx_ring_num (lif);

	if (rq < 0 || lq < 0) {
		D ("failed to get number of rings");
		return -1;
	}
	D ("Right rings is %d, Left rings is %d", rq, lq);
	
	if (f_flag) {
		daemon (0, 0);
	}


	rq = (rq < q) ? rq : q;
	lq = (lq < q) ? lq : q;


	/* Assign threads for each RX rings of Right interface */
	for (n = 0; n < rq; n++) {
		struct vnfapp * va;
		va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		va->rx_q = n;
		va->tx_q = n % lq;
		va->rx_if = rif;
		va->tx_if = lif;
		va->rx_fd = nm_vl_rx_ring (rif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (lif, va->tx_q, &va->tx_ring);

		pthread_create (&va->tid, NULL, processing_thread, va);
	}
	
	/* Assign threads for each RX rings of Left interfaces  */
	for (n = 0; n < lq; n++) {
		struct vnfapp * va;
		va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va, 0, sizeof (struct vnfapp));

		va->rx_q = n;
		va->tx_q = n % rq;
		va->rx_if = lif;
		va->tx_if = rif;
		va->rx_fd = nm_vl_rx_ring (lif, va->rx_q, &va->rx_ring);
		va->tx_fd = nm_vl_tx_ring (rif, va->tx_q, &va->tx_ring);

		pthread_create (&va->tid, NULL, processing_thread, va);
	}



	while (1) {
		/* controlling module will be implemented here */
		sleep (100);
	}

	return 0;
}
