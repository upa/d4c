
/* D4C: Dirty Deeds Done Dirt Cheap */

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
#include "ssap_trie.h"

#define NM_BURST_MAX	1024

#define ADDR4COPY(s, d) *(((u_int32_t *)(d))) = *(((u_int32_t *)(s)))
#define ADDRCMP(s, d) (*(((u_int32_t *)(d))) == *(((u_int32_t *)(s))))

#define THREAD_MAX	64	/* max number of threads (queuenum) */
#define MONITOR_PORT	5353	/* tcp port num for packet counter */

int verbose = 0;
int vale_rings = 0;

struct ether_vlan {
	__u8    ether_dhost[ETH_ALEN];
	__u8    ether_shost[ETH_ALEN];
	__u16   vlan_tpid;
	__u16   vlan_tci;
	__u16   ether_type;
} __attribute__ ((__packed__));


struct vnfapp {
	pthread_t tid;

	/* netmap related */
	int rx_fd, tx_fd;
	int rx_q, tx_q;
	char * rx_if, * tx_if;
	struct netmap_ring * rx_ring, * tx_ring;

	struct nm_desc * src, * dst;	/* used for only single mode */

	/* packet counters */
	u_int32_t dropped_response_pkt;
	u_int32_t dropped_response_byte;
	u_int32_t dropped_query_pkt;
	u_int32_t dropped_query_byte;

	void * data;
};

struct d4c {
	struct ssap_trie	* match_table;	/* ptree for dns_match */
	patricia_tree_t * dst_table;
	patricia_tree_t * src_table;

	int vnfapps_num;
	struct vnfapp * vnfapps[THREAD_MAX];

	int accept_sock;	/* fd after accept */
	int monitor_sock;	/* tcp socket for packet counter */
	int monitor_port;	/* port number for tcp socket */
};

struct d4c d4c;

#define GATHER_COUNTERS(val, n)					\
	do {							\
		val = 0;					\
		for ((n) = 0; (n) < d4c.vnfapps_num; (n)++) {	\
			val += d4c.vnfapps[(n)]->val;		\
		}						\
	} while (0)						\


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


/* DNS Filtering Query related codes */

#define DNS_MATCH_QUELY_LEN	256

struct dns_match {
	char query[DNS_MATCH_QUELY_LEN];
	int len;

	u_int32_t dropped_pkt;
	u_int32_t dropped_byte;
};



int
dns_reassemble_domain (char * domain, char * buf, size_t buflen, size_t pktlen)
{
	char * p;
	unsigned char s, n;

 	p = domain;
	s = domain[0];

	/* check, is domain compressed ? */
	if ((s & 0xc0) == 0xc0) {
		return 0;
	}

	/* skip 1st number of chars */
	p++;

	for (n = 0; n < buflen && n < 255; n++) {

		*(buf + n) = *(p + n);

		if (s == 0) {
			s = *(p + n);
			if ((s & 0xc0) == 0xc0) {
				/* compressed. break... */
				return 0;
			}
			*(buf + n) = '.';
			
			if (s == 0) {
				*(buf + n) = '\0';
				break;
			}
			continue;
		}
		s--;
	}

	if (n > 254) {
		D ("domain name length is over 255");
		return 0;
	}

	if (verbose)
		D ("Reassemble QNAME '%s'", buf);

	return n;
}


int
dns_add_match (struct ssap_trie * root, char * query)
{
	struct dns_match * m;

	m = (struct dns_match *) malloc (sizeof (struct dns_match));
	memset (m, 0, sizeof (struct dns_match));

	strncpy (m->query, query, DNS_MATCH_QUELY_LEN);
	m->len = strlen (query);
	m->dropped_pkt = 0;
	m->dropped_byte = 0;

	ssap_trie_add (root, query, m);

	return 1;
}

struct dns_match *
dns_find_match (struct ssap_trie * root, struct dns_match * m)
{
	struct ssap_trie * trie;

	trie = ssap_trie_search (root, m->query);

	if (!trie)
		return NULL;

	return (struct dns_match *) trie->data;
}

struct dns_match *
dns_check_match (struct dns_hdr * dns, size_t pktlen, struct ssap_trie * root)
{
	char * qn;
	struct dns_match m, * mr;

	/* check only one qname */

	qn = dns->qname;
	
	m.len = dns_reassemble_domain (qn, m.query,
				       DNS_MATCH_QUELY_LEN, pktlen);

	mr = dns_find_match (root, &m);
	if (mr) {
		/* find ! drop ! */
		if (verbose) {
			D ("Match %s is find for query '%s'",
			   mr->query, m.query);
		}
		return mr;
	}

	return NULL;
}

static void
dns_walk_action (void * data)
{
	struct dns_match * m;

	m = (struct dns_match *) data;
	printf ("%s\n", m->query);
}


static void
dns_walk_monitor (void * data)
{
	char buf[1024];
	struct dns_match * m = (struct dns_match *) data;

	memset (buf, 0, sizeof (buf));

	snprintf (buf, sizeof (buf),
		  "%s dropped_pkt %u dropped_byte %u\n",
		  m->query, m->dropped_pkt, m->dropped_byte);

	write (d4c.accept_sock, buf, strlen (buf) + 1);
}


/* prefix filter related codes for patricia tree */

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
	char * p, * args[2] = { NULL, NULL };

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

	if (!args[1])
		*len = 32;
	else
		*len = atoi (args[1]);

	return inet_pton (AF_INET, args[0], prefix);
}


u_int
move (struct vnfapp * va, struct netmap_ring * rx_ring, struct netmap_ring * tx_ring)
{
	u_int burst, m, j, k;
	
	u_int16_t ether_type;
	struct ether_header * eth;
	struct ether_vlan * veth;
	struct ip * ip;
	struct udphdr * udp;
	struct dns_hdr * dns;
	struct dns_match * match;
	struct netmap_slot * rs, * ts;

#ifdef	ZEROCOPY
	u_int idx;
#else
	char * spkt;
	char * dpkt;
#endif

	j = rx_ring->cur;
	k = tx_ring->cur;
	burst = NM_BURST_MAX;

	m = nm_ring_space (rx_ring);
	if (m < burst)
		burst = m;

	m = nm_ring_space (tx_ring);
	if (m < burst)
		burst = m;

	m = burst;

	while (burst-- > 0) {

		rs = &rx_ring->slot[j];
		ts = &tx_ring->slot[k];

		if (ts->buf_idx < 2 || rs->buf_idx < 2) {
			D ("wrong index rx[%d] = %d -> tx[%d] = %d",
			   j, rs->buf_idx, k, ts->buf_idx);
			sleep (2);
		}

		eth = (struct ether_header *)
			NETMAP_BUF (rx_ring, rs->buf_idx);
		ip = (struct ip *) (eth + 1);

		ether_type = eth->ether_type;

		if (ether_type == htons (ETHERTYPE_VLAN)) {
			veth = (struct ether_vlan *)
				NETMAP_BUF (rx_ring, rs->buf_idx);
			ether_type = veth->ether_type;
			ip = (struct ip *)(veth + 1);
		}

		if (ether_type != htons (ETHERTYPE_IP)) {
			/* XXX: IPv6 should be handled. */
			goto packet_forward;
		}

		/* is DNS packet ? */
		if (ip->ip_p != IPPROTO_UDP)
			goto packet_forward;
		
		udp = (struct udphdr *) (((char *) ip) + (ip->ip_hl * 4));

		if (udp->source != htons (53) && udp->dest != htons (53))
			goto packet_forward;

		dns = (struct dns_hdr *) (udp + 1);

		/* If dns packet is response and not authoritative,
		 * the dns packet comes from a resolver server on
		 * other AS !! It is DDoS packet !! Drop !!
		 * (but, if it is from accepted source preifx, forwarded.
		 */

		if (DNS_IS_RESPONSE (dns) &&
		    !DNS_IS_AUTHORITATIVE (dns) &&
		    find_patricia_entry (d4c.dst_table, &ip->ip_dst, 32) &&
		    !find_patricia_entry (d4c.src_table, &ip->ip_src, 32)) {
			if (verbose) {
				D ("DDoS DNS Response from %s, Drop.",
				   inet_ntoa (ip->ip_src));
			}
			va->dropped_response_pkt++;
			va->dropped_response_byte += rs->len;
			goto packet_drop;
		}
		
		/* IF dns QNAME section is matched for installed tree, drop  */
		match = dns_check_match (dns, rs->len, d4c.match_table);
		//match = NULL;
		if (match) {
			va->dropped_query_pkt++;
			va->dropped_query_byte += rs->len;
			match->dropped_pkt++;
			match->dropped_byte += rs->len;
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
		spkt = NETMAP_BUF (rx_ring, rs->buf_idx);
		dpkt = NETMAP_BUF (tx_ring, ts->buf_idx);
		nm_pkt_copy (spkt, dpkt, rs->len);
		ts->len = rs->len;
#endif
		
	packet_drop:
		j = nm_ring_next (rx_ring, j);
		k = nm_ring_next (tx_ring, k);
	}

	rx_ring->head = rx_ring->cur = j;
	tx_ring->head = tx_ring->cur = k;

	return m;
}

u_int
move2 (struct vnfapp * va)
{
	return move (va, va->rx_ring, va->tx_ring);
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

		if (!nm_ring_empty (va->rx_ring)) {
			ioctl (va->rx_fd, NIOCRXSYNC, va->rx_q);
			move2 (va);
			ioctl (va->tx_fd, NIOCTXSYNC, va->tx_q);
		}
	}

	return NULL;
}

void *
processing_single_thread (void * param)
{
	struct vnfapp * va = (struct vnfapp *) param;
	struct nm_desc * src = va->src;
	struct nm_desc * dst = va->dst;
	struct pollfd x[1];
        struct netmap_ring *txring, *rxring;
	u_int si, di;

	pthread_detach (pthread_self ());

	x[0].fd = src->fd;
	x[0].events = POLLIN;

	while (1) {

		poll (x, 1, -1);

		si = src->first_rx_ring;
		di = dst->first_tx_ring;

		while (si <= src->last_rx_ring && di <= dst->last_tx_ring) {
			rxring = NETMAP_RXRING(src->nifp, si);
			txring = NETMAP_TXRING(dst->nifp, di);
			if (nm_ring_empty(rxring)) {
				si++;
				continue;
			}
			if (nm_ring_empty(txring)) {
				di++;
				continue;
			}
			move (va, rxring, txring);
		}
	}

	return NULL;
}


/*
 * packet counter thread.
 */

int
tcp_server_socket (int port)
{
	int sock, ret, val = 1;
	struct sockaddr_in saddr;

	sock = socket (AF_INET, SOCK_STREAM, 0);

	memset (&saddr, 0, sizeof (saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons (port);
	saddr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);

	ret = setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val));
	if (ret < 0) {
		perror ("monitor socket: failed to set SO_REUSEADDR");
		return 0;
	}

	ret = bind (sock, (struct sockaddr *) &saddr, sizeof (saddr));
	if (ret < 0) {
		perror ("monitor socket: bind failed");
		return 0;
	}
	
	return sock;
}

void *
processing_monitor_socket (void * param)
{
	int n, fd;
	socklen_t len;
	char buf[1024];
	struct sockaddr_in saddr;
	struct pollfd x[1];

	u_int32_t dropped_response_pkt;
	u_int32_t dropped_response_byte;
	u_int32_t dropped_query_pkt;
	u_int32_t dropped_query_byte;

	d4c.monitor_sock = tcp_server_socket (d4c.monitor_port);
	if (!d4c.monitor_sock) {
		D ("faield to create monitor socket");
		return NULL;
	}
	
	x[0].fd = d4c.monitor_sock;
	x[0].events = POLLIN | POLLERR;

	D ("start to listen monitor socket");
	listen (d4c.monitor_sock, 1);
	
	while (1) {
		poll (x, 1, -1);

		if (x[0].revents & POLLIN) {
			/* accept new socket, write counters and close */

			fd = accept (d4c.monitor_sock,
				     (struct sockaddr *)&saddr, &len);
			d4c.accept_sock = fd;

			GATHER_COUNTERS (dropped_response_pkt, n);
			GATHER_COUNTERS (dropped_response_byte, n);
			GATHER_COUNTERS (dropped_query_pkt, n);
			GATHER_COUNTERS (dropped_query_byte, n);

			snprintf (buf, sizeof (buf),
				  "dropped_response_pkt %u\n"
				  "dropped_response_byte %u\n"
				  "dropped_query_pkt %u\n"
				  "dropped_query_byte %u\n",
				  dropped_response_pkt,
				  dropped_response_byte,
				  dropped_query_pkt,
				  dropped_query_byte);

			write (fd, buf, strlen (buf) + 1);

			ssap_trie_walk (d4c.match_table, dns_walk_monitor);

			close (fd);
			x[0].revents = 0;
		}
	}


	return NULL;
}


void
usage (void)
{
	printf ("Usage of d4c\n"
		"\t" " * required options.\n"
		"\t" "-r : Right interface name (netmap:ethX)\n"
		"\t" "-l : Left interface name (netmap:ethY)\n"
		"\n"
		"\t" " * DNS filtering options.\n"
		"\t" "-d : Destination prefixes of filtered DNS responses\n"
		"\t" "-s : Source prefixes of NOT filtered DNS responses\n"
		"\t" "-m : Filter suffix of DNS Query Name\n"
		"\n"
		"\t" " * misc.\n"
		"\t" "-q : Max number of threads for interface\n"
		"\t" "-e : Number of Rings of a vale port\n"
		"\t" "-p : TCP port number for packet counter (default 5353)\n"
		"\t" "-c : enable packet counter thread (default off)\n"
		"\t" "-f : Daemon mode\n"
		"\t" "-v : Verbose mode\n"
		"\t" "-h : Print this help\n"
		"\t" "-o : single thread mode\n"
		"");
		

	return;
}

int
main (int argc, char ** argv)
{

	int ret, q, n, len, ch, f_flag = 0, c_flag = 0, o_flag = 0;
	char * rif, * lif;
	struct in_addr prefix;
	struct nm_desc * pr = NULL, * pl = NULL;
	
	q = 256;
	rif = NULL;
	lif = NULL;

	memset (&d4c, 0, sizeof (d4c));
	d4c.dst_table = New_Patricia (32);
	d4c.src_table = New_Patricia (32);
	d4c.match_table = ssap_trie_new ('X');
	d4c.vnfapps_num = 0;
	d4c.monitor_port = MONITOR_PORT;

	while ((ch = getopt (argc, argv, "r:l:q:e:d:s:m:p:cfvho")) != -1) {
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
		case 'm' :
			D ("Install match query %s", optarg);
			ret = dns_add_match (d4c.match_table, optarg);
			if (!ret) {
				D ("failed to install match query %s", optarg);
				return -1;
			}
			break;
		case 'p' :
			d4c.monitor_port = atoi (optarg);
			D ("port number for packet counter is %d",
			   d4c.monitor_port);
			break;
		case 'c' :
			c_flag = 1;
			break;
		case 'f' :
			f_flag = 1;
			break;
		case 'v' :
			verbose = 1;
			break;
		case 'o' :
			o_flag = 1;
			break;
		case 'h' :
		default :
			usage ();
			return -1;
		}
	}
	
	if (verbose) {
		D ("d4c.match_table walk start");
		ssap_trie_walk (d4c.match_table, dns_walk_action);
		D ("d4c.match_table walk end");
	}

	if (rif == NULL || lif == NULL) {
		D ("left anr right interfaces must be specified.");
		usage ();
		return -1;
	}
	
	pr = nm_open (rif, NULL, 0, NULL);
	if (!pr) {
		D ("can not open %s", rif);
		return -1;
	}

	pl = nm_open (lif, NULL, 0, NULL);
	if (!pr) {
		D ("can not open %s", lif);
		return -1;
	}
	
	if (o_flag) {
		/* single thread mode */
		struct vnfapp * va_r_l;
		va_r_l = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va_r_l, 0, sizeof (struct vnfapp));
		va_r_l->src = pr;
		va_r_l->dst = pl;
		d4c.vnfapps[d4c.vnfapps_num++] = va_r_l;
		pthread_create (&va_r_l->tid, NULL, processing_single_thread, va_r_l);

		struct vnfapp * va_l_r;
		va_l_r = (struct vnfapp *) malloc (sizeof (struct vnfapp));
		memset (va_l_r, 0, sizeof (struct vnfapp));
		va_l_r->src = pl;
		va_l_r->dst = pr;
		d4c.vnfapps[d4c.vnfapps_num++] = va_l_r;
		pthread_create (&va_l_r->tid, NULL, processing_single_thread, va_l_r);
	} else {

		/* Assign threads for each RX rings of Right interface */
		for (n = pl->first_rx_ring; n <= pl->last_rx_ring; n++) {
			struct vnfapp * va;
			va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
			memset (va, 0, sizeof (struct vnfapp));
			va->rx_q = n;
			va->tx_q = n % (pr->last_tx_ring - pr->first_tx_ring + 1);
			va->rx_if = rif;
			va->tx_if = lif;
			va->rx_fd = pl->fd;
			va->tx_fd = pr->fd;
			va->rx_ring = NETMAP_RXRING (pl->nifp, va->rx_q);
			va->tx_ring = NETMAP_TXRING (pr->nifp, va->tx_q);

			d4c.vnfapps[d4c.vnfapps_num++] = va;

			pthread_create (&va->tid, NULL, processing_thread, va);
		}
	
		/* Assign threads for each RX rings of Left interfaces  */
		for (n = pr->first_rx_ring; n <= pr->last_rx_ring; n++) {
			struct vnfapp * va;
			va = (struct vnfapp *) malloc (sizeof (struct vnfapp));
			memset (va, 0, sizeof (struct vnfapp));
			va->rx_q = n;
			va->tx_q = n % (pl->last_tx_ring - pl->first_tx_ring + 1);
			va->rx_if = lif;
			va->tx_if = rif;
			va->rx_fd = pr->fd;
			va->tx_fd = pl->fd;
			va->rx_ring = NETMAP_RXRING (pr->nifp, va->rx_q);
			va->tx_ring = NETMAP_TXRING (pl->nifp, va->tx_q);

			d4c.vnfapps[d4c.vnfapps_num++] = va;

			pthread_create (&va->tid, NULL, processing_thread, va);
		}
	}

        if (f_flag) {
                daemon (0, 0);
        }

	if (c_flag) {
		processing_monitor_socket (NULL);
	} else {
		while (1) sleep (100);
	}

	return 0;
}
