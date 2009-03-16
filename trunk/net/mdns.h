/*
 *	Build UDP.
 *
 *	Author: Andrei SAMBRA (andrei.sambra@gmail.com)
 *	Licence type: GNU GPLv3
 */

#include <libnet.h>

void send_mdns(char *device)
{
    u_char enet_dst[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    u_int8_t enet_src[6];
    struct libnet_ether_addr* s_neaddr;
    
    libnet_t *l = NULL;
    u_long src_ip = 0, dst_ip = 0;
    int i=0, j, c;
    libnet_ptag_t t;
    libnet_ptag_t dns;
    
    char errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(
            LIBNET_LINK_ADV,
            device,				/* network interface */
            errbuf);				/* errbuf */

    if (l == NULL)
    {
        /* should run through the queue and free any stragglers */
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    /* get source IP */
    src_ip = libnet_get_ipaddr4(l);
    
    s_neaddr = libnet_get_hwaddr(l);
    for(i = 0; i < 6; i++)
        enet_src[i] = s_neaddr->ether_addr_octet[i];

    libnet_destroy(l);

    /* prepare video buffer */
    setvbuf(stdout,NULL,_IONBF,0);

    for (j=1;j<255;j++)
    {
	/* a hack to iterate through all values of the 4th byte of the IPv4 addr */
	dst_ip = ntohl((htonl(src_ip) & 0xFFFFFF00) + j);
	
	l = libnet_init(
            LIBNET_LINK_ADV,
            device,                       /* network interface */
            errbuf);                      /* errbuf */

	if (l == NULL)
	{
	    /* run through the queue and free any stragglers */
	    fprintf(stderr, "libnet_init() failed: %s", errbuf);
	    exit(EXIT_FAILURE);
	}
	
	dns = libnet_build_dnsv4(
	    LIBNET_UDP_DNSV4_H,				/* TCP or UDP */
	    0x7777,				/* id */
	    0x0100,				/* request */
	    1,					/* num_q */
	    0,					/* num_anws_rr */
	    0,					/* num_auth_rr */
	    0,					/* num_addi_rr */
	    NULL,
	    0,
	    l,
	    0
	    );
	
	t = libnet_build_udp(
	    0x14E9,				/* source port */
	    0x14E9,				/* destination port */
	    LIBNET_UDP_H + LIBNET_UDP_DNSV4_H, /* packet length */
	    0,                                 	/* checksum */
	    NULL,				/* payload */
	    0,					/* payload size */
	    l,					/* libnet handle */
	    0);
	
	if (t == -1)
	{
	    fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
	    libnet_destroy(l);
	    exit(EXIT_FAILURE);
	}

	t = libnet_build_ipv4(
	    LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H, 	/* length */
	    0,					/* TOS */
	    0x42,				/* IP ID */
	    0,					/* IP Frag */
	    64,					/* TTL */
	    IPPROTO_UDP,			/* protocol */
	    0,                                  /* checksum */
	    src_ip,                             /* source IP */
	    dst_ip,                             /* destination IP */
	    NULL,                               /* payload */
	    0,                                  /* payload size */
	    l,                                  /* libnet handle */
	    0);
	if (t == -1)
	{
	    fprintf(stderr, "Can't build IPv4 header: %s\n", libnet_geterror(l));
	    libnet_destroy(l);
	    exit(EXIT_FAILURE);
	}
  
	t = libnet_build_ethernet(
	    enet_dst,                           /* ethernet destination */
	    enet_src,                           /* ethernet destination */
	    ETHERTYPE_IP,                       /* protocol type */
	    NULL,                               /* payload */
	    0,                                  /* payload length */
	    l,                                  /* libnet handle */
	    0);                                 /* 0 = build new header*/    
	if (t == -1)
	{
	    fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
	    libnet_destroy(l);
	    exit(EXIT_FAILURE);
	}

	c = libnet_write(l);
    
	if (c == -1)
	{
	    fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
	    libnet_destroy(l);
	    exit(EXIT_FAILURE);
	}
	else
	{
	    fprintf(stdout, "Wrote %d byte UDP (mDNS) packet number %d; check the wire.\r", c, j);
	}
	
	libnet_destroy(l);
    } /* end for loop */
    
    printf("\n");
}
/* EOF */
