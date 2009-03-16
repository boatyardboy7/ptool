/*
 *	Build ICMP.
 *
 *	Author: Andrei SAMBRA (andrei.sambra@gmail.com)
 *	Licence type: GNU GPLv3
 */

#include <libnet.h>

void send_icmp(char *device)
{
    u_char enet_dst[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    u_int8_t enet_src[6];
    struct libnet_ether_addr* s_neaddr;
    
    libnet_t *l = NULL;
    u_long src_ip = 0, dst_ip = 0;
    int i=0, j, c;
    libnet_ptag_t t;

    char errbuf[LIBNET_ERRBUF_SIZE];

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
	    /* we should run through the queue and free any stragglers */
	    fprintf(stderr, "libnet_init() failed: %s", errbuf);
	    exit(EXIT_FAILURE);
	}
	
	t = libnet_build_icmpv4_echo(
	    ICMP_ECHO,                            /* type */
	    0,                                    /* code */
	    0,                                    /* checksum */
	    0x42,                                 /* id */
	    0x42,                                 /* sequence number */
	    NULL,                                 /* payload */
	    0,                                    /* payload size */
	    l,                                    /* libnet handle */
	    0);

	if (t == -1)
	{
	    fprintf(stderr, "Can't build ICMP header: %s\n", libnet_geterror(l));
	    libnet_destroy(l);
	    exit(EXIT_FAILURE);
	}
    
	
	t = libnet_build_ipv4(
	    LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H, /* length */
	    0,					/* TOS */
	    0x42,                               /* IP ID */
	    0,                                  /* IP Frag */
	    64,                                 /* TTL */
            IPPROTO_ICMP,                       /* protocol */
            0,                                  /* checksum */
            src_ip,                             /* source IP */
            dst_ip,                             /* destination IP */
            NULL,                               /* payload */
            0,                                  /* payload size */
            l,                                  /* libnet handle */
            0);
	
	if (t == -1)
	{
	    fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
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
	    fprintf(stdout, "Wrote %d byte ICMP packet number %d; check the wire.\r", c, j);
	}

	libnet_destroy(l);
    } /* end for loop */

    printf("\n");
}
/* EOF */
