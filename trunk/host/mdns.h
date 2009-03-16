/*
 *	Build UDP.
 *
 *	Author: Andrei SAMBRA (andrei.sambra@gmail.com)
 *	Licence type: GNU GPLv3
 */

#include <libnet.h>

void send_mdns(char *device, char *D_IP)
{
    //u_char enet_dst[6] = {0x01, 0x00, 0x5e, 0x01, 0x01, 0x01}; /* IPv4mcast */
    u_char enet_dst[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    u_int8_t enet_src[6];
    struct libnet_ether_addr* s_neaddr;
    
    libnet_t *l = NULL;
    u_long src_ip = 0, dst_ip = 0;
    int i=0, c;
    libnet_ptag_t t;
    libnet_ptag_t dns;

//    char *query;
//    char payload[1024];
    u_short payload_s = 0;
    
    char errbuf[LIBNET_ERRBUF_SIZE];

    l = libnet_init(
            LIBNET_LINK_ADV,
            device,				/* network interface */
            errbuf);				/* errbuf */

    if (l == NULL)
    {
        /* we should run through the queue and free any stragglers */
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }

    //D_IP = "224.0.0.251";
    //query = "192.168.0.11.in-addr.arpa";
    //query = D_IP;
    //D_IP = "224.0.0.251";

    
    /* get source IP */
    src_ip = libnet_get_ipaddr4(l);
    
    s_neaddr = libnet_get_hwaddr(l);
    for(i = 0; i < 6; i++)
        enet_src[i] = s_neaddr->ether_addr_octet[i];

    if (!dst_ip && (dst_ip = libnet_name2addr4(l, D_IP, LIBNET_RESOLVE)) == -1)
    {
        fprintf(stderr, "Bad destination IP address: %s\n", D_IP);
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }
    
    /* build DNS payload */
    /*payload_s = snprintf(payload, sizeof payload, "%c%s%c%c%c%c%c",
			(char)(strlen(query)&0xff), query, 0x00, 0x00, 0x0c, 0x00, 0x01);
	*/		/*					      0c=PTR  08=QU/00=QM 	 */
    
    dns = libnet_build_dnsv4(
        LIBNET_UDP_DNSV4_H,			/* TCP or UDP */
        0x9999,					/* id */
        0x0000,					/* request */
        1,					/* num_q */
        0,					/* num_anws_rr */
        0,					/* num_auth_rr */
        0,					/* num_addi_rr */
        NULL,
        payload_s,
        l,
        0
        );
	
    t = libnet_build_udp(
        0x6666,					/* source port */
        0x14E9,					/* destination port */
        LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + payload_s, 	/* packet length */
        0,                                 	/* checksum */
        NULL,					/* payload */
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
        LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_UDP_DNSV4_H + payload_s, 	/* length */
        0,					/* TOS */
        0x42,					/* IP ID */
        0,					/* IP Frag */
        64,					/* TTL */
        IPPROTO_UDP,				/* protocol */
        0,					/* checksum */
        src_ip,					/* source IP */
        dst_ip,					/* destination IP */
        NULL,					/* payload */
        0,					/* payload size */
        l,					/* libnet handle */
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
        fprintf(stdout, "Wrote %d byte UDP (mDNS) packet; check the wire.\n", c);
    }

    libnet_destroy(l);
}
/* EOF */
