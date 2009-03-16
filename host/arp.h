/*
 *	Build ARP.
 *
 *	Author: Andrei SAMBRA (andrei.sambra@gmail.com)
 *	Licence type: GNU GPLv3
 */

#include <libnet.h>

void send_arp(char *device, char *D_IP)
{
    u_char enet_dst[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    int c, i;
    u_int32_t src_ip, dst_ip;
    struct libnet_ether_addr* s_neaddr;
    u_int8_t enet_src[6];
    libnet_t *l;
    libnet_ptag_t t;
    u_int8_t *packet;
    u_int32_t packet_s;
    char errbuf[LIBNET_ERRBUF_SIZE];
    
    l = libnet_init(
            LIBNET_LINK_ADV,                        /* injection type */
            device,                                 /* network interface */
            errbuf);                                /* errbuf */

    if (l == NULL)
    {
        fprintf(stderr, "%s", errbuf);
        exit(EXIT_FAILURE);
    }
	else

    /* get source IP */
    src_ip = libnet_get_ipaddr4(l);
    
    /* get source MAC addr */
    s_neaddr = libnet_get_hwaddr(l);
    for(i = 0; i < 6; i++)
        enet_src[i] = s_neaddr->ether_addr_octet[i];
    
    if (!(dst_ip = libnet_name2addr4(l, D_IP, LIBNET_RESOLVE)))
    {
        fprintf(stderr, "Bad destination IP address: %s\n", D_IP);
        libnet_destroy(l);
        exit(EXIT_FAILURE);
    }
   
    t = libnet_build_arp(
	    ARPHRD_ETHER,			/* hardware address format */
	    ETHERTYPE_IP,			/* protocol address format */
	    6,					/* hardware address length */
	    4,					/* protocol address length */
	    ARPOP_REQUEST,			/* operation type */
            enet_src,				/* sender hardware addr */
            (u_int8_t *)&src_ip,		/* sender protocol addr */
            enet_dst,				/* target hardware addr */
            (u_int8_t *)&dst_ip,		/* target protocol addr */
            NULL,				/* payload */
	    0,					/* payload length */
	    l,					/* libnet context */
	    0);					/* 0 = build new header*/
    
    if (t == -1)
    {
        fprintf(stderr, "Can't build ARP header: %s\n", libnet_geterror(l));
        libnet_destroy(l);
	exit(EXIT_FAILURE);
    }

    t = libnet_build_ethernet(
            enet_dst,                           /* ethernet destination */
	    enet_src,				/* ethernet destination */
	    ETHERTYPE_ARP,                      /* protocol type */
            NULL,				/* payload */
	    0,					/* payload length */
	    l,					/* libnet handle */
	    0);					/* 0 = build new header*/    
    if (t == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(l));
        
	libnet_destroy(l);
	exit(EXIT_FAILURE);
    }

    if (libnet_adv_cull_packet(l, &packet, &packet_s) == -1)
    {
        fprintf(stderr, "%s", libnet_geterror(l));
    }
    else
    {
        libnet_adv_free_packet(l, packet);
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
        fprintf(stderr, "Wrote %d byte ARP packet; check the wire.\n", c);
    }
    
    libnet_destroy(l);
}

/* EOF */
