/*
 *	Main function of promisc tool.
 *	v0.3
 *
 *	Author: Andrei SAMBRA (andrei.sambra@gmail.com)
 *	Licence type: GNU GPLv3
 */

#include <libnet.h>
#include <pthread.h>

#include "arp.h"
#include "icmp.h"
#include "mdns.h"

int main(int argc, char *argv[])
{
    if ((argc < 3) || (getuid() != 0))
    {
	printf("\nUSAGE (with root priviledges): %s <proto> <device>\n", argv[0]);
	printf("example: %s arp eth0\n\n", argv[0]);
        exit(1);
    }

    /* decide which protocol to use */
    if (strcmp(argv[1], "arp") == 0)
    {
        printf("Packet shaping using libnet 1.1: ARP [LINK]\n");
	send_arp(argv[2]);		/* Use ARP protocol */
    }
    else if (strcmp(argv[1], "icmp") == 0)
    {
	printf("Packet shaping using libnet 1.1: ICMP [LINK]\n");
	send_icmp(argv[2]);		/* Use ICMP protocol */
    }
    else if (strcmp(argv[1], "mdns") == 0)
    {
	printf("Packet shaping using libnet 1.1: UDP mDNS [LINK]\n");
	send_mdns(argv[2]);             /* Use UDP protocol */
    }
    else
    {
        printf("Unknown protocol, please specify either arp, icmp or mdns.\n\n");
        exit(EXIT_FAILURE);
    }
  
    return (EXIT_SUCCESS);
}
