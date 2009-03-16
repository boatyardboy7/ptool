/*
 *	Main function of promisc tool.
 *	v0.3
 *
 *	Author: Andrei SAMBRA (andrei.sambra@gmail.com)
 *	Licence type: GNU GPLv3
 */

#include <libnet.h>

#include "arp.h"
#include "icmp.h"
#include "mdns.h"

int main(int argc, char *argv[])
{
    if ((argc < 4) || (getuid() != 0))
    {
	printf("\nUSAGE: %s <proto> <device> <destination ip>\n", argv[0]);
	printf("example: %s arp eth0 10.0.0.1 \n\n", argv[0]);
        exit(1);
    }

    /* decide which protocol to use */
    if (strcmp(argv[1], "arp") == 0)
    {
	printf("Packet shaping using libnet 1.1: ARP [LINK]\n");
        send_arp(argv[2], argv[3]);             /* Use ARP protocol */
    }
    else if (strcmp(argv[1], "icmp") == 0)
    {
	printf("Packet shaping using libnet 1.1: ICMP [LINK]\n");
        send_icmp(argv[2], argv[3]);             /* Use ICMP protocol */
    }
    else if (strcmp(argv[1], "mdns") == 0)
    {
	printf("Packet shaping using libnet 1.1: mDNS [LINK]\n");
	send_mdns(argv[2], argv[3]);             /* Use UDP protocol */
    }
    else
    {
	printf("Packet shaping using libnet 1.1: UDP mDNS [LINK]\n");
        printf("Unknown protocol, please specify either arp, icmp or mdns(UDP).\n\n");
        exit(EXIT_FAILURE);
    }
  
    return (EXIT_SUCCESS);
}
