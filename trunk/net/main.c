/*
 *	Main function of promisc tool.
 *	v0.3.1
 *
 *	Author: Andrei SAMBRA (andrei.sambra@gmail.com)
 *	Licence type: GNU GPLv3
 */

#include <libnet.h>
#include <pthread.h>

#include "func.h"
#include "arp.h"
#include "icmp.h"

void usage(char *prog);

int main(int argc, char *argv[])
{
	char *device, *proto;
	int opt=0;

	while ((opt = getopt(argc, argv, "hp:i:")) != -1) {
		switch (opt) {
			case 'p':
				proto = optarg;
				break;
			case 'h':
				usage(argv[0]);
				exit(EXIT_SUCCESS);
			case 'i':
				device = optarg;
				break;
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
		}
	}
	
	printf("argc=%d | optind=%d\n", argc, optind);

	if (optind != 5) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* decide which protocol to use */
	if (strcmp(proto, "arp") == 0)
	{
		printf("Packet shaping using libnet 1.1: ARP [LINK IPv4]\n");
		send_arp(device);             /* Use ARP protocol */
		
	}
	else if (strcmp(proto, "icmp") == 0)
	{
		printf("Packet shaping using libnet 1.1: ICMPv4 [LINK IPv4]\n");
		send_icmp(device);             /* Use ICMPv4 protocol */
	}
	else
	{
		printf("Unknown protocol, please specify either arp, icmp.\n\n");
		exit(EXIT_FAILURE);
	}
  
	return (EXIT_SUCCESS);
}

void usage(char *prog)
{

	printf("\nUSAGE (as root): %s -p <proto> -i <device> \n\n", prog);
	printf("example: %s -p icmp -i eth0 \n", prog);
}

