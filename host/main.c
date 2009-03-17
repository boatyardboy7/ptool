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
#include "read.h"
#include "icmp6.h"

void usage(char *prog);

int main(int argc, char *argv[])
{
	char *device, *proto, *ip;
	int opt=0;

	int rc;
	pthread_t thread;
	struct thread_data t_args;

	struct addrinfo *res;
	int error;

	char *filter = malloc(sizeof(char)*128);	/* length reserved for future IPv6 */

	while ((opt = getopt(argc, argv, "hp:i:d:")) != -1) {
		switch (opt) {
			case 'p':
				proto = optarg;
				break;
			case 'd':
				ip = optarg;
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

	if (optind != 7) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* get IP version */
	error = getaddrinfo(ip, NULL, NULL, &res);
	
	if (0 != error)
	{   
		fprintf(stderr, "error in getaddrinfo: %s\n", gai_strerror(error));
		exit(1);
	}   
 
	if (res == NULL)
	{   
		fprintf(stderr, "getaddrinfo found no results\n");
		exit(0);
	}

	/* build filter */
	strcat(filter, "host ");       /* add 'and host' */
	strcat(filter, ip);            /* add IP address */
	strcat(filter, " and ");
	if ((strcmp(proto, "icmp") == 0) && (res->ai_family == PF_INET6))
		strcat(filter, "icmp6");
	else
		strcat(filter, proto);          /* add protocol */

	/* create a new thread for the sniffer */
	t_args.thread_id = 0;
	t_args.dev = device;
	t_args.filter = filter;
	rc = pthread_create(&thread, NULL, catch_reply, (void *) &t_args);
	/* end thread part */
    
	sleep(1);

	/* decide which protocol to use */
	if (strcmp(proto, "arp") == 0)
	{
		if (res->ai_family == PF_INET6)
		{
			printf("Packet shaping using libnet 1.1: NDP [LINK IPv4]\n");
			printf("Not implemented yet!");             /* Use ARP protocol */
		}
		else
		{
			printf("Packet shaping using libnet 1.1: ARP [LINK IPv4]\n");
			send_arp(device, ip);             /* Use ARP protocol */
		}
	}
	else if (strcmp(proto, "icmp") == 0)
	{
		if (res->ai_family == PF_INET6)
		{
			printf("Packet shaping using libnet 1.1: ICMPv6 [LINK]\n");
			send_icmp6(device, ip);             /* Use ICMPv6 protocol */
		}
		else
		{
			printf("Packet shaping using libnet 1.1: ICMPv4 [LINK IPv4]\n");
			send_icmp(device, ip);             /* Use ICMPv4 protocol */
		}
	}
	else
	{
		printf("Unknown protocol, please specify either arp, icmp.\n\n");
		exit(EXIT_FAILURE);
	}
  
	/* clear threads */
	sleep(5); // wait for more replies
	
	pthread_kill(thread, SIGTERM);
	pthread_exit(NULL);

	free filter;
	
	return (EXIT_SUCCESS);
}

void usage(char *prog)
{

	printf("\nUSAGE (as root): %s -p <proto> -i <device> -d <destination ip>\n\n", prog);
	printf("example: %s -p icmp -i eth0 -d 10.0.0.1 \n", prog);
	printf("OR:	 %s -p icmp -i eth0 -d fe80::218:f3ff:fea1:26d6\n\n", prog);
}

