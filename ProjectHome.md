Detect hosts running in promiscuous mode, using either pt-host - targets the specified host, or pt-net which targets the local subnet.

The method to detect these hosts is by sending an ICMP or an ARP request to the host/network. The packet is sent to the correct IP address but with a bogus Ethernet address. If the target(s) operate in promiscuous mode, then it(they) will reply to the request.

Programs:

**pt-host supports both IPv4 and IPv6 for ICMP requests, and IPv4 for ARP requests.**

**pt-net supports only IPv4 for now but contains a self capture method (threaded) in order to catch replies**

The tool was compiled successfully on Linux machines as well as SUN OS and MAC OS.

Required libraries:

**libnet1.1+, libpcap, pthreads**

Please submit any bug reports to andrei.sambra at gmail dot com.

**UPDATE: libnet hasn't been maintained in a long while. This means that I will probably drop the current implementation of ptool, and rebuild it using python+scapy (or maybe ruby?)**