# Params
OPTS = -Wall
LIBS = -lnet
DEFINES = `libnet-config --defines`

all:
	gcc main.c \
		arp.h icmp.h mdns.h \
		-o pt-host \
		${OPTS} \
		${LIBS} \
		${DEFINES}
clean:
	rm pt-host
