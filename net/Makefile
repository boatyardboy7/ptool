# Params
OPTS = -Wall
LIBS = -lnet -lpthread -lpcap
DEFINES = `libnet-config --defines`

all:
	gcc main.c \
		arp.h icmp.h \
		func.h \
		-o pt-net \
		${OPTS} \
		${LIBS} \
		${DEFINES}
clean:
	rm pt-net
