# Params
OPTS = -Wall
LIBS = -lnet -lpcap -lpthread
DEFINES = `libnet-config --defines`

all:
	gcc main.c \
		func.h icmp.h \
		icmp6.h arp.h \
		read.h \
		-o pt-host \
		${OPTS} \
		${LIBS} \
		${DEFINES}
clean:
	rm pt-host
