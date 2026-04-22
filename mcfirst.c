/*
 * Copyright (C) 2005, 2006  Stig Venaas <venaas@uninett.no>
 * $Id:$
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "ssmping.h"

extern int optind;
extern char *optarg;

int main(int argc, char **argv) {
    int famarg, family, ver, s, ndesc, cnt, count, countarg;
    char *addr1, *addr2, *srv, recvbuf[65535];
    uint16_t runtime, rate;
    uint32_t intface;
    int32_t hops;
    struct sockaddr_storage ucaddr, mcaddr;
    size_t namelen, recvbuflen; 
    uint32_t firstbytes, bytes;
    struct timeval now, rcvtime, firsttime, endtime, jointime, tstamp, diff;
    fd_set readfds;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    double msecs;
    
    gettime(&endtime);
    
#ifdef WIN32
    WORD wVersionRequested;
    WSADATA wsaData;

    wVersionRequested = MAKEWORD( 2, 0 );
    WSAStartup(wVersionRequested, &wsaData);
    /* lots of complicated Win32 error checking expected - sigh - */
#endif
    
    parseargs(argc, argv, FIRSTMODE, &famarg, &ver, NULL, &intface, &countarg, &addr1, &addr2, &runtime, &rate, &srv);

    if (runtime)
	endtime.tv_sec += runtime;

    family = famarg;

    /* addr2 next addr1 in order to request mc if only one arg */
    if (names2addrsocks(&s, NULL, addr2, addr1, srv, &family, &ucaddr, &mcaddr)) {
	if (addr2)
	    errx("Failed to create socket for %s %s", addr1, addr2);
	else
	    errx("Failed to create socket for %s", addr1);
    }
    
    prep_sock(family, s);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    namelen = (mcaddr.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));

#ifdef WIN32
    {
	struct sockaddr_storage any = mcaddr;
	setaddr(&any, NULL, "::", "0.0.0.0");
	if (bind(s, (struct sockaddr *)&any, namelen) < 0)
	    errx("bind [INADDR_ANY]");
    }
#else    
    if (bind(s, (struct sockaddr *)&mcaddr, namelen) < 0)
	errx("bind [multicast]");
#endif
     /* using name to specify interface is wrong, only problem for old API */
    recvbuflen = sizeof(recvbuf);

    if (addr2) {
	joinchannel(s, (struct sockaddr *)&ucaddr, (struct sockaddr *)&mcaddr, intface, NULL);
        printf("mcfirst joined (S,G) = (%s,%s)\n",
	       addr2string((struct sockaddr *)&ucaddr, namelen),
	       addr2string((struct sockaddr *)&mcaddr, namelen));
    } else {
	joingroup(s, (struct sockaddr *)&mcaddr, intface, NULL);
	printf("mcfirst joined (*,G) = (*,%s)\n", addr2string((struct sockaddr *)&mcaddr, namelen));
    }
    
    gettime(&jointime);

    if (!runtime && !countarg)
	countarg = 1;
    bytes = 0;
    
    for (count = 0; !countarg || count < countarg; count++) {
	for(;;) {
	    FD_ZERO(&readfds);
	    FD_SET(s, &readfds);
	
	    gettime(&now);
	    timediff(&diff, &now, &endtime);	    
	    ndesc = select(s + 1, &readfds, (fd_set *)0, (fd_set *)0, runtime ? &diff : NULL);
	    gettime(&now);
	    if (runtime && (timecmp(&endtime, &now) <= 0))
		goto done;
	    
	    if (ndesc < 1)
		continue;

	    cnt = recvfromhopstime(s, (void *)&recvbuf, recvbuflen, 0, (struct sockaddr *)&from,
				   &fromlen, &hops, &tstamp, NULL);

	    if (cnt == -1) {
		err("recv failed");
		continue;
	    }

	    break;
	}

	rcvtime = tstamp.tv_sec ? tstamp : now;
	if (!count) {
	    firsttime = rcvtime;
	    firstbytes = cnt;
	}
	bytes += cnt;

	if (!rate) {
	    fromlen = from.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	    timediff(&diff, &jointime, &rcvtime);
	
	    printf("Received %d bytes from %s after %ld.%03ld ms (ttl/hops %d)\n", cnt,
		   addr2string((struct sockaddr *) &from, fromlen),
		   diff.tv_sec * 1000 + diff.tv_usec / 1000, diff.tv_usec % 1000,
		   hops);
	}
    }
    
 done:
    
    timediff(&diff, &jointime, &rcvtime);
    printf("%d bytes (payload) and %d packets received in %ld.%03ld seconds\n", bytes, count, diff.tv_sec, (diff.tv_usec + 500) / 1000);
    if (count < 2)
	return !count;
	
    timediff(&diff, &firsttime, &rcvtime);
    msecs = (double)diff.tv_sec * 1000 + (double)diff.tv_usec / 1000;
    if (!msecs)
	return !count;
    
    bytes -= firstbytes;
    printf("Average rate: %.3f kbits of payload per second\n",
	   (double)bytes / msecs * 8);

    /* estimate bytes including minimum packet headers */
    bytes += (count - 1) * (mcaddr.ss_family == AF_INET ? 28 : 48);
    printf("Estimated average rate including all headers: %.3f kbits per second\n",
	   (double)bytes / msecs * 8);
    return !count;
}
