/*
 * Copyright (C) 2005, 2006 Stig Venaas <venaas@uninett.no>
 * $Id:$
 *
 * Contributions:
 * Solaris support by Alexander Gall <gall@switch.ch>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "ssmping.h"

#ifndef WIN32
void zerosrcinterface(struct msghdr *msgh) {
    struct cmsghdr *cmsgh;
    
    switch (((struct sockaddr *)(msgh->msg_name))->sa_family) {
    case AF_INET:
	{
#ifdef IP_PKTINFO
	    struct in_pktinfo *pktinfo;
	    
	    for (cmsgh = CMSG_FIRSTHDR(msgh); cmsgh; cmsgh = CMSG_NXTHDR(msgh, cmsgh))
		if ((cmsgh->cmsg_level == IPPROTO_IP) &&
		    (cmsgh->cmsg_type == IP_PKTINFO)) {
		    pktinfo = (struct in_pktinfo *)CMSG_DATA(cmsgh);
		    pktinfo->ipi_ifindex = 0;
		    break;
		}
#endif
	    /* if not defined we only got source address (I think) */
	    return;
	}
    case AF_INET6:
	{
	    struct in6_pktinfo *pktinfo;

	    for (cmsgh = CMSG_FIRSTHDR(msgh); cmsgh; cmsgh = CMSG_NXTHDR(msgh, cmsgh))
		if ((cmsgh->cmsg_level == IPPROTO_IPV6) &&
		    (cmsgh->cmsg_type == IPV6_PKTINFO)) {
		    pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsgh);
		    pktinfo->ipi6_ifindex = 0;
		    break;
		}
	    return;
	}
    }
}
#endif

int parsequery(char *buf, int len, int *rqver, uint16_t *rqsize, struct sockaddr *group) {
    uint16_t t, l, tmp;
    char *v, *p = buf;

    *rqver = 0;
    *rqsize = 0;
    group->sa_family = AF_UNSPEC;
    
    while (p - buf + 4 <= len) {
	memcpy(&tmp, p, 2);
        t = ntohs(tmp);
        p += 2;
	memcpy(&tmp, p, 2);
        l = ntohs(tmp);
        p += 2;
        if (l) {
            if (p - buf + l > len)
                return -1;
            v = p;
            p += l;
        }

	switch (t) {
	case SSMPING_RQVER:
	    *rqver = 1;
	    break;
	case SSMPING_REPLYSIZE:
	    if (l != 2)
		return -1;
	    memcpy(rqsize, v, 2);
	    *rqsize = ntohs(*rqsize);
	    break;
	case SSMPING_GROUP:
	    if (l < 1)
		return -1;
	    if (*v == 1) { /* IPv4 */
		if (l != 5)
		    return -1;
		memcpy(&((struct sockaddr_in *)group)->sin_addr, v + 1, 4);
		group->sa_family = AF_INET;
		return 0;
	    }
	    if (*v == 2) { /* IPv6 */
		if (l != 17)
		    return -1;
		memcpy(&((struct sockaddr_in6 *)group)->sin6_addr, v + 1, 16);
		group->sa_family = AF_INET6;
		return 0;
	    }
	    return -1;
	}
    }
    return -1;
}

int addrok(struct sockaddr *addr) {
    switch(addr->sa_family) {
    case AF_INET:
	{
	    struct sockaddr_in *a = (struct sockaddr_in *)addr;
	    return *(((uint8_t *)&a->sin_addr) + 3) == 234;
	}
    case AF_INET6:
	{
	    const char groupid[4] = { 0x43, 0x21, 0x12, 0x34 };
	    struct sockaddr_in6 *a = (struct sockaddr_in6 *)addr;
	    return !memcmp(((char *)&a->sin6_addr) + 12, groupid, 4);
	}
    }
    return 0;
}

void respond(int s) {
    static char inbuf[65535], outbuf[65535];
    char *p;
    struct sockaddr *sa, *gsa;
    struct sockaddr_storage addr, gaddr;
    socklen_t addrlen = sizeof(addr);
    int incnt, outcnt, rqver;
    size_t outbuflen;
    uint16_t rqsize;
#ifndef WIN32
    struct msghdr msgh;
    struct iovec iovec;
    char control[10240];
#endif
    
    sa = (struct sockaddr *)&addr;
    gsa = (struct sockaddr *)&gaddr;
    
#ifdef WIN32
    incnt = recvfrom(s, inbuf, sizeof(inbuf), 0, sa, &addrlen);
#else    
    memset(&msgh, 0, sizeof(struct msghdr));
    msgh.msg_iov = &iovec;
    msgh.msg_iovlen = 1;
    msgh.msg_control = control;
    msgh.msg_controllen = sizeof(control);
    msgh.msg_name = (void *)sa;
    msgh.msg_namelen = addrlen;

    memset(&iovec, 0, sizeof(struct iovec));
    iovec.iov_base = (caddr_t)inbuf;
    iovec.iov_len = sizeof(inbuf);

    incnt = recvmsg(s, &msgh, 0);
    addrlen = msgh.msg_namelen;
#endif    
    if (incnt <= 0)
	return;
    if (*inbuf != SSMPING_REQUEST) /* not a request, possibly our own reply */
	return;
    
    printf("received request from %s\n", addr2string(sa, addrlen));

    gaddr = addr; /* would be sufficient to copy port */
    parsequery(inbuf + 1, incnt - 1, &rqver, &rqsize, gsa);
    
    *outbuf = SSMPING_REPLY;
    memcpy(outbuf + 1, inbuf + 1, incnt - 1);
    outcnt = incnt;
    outbuflen = sizeof(outbuf);
    p = outbuf + outcnt;
    
    if (rqver && (p + tlvspace(strlen(SSMPING_SERVERVERSIONSTRING)) < outbuf + outbuflen)) {
	p = tlvadd(p, SSMPING_VER, strlen(SSMPING_SERVERVERSIONSTRING), SSMPING_SERVERVERSIONSTRING);
	p += strlen(SSMPING_SERVERVERSIONSTRING);
    }
    
    outcnt = p - outbuf;

    if (rqsize && (rqsize <= outbuflen) && (outcnt + tlvspace(0) <= rqsize)) {
	p = tlvaddzero(p, SSMPING_PAD, rqsize - outcnt - tlvspace(0));
	outcnt = rqsize;
    }
	
#ifdef WIN32    
    /* send unicast */
    if (sendto(s, outbuf, outcnt, 0, sa, addrlen) < 0)
	err("sendto");
#else
    memset(&iovec, 0, sizeof(struct iovec));
    iovec.iov_base = (caddr_t)outbuf;
    iovec.iov_len = outcnt;

    /* received ancillary data with destination address and interface */
    /* we use that now to specify source address */
    /* setting interface to 0, don't want to specify that */
    zerosrcinterface(&msgh);

    /* send unicast */
    if (sendmsg(s, &msgh, 0) < 0)
	err("sendto");
#endif    

    if (gsa->sa_family == AF_UNSPEC) {
	gsa->sa_family = sa->sa_family;
	setaddr(&gaddr, NULL, "ff3e::4321:1234", "232.43.211.234");
    } else if (!addrok(gsa)) {
	printf("received request with invalid group address %s\n", addr2string(gsa, addrlen));
	return;
    }
    
    /* send multicast */
#ifdef WIN32
    if (sendto(s, outbuf, outcnt, 0, gsa, addrlen) < 0)
	err("sendto");
#else    
    msgh.msg_name = (void *)gsa;
    if (sendmsg(s, &msgh, 0) < 0)
	err("sendto");
#endif    
}

void sethops(int s6, int s4, int hops) {
#ifdef __sun
    uint8_t mcttl = hops;
#else
    int mcttl = hops;
#endif    
    int ttl = hops;
    int hopcount = hops;
    
    if (s6 >= 0) {
	if (setsockopt(s6, IPPROTO_IPV6, IPV6_UNICAST_HOPS, (char *)&hopcount, sizeof(hopcount)) == -1)
	    err("setsockopt IPV6_UNICAST_HOPS");
	if (setsockopt(s6, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, (char *)&hopcount, sizeof(hopcount)) == -1)
	    err("setsockopt IPV6_MULTICAST_HOPS");
    }
    if (s4 < 0)
	return;

    if (setsockopt(s4, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof(ttl)) == -1)
	err("setsockopt IP_TTL");    
    if (setsockopt(s4, IPPROTO_IP, IP_MULTICAST_TTL, (char *)&mcttl, sizeof(mcttl)) == -1)
	err("setsockopt IP_MULTICAST_TTL");
}

int setpktinfo(int s, int family) {
#ifdef WIN32
    return 0;
#else    
    int on = 1;

    switch (family) {
    case AF_INET:
	return setsockopt(s, IPPROTO_IP,
#ifdef IP_PKTINFO
			  IP_PKTINFO,
#else
			  IP_RECVDSTADDR,
#endif
			  &on, sizeof(on));
    case AF_INET6:
	return  setsockopt(s, IPPROTO_IPV6,
#ifdef IPV6_RECVPKTINFO
                   IPV6_RECVPKTINFO,
#else              
                   IPV6_PKTINFO,
#endif             
			   &on, sizeof(on));
    }
    return -1;
#endif    
}

int main(int argc, char **argv) {
    struct addrinfo hints, *res, *res0;
    int e, s, s4 = -1, s6 = -1, max, ndesc;
    fd_set readfds;

#ifdef WIN32
    WORD wVersionRequested;
    WSADATA wsaData;

    wVersionRequested = MAKEWORD( 2, 0 );
    WSAStartup(wVersionRequested, &wsaData);
    /* lots of complicated Win32 error checking expected - sigh - */
#endif
    
    setvbuf(stdout, NULL, _IONBF, 0);
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE;

    if ((e = getaddrinfo(NULL, "4321", &hints, &res0))) {
#ifdef WIN32
	err("getaddrinfo failed with error code %d", e);
#else
	err("getaddrinfo failed: %s", gai_strerror(e));
#endif
    }

    for (res = res0; res; res = res->ai_next) {
	s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (s < 0) {
	    err("socket");
	    continue;
	}
	if (setpktinfo(s, res->ai_family) == -1) {
	    err("setpktinfo");
	    continue;
	}

#ifdef IPV6_V6ONLY
	{
	    int on = 1;
	    if ((res->ai_family == AF_INET6) &&
		(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) == -1))
		err("setsockopt IPV6_V6ONLY");
	}
#endif

	if (bind(s, res->ai_addr, res->ai_addrlen) < 0) {
	    err("bind");
	    continue;
	}
	
	switch (res->ai_family) {
	case AF_INET6:
	    s6 = s;
	    break;
	case AF_INET:
	    s4 = s;
	    break;
	default:
	    printf("Only supporting IPv4 and IPv6 families\n");
	}
    }  
    freeaddrinfo(res0);

    max = s4 > s6 ? s4 : s6;
    if (max == -1)
	errx("both v4 and v6 binds failed");

    sethops(s6, s4, 64);
    for(;;) {    
	FD_ZERO(&readfds);
	if (s4 >= 0)
	    FD_SET(s4, &readfds);
	if (s6 >= 0)
	    FD_SET(s6, &readfds);

	ndesc = select(max + 1, &readfds, (fd_set *)0, (fd_set *)0, NULL);
	if (ndesc < 1)
	    errx("select returned < 1");

	if (s4 >= 0 && FD_ISSET(s4, &readfds))
	    respond(s4);

	if (s6 >= 0 && FD_ISSET(s6, &readfds))
	    respond(s6);
    }
}
