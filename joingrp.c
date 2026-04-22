/*
 * Copyright (C) 2005  Stig Venaas <venaas@uninett.no>
 * $Id:$
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "ssmping.h"

void joingroup(int s, struct sockaddr *grp, uint32_t intface, struct sockaddr *ifaddr) {
    int e;
#ifdef MCAST_JOIN_GROUP
    int level;
    socklen_t addrlen;
    struct group_req greq;
#endif

    if (grp && ifaddr && ifaddr->sa_family != grp->sa_family) {
	fprintf(stderr, "joingroup failed, group and interface must be of same address family\n");
	exit(1);
    }
    
    switch (grp->sa_family) {
    case AF_INET:
#ifdef MCAST_JOIN_GROUP
	addrlen = sizeof(struct sockaddr_in);
	level = IPPROTO_IP;
#else
	{
	    struct ip_mreq mreq;
	    memset(&mreq, 0, sizeof(mreq));
	    mreq.imr_multiaddr = ((struct sockaddr_in *)grp)->sin_addr;
	    if (ifaddr)
		mreq.imr_interface = ((struct sockaddr_in *)ifaddr)->sin_addr;
	    e = setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&mreq, sizeof(mreq));
	}
#endif
	break;
    case AF_INET6:
#ifdef MCAST_JOIN_GROUP
	addrlen = sizeof(struct sockaddr_in6);
	level = IPPROTO_IPV6;
#else
	{
	    struct ipv6_mreq mreq6;
	    memset(&mreq6, 0, sizeof(mreq6));
	    mreq6.ipv6mr_multiaddr = ((struct sockaddr_in6 *)grp)->sin6_addr;
	    mreq6.ipv6mr_interface = intface;
	    e = setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, (char *)&mreq6, sizeof(mreq6));
	}
#endif
	break;
    default:
	fprintf(stderr, "joingroup failed, unsupported address family\n");
	exit(1);
    }

#ifdef MCAST_JOIN_GROUP
    memset(&greq, 0, sizeof(greq));
    memcpy(&greq.gr_group, grp, addrlen);
    greq.gr_interface = intface;
    e = setsockopt(s, level, MCAST_JOIN_GROUP, (char *)&greq, sizeof(greq));
#endif

    if (e < 0)
	errx("Failed to join multicast group");
}
