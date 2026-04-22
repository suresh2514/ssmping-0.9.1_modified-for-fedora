/*
 * Copyright (C) 2005  Stig Venaas <venaas@uninett.no>
 * $Id:$
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "ssmping.h"

#ifndef MCAST_JOIN_SOURCE_GROUP
#ifdef WIN32 /* Only useful on Vista */
#define MCAST_JOIN_SOURCE_GROUP         45
#endif
#ifdef linux
#define MCAST_JOIN_SOURCE_GROUP         46
#endif
struct group_source_req {
  uint32_t                gsr_interface; /* interface index */
  struct sockaddr_storage gsr_group;     /* group address */
  struct sockaddr_storage gsr_source;    /* source address */
};
#endif

void joinchannel(int s, struct sockaddr *src, struct sockaddr *grp, uint32_t intface, struct sockaddr *ifaddr) {
#ifdef MCAST_JOIN_SOURCE_GROUP
    int level;
    socklen_t addrlen;

#ifdef WIN32
    struct ip_mreq_source imsr;
#endif
    struct group_source_req gsreq;
    
    if (src->sa_family != grp->sa_family) {
	fprintf(stderr, "joinchannel failed, source and group must be of same address family\n");
	exit(1);
    }

    if (ifaddr && ifaddr->sa_family != grp->sa_family) {
	fprintf(stderr, "joinchannel failed, group and interface must be of same address family\n");
	exit(1);
    }
    
    switch (grp->sa_family) {
    case AF_INET:
	addrlen = sizeof(struct sockaddr_in);
	level = IPPROTO_IP;
	break;
    case AF_INET6:
	addrlen = sizeof(struct sockaddr_in6);
	level = IPPROTO_IPV6;
	break;
    default:
	fprintf(stderr, "joinchannel failed, unsupported address family\n");
	exit(1);
    }

    memset(&gsreq, 0, sizeof(gsreq));
    memcpy(&gsreq.gsr_source, src, addrlen);
    memcpy(&gsreq.gsr_group, grp, addrlen);
    gsreq.gsr_interface = intface;
#ifndef WIN32
    if (setsockopt(s, level, MCAST_JOIN_SOURCE_GROUP, (char *)&gsreq, sizeof(gsreq)) < 0)
	errx("Failed to join multicast channel");
#else
    if (setsockopt(s, level, MCAST_JOIN_SOURCE_GROUP, (char *)&gsreq, sizeof(gsreq)) >= 0)
	return;
    if (level != IPPROTO_IP)
	errx("Failed to join multicast channel");

    /* For Windows XP the above setsockopt fails, below works for IPv4
     * While for Windows Vista the above should work
     */
    
    memset(&imsr, 0, sizeof(imsr));
    imsr.imr_sourceaddr = ((struct sockaddr_in *)src)->sin_addr;
    imsr.imr_multiaddr = ((struct sockaddr_in *)grp)->sin_addr;
    imsr.imr_interface = ((struct sockaddr_in *)ifaddr)->sin_addr;

    if (setsockopt(s, level, IP_ADD_SOURCE_MEMBERSHIP, (char *)&imsr, sizeof(imsr)) < 0)
	errx("Failed to join multicast channel");
#endif
#else
    errx("Not built with SSM support, failed to join multicast channel");
#endif    
}
