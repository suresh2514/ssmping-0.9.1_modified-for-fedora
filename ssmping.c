/*
 * Copyright (C) 2005  Stig Venaas <venaas@uninett.no>
 * $Id: ssmping.c,v 1.22 2005/11/29 16:27:26 sv Exp $
 *
 * Contributions:
 * Solaris support by Alexander Gall <gall@switch.ch>
 * Initial Windows support by Nick Lamb <njl@ecs.soton.ac.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "ssmping.h"

extern int optind;
extern char *optarg;

int main(int argc, char **argv) {
    int family, count, ver, us, ms;
    char *pingee, *group, source[INET6_ADDRSTRLEN];
    uint16_t size;
    uint32_t intface;
    struct sockaddr_storage name, ucaddr, mcaddr, grpaddr;
    socklen_t namelen;
#ifdef WIN32
    WORD wVersionRequested;
    WSADATA wsaData;

    wVersionRequested = MAKEWORD( 2, 0 );
    WSAStartup(wVersionRequested, &wsaData);
    /* lots of complicated Win32 error checking expected - sigh - */
#endif

    parseargs(argc, argv, SSMMODE, &family, &ver, &size, &intface, &count, &pingee, &group, NULL, NULL, NULL);

    if (names2addrsocks(&us, &ms, pingee, group, "4321", &family, &ucaddr, &mcaddr))
	errx("name2addrsocks failed");
    
    prep_sock(family, us);
    prep_sock(family, ms);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    findsrc((struct sockaddr *)&name, (struct sockaddr *)&ucaddr);
    namelen = SOCKADDR_SIZE(name);
    
    setport((struct sockaddr *)&name, 0);

#if defined(SO_BINDTODEVICE) && !defined(WIN32)
    if (intface) {
	char ifname[IF_NAMESIZE];
	if (if_indextoname(intface, ifname) == NULL)
	    errx("if_indextoname");
	if (setsockopt(us, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0)
	    errx("setsockopt SO_BINDTODEVICE on unicast socket");
    }
#endif

    if (bind(us, (struct sockaddr *)&name, namelen) < 0)
	errx("bind");

    if (connect(us, (struct sockaddr *)&ucaddr, namelen) < 0)
	errx("connect");

    if (getsockname(us, (struct sockaddr *)&name, &namelen) == -1)
	errx("getsockname");

    /* Set multicast group address with family from name, address from mcaddr/default */
    grpaddr = name;
    setaddr(&grpaddr, group ? &mcaddr : NULL, "ff3e::4321:1234", "232.43.211.234");

    /* Copy port from ucaddr (server's port 4321) for multicast reception */
    switch (grpaddr.ss_family) {
    case AF_INET:
	((struct sockaddr_in *)&grpaddr)->sin_port = ((struct sockaddr_in *)&ucaddr)->sin_port;
	break;
    case AF_INET6:
	((struct sockaddr_in6 *)&grpaddr)->sin6_port = ((struct sockaddr_in6 *)&ucaddr)->sin6_port;
	break;
    }

#if defined(SO_BINDTODEVICE) && !defined(WIN32)
    /* Set SO_BINDTODEVICE before binding for better multicast routing */
    if (intface) {
	char ifname[IF_NAMESIZE];
	if (if_indextoname(intface, ifname) == NULL)
	    errx("if_indextoname");
	if (setsockopt(ms, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0)
	    errx("setsockopt SO_BINDTODEVICE");
    }
#endif

    /* Bind multicast socket to INADDR_ANY with port 4321 */
    {
	struct sockaddr_storage any = grpaddr;
	setaddr(&any, NULL, "::", "0.0.0.0");
	if (bind(ms, (struct sockaddr *)&any, namelen) < 0)
	    errx("bind [multicast]");
    }
     /* using name to specify interface is wrong, only problem for old API */
    joinchannel(ms, (struct sockaddr *)&ucaddr,
		(struct sockaddr *)&grpaddr, intface, (struct sockaddr *)&name);
    strcpy(source, addr2string((struct sockaddr *)&ucaddr, namelen));
    printf("ssmping joined (S,G) = (%s,%s)\n", source,
	   addr2string((struct sockaddr *)&grpaddr, namelen));
    printf("pinging S from %s\n", addr2string((struct sockaddr *)&name, namelen));

    return doit(ver, size, count, us, ms, &ucaddr, &grpaddr, source);
}    
