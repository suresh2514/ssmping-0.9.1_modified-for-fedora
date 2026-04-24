/*
 * Copyright (C) 2005  Stig Venaas <venaas@uninett.no>
 * $Id: asmping.c,v 1.4 2005/11/29 16:27:26 sv Exp $
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
    int famarg, family, count, ver, us, ms;
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

    parseargs(argc, argv, ASMMODE, &famarg, &ver, &size, &intface, &count, &pingee, &group, NULL, NULL, NULL);
    family = famarg;
    
    if (names2addrsocks(&us, &ms, pingee, group, "4321", &family, &ucaddr, &mcaddr))
	errx("Failed to create socket for %s", group);

    prep_sock(family, us);
    prep_sock(family, ms);
    setvbuf(stdout, NULL, _IONBF, 0);
    
    findsrc((struct sockaddr *)&name, (struct sockaddr *)&ucaddr);
    namelen = SOCKADDR_SIZE(name);
    
    setport((struct sockaddr *)&name, 0);

    if (bind(us, (struct sockaddr *)&name, namelen) < 0)
	errx("bind");

    if (connect(us, (struct sockaddr *)&ucaddr, namelen) < 0)
	errx("connect");

    if (getsockname(us, (struct sockaddr *)&name, &namelen) == -1)
	errx("getsockname");
    
    grpaddr = name;
    setaddr(&grpaddr, group ? &mcaddr : NULL, "ff3e::4321:1234", "232.43.211.234");
#ifdef WIN32
    {
	struct sockaddr_storage any = name;
	setaddr(&any, NULL, "::", "0.0.0.0");
	if (bind(ms, (struct sockaddr *)&any, namelen) < 0)
	    errx("bind [INADDR_ANY]");
    }
#else    
    if (bind(ms, (struct sockaddr *)&grpaddr, namelen) < 0)
	errx("bind [multicast]");
#endif
     /* using name to specify interface is wrong, only problem for old API */
    joingroup(ms, (struct sockaddr *)&grpaddr, intface, (struct sockaddr *)&name);
    strcpy(source, addr2string((struct sockaddr *)&ucaddr, namelen));
    printf("asmping joined (S,G) = (*,%s)\n",
	   addr2string((struct sockaddr *)&grpaddr, namelen));
    printf("pinging %s from %s\n", source, addr2string((struct sockaddr *)&name, namelen));

    return doit(ver, size, count, us, ms, &ucaddr, &grpaddr, source);
}    
