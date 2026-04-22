/*
 * Copyright (C) 2005  Stig Venaas <venaas@uninett.no>
 * $Id: ssmpingc.c,v 1.4 2005/11/29 16:27:26 sv Exp $
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "ssmping.h"

void errx(char *format, ...) {
    extern int errno;

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    if (errno) {
	fprintf(stderr, ": ");
	perror(NULL);
	fprintf(stderr, "errno=%d\n", errno);
    } else
	fprintf(stderr, "\n");
    exit(1);
}

void err(char *format, ...) {
    extern int errno;

    va_list ap;
    va_start(ap, format);
    vfprintf(stderr, format, ap);
    va_end(ap);
    if (errno) {
	fprintf(stderr, ": ");
	perror(NULL);
	fprintf(stderr, "errno=%d\n", errno);
    } else
	fprintf(stderr, "\n");
}

void setaddr(struct sockaddr_storage *ss, struct sockaddr_storage *group, const char *addr6, const char *addr4) {
    struct addrinfo hints, *res;
    int e;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = ((struct sockaddr *)ss)->sa_family;
    hints.ai_socktype = SOCK_DGRAM;

    switch (((struct sockaddr *)ss)->sa_family) {
    case AF_INET:
	if ((e = getaddrinfo(addr4, NULL, &hints, &res)))
	    break;
	((struct sockaddr_in *)ss)->sin_addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
	if (group)
	    memcpy(&((struct sockaddr_in *)ss)->sin_addr,
		   &((struct sockaddr_in *)group)->sin_addr, 3);
	return;
    case AF_INET6:
	if ((e = getaddrinfo(addr6, NULL, &hints, &res)))
	    break;
	((struct sockaddr_in6 *)ss)->sin6_addr = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
	if (group)
	    memcpy(&((struct sockaddr_in6 *)ss)->sin6_addr,
		   &((struct sockaddr_in6 *)group)->sin6_addr, 12);
	return;
    default:
	fprintf(stderr, "Unsupported address family\n");
	exit(1);
    }

    /* Only down here if gettaddrinfo failed */
#ifdef WIN32    
    err("getaddrinfo failed with error code %d", e);
#else    
    err("getaddrinfo failed: %s", gai_strerror(e));
#endif    
}

char *addr2string(struct sockaddr *addr, socklen_t len) {
    static char addr_buf[2][INET6_ADDRSTRLEN];
    static int i = 0;
    i = !i;
    if (getnameinfo(addr, len, addr_buf[i], sizeof(addr_buf[i]),
		    NULL, 0, NI_NUMERICHOST)) {
	err("getnameinfo");
	return NULL;
    }
    return addr_buf[i];
}

size_t tlvspace(size_t size) {
    return size + 2 * sizeof(uint16_t);
}

char *tlvadd(char *p, uint16_t t, uint16_t l, void *v) {
    uint16_t tmp;

    tmp = htons(t);
    memcpy(p, &tmp, 2);
    p += 2;
    
    tmp = htons(l);
    memcpy(p, &tmp, 2);
    p += 2;

    if (l)
	memcpy(p, v, l);
    return p;
}

char *tlvaddzero(char *p, uint16_t t, uint16_t l) {
    uint16_t tmp;

    tmp = htons(t);
    memcpy(p, &tmp, 2);
    p += 2;
    
    tmp = htons(l);
    memcpy(p, &tmp, 2);
    p += 2;

    if (l)
	memset(p, 0, l);
    return p;
}
