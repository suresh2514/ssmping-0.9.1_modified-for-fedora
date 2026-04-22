/*
 * Copyright (C) 2005, 2006  Stig Venaas <venaas@uninett.no>
 * $Id:$
 *
 * Contributions:
 * Solaris support by Alexander Gall <gall@switch.ch>
 * Initial Windows support by Nick Lamb <njl@ecs.soton.ac.uk>
 * llsqrt() taken from Linux's iputils package
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include "ssmping.h"

#ifdef WIN32
#include <mswsock.h>
#include <windns.h>

/* further definitions missing from my mswsock.h */
#ifndef WSAID_WSARECVMSG
/* http://cvs.winehq.org/cvsweb/wine/include/mswsock.h */
#define WSAID_WSARECVMSG {0xf689d7c8,0x6f1f,0x436b,{0x8a,0x53,0xe5,0x4f,0xe3,0x51,0xc3,0x22}}
#endif
#ifndef CMSG_FIRSTHDR
#define CMSG_FIRSTHDR(pwsamsg) (pwsamsg)->Control.len >= sizeof(WSACMSGHDR) ? (WSACMSGHDR *)((pwsamsg)->Control.buf) : NULL
#endif
#ifndef CMSG_NXTHDR
#define CMSG_NXTHDR(pwsamsg, cmsg) my_cmsg_nxthdr(pwsamsg, cmsg)
WSACMSGHDR *my_cmsg_nxthdr(WSAMSG *mhdr, WSACMSGHDR *cmsg) {
    WSACMSGHDR *cmsgh = (WSACMSGHDR *)(((char *)cmsg) + cmsg->cmsg_len);
    /* should also do alignment above */
    return (char *)(cmsgh + 1) <= (char *)mhdr->Control.buf + mhdr->Control.len ? cmsgh : NULL;
}
#endif
#ifndef MSG_MCAST
#define MSG_MCAST 2048
#endif
#ifndef IPV6_HOPLIMIT
#define IPV6_HOPLIMIT 21
#endif
#ifndef CMSG_DATA
#define MY_CMSG_LEN(len) (len)+sizeof(WSACMSGHDR)
#define CMSG_DATA(cmsg) ((char *)(cmsg)+sizeof(WSACMSGHDR))
#endif
#ifndef _CMSG_DATA_ALIGN
#define _CMSG_DATA_ALIGN(len) (((len) + sizeof (size_t) - 1) & (size_t) ~(sizeof (size_t) - 1))
#endif
#endif

#ifndef MY_CMSG_LEN
#define MY_CMSG_LEN CMSG_LEN
#endif

/* llsqrt() taken from Linux's iputils package */
static long llsqrt(unsigned long long a) {
    long long prev = ~((unsigned long long) 1 << 63);
    long long x = a;

    if (x > 0) {
	while (x < prev) {
	    prev = x;
	    x = (x + (a / x)) / 2;
	}
    }
    return (long) x;
}

void gettime(struct timeval *tv) {
#ifdef WIN32
    long long hns;
    FILETIME ft;

    GetSystemTimeAsFileTime(&ft);
    hns = (4294967296LL * ft.dwHighDateTime + ft.dwLowDateTime) / 10
	- 11644473600000000LL ; /* fix up UNIX 1970 vs Win32 1601 */
    tv->tv_sec = (hns / 1000000);
    tv->tv_usec = (hns % 1000000);
#else
    gettimeofday(tv, NULL);
#endif    
}

void setport(struct sockaddr *sa, int port) {
    switch (sa->sa_family) {
    case AF_INET:
	{
	    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
	    sin->sin_port = htons(port);
	    return;
	}
	
    case AF_INET6:
	{
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
	    sin6->sin6_port = htons(port);
	    return;
	}
    }
}

/* returns t2 - t1 if t2 > t1, else 0 */
void timediff(struct timeval *diff, struct timeval *t1, struct timeval *t2) {
    if (t2->tv_sec >= t1->tv_sec) {
	diff->tv_sec = t2->tv_sec - t1->tv_sec;
	if (t2->tv_usec >= t1->tv_usec) {
	    diff->tv_usec = t2->tv_usec - t1->tv_usec;
	    return;
	}
	if (diff->tv_sec) {
	    diff->tv_sec--;
	    diff->tv_usec = 1000000 - t1->tv_usec + t2->tv_usec;
	    return;
	}
    }
    diff->tv_sec = 0;
    diff->tv_usec = 0;
    return;
}

/* returns -1, 0, 1 if t1 < t2, t1 == t2, t1 > t2 resp */
int timecmp(struct timeval *t1, struct timeval *t2) {
    if (t1->tv_sec < t2->tv_sec)
	return -1;
    if (t1->tv_sec > t2->tv_sec)
	return 1;
    if (t1->tv_usec < t2->tv_usec)
	return -1;
    if (t1->tv_usec > t2->tv_usec)
	return 1;
    return 0;
}

int addr_equal(struct sockaddr *a, struct sockaddr *b) {
    switch (a->sa_family) {
    case AF_INET:
	return !memcmp(&((struct sockaddr_in*)a)->sin_addr,
		      &((struct sockaddr_in*)b)->sin_addr,
		      sizeof(struct in_addr));
    case AF_INET6:
	return IN6_ARE_ADDR_EQUAL(&((struct sockaddr_in6*)a)->sin6_addr,
				  &((struct sockaddr_in6*)b)->sin6_addr);
    default:
	/* Must not reach */
	return 1;
    }
}

int dupcheck(char s, unsigned int t) {
    static int first = 1;
    static unsigned int recent[2][100];
    int i = s % 2;
    int j = t % 100;

    if (first) {
	first = 0;
	memset(recent, 0, sizeof(recent));
	recent[0][0] = 1;
	recent[1][0] = 1;
    }

    if (recent[i][j] == t)
	return 1;

    recent[i][j] = t;
    return 0;
}

void prep_sock(int family, int s) {
    int on = 1;

    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) == -1)
	errx("setsockopt SO_REUSEADDR");

#ifdef SO_TIMESTAMP
    if (setsockopt(s, SOL_SOCKET, SO_TIMESTAMP, (char *)&on, sizeof(on)) == -1)
	errx("setsockopt SO_TIMESTAMP");
#endif

    switch (family) {
    case AF_INET6:
#ifdef IPV6_RECVHOPLIMIT
	if (setsockopt(s, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) == -1)
	    errx("setsockopt IPV6_RECVHOPLIMIT");
#else
	if (setsockopt(s, IPPROTO_IPV6, IPV6_HOPLIMIT, (char *)&on, sizeof(on)) == -1)
	    errx("setsockopt IPV6_HOPLIMIT");
#endif
	break;
    case AF_INET:
#ifdef IP_RECVTTL
	if (setsockopt(s, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on)) == -1)
	    errx("setsockopt IP_RECVTTL");
#else
	if (setsockopt(s, IPPROTO_IP, IP_TTL, (char *)&on, sizeof(on)) == -1)
	    errx("setsockopt IP_TTL");
#endif
	break;
    }
}

void findsrc(struct sockaddr *src, struct sockaddr *dst) {
    int s;
    socklen_t len;
    
    len = dst->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    s = socket(dst->sa_family, SOCK_DGRAM, 0);
    if (s < 0)
        errx("socket");
    
    /* connect to get sockname */
    if (connect(s, dst, len) < 0)
        errx("connect");

    if (getsockname(s, src, &len) == -1)
        errx("getsockname");
    
    close(s);
}

/* mc is a flag saying if multicast or unicast, only used on WIN32 */
int recvfromhopstime(int s, void *buf, size_t len, int flags, struct sockaddr *from,
		     socklen_t *fromlen, int32_t *hops, struct timeval *tstamp, char *mc) {
#ifdef WIN32
    GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
    long ioctlcount;
    static int (*WSARecvMsg)() = NULL;
    WSAMSG msgh;
    WSABUF iovec;
    WSACMSGHDR *cmsgh;
#else    
    struct msghdr msgh;
    struct iovec iovec;
    struct cmsghdr *cmsgh;
#endif
    char control[1024];
    int cnt;

#ifdef WIN32
    if (!WSARecvMsg) {
	if (WSAIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, &WSARecvMsg_GUID, sizeof(WSARecvMsg_GUID), &WSARecvMsg, sizeof(WSARecvMsg), &ioctlcount, NULL, NULL)) {
	    fprintf(stderr, "WSAIoctl failed with code %d\n", WSAGetLastError());
	    return -1;
	}
    }
#endif
    
    if (hops)
	*hops = -1;
    if (tstamp)
	memset(tstamp, 0, sizeof(struct timeval));
    
#ifdef WIN32
    memset(&msgh, 0, sizeof(msgh));
    msgh.lpBuffers = &iovec;
    msgh.dwBufferCount = 1;
    msgh.Control.buf = control;
    msgh.Control.len = sizeof(control);
    memset(control, 0, sizeof(control));
    msgh.name = from;
    msgh.namelen = *fromlen;
    msgh.dwFlags = 0;
    memset(&iovec, 0, sizeof(iovec));
    iovec.buf = buf;
    iovec.len = len;

    if (WSARecvMsg(s, &msgh, &cnt, NULL, NULL)) {
	    fprintf(stderr, "WSARecvMsg failed with code %d\n", WSAGetLastError());
	    return -1;
    }

    if (mc)
	*mc = (msgh.dwFlags & MSG_MCAST) == MSG_MCAST;

#else    
    memset(&msgh, 0, sizeof(struct msghdr));
    msgh.msg_iov = &iovec;
    msgh.msg_iovlen = 1;
    msgh.msg_control = control;
    msgh.msg_controllen = sizeof(control);
    msgh.msg_name = from;
    msgh.msg_namelen = *fromlen;
    memset(&iovec, 0, sizeof(struct iovec));
    iovec.iov_base = (caddr_t)buf;
    iovec.iov_len = len;

    cnt = recvmsg(s, &msgh, 0);
#endif
    
    if (cnt < 1 || (!hops && !tstamp))
	return cnt;

#if 0
    printf("flags=%d\n", msgh.dwFlags);
    {
	int i;
	for (i = 0; i < 16; i++)
	    printf("%hhd\n", control[i]);
    }

    printf("control length = %d\n", msgh.Control.len);
#endif
    
    for (cmsgh = CMSG_FIRSTHDR(&msgh); cmsgh; cmsgh = CMSG_NXTHDR(&msgh, cmsgh))
	switch (cmsgh->cmsg_level) {
#ifdef SCM_TIMESTAMP
	case SOL_SOCKET:
	    if (cmsgh->cmsg_type == SCM_TIMESTAMP &&
		cmsgh->cmsg_len >= MY_CMSG_LEN(sizeof(struct timeval)))
		*tstamp = *(struct timeval *)CMSG_DATA(cmsgh);
	    break;
#endif
	case IPPROTO_IP:
	    if (cmsgh->cmsg_type == IP_TTL && cmsgh->cmsg_len >= MY_CMSG_LEN(sizeof(int32_t)))
		*hops = *(int *)CMSG_DATA(cmsgh);
#ifdef IP_RECVTTL
	    /* Only found Solaris 9 to use IP_RECVTTL so far */
	    if (cmsgh->cmsg_type == IP_RECVTTL && cmsgh->cmsg_len >= 13)
		*hops = *(int8_t *)CMSG_DATA(cmsgh);
#endif
	    break;
	case IPPROTO_IPV6:
	    if (cmsgh->cmsg_type == IPV6_HOPLIMIT && cmsgh->cmsg_len >= MY_CMSG_LEN(sizeof(int)))
		*hops = *(int *)CMSG_DATA(cmsgh);
	    break;
	}
    return cnt;
}

size_t initsendbuf(char *buf, size_t buflen, pid_t pid, int ver, uint16_t size, struct sockaddr_storage *group,
		   void **seq, void **timestamp) {
    char *p = buf;
    uint32_t int32[2];
    
    if (buflen < 1)
	errx("Send buffer too small");
    *p++ = SSMPING_REQUEST;

    if (p + tlvspace(4) > buf + buflen)
	errx("Send buffer too small");
    int32[0] = pid;
    int32[0] = htonl(int32[0]);
    p = tlvadd(p, SSMPING_PID, 4, int32);
    p += 4;
    
    int32[0] = 0;
    int32[1] = 0;

    if (p + tlvspace(4) > buf + buflen)
	errx("Send buffer too small");
    p = tlvadd(p, SSMPING_SEQ, 4, int32);
    *seq = p;
    p += 4;
    
    if (p + tlvspace(8) > buf + buflen)
	errx("Send buffer too small");
    p = tlvadd(p, SSMPING_TIMESTAMP, 8, int32);
    *timestamp = p;
    p += 8;

    if (ver) {
	if (p + tlvspace(0) > buf + buflen)
	    errx("Send buffer too small");
	p = tlvadd(p, SSMPING_RQVER, 0, NULL);
    }

    if (size) {
	uint16_t tsize = htons(size);
	if (p + tlvspace(2) > buf + buflen)
	    errx("Send buffer too small");
	p = tlvadd(p, SSMPING_REPLYSIZE, 2, &tsize);
	p += 2;
    }
    
    switch (((struct sockaddr *)group)->sa_family) {
    case AF_INET:
	if (p + tlvspace(5) > buf + buflen)
	    errx("Send buffer too small");
	/* ugly hack, starting 1 byte before address to have room for family */
	p = tlvadd(p, SSMPING_GROUP, 5, ((char *)&(((struct sockaddr_in *)group)->sin_addr)) - 1);
	*p = 1; /* IANA has assigned 1 for IPv4 */
	p += 5;
	break;
    case AF_INET6:
	if (p + tlvspace(17) > buf + buflen)
	    errx("Send buffer too small");
	/* ugly hack, starting 1 byte before address to have room for family */
	p = tlvadd(p, SSMPING_GROUP, 17, ((char *)&(((struct sockaddr_in6 *)group)->sin6_addr)) - 1);
	*p = 2; /* IANA has assigned 2 for IPv6 */
	p += 17;
	break;
    }
    return p - buf;
}

int parsepacket(char *buf, size_t len, char **verstring, struct ssmpingdata *data) {
    uint16_t t, l, tmp;
    char *v, *p = buf;
    uint32_t val;
    int pid = 0, seq = 0, timestamp = 0;

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
	case SSMPING_PID:
	    if (l != 4)
		return -1;
	    memcpy(&val, v, 4);
	    data->pid = ntohl(val);
	    pid = 1;
	    break;
	case SSMPING_SEQ:
	    if (l != 4)
		return -1;
	    memcpy(&val, v, 4);
	    data->seq = ntohl(val);
	    seq = 1;
	    break;
	case SSMPING_TIMESTAMP:
	    if (l != 8)
		return -1;
	    memcpy(&val, v, 4);
	    data->timestamp.tv_sec = ntohl(val);
	    memcpy(&val, v + 4, 4);
	    data->timestamp.tv_usec = ntohl(val);
	    timestamp = 1;
	    break;
	case SSMPING_VER:
	    if (!l)
		return -1;
	    if (!*verstring) {
		*verstring = malloc(l);
		if (*verstring) {
		    memcpy(*verstring, v, l);
		    (*verstring)[l] = '\0';
		}
	    }
	    break;
	}
    }
    if (p - buf != len)
	return -1;
    return 0;
}

int ismc(struct sockaddr *sa) {
    switch (sa->sa_family) {
    case AF_INET: return IN_MULTICAST(ntohl(((struct sockaddr_in *)sa)->sin_addr.s_addr));
    case AF_INET6: return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)sa)->sin6_addr);
    }
    return 0;
}

#ifdef WIN32
#ifndef DNS_TYPE_SRV
#define DNS_TYPE_SRV 33
#endif

char *getsrv(const char *name) {
    DNS_RECORD *dnsrecords, *dnsrecord;
    void *dnsrsv;
    char *srvname;
    
    srvname = malloc(strlen(name) + strlen("_ldap._tcp.") + 1);
    sprintf(srvname, "_ldap._tcp.%s", name);
    
    if (DnsQuery_A(srvname, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, &dnsrecords, &dnsrsv))
	return NULL;
    for (dnsrecord = dnsrecords; dnsrecord; dnsrecord = dnsrecord->pNext) {
#if 0	
	printf("dnsname = %s\n", dnsrecord->pName);
	printf("dnstype = %d\n", dnsrecord->wType);
#endif	
	if (dnsrecord->wType == DNS_TYPE_SRV) {
	    free(srvname);
	    return dnsrecord->Data.Srv.pNameTarget;
	}
    }
    free(srvname);
    DnsRecordListFree(dnsrecords, DnsFreeRecordList);
    return NULL;
}
#endif    

/* return 0 if ok, -1 on error. creates sockets s1, s2 if not NULL
 * mcaddr must be mc and ucaddr uc, unless both specified, in which
 * case one must be uc and the other mc
 */
int names2addrsocks(int *s1, int *s2, const char *ucaddr, const char *mcaddr, const char *srv, int *family,
		     struct sockaddr_storage *ucsa, struct sockaddr_storage *mcsa) {
    struct addrinfo hints, *res1, *res2;
    const char *addr;
    int e;
    
    addr = mcaddr ? mcaddr : ucaddr;
    if (!addr)
	return -1;
    
    if (s1)
	*s1 = -1;
    if (s2)
	*s2 = -1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = *family;
    hints.ai_socktype = SOCK_DGRAM;

#ifdef WIN32
    printf("SRV target %s\n", getsrv(addr));
#endif
    
    if ((e = getaddrinfo(addr, srv, &hints, &res1))) {
#ifdef WIN32
	err("getaddrinfo failed with error code %d", e);
#else    
	err("getaddrinfo failed: %s", gai_strerror(e));
#endif
	return -1;
    }
    for (; res1; res1 = res1->ai_next) {
	if (s1) {
	    *s1 = socket(res1->ai_family, res1->ai_socktype, res1->ai_protocol);
	    if (*s1 < 0) {
		err("socket");
		continue;
	    }
	}
	if (s2) {
	    *s2 = socket(res1->ai_family, res1->ai_socktype, res1->ai_protocol);
	    if (*s2 < 0) {
		if (s1) {
		    close(*s1);
		    *s1 = -1;
		}
		err("socket");
		continue;
	    }
	}
	
	*family = res1->ai_family;
		
	if (!ucaddr || !mcaddr) {
	    if (ismc(res1->ai_addr)) {
		if (mcaddr) {
		    memcpy(mcsa, res1->ai_addr, res1->ai_addrlen);
		    return 0;
		}
		err("Argument must be a unicast address");
		return -1;
	    }
	    if (ucaddr) {
		memcpy(ucsa, res1->ai_addr, res1->ai_addrlen);
		return 0;
	    }
	    err("Argument must be a multicast address");
	    return -1;
	}
    
	hints.ai_family = *family;
	if ((e = getaddrinfo(ucaddr, srv, &hints, &res2))) {
#ifdef WIN32
	    err("getaddrinfo failed with error code %d", e);
#else    
	    err("getaddrinfo failed: %s", gai_strerror(e));
#endif
	    if (s1) {
		close(*s1);
		*s1 = -1;
	    }
	    if (s2) {
		close(*s2);
		*s2 = -1;
	    }
	    continue;
	}
		
	if (ismc(res1->ai_addr)) {
	    if (ismc(res2->ai_addr)) {
		err("Both addresses cannot be multicast addresses");
		return -1;
	    }
	    memcpy(mcsa, res1->ai_addr, res1->ai_addrlen);
	    memcpy(ucsa, res2->ai_addr, res2->ai_addrlen);
	    return 0;
	}
	if (ismc(res2->ai_addr)) {
	    memcpy(ucsa, res1->ai_addr, res1->ai_addrlen);
	    memcpy(mcsa, res2->ai_addr, res2->ai_addrlen);
	    return 0;
	}
	err("Both addresses cannot be unicast addresses");
	return -1;
    }
    return -1;
}

void parseargs(int argc, char **argv, int mode, int *family, int *ver, uint16_t *size, uint32_t *intface,
	       int *count, char **addr1, char **addr2, uint16_t *runtime, uint16_t *rate, char **srv) {
    int c;
    
    *family = AF_UNSPEC;
    *intface = 0;
    *count = 0;
    *addr2 = NULL;
    *ver = 0;
    if (size)
	*size = 0;
    if (runtime)
	*runtime = 0;
    if (rate)
	*rate = 0;
    
    while ((c = getopt(argc, argv,
#ifdef WIN32
		       mode == FIRSTMODE ? "46vrc:t:" : "46vc:s:"
#else
		       mode == FIRSTMODE ? "46vrI:c:t:" : "46vI:c:s:"
#endif		       
		       )) != -1) {
        switch (c) {
        case '4':
	    *family = AF_INET;
	    break;
        case '6':
	    *family = AF_INET6;
	    break;
        case 'v':
	    *ver = 1;
	    break;
        case 'r':
	    if (rate)
		*rate = 1;
	    break;
#ifndef WIN32
	case 'I':
	    *intface = if_nametoindex(optarg);
	    if (*intface)
		break;
	    fprintf(stderr, "Unknown interface %s\n", optarg);
	    exit(1);
#endif	    
	case 'c':
	    *count = atoi(optarg);
	    if (*count > 0)
		break;
	    fprintf(stderr, "Count must be positive\n");
	    goto usage;
	case 's':
	    *size = atoi(optarg);
	    if (*size > 0)
		break;
	    fprintf(stderr, "Invalid size\n");
	    goto usage;
	case 't':
	    *runtime = atoi(optarg);
	    if (*runtime > 0)
		break;
	    fprintf(stderr, "Invalid time to run\n");
	    goto usage;

	default:
	    goto usage;
	}
    }

    switch (mode) {
    case FIRSTMODE:
	/* require two-three more arguments */
	switch (argc - optind) {
	case 2:
	    *addr1 = argv[optind++];
	    *srv = argv[optind];
	    return;
	case 3:
	    *addr1 = argv[optind++];
	    *addr2 = argv[optind++];
	    *srv = argv[optind];
	    return;
	default:
	    goto usage;
	}
    case ASMMODE:
	/* require exactly two arguments after the options */
	if (argc - optind != 2)
	    goto usage;
	*addr2 = argv[optind++];
	*addr1 = argv[optind];
	return;
    case SSMMODE:
	/* require exactly one more argument */
	if (argc - optind != 1)
	    goto usage;
	*addr1 = argv[optind];
	return;
    }

 usage:
    fprintf(stderr, "%s version %s\n\n", argv[0], SSMPING_VERSIONSTRING);
    switch (mode) {
    case FIRSTMODE:
	fprintf(stderr,
#ifdef WIN32
		"Usage:\n%s [ -46vr ] [ -c count ] [ -t time ] [source] group port\nor\n%s [ -46vr ] [ -c count ] [ -t time ] group [source] port\n"
#else    
		"Usage:\n%s [ -46vr ] [ -I interface ] [ -c count ] [ -t time ] [source] group port\nor\n%s [ -46vr ] [ -I interface ] [ -c count ] [ -t time ] group [source] port\n"
#endif    
		, argv[0], argv[0]);
	break;
    case ASMMODE:
	fprintf(stderr,
#ifdef WIN32
		"Usage:\n%s [ -46v ] [ -c count ] [ -s size ] group destination\nor\n%s [ -46v ] [ -c count ] [ -s size ] destination group\n"
#else		
		"Usage:\n%s [ -46v ] [ -I interface ] [ -c count ] [ -s size ] group destination\nor\n%s [ -46v ] [ -I interface ] [ -c count ] [ -s size ] destination group\n"
#endif
		, argv[0], argv[0]);
	break;
    case SSMMODE:
	fprintf(stderr,
#ifdef WIN32
		"Usage:\n%s [ -46v ] [ -c count ] [ -s size ] destination\n"
#else
		"Usage:\n%s [ -46v ] [ -I interface ] [ -c count ] [ -s size ] destination\n"
#endif	    
		, argv[0]);
	break;
    }
    exit(1);
}

/* finish needs to be visible for interrupt() */
int finish = 0;

void interrupt(int signo) {
    finish = 1;
}

int doit(int ver, int size, int count, int us, int ms, struct sockaddr_storage *ucaddr,
	 struct sockaddr_storage *grpaddr, char *source) {
    int s, cnt, max, ndesc, gotver = 0;
    int32_t hops;
    unsigned int uccount = 0, mccount = 0, mcminseq;
    long rtt, ucmin, ucmax, mcmin, mcmax, mdev;
    long long ucsum, ucsqsum, mcsum, mcsqsum, mean;
    fd_set readfds;
    pid_t pid;
    struct ssmpingdata recvdata;
    struct sockaddr_storage from;
    socklen_t fromlen = sizeof(from);
    size_t sendbuflen, recvbuflen, sendlen;
    struct timeval now, jointime, tstamp, diff, timeout, nextping;
    char mc, sendbuf[1024], recvbuf[1024], *sendtimestamp, *verstring = NULL;
    void *sendseq;
    uint32_t u32t, seq = 0;
    int32_t dist; 
#ifndef WIN32
    struct sigaction sa_int;
#endif

    gettime(&jointime);
    
    sendbuflen = sizeof(sendbuf);
    recvbuflen = sizeof(recvbuf);
    
    pid = getpid();
    
    sendlen = initsendbuf(sendbuf, sendbuflen, pid, ver, size, grpaddr, &sendseq, (void **)&sendtimestamp);
    
    max = us > ms ? us : ms;

#ifndef WIN32
    sa_int.sa_handler = interrupt;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    sigaction(SIGINT, &sa_int, NULL);
#else
    signal(SIGBREAK, interrupt);
    signal(SIGINT, interrupt);
#endif
    
    /* the next ping (the first one), should be immediately */
    gettime(&nextping);

    for(;;) {
	FD_ZERO(&readfds);
	FD_SET(us, &readfds);
	FD_SET(ms, &readfds);
	
	/* set timeout to now - nextping or 0 if past nextping time */
	gettime(&now);
	timediff(&timeout, &now, &nextping);
	ndesc = select(max + 1, &readfds, (fd_set *)0, (fd_set *)0, &timeout);
	gettime(&now);

	if (finish)
	    break;
	
	if (timecmp(&nextping, &now) <= 0) {
	    if (count && seq >= count)
		break;
	    nextping.tv_sec++;
	    seq++;
	    u32t = htonl(seq);
	    memcpy(sendseq, &u32t, 4);
	    u32t = htonl(now.tv_sec);
	    memcpy(sendtimestamp, &u32t, 4);
	    u32t = htonl(now.tv_usec);
	    memcpy(sendtimestamp + 4, &u32t, 4);
	    if (send(us, (void *)&sendbuf, sendlen, 0) < 0)
		err("send");
	}

	if (ndesc < 1)
	    continue;

	s = FD_ISSET(us, &readfds) ? us : ms;

	cnt = recvfromhopstime(s, (void *)&recvbuf, recvbuflen, 0,
			   (struct sockaddr *)&from, &fromlen, &hops, &tstamp, &mc);

	if (cnt == -1) {
	    err("recv failed");
	    continue;
	}
	if (cnt < sendlen) {
	    printf("packet too small\n");
	    continue;
	}
	fromlen = from.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
	if (!addr_equal((struct sockaddr *)&from, (struct sockaddr *)ucaddr)) {
	    printf("ignoring packet from wrong host (%s)\n",
		   addr2string((struct sockaddr *) &from, fromlen));
	    continue;
	}

	if (*recvbuf != SSMPING_REPLY) {
	    printf("received non-reply packet\n");
	    continue;
	}
	
	parsepacket(recvbuf + 1, cnt - 1, &verstring, &recvdata);
	
#ifndef WIN32
	mc = s == ms;
#endif
	
	if (recvdata.pid != pid) {
	    printf("received someone else's %sicast reply\n", mc ? "mult" : "un");
	    continue;
	}

	timediff(&diff, &recvdata.timestamp, tstamp.tv_sec ? &tstamp : &now);

	if (verstring && !gotver) {
	    gotver = 1;
	    printf("Server version: %s\n", verstring);
	}

	if (size && cnt != size)
	    printf("Warning, requested packet size %d, got %d\n", size, cnt);
	
	if (hops < 0)
	    dist = -1;
	else if (hops > 64) /* assuming Windows using ttl 128 */
	    dist = 128 - hops;
	else
	    dist = 64 - hops;
	
	printf("%sicast from %s, seq=%d dist=%d time=%ld.%03ld ms",
	       mc ? "mult" : "  un",
	       addr2string((struct sockaddr *) &from, fromlen),
	       recvdata.seq, dist,
	       diff.tv_sec * 1000 + diff.tv_usec / 1000, diff.tv_usec % 1000);

	rtt = (long)diff.tv_sec * 1000000 + (long)diff.tv_usec;

	if (dupcheck(mc, recvdata.seq)) {
	    printf(" (DUP!)\n");
	    continue;
	}

	printf("\n");
	
	if (s == us) {
	    if (uccount == 0) {
		ucsum = ucmin = ucmax = rtt;
		ucsqsum = (long long) rtt * rtt;
	    } else {
		if (rtt < ucmin)
		    ucmin = rtt;
		if (rtt > ucmax)
		    ucmax = rtt;
		ucsum += rtt;
		ucsqsum += (long long) rtt * rtt;
	    }
	    uccount++;
	} else {
	    if (mccount == 0) {
		mcminseq = recvdata.seq;
		mcsum = mcmin = mcmax = rtt;
		mcsqsum = (long long) rtt * rtt;
	    } else {
		if (recvdata.seq < mcminseq)
		    mcminseq = recvdata.seq;
		if (rtt < mcmin)
		    mcmin = rtt;
		if (rtt > mcmax)
		    mcmax = rtt;
		mcsum += rtt;
		mcsqsum += (long long) rtt * rtt;
	    }
	    mccount++;
	}
    }

    timediff(&diff, &jointime, &now);
    
    printf("\n");
    printf("--- %s statistics ---\n", source);
    printf("%d packets transmitted, time %ld ms\n", seq, diff.tv_sec * 1000 + diff.tv_usec / 1000);
    printf("unicast:\n");
    printf("   %d packets received, %d%% packet loss\n", uccount, 100 * (seq - uccount) / seq);
    if (uccount) {
	mean = ucsum / uccount;
	mdev = llsqrt(ucsqsum / uccount - mean * mean);
	printf("   rtt min/avg/max/std-dev = %ld.%03ld/%ld.%03ld/%ld.%03ld/%ld.%03ld ms\n",
	       ucmin / 1000, ucmin % 1000,
	       (unsigned long) mean / 1000, (long) mean % 1000,
	       ucmax / 1000, ucmax % 1000,
	       mdev / 1000, mdev % 1000);
    }

    printf("multicast:\n");
    if (!mccount) {
	printf("   0 packets received, 100%% packet loss\n");
	return 1;
    }

    printf("   %d packets received, %d%% packet loss since first mc packet (seq %d) recvd\n",
	   mccount,
	   100 * (seq - mcminseq + 1 - mccount) / (seq - mcminseq + 1),
	   mcminseq /*diff.tv_sec * 1000 + diff.tv_usec / 1000*/ );
    mean = mcsum / mccount;
    mdev = llsqrt(mcsqsum / mccount - mean * mean);
    printf("   rtt min/avg/max/std-dev = %ld.%03ld/%ld.%03ld/%ld.%03ld/%ld.%03ld ms\n",
	   mcmin / 1000, mcmin % 1000,
	   (unsigned long) mean / 1000, (long) mean % 1000,
	   mcmax / 1000, mcmax % 1000,
	   mdev / 1000, mdev % 1000);
    return 0;
}    
