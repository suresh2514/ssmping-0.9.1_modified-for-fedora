/*
 * Copyright (C) 2005  Stig Venaas <venaas@uninett.no>
 * $Id: ssmping.h,v 1.3 2005/10/18 14:50:31 sv Exp $
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 */

#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#ifdef WIN32
#include <windows.h>
#include <ws2tcpip.h>
#include <winsock.h>
#include <winsock2.h>
#else
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netdb.h>
#endif

/* Needed for Solaris 9 */
#ifndef CMSG_LEN
#define CMSG_LEN(len) (_CMSG_DATA_ALIGN (sizeof (struct cmsghdr)) + (len))
#endif

#ifndef IPV6_V6ONLY
#ifdef linux
#define IPV6_V6ONLY 26
#endif
#endif

#define SSMMODE 1
#define ASMMODE 2
#define FIRSTMODE 3

#define SSMPING_VERSIONSTRING "0.9.1 (20080418)"
#define SSMPING_SERVERVERSIONSTRING "0.9.1 (20080418) [asm][size]"
#define SSMPING_REQUEST 'Q'
#define SSMPING_REPLY 'A'

#define SSMPING_PID 1
#define SSMPING_SEQ 2
#define SSMPING_TIMESTAMP 3
#define SSMPING_GROUP 4
#define SSMPING_RQVER 5
#define SSMPING_VER 6
#define SSMPING_REPLYSIZE 7
#define SSMPING_PAD 8

#define SOCKADDR_SIZE(addr) (addr.ss_family == AF_INET ? \
                            sizeof(struct sockaddr_in) : \
                            sizeof(struct sockaddr_in6))

struct ssmpingdata {
    uint32_t pid;
    uint32_t seq;
    struct timeval timestamp;
};

void errx(char *, ...);
void err(char *, ...);

void gettime(struct timeval *);
void timediff(struct timeval *, struct timeval *, struct timeval *);
int timecmp(struct timeval *, struct timeval *);
     
void setport(struct sockaddr *, int);
void setaddr(struct sockaddr_storage *, struct sockaddr_storage *, const char *, const char *);
char *addr2string(struct sockaddr *, socklen_t);

size_t tlvspace(size_t);
char *tlvadd(char *, uint16_t, uint16_t, void *);
char *tlvaddzero(char *, uint16_t, uint16_t);

void parseargs(int, char **, int, int *, int *, uint16_t *, uint32_t *, int *, char **, char **, uint16_t *, uint16_t *, char **);

int doit(int, int, int, int, int, struct sockaddr_storage *, struct sockaddr_storage *, char *);

int names2addrsocks(int *, int *, const char *, const char *, const char *, int *, struct sockaddr_storage *, struct sockaddr_storage *);

void prep_sock(int, int);

void findsrc(struct sockaddr *, struct sockaddr *);

int recvfromhopstime(int, void *, size_t, int, struct sockaddr *, socklen_t *, int32_t *, struct timeval *, char *);     
char *addr2string(struct sockaddr *, socklen_t);

void joinchannel(int, struct sockaddr *, struct sockaddr *, uint32_t, struct sockaddr *);
void joingroup(int, struct sockaddr *, uint32_t, struct sockaddr *);
