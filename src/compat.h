/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/**
   \file

   Portablity definitions
*/


#pragma once

#include <fastd_config.h>

#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#ifndef ETH_ALEN
/** The length of a MAC address */
#define ETH_ALEN 6
#endif

#ifndef ETH_HLEN
/** The length of the standard ethernet header */
#define ETH_HLEN 14
#endif

#ifndef HAVE_ETHHDR
/** An ethernet header */
struct ethhdr {
	uint8_t h_dest[ETH_ALEN];			/**< The destination MAC address field */
	uint8_t h_source[ETH_ALEN];			/**< The source MAC address field */
	uint16_t h_proto;				/**< The EtherType/length field */
} __attribute__((packed));
#endif

#if defined(USE_FREEBIND) && !defined(IP_FREEBIND)
/** Compatiblity define for systems supporting, but not defining IP_FREEBIND */
#define IP_FREEBIND 15
#endif


#ifndef SOCK_NONBLOCK
/** Defined if SOCK_NONBLOCK doesn't have an effect */
#define NO_HAVE_SOCK_NONBLOCK

/** Compatiblity define for systems not supporting SOCK_NONBLOCK */
#define SOCK_NONBLOCK 0
#endif


/** The type of the third parameter of getgrouplist */
#ifdef __APPLE__
#define GROUPLIST_TYPE int
#else
#define GROUPLIST_TYPE gid_t
#endif


#ifndef HAVE_GET_CURRENT_DIR_NAME

/** Replacement function for *BSD systems not supporting get_current_dir_name() */
static inline char *get_current_dir_name(void) {

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__APPLE__) || defined(__ANDROID__)

	return getcwd(NULL, 0);

#else

#error unknown system, get_current_dir_name() not implemented

#endif

}

#endif


#ifdef __APPLE__

#include <mach/mach_time.h>

#define CLOCK_MONOTONIC 0
#define clockid_t int

static inline int clock_gettime(clockid_t clk_id __attribute__((unused)), struct timespec *tp) {
	static mach_timebase_info_data_t timebase_info = {};

	if (!timebase_info.denom)
		mach_timebase_info(&timebase_info);

	uint64_t time = (((long double)mach_absolute_time())*timebase_info.numer) / timebase_info.denom;

	tp->tv_sec = time / 1000000000;
	tp->tv_nsec = time % 1000000000;

	return 0;
}


#endif
