// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Portablity definitions
*/


#pragma once

#include <generated/build.h>

#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include <sys/types.h>

#include <sys/socket.h>

#include <netinet/in.h>


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

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || \
	defined(__APPLE__) || defined(__ANDROID__)

	return getcwd(NULL, 0);

#else

#error unknown system, get_current_dir_name() not implemented

#endif
}

#endif
