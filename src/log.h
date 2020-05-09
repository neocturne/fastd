// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Logging functions and macros
*/


#pragma once

#include "types.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>


/** A log level specification */
typedef enum fastd_loglevel {
	LL_UNSPEC = 0,           /**< Nothing is logged */
	LL_FATAL,                /**< Only fatal errors are logged */
	LL_ERROR,                /**< Only errors are logged */
	LL_WARN,                 /**< Only warning and errors are logged */
	LL_INFO,                 /**< General informational messages are logged */
	LL_VERBOSE,              /**< More verbose logging */
	LL_DEBUG,                /**< Debug messages are logged, excluding messages potentially occuring very often */
	LL_DEBUG2,               /**< All debug messages a logged */
	LL_DEFAULT = LL_VERBOSE, /**< The default log level */
} fastd_loglevel_t;


size_t fastd_snprint_peer_address(
	char *buffer, size_t size, const fastd_peer_address_t *address, const char *iface, bool bind_address,
	bool hide);


void fastd_logf(const fastd_loglevel_t level, const char *format, ...);

/** Logs a formatted fatal error message */
#define pr_fatal(args...) fastd_logf(LL_FATAL, args)
/** Logs a formatted error message */
#define pr_error(args...) fastd_logf(LL_ERROR, args)
/** Logs a formatted warning message */
#define pr_warn(args...) fastd_logf(LL_WARN, args)
/** Logs a formatted informational message */
#define pr_info(args...) fastd_logf(LL_INFO, args)
/** Logs a formatted verbose message */
#define pr_verbose(args...) fastd_logf(LL_VERBOSE, args)
/** Logs a formatted debug message */
#define pr_debug(args...) fastd_logf(LL_DEBUG, args)
/** Logs a formatted debug2 message */
#define pr_debug2(args...) fastd_logf(LL_DEBUG2, args)

/** Logs a simple error message adding the error found in \e errno */
#define pr_error_errno(message) pr_error("%s: %s", message, strerror(errno))
/** Logs a simple warning message adding the error found in \e errno */
#define pr_warn_errno(message) pr_warn("%s: %s", message, strerror(errno))
/** Logs a simple debug message adding the error found in \e errno */
#define pr_debug_errno(message) pr_debug("%s: %s", message, strerror(errno))
/** Logs a simple debug2 message adding the error found in \e errno */
#define pr_debug2_errno(message) pr_debug2("%s: %s", message, strerror(errno))

/** Logs a formatted fatal error message and aborts the program */
#define exit_fatal(args...)     \
	do {                    \
		pr_fatal(args); \
		abort();        \
	} while (0)
/** Logs a simple fatal error message after a bug was found and aborts the program */
#define exit_bug(message) exit_fatal("BUG: %s", message)
/** Logs a formatted error message and exits with an error status */
#define exit_error(args...)     \
	do {                    \
		pr_error(args); \
		exit(1);        \
	} while (0)
/** Logs a simple error message adding the error found in \e errno and exits with an error status */
#define exit_errno(message) exit_error("%s: %s", message, strerror(errno))
