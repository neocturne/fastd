/*
  Copyright (c) 2012-2013, Matthias Schiffer <mschiffer@universe-factory.net>
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


#include "fastd.h"
#include "peer.h"

#include <syslog.h>
#include <arpa/inet.h>
#include <net/if.h>


static inline size_t snprintf_safe(char *buffer, size_t size, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	int ret = vsnprintf(buffer, size, format, ap);
	va_end(ap);

	if (ret < 0)
		return 0;

	return min_size_t(ret, size);
}

static size_t snprint_peer_address(const fastd_context_t *ctx, char *buffer, size_t size, const fastd_peer_address_t *address, bool bind_address) {
	char addr_buf[INET6_ADDRSTRLEN] = "";

	switch (address->sa.sa_family) {
	case AF_UNSPEC:
		if (bind_address)
			return snprintf_safe(buffer, size, "any:%u", ntohs(address->in.sin_port));
		else
			return snprintf(buffer, size, "any");

	case AF_INET:
		if (!bind_address && ctx->conf->hide_ip_addresses)
			return snprintf_safe(buffer, size, "[hidden]:%u", ntohs(address->in.sin_port));
		else if (inet_ntop(AF_INET, &address->in.sin_addr, addr_buf, sizeof(addr_buf)))
			return snprintf_safe(buffer, size, "%s:%u", addr_buf, ntohs(address->in.sin_port));
		else
			return 0;

	case AF_INET6:
		if (!bind_address && ctx->conf->hide_ip_addresses)
			return snprintf_safe(buffer, size, "[hidden]:%u", ntohs(address->in.sin_port));
		if (inet_ntop(AF_INET6, &address->in6.sin6_addr, addr_buf, sizeof(addr_buf))) {
			if (IN6_IS_ADDR_LINKLOCAL(&address->in6.sin6_addr)) {
				char ifname_buf[IF_NAMESIZE];
				if (if_indextoname(address->in6.sin6_scope_id, ifname_buf))
					return snprintf_safe(buffer, size, "[%s%%%s]:%u", addr_buf, if_indextoname(address->in6.sin6_scope_id, ifname_buf), ntohs(address->in6.sin6_port));
			}

			return snprintf_safe(buffer, size, "[%s]:%u", addr_buf, ntohs(address->in6.sin6_port));
		}
		else
			return 0;

	default:
		exit_bug(ctx, "unsupported address family");
	}
}

static size_t snprint_peer_str(const fastd_context_t *ctx, char *buffer, size_t size, const fastd_peer_t *peer) {
	if (peer->config && peer->config->name) {
		return snprintf_safe(buffer, size, "<%s>", peer->config->name);
	}
	else {
		char buf[65];
		if (ctx->conf->protocol->describe_peer(ctx, peer, buf, sizeof(buf)))
			return snprintf_safe(buffer, size, "{%s}", buf);
		else
			return snprintf_safe(buffer, size, "(null)");
	}
}

static int fastd_vsnprintf(const fastd_context_t *ctx, char *buffer, size_t size, const char *format, va_list ap) {
	char *buffer_start = buffer;
	char *buffer_end = buffer+size;

	*buffer = 0;

	for (; *format; format++) {
		const void *p;
		const fastd_eth_addr_t *eth_addr;

		if (buffer >= buffer_end)
			break;

		if (*format != '%') {
			*buffer = *format;
			buffer++;
			continue;
		}

		format++;

		switch(*format) {
		case 'i':
			buffer += snprintf_safe(buffer, buffer_end-buffer, "%i", va_arg(ap, int));
			break;

		case 'u':
			buffer += snprintf_safe(buffer, buffer_end-buffer, "%u", va_arg(ap, unsigned int));
			break;

		case 'U':
			buffer += snprintf_safe(buffer, buffer_end-buffer, "%llu", (unsigned long long)va_arg(ap, uint64_t));
			break;

		case 's':
			buffer += snprintf_safe(buffer, buffer_end-buffer, "%s", va_arg(ap, char*));
			break;

		case 'p':
			buffer += snprintf_safe(buffer, buffer_end-buffer, "%p", va_arg(ap, void*));
			break;

		case 'E':
			eth_addr = va_arg(ap, const fastd_eth_addr_t*);

			if (eth_addr) {
				if (ctx->conf->hide_mac_addresses)
					buffer += snprintf_safe(buffer, buffer_end-buffer, "[hidden]");
				else
					buffer += snprintf_safe(buffer, buffer_end-buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
								eth_addr->data[0], eth_addr->data[1], eth_addr->data[2],
								eth_addr->data[3], eth_addr->data[4], eth_addr->data[5]);
			}
			else {
				buffer += snprintf_safe(buffer, buffer_end-buffer, "(null)");
			}
			break;

		case 'P':
			p = va_arg(ap, const fastd_peer_t*);

			if (p)
				buffer += snprint_peer_str(ctx, buffer, buffer_end-buffer, (const fastd_peer_t*)p);
			else
				buffer += snprintf_safe(buffer, buffer_end-buffer, "(null)");
			break;

		case 'I':
		case 'B':
			p = va_arg(ap, const fastd_peer_address_t*);

			if (p)
				buffer += snprint_peer_address(ctx, buffer, buffer_end-buffer, (const fastd_peer_address_t*)p, *format == 'B');
			else
				buffer += snprintf_safe(buffer, buffer_end-buffer, "(null)");
			break;

		default:
			pr_warn(ctx, "fastd_vsnprintf: unknown format conversion specifier '%c'", *format);
			*buffer_start = 0;
			return -1;
		}
	}

	if (buffer < buffer_end)
		*buffer = 0;

	return buffer-buffer_start;
}

static inline const char* get_log_prefix(fastd_loglevel_t log_level) {
	switch(log_level) {
	case LL_FATAL:
		return "Fatal: ";
	case LL_ERROR:
		return "Error: ";
	case LL_WARN:
		return "Warning: ";
	case LL_INFO:
		return "Info: ";
	case LL_VERBOSE:
		return "Verbose: ";
	case LL_DEBUG:
		return "DEBUG: ";
	case LL_DEBUG2:
		return "DEBUG2: ";
	default:
		return "";
	}
}

static inline int get_syslog_level(fastd_loglevel_t log_level) {
	switch(log_level) {
	case LL_FATAL:
		return LOG_CRIT;
	case LL_ERROR:
		return LOG_ERR;
	case LL_WARN:
		return LOG_WARNING;
	case LL_INFO:
		return LOG_NOTICE;
	case LL_VERBOSE:
		return LOG_INFO;
	default:
		return LOG_DEBUG;
	}
}

void fastd_logf(const fastd_context_t *ctx, fastd_loglevel_t level, const char *format, ...) {
	char buffer[1024];
	char timestr[100] = "";
	va_list ap;

	va_start(ap, format);
	fastd_vsnprintf(ctx, buffer, sizeof(buffer), format, ap);
	va_end(ap);

	buffer[sizeof(buffer)-1] = 0;

	if (!ctx->log_initialized || level <= ctx->conf->log_stderr_level || ctx->conf->log_files) {
		time_t t;
		struct tm tm;

		t = time(NULL);
		if (localtime_r(&t, &tm) != NULL) {
			if (strftime(timestr, sizeof(timestr), "%F %T %z --- ", &tm) <= 0)
				*timestr = 0;
		}
	}

	if (!ctx->log_initialized || level <= ctx->conf->log_stderr_level)
		fprintf(stderr, "%s%s%s\n", timestr, get_log_prefix(level), buffer);

	if (ctx->log_initialized) {
		if (level <= ctx->conf->log_syslog_level)
			syslog(get_syslog_level(level), "%s", buffer);

		fastd_log_fd_t *file;
		for (file = ctx->log_files; file; file = file->next) {
			if (level <= file->config->level)
				dprintf(file->fd, "%s%s%s\n", timestr, get_log_prefix(level), buffer);
		}
	}
}
