/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
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

#include <arpa/inet.h>


static inline int snprintf_safe(char *buffer, size_t size, const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	int ret = vsnprintf(buffer, size, format, ap);
	va_end(ap);

	return ret < 0 ? 0 : ret > size ? size : ret;
}

static int snprint_peer_address(const fastd_context *ctx, char *buffer, size_t size, const fastd_peer_address *address) {
	char addr_buf[INET6_ADDRSTRLEN] = "";

	switch (address->sa.sa_family) {
	case AF_UNSPEC:
		return snprintf(buffer, size, "floating");

	case AF_INET:
		if (inet_ntop(AF_INET, &address->in.sin_addr, addr_buf, sizeof(addr_buf)))
			return snprintf_safe(buffer, size, "%s:%u", addr_buf, ntohs(address->in.sin_port));
		else
			return 0;

	case AF_INET6:
		if (inet_ntop(AF_INET6, &address->in6.sin6_addr, addr_buf, sizeof(addr_buf)))
			return snprintf_safe(buffer, size, "[%s]:%u", addr_buf, ntohs(address->in6.sin6_port));
		else
			return 0;

	default:
		exit_bug(ctx, "unsupported address family");
	}
}

static int snprint_peer_str(const fastd_context *ctx, char *buffer, size_t size, const fastd_peer *peer) {
	if (peer->config && peer->config->name)
		return snprintf_safe(buffer, size, "<%s>", peer->config->name);
	else
		return snprintf_safe(buffer, size, "<(null)>");
}

int fastd_vsnprintf(const fastd_context *ctx, char *buffer, size_t size, const char *format, va_list ap) {
	char *buffer_start = buffer;
	char *buffer_end = buffer+size;

	*buffer = 0;

	for (; *format; format++) {
		const void *p;
		const fastd_eth_addr *eth_addr;

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

		case 's':
			buffer += snprintf_safe(buffer, buffer_end-buffer, "%s", va_arg(ap, char*));
			break;

		case 'p':
			buffer += snprintf_safe(buffer, buffer_end-buffer, "%p", va_arg(ap, void*));
			break;

		case 'E':
			eth_addr = va_arg(ap, const fastd_eth_addr*);

			if (eth_addr) {
				buffer += snprintf_safe(buffer, buffer_end-buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
							eth_addr->data[0], eth_addr->data[1], eth_addr->data[2],
							eth_addr->data[3], eth_addr->data[4], eth_addr->data[5]);
			}
			else {
				buffer += snprintf_safe(buffer, buffer_end-buffer, "(null)");
			}
			break;

		case 'P':
			p = va_arg(ap, const fastd_peer*);

			if (p)
				buffer += snprint_peer_str(ctx, buffer, buffer_end-buffer, (const fastd_peer*)p);
			else
				buffer += snprintf_safe(buffer, buffer_end-buffer, "(null)");
			break;

		case 'I':
			p = va_arg(ap, const fastd_peer_address*);

			if (p)
				buffer += snprint_peer_address(ctx, buffer, buffer_end-buffer, (const fastd_peer_address*)p);
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

static inline const char* get_log_prefix(int log_level) {
	switch(log_level) {
	case LOG_CRIT:
		return "Fatal: ";
	case LOG_ERR:
		return "Error: ";
	case LOG_WARNING:
		return "Warning: ";
	case LOG_NOTICE:
		return "Info: ";
	case LOG_INFO:
		return "Verbose: ";
	case LOG_DEBUG:
		return "DEBUG: ";
	default:
		return "";
	}
}

void fastd_logf(const fastd_context *ctx, int level, const char *format, ...) {
	char buffer[1024];
	char timestr[100] = "";
	va_list ap;

	va_start(ap, format);
	fastd_vsnprintf(ctx, buffer, sizeof(buffer), format, ap);
	va_end(ap);

	buffer[sizeof(buffer)-1] = 0;

	if (ctx->conf == NULL || level <= ctx->conf->log_stderr_level || ctx->conf->log_files) {
		time_t t;
		struct tm tm;

		t = time(NULL);
		if (localtime_r(&t, &tm) != NULL) {
			if (strftime(timestr, sizeof(timestr), "%F %T %z --- ", &tm) <= 0)
				*timestr = 0;
		}
	}

	if (ctx->conf == NULL || level <= ctx->conf->log_stderr_level)
		fprintf(stderr, "%s%s%s\n", timestr, get_log_prefix(level), buffer);

	if (ctx->conf != NULL && level <= ctx->conf->log_syslog_level)
		syslog(level, "%s", buffer);

	fastd_log_fd *file;
	for (file = ctx->log_files; file; file = file->next) {
		if (level <= file->config->level)
			dprintf(file->fd, "%s%s%s\n", timestr, get_log_prefix(level), buffer);
	}
}
