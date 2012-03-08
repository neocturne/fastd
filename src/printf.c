/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
  Partly based on QuickTun Copyright (c) 2010, Ivo Smits <Ivo@UCIS.nl>.
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

#include <arpa/inet.h>


#pragma GCC diagnostic ignored "-Wformat-security"

void fastd_printf(const fastd_context *ctx, const char *format, ...) {
	va_list ap;
	va_start(ap, format);

	char *format_dup = strdup(format);
	char *str;
	for (str = format_dup; *str; str++) {
		if (*str != '%') {
			fputc(*str, stderr);
			continue;
		}

		int len, flag_l = 0, flag_L = 0, flag_j = 0, flag_z = 0, flag_t = 0;

		for(len = 1; str[len]; len++) {
			char last;
			bool finished = true;
			char addr_buf[INET6_ADDRSTRLEN];
			void *p;
			fastd_eth_addr *eth_addr;

			switch (str[len]) {
			case 'l':
				flag_l++;
				finished = false;
				break;

			case 'L':
				flag_L++;
				finished = false;
				break;

			case 'j':
				flag_j++;
				finished = false;
				break;

			case 'z':
				flag_z++;
				finished = false;
				break;

			case 't':
				flag_t++;
				finished = false;
				break;

			case '%':
				fputc('%', stderr);
				break;

			case 'd':
			case 'i':
			case 'o':
			case 'u':
			case 'x':
			case 'X':
				last = str[len+1];
				str[len+1] = 0;

				if (flag_j)
					fprintf(stderr, str, va_arg(ap, intmax_t));
				else if (flag_z)
					fprintf(stderr, str, va_arg(ap, size_t));
				else if (flag_t)
					fprintf(stderr, str, va_arg(ap, ptrdiff_t));
				else if (flag_l == 0)
					fprintf(stderr, str, va_arg(ap, int));
				else if (flag_l == 1)
					fprintf(stderr, str, va_arg(ap, long));
				else
					fprintf(stderr, str, va_arg(ap, long long));

				str[len+1] = last;
				break;

			case 'e':
			case 'f':
			case 'F':
			case 'g':
			case 'G':
			case 'a':
			case 'A':
				last = str[len+1];
				str[len+1] = 0;

				if (flag_L)
					fprintf(stderr, str, va_arg(ap, long double));
				else
					fprintf(stderr, str, va_arg(ap, double));

				str[len+1] = last;
				break;

			case 'c':
				last = str[len+1];
				str[len+1] = 0;

				fprintf(stderr, str, va_arg(ap, int));

				str[len+1] = last;
				break;

			case 's':
			case 'p':
				last = str[len+1];
				str[len+1] = 0;

				fprintf(stderr, str, va_arg(ap, void*));

				str[len+1] = last;
				break;

			case 'm':
				last = str[len+1];
				str[len+1] = 0;

				fprintf(stderr, str);

				str[len+1] = last;
				break;

			case 'I':
				p = va_arg(ap, void*);

				if (p) {
					if (inet_ntop(flag_l ? AF_INET6 : AF_INET, p, addr_buf, sizeof(addr_buf)))
						fprintf(stderr, "%s", addr_buf);
				}
				else {
					fprintf(stderr, "(null)");
				}
				break;

			case 'E':
				eth_addr = va_arg(ap, fastd_eth_addr*);

				if (eth_addr) {
					fprintf(stderr, "%02x:%02x:%02x:%02x:%02x:%02x",
						eth_addr->data[0], eth_addr->data[1], eth_addr->data[2],
						eth_addr->data[3], eth_addr->data[4], eth_addr->data[5]);
				}
				else {
					fprintf(stderr, "(null)");
				}
				break;

			case 'P':
				p = va_arg(ap, void*);

				if (p) {
					char* str = ctx->conf->method->peer_str(ctx, (fastd_peer*)p);
					fprintf(stderr, "%s", str);
					free(str);
				}
				else {
					fprintf(stderr, "(null)");
				}
				break;

			default:
				finished = false;
			}

			if (finished) {
				str += len;
				break;
			}
		}
	}

	free(format_dup);

	va_end(ap);
}
