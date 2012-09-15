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


#include "linux_alg.h"

#include <linux/if_alg.h>
#include <unistd.h>


#ifndef SOL_ALG
#define SOL_ALG 279
#endif


void fastd_linux_alg_init(fastd_context *ctx) {
	ctx->algfd_ghash = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (ctx->algfd_ghash < 0)
		goto error_ghash;

	struct sockaddr_alg sa_ghash = {};
	sa_ghash.salg_family = AF_ALG;
	strcpy((char*)sa_ghash.salg_type, "hash");
	strcpy((char*)sa_ghash.salg_name, "ghash");
	if (bind(ctx->algfd_ghash, (struct sockaddr*)&sa_ghash, sizeof(sa_ghash)) < 0) {
		close(ctx->algfd_ghash);
		goto error_ghash;
	}

	return;

 error_ghash:
	pr_info(ctx, "no kernel support for GHASH was found, falling back to userspace implementation");
	ctx->algfd_ghash = -1;
}

void fastd_linux_alg_close(fastd_context *ctx) {
	if (ctx->algfd_ghash >= 0)
		close(ctx->algfd_ghash);
}


int fastd_linux_alg_ghash_init(fastd_context *ctx, uint8_t key[16]) {
	if (ctx->algfd_ghash < 0)
		return -1;

	if (setsockopt(ctx->algfd_ghash, SOL_ALG, ALG_SET_KEY, key, 16) < 0) {
		pr_error_errno(ctx, "fastd_linux_alg_ghash_init: setsockopt");
		return -1;
	}

	int ret = accept(ctx->algfd_ghash, NULL, NULL);

	if (ret < 0) {
		pr_error_errno(ctx, "fastd_linux_alg_ghash_init: accept");
		return -1;
	}

	return ret;
}

bool fastd_linux_alg_ghash(fastd_context *ctx, int fd, uint8_t out[16], const void *data, size_t len) {
	if (!len)
		return false;

	const uint8_t *in = data;
	const uint8_t *end = in+len;

	while (in < end) {
		int bytes = write(fd, in, end-in);
		if (bytes < 0) {
			pr_error_errno(ctx, "fastd_linux_alg_ghash: write");
			return false;
		}

		in += bytes;
	}

	end = out+16;

	while (out < end) {
		int bytes = read(fd, out, end-out);
		if (bytes < 0) {
			pr_error_errno(ctx, "fastd_linux_alg_ghash: read");
			return false;
		}

		out += bytes;
	}

	return true;
}
