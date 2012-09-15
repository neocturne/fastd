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

#include <alloca.h>
#include <linux/if_alg.h>
#include <unistd.h>


#ifndef SOL_ALG
#define SOL_ALG 279
#endif


void fastd_linux_alg_init(fastd_context *ctx) {
	ctx->algfd_ghash = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (ctx->algfd_ghash < 0)
		goto ghash_done;

	struct sockaddr_alg sa = {};
	sa.salg_family = AF_ALG;
	strcpy((char*)sa.salg_type, "hash");
	strcpy((char*)sa.salg_name, "ghash");
	if (bind(ctx->algfd_ghash, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		close(ctx->algfd_ghash);
		ctx->algfd_ghash = -1;
	}

 ghash_done:
	if (ctx->algfd_ghash < 0)
		pr_info(ctx, "no kernel support for GHASH was found, falling back to userspace implementation");

	ctx->algfd_aesctr = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (ctx->algfd_aesctr < 0)
		goto aesctr_done;

	strcpy((char*)sa.salg_type, "skcipher");
	strcpy((char*)sa.salg_name, "ctr(aes)");
	if (bind(ctx->algfd_aesctr, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
		close(ctx->algfd_aesctr);
		ctx->algfd_aesctr = -1;
	}

 aesctr_done:
	if (ctx->algfd_aesctr < 0)
		pr_info(ctx, "no kernel support for AES-CTR was found, falling back to userspace implementation");
}

void fastd_linux_alg_close(fastd_context *ctx) {
	if (ctx->algfd_ghash >= 0)
		close(ctx->algfd_ghash);

	if (ctx->algfd_aesctr >= 0)
		close(ctx->algfd_aesctr);
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

	if (write(fd, data, len) < 0) {
		pr_error_errno(ctx, "fastd_linux_alg_ghash: write");
		return false;
	}

	if (read(fd, out, 16) < 16) {
		pr_error_errno(ctx, "fastd_linux_alg_ghash: read");
		return false;
	}

	return true;
}

int fastd_linux_alg_aesctr_init(fastd_context *ctx, uint8_t *key, size_t keylen) {
	if (ctx->algfd_aesctr < 0)
		return -1;

	if (setsockopt(ctx->algfd_aesctr, SOL_ALG, ALG_SET_KEY, key, keylen) < 0) {
		pr_error_errno(ctx, "fastd_linux_alg_aesctr_init: setsockopt");
		return -1;
	}

	int ret = accept(ctx->algfd_aesctr, NULL, NULL);

	if (ret < 0) {
		pr_error_errno(ctx, "fastd_linux_alg_aesctr_init: accept");
		return -1;
	}

	return ret;
}

bool fastd_linux_alg_aesctr(fastd_context *ctx, int fd, void *out, const void *in, size_t len, const uint8_t iv[16]) {
	if (!len)
		return false;

	struct iovec vec = { .iov_base = (void*)in, .iov_len = len };

	static const size_t cmsglen = sizeof(struct cmsghdr)+sizeof(struct af_alg_iv)+16;
	struct cmsghdr *cmsg = alloca(cmsglen);
	cmsg->cmsg_len = cmsglen;
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_IV;

	struct af_alg_iv *alg_iv = (void*)CMSG_DATA(cmsg);
	alg_iv->ivlen = 16;
	memcpy(alg_iv->iv, iv, 16);

	struct msghdr msg = {
		.msg_iov = &vec,
		.msg_iovlen = 1,
		.msg_control = cmsg,
		.msg_controllen = cmsglen
	};

	if (sendmsg(fd, &msg, 0) < 0) {
		pr_error_errno(ctx, "fastd_linux_alg_aesctr: sendmsg");
		return false;
	}

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	vec.iov_base = out;

	if (recvmsg(fd, &msg, 0) < 0) {
		pr_error_errno(ctx, "fastd_linux_alg_aesctr: recvmsg");
		return false;
	}

	return true;
}
