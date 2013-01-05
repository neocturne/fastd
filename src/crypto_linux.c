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
#include "crypto.h"

#include <alloca.h>
#include <linux/if_alg.h>


#ifndef SOL_ALG
#define SOL_ALG 279
#endif


#ifdef USE_CRYPTO_AES128CTR
#ifdef WITH_CRYPTO_AES128CTR_LINUX

struct fastd_crypto_aes128ctr_context {
	int fd;
};

struct fastd_crypto_aes128ctr_state {
	int fd;
};

static fastd_crypto_aes128ctr_context_t* aes128ctr_init(fastd_context_t *ctx) {
	int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (fd < 0)
		goto error;

	struct sockaddr_alg sa = {};
	sa.salg_family = AF_ALG;
	strcpy((char*)sa.salg_type, "skcipher");
	strcpy((char*)sa.salg_name, "ctr(aes)");
	if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0)
		goto error;

	fastd_crypto_aes128ctr_context_t *cctx = malloc(sizeof(fastd_crypto_aes128ctr_context_t));
	cctx->fd = fd;
	return cctx;

 error:
	if (fd >= 0)
		close(fd);

	pr_error(ctx, "no kernel support for AES-CTR was found");
	return NULL;
}

static fastd_crypto_aes128ctr_state_t* aes128ctr_set_key(fastd_context_t *ctx, const fastd_crypto_aes128ctr_context_t *cctx, const fastd_block128_t *key) {
	if (setsockopt(cctx->fd, SOL_ALG, ALG_SET_KEY, key->b, 16) < 0) {
		pr_error_errno(ctx, "aes128ctr_set_key(linux): setsockopt");
		return NULL;
	}

	int fd = accept(cctx->fd, NULL, NULL);

	if (fd < 0) {
		pr_error_errno(ctx, "aes128ctr_set_key(linux): accept");
		return NULL;
	}

	fastd_crypto_aes128ctr_state_t *cstate = malloc(sizeof(fastd_crypto_aes128ctr_state_t));
	cstate->fd = fd;

	return cstate;
}

static bool aes128ctr_crypt(fastd_context_t *ctx, const fastd_crypto_aes128ctr_state_t *cstate, fastd_block128_t *out, const fastd_block128_t *in, size_t len, const fastd_block128_t *iv) {
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

	if (sendmsg(cstate->fd, &msg, 0) < 0) {
		pr_error_errno(ctx, "aes128ctr_crypt(linux): sendmsg");
		return false;
	}

	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	vec.iov_base = out;

	if (recvmsg(cstate->fd, &msg, 0) < 0) {
		pr_error_errno(ctx, "aes128ctr_crypt(linux): recvmsg");
		return false;
	}

	return true;
}

static void aes128ctr_free_state(fastd_context_t *ctx, fastd_crypto_aes128ctr_state_t *cstate) {
	if (cstate) {
		close(cstate->fd);
		free(cstate);
	}
}

static void aes128ctr_free(fastd_context_t *ctx, fastd_crypto_aes128ctr_context_t *cctx) {
	if (cctx) {
		close(cctx->fd);
		free(cctx);
	}
}

fastd_crypto_aes128ctr_t fastd_crypto_aes128ctr_linux = {
	.name = "linux",

	.init = aes128ctr_init,
	.set_key = aes128ctr_set_key,
	.crypt = aes128ctr_crypt,

	.free_state = aes128ctr_free_state,
	.free = aes128ctr_free,
};

#endif
#endif

#ifdef USE_CRYPTO_GHASH
#ifdef WITH_CRYPTO_GHASH_LINUX

struct fastd_crypto_ghash_context {
	int fd;
};

struct fastd_crypto_ghash_state {
	int fd;
};

static fastd_crypto_ghash_context_t* ghash_init(fastd_context_t *ctx) {
	int fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (fd < 0)
		goto error;

	struct sockaddr_alg sa = {};
	sa.salg_family = AF_ALG;
	strcpy((char*)sa.salg_type, "hash");
	strcpy((char*)sa.salg_name, "ghash");
	if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0)
		goto error;

	fastd_crypto_ghash_context_t *cctx = malloc(sizeof(fastd_crypto_ghash_context_t));
	cctx->fd = fd;
	return cctx;

 error:
	if (fd >= 0)
		close(fd);

	pr_error(ctx, "no kernel support for GHASH was found");
	return NULL;
}

static fastd_crypto_ghash_state_t* ghash_set_h(fastd_context_t *ctx, const fastd_crypto_ghash_context_t *cctx, const fastd_block128_t *h) {
	if (setsockopt(cctx->fd, SOL_ALG, ALG_SET_KEY, h, 16) < 0) {
		pr_error_errno(ctx, "ghash_set_h(linux): setsockopt");
		return NULL;
	}

	int fd = accept(cctx->fd, NULL, NULL);

	if (fd < 0) {
		pr_error_errno(ctx, "ghash_set_h(linux): accept");
		return NULL;
	}

	fastd_crypto_ghash_state_t *cstate = malloc(sizeof(fastd_crypto_ghash_state_t));
	cstate->fd = fd;

	return cstate;
}

static bool ghash_hash(fastd_context_t *ctx, const fastd_crypto_ghash_state_t *cstate, fastd_block128_t *out, const fastd_block128_t *in, size_t n_blocks) {
	if (!n_blocks)
		return false;

	if (write(cstate->fd, in, n_blocks*16) < 0) {
		pr_error_errno(ctx, "ghash_hash(linux): write");
		return false;
	}

	if (read(cstate->fd, out, 16) < 16) {
		pr_error_errno(ctx, "ghash_hash(linux): read");
		return false;
	}

	return true;
}

static void ghash_free_state(fastd_context_t *ctx, fastd_crypto_ghash_state_t *cstate) {
	if (cstate) {
		close(cstate->fd);
		free(cstate);
	}
}

static void ghash_free(fastd_context_t *ctx, fastd_crypto_ghash_context_t *cctx) {
	if (cctx) {
		close(cctx->fd);
		free(cctx);
	}
}

fastd_crypto_ghash_t fastd_crypto_ghash_linux = {
	.name = "linux",

	.init = ghash_init,
	.set_h = ghash_set_h,
	.hash = ghash_hash,

	.free_state = ghash_free_state,
	.free = ghash_free,
};

#endif
#endif
