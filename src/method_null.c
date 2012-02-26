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
#include "task.h"


static size_t null_max_packet_size(fastd_context *ctx) {
	return fastd_max_packet_size(ctx);
}

static void null_init(fastd_context *ctx, const fastd_peer *peer) {
	struct iovec buffer = { .iov_base = NULL, .iov_len = 0 };
	fastd_task_put_send(ctx, peer, buffer);
}

static void null_handle_recv(fastd_context *ctx, const fastd_peer *peer, struct iovec buffer) {
	fastd_task_put_handle_recv(ctx, peer, buffer);
}

static void null_send(fastd_context *ctx, const fastd_peer *peer, struct iovec buffer) {
	fastd_task_put_send(ctx, peer, buffer);
}


const fastd_method fastd_method_null = {
	.name = "null",
	.method_max_packet_size = null_max_packet_size,
	.method_init = null_init,
	.method_handle_recv = null_handle_recv,
	.method_send = null_send,
};
