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


#define _GNU_SOURCE

#include "fastd.h"
#include "task.h"
#include "peer.h"
#include "handshake.h"

#include <arpa/inet.h>


static void protocol_init(fastd_context *ctx, fastd_config *conf) {
	if (conf->n_floating > 1)
		exit_error(ctx, "with protocol `null' use can't define more than one floating peer");
}

static size_t protocol_max_packet_size(fastd_context *ctx) {
	return fastd_max_packet_size(ctx);
}

static size_t protocol_min_head_space(fastd_context *ctx) {
	return 0;
}

static void protocol_handshake_init(fastd_context *ctx, fastd_peer *peer) {
	fastd_buffer buffer = fastd_handshake_new_init(ctx, peer, 0);
	fastd_task_put_send_handshake(ctx, peer, buffer);
}

static void establish(fastd_context *ctx, fastd_peer *peer) {
	fastd_peer_seen(ctx, peer);

	if (fastd_peer_is_temporary(peer)) {
		fastd_peer *perm_peer;
		for (perm_peer = ctx->peers; perm_peer; perm_peer = perm_peer->next) {
			if (fastd_peer_is_floating(perm_peer))
				break;
		}

		if (!perm_peer) {
			return;
		}

		fastd_peer_set_established_merge(ctx, perm_peer, peer);
	}
	else {
		fastd_peer_set_established(ctx, peer);
	}
}

static void protocol_handshake_handle(fastd_context *ctx, fastd_peer *peer, const fastd_handshake *handshake) {
	fastd_buffer buffer;

	switch(handshake->type) {
	case 1:
		buffer = fastd_handshake_new_reply(ctx, peer, handshake, 0);
		fastd_task_put_send_handshake(ctx, peer, buffer);
		break;

	case 2:
		establish(ctx, peer);
		buffer = fastd_handshake_new_reply(ctx, peer, handshake, 0);
		fastd_task_put_send_handshake(ctx, peer, buffer);
		break;

	case 3:
		establish(ctx, peer);
		break;

	default:
		pr_debug(ctx, "received handshake reply with unknown type %u", handshake->type);
	}

}

static void protocol_handle_recv(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (fastd_peer_is_established(peer) && buffer.len) {
		/* this could be optimized a bit */
		fastd_peer_clean_handshakes(ctx, peer);

		fastd_peer_seen(ctx, peer);
		fastd_task_put_handle_recv(ctx, peer, buffer);
	}
	else {
		fastd_buffer_free(buffer);
	}
}

static void protocol_send(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_task_put_send(ctx, peer, buffer);
}

static void protocol_free_peer_state(fastd_context *ctx, fastd_peer *peer) {
}

static void protocol_generate_key(fastd_context *ctx) {
	exit_error(ctx, "trying to generate key for `null' protocol");
}

const fastd_protocol fastd_protocol_null = {
	.name = "null",

	.init = protocol_init,

	.max_packet_size = protocol_max_packet_size,
	.min_encrypt_head_space = protocol_min_head_space,
	.min_decrypt_head_space = protocol_min_head_space,

	.handshake_init = protocol_handshake_init,
	.handshake_handle = protocol_handshake_handle,

	.handle_recv = protocol_handle_recv,
	.send = protocol_send,

	.free_peer_state = protocol_free_peer_state,

	.generate_key = protocol_generate_key,
};
