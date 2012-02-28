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


#include "handshake.h"
#include "packet.h"
#include "task.h"

#include <string.h>


void fastd_handshake_send(fastd_context *ctx, fastd_peer *peer) {
	size_t method_len = strlen(ctx->conf->method->name);
	size_t len = sizeof(fastd_packet_request)+method_len;
	fastd_buffer buffer = fastd_buffer_alloc(len, 0);
	fastd_packet_request *request = buffer.base;

	request->reply = 0;
	request->cp = 0;
	request->req_id = ++peer->last_req_id;
	request->rsv = 0;
	request->flags = 0;
	request->proto = ctx->conf->protocol;
	request->method_len = method_len;
	strncpy(request->method_name, ctx->conf->method->name, method_len);

	fastd_task_put_send_handshake(ctx, peer, buffer);
}

void fastd_handshake_handle(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	if (buffer.len < sizeof(fastd_packet_any))
		goto end_free;

	fastd_packet *packet = buffer.base;

	if (!packet->any.reply && !packet->any.cp) {
		if (buffer.len < sizeof(fastd_packet_request))
			goto end_free;

		if (buffer.len < sizeof(fastd_packet_request) + packet->request.method_len)
			goto end_free;

		if (packet->request.flags)
			goto end_free; // TODO

		if (packet->request.proto != ctx->conf->protocol)
			goto end_free; // TODO

		if (packet->request.method_len != strlen(ctx->conf->method->name) ||
		    strncmp(packet->request.method_name, ctx->conf->method->name, packet->request.method_len))
			goto end_free; // TODO

		fastd_buffer reply_buffer = fastd_buffer_alloc(sizeof(fastd_packet_reply), 0);
		fastd_packet_reply *reply = reply_buffer.base;

		reply->reply = 1;
		reply->cp = 0;
		reply->req_id = packet->request.req_id;
		reply->rsv = 0;
		reply->reply_code = REPLY_SUCCESS;

		fastd_task_put_send_handshake(ctx, peer, reply_buffer);
	}
	else if (packet->any.reply) {
		if (buffer.len < sizeof(fastd_packet_reply))
			goto end_free;

		if (!packet->reply.cp) {
			if (packet->reply.req_id != peer->last_req_id)
				goto end_free;
		}
		else {
			goto end_free; // TODO
		}

		switch (packet->reply.reply_code) {
		case REPLY_SUCCESS:
			pr_info(ctx, "Handshake successful.");
			pr_info(ctx, "Connection established.");
			peer->state = STATE_ESTABLISHED;
			ctx->conf->method->method_init(ctx, peer);
			break;

		default:
			pr_warn(ctx, "Handshake failed with code %i.", packet->reply.reply_code);
		}
	}

 end_free:
	fastd_buffer_free(buffer);
}
