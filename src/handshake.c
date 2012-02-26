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


void fastd_handshake_send(fastd_context *ctx, const fastd_peer *peer) {
	size_t method_len = strlen(ctx->conf->method->name);
	size_t len = sizeof(fastd_packet_request)+method_len;
	fastd_packet_request *request = malloc(len);

	request->reply = 0;
	request->cp = 0;
	request->req_id = 0;
	request->rsv = 0;
	request->flags = 0;
	request->proto = ctx->conf->protocol;
	request->method_len = method_len;
	strncpy(request->method_name, ctx->conf->method->name, method_len);

	struct iovec buffer = { .iov_base = request, .iov_len = len };
	fastd_task_put_send_handshake(ctx, peer, buffer);
}

void fastd_handshake_handle(fastd_context *ctx, const fastd_peer *peer, uint8_t packet_type, struct iovec buffer) {
	if (packet_type != 1)
		return; // TODO

	if (buffer.iov_len < sizeof(fastd_packet_any))
		return;

	fastd_packet *packet = buffer.iov_base;

	if (!packet->any.reply && !packet->any.cp) {
		if (buffer.iov_len < sizeof(fastd_packet_request))
			return;

		if (buffer.iov_len < sizeof(fastd_packet_request) + packet->request.method_len)
			return;

		if (packet->request.flags)
			return; // TODO

		if (packet->request.proto != ctx->conf->protocol)
			return; // TODO

		if (packet->request.method_len != strlen(ctx->conf->method->name) ||
		    strncmp(packet->request.method_name, ctx->conf->method->name, packet->request.method_len))
			return; // TODO


		fastd_packet_reply *reply = malloc(sizeof(fastd_packet_reply));

		reply->reply = 1;
		reply->cp = 0;
		reply->req_id = packet->request.req_id;
		reply->rsv = 0;
		reply->reply_code = REPLY_SUCCESS;

		free(packet);

		buffer.iov_base = reply;
		buffer.iov_len = sizeof(fastd_packet_reply);

		fastd_task_put_send_handshake(ctx, peer, buffer);
	}
}
