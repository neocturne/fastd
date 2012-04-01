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


#include "task.h"


fastd_task* fastd_task_get(fastd_context *ctx) {
	return container_of(fastd_queue_get(ctx, &ctx->task_queue), fastd_task, entry);
}

static void fastd_task_put_send_type(fastd_context *ctx, fastd_peer *peer, uint8_t packet_type, fastd_buffer buffer) {
	fastd_task *task = malloc(sizeof(fastd_task));

	task->type = TASK_SEND;
	task->peer = peer;
	task->send.packet_type = packet_type;
	task->send.buffer = buffer;

	fastd_queue_put(ctx, &ctx->task_queue, &task->entry, 0);
}

void fastd_task_put_send_handshake(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_task_put_send_type(ctx, peer, PACKET_HANDSHAKE, buffer);
}

void fastd_task_put_send(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_task_put_send_type(ctx, peer, PACKET_DATA, buffer);
}

void fastd_task_put_handle_recv(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer) {
	fastd_task *task = malloc(sizeof(fastd_task));

	task->type = TASK_HANDLE_RECV;
	task->peer = peer;
	task->handle_recv.buffer = buffer;

	fastd_queue_put(ctx, &ctx->task_queue, &task->entry, 0);
}

static bool is_handshake(fastd_queue_entry *data, void *extra) {
	fastd_task *task = container_of(data, fastd_task, entry);
	fastd_peer *peer = extra;

	if (task->peer != peer)
		return true;

	return (task->type == TASK_HANDSHAKE);
}

void fastd_task_schedule_handshake(fastd_context *ctx, fastd_peer *peer, int timeout) {
	if (fastd_queue_has_entry(ctx, &ctx->task_queue, is_handshake, peer)) {
		pr_debug(ctx, "not sending a handshake to %P, there still is one queued", peer);
		return;
	}

	pr_debug(ctx, "scheduling handshake with %P", peer);

	fastd_task *task = malloc(sizeof(fastd_task));

	task->type = TASK_HANDSHAKE;
	task->peer = peer;

	fastd_queue_put(ctx, &ctx->task_queue, &task->entry, timeout);
}

static bool is_keepalive(fastd_queue_entry *data, void *extra) {
	fastd_task *task = container_of(data, fastd_task, entry);
	fastd_peer *peer = extra;

	if (task->peer != peer)
		return true;

	return (task->type == TASK_KEEPALIVE);
}

void fastd_task_schedule_keepalive(fastd_context *ctx, fastd_peer *peer, int timeout) {
	if (fastd_queue_has_entry(ctx, &ctx->task_queue, is_keepalive, peer)) {
		pr_debug(ctx, "not sending a keepalive to %P, there still is one queued", peer);
		return;
	}

	fastd_task *task = malloc(sizeof(fastd_task));

	task->type = TASK_KEEPALIVE;
	task->peer = peer;

	fastd_queue_put(ctx, &ctx->task_queue, &task->entry, timeout);
}

typedef struct _replace_peer_extra {
	fastd_peer *old_peer;
	fastd_peer *new_peer;
} replace_peer_extra;


static bool replace_peer(fastd_queue_entry *data, void *extra) {
	replace_peer_extra *e = extra;
	fastd_task *task = container_of(data, fastd_task, entry);
	fastd_peer *old_peer = e->old_peer;
	fastd_peer *new_peer = e->new_peer;

	if (task->peer == old_peer)
		task->peer = new_peer;

	return true;
}

void fastd_task_replace_peer(fastd_context *ctx, fastd_peer *old_peer, fastd_peer *new_peer) {
	replace_peer_extra extra = {old_peer, new_peer};
	fastd_queue_filter(ctx, &ctx->task_queue, replace_peer, &extra);
}

typedef struct _delete_task_extra {
	fastd_peer *peer;
	bool handshake_only;
	bool keepalive_only;
} delete_task_extra;

static bool delete_task(fastd_queue_entry *data, void *extra) {
	delete_task_extra *e = extra;
	fastd_task *task = container_of(data, fastd_task, entry);
	fastd_peer *peer = e->peer;

	if (task->peer != peer)
		return true;

	if (e->handshake_only && task->type != TASK_HANDSHAKE)
		return true;

	if (e->keepalive_only && task->type != TASK_KEEPALIVE)
		return true;

	switch (task->type) {
	case TASK_SEND:
		fastd_buffer_free(task->send.buffer);
		break;

	case TASK_HANDLE_RECV:
		fastd_buffer_free(task->handle_recv.buffer);
		break;

	case TASK_HANDSHAKE:
		break;

	case TASK_KEEPALIVE:
		break;
	}

	free(task);

	return false;
}

void fastd_task_delete_peer(fastd_context *ctx, fastd_peer *peer) {
	delete_task_extra extra = {peer, false, false};
	fastd_queue_filter(ctx, &ctx->task_queue, delete_task, &extra);
}

void fastd_task_delete_peer_handshakes(fastd_context *ctx, fastd_peer *peer) {
	delete_task_extra extra = {peer, true, false};
	fastd_queue_filter(ctx, &ctx->task_queue, delete_task, &extra);
}

void fastd_task_delete_peer_keepalives(fastd_context *ctx, fastd_peer *peer) {
	delete_task_extra extra = {peer, false, true};
	fastd_queue_filter(ctx, &ctx->task_queue, delete_task, &extra);
}
