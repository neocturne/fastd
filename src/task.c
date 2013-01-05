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


#include "task.h"


fastd_task_t* fastd_task_get(fastd_context_t *ctx) {
	return container_of(fastd_queue_get(ctx, &ctx->task_queue), fastd_task_t, entry);
}

static bool is_handshake(fastd_queue_entry_t *data, void *extra) {
	fastd_task_t *task = container_of(data, fastd_task_t, entry);
	fastd_peer_t *peer = extra;

	if (task->peer != peer)
		return false;

	return (task->type == TASK_HANDSHAKE);
}

void fastd_task_schedule_handshake(fastd_context_t *ctx, fastd_peer_t *peer, int timeout) {
	if (fastd_queue_has_entry(ctx, &ctx->task_queue, is_handshake, peer)) {
		pr_debug(ctx, "not sending a handshake to %P, there still is one queued", peer);
		return;
	}

	fastd_task_t *task = malloc(sizeof(fastd_task_t));

	task->type = TASK_HANDSHAKE;
	task->peer = peer;

	fastd_queue_put(ctx, &ctx->task_queue, &task->entry, timeout);
}

static bool is_keepalive(fastd_queue_entry_t *data, void *extra) {
	fastd_task_t *task = container_of(data, fastd_task_t, entry);
	fastd_peer_t *peer = extra;

	if (task->peer != peer)
		return false;

	return (task->type == TASK_KEEPALIVE);
}

void fastd_task_schedule_keepalive(fastd_context_t *ctx, fastd_peer_t *peer, int timeout) {
	if (fastd_queue_has_entry(ctx, &ctx->task_queue, is_keepalive, peer)) {
		pr_debug(ctx, "not sending a keepalive to %P, there still is one queued", peer);
		return;
	}

	fastd_task_t *task = malloc(sizeof(fastd_task_t));

	task->type = TASK_KEEPALIVE;
	task->peer = peer;

	fastd_queue_put(ctx, &ctx->task_queue, &task->entry, timeout);
}

typedef struct replace_peer_extra {
	fastd_peer_t *old_peer;
	fastd_peer_t *new_peer;
} replace_peer_extra_t;


static bool replace_peer(fastd_queue_entry_t *data, void *extra) {
	replace_peer_extra_t *e = extra;
	fastd_task_t *task = container_of(data, fastd_task_t, entry);
	fastd_peer_t *old_peer = e->old_peer;
	fastd_peer_t *new_peer = e->new_peer;

	if (task->peer == old_peer)
		task->peer = new_peer;

	return true;
}

void fastd_task_replace_peer(fastd_context_t *ctx, fastd_peer_t *old_peer, fastd_peer_t *new_peer) {
	replace_peer_extra_t extra = {old_peer, new_peer};
	fastd_queue_filter(ctx, &ctx->task_queue, replace_peer, &extra);
}

typedef struct delete_task_extra {
	fastd_peer_t *peer;
	bool handshake_only;
	bool keepalive_only;
} delete_task_extra_t;

static bool delete_task(fastd_queue_entry_t *data, void *extra) {
	delete_task_extra_t *e = extra;
	fastd_task_t *task = container_of(data, fastd_task_t, entry);
	fastd_peer_t *peer = e->peer;

	if (task->peer != peer)
		return true;

	if (e->handshake_only && task->type != TASK_HANDSHAKE)
		return true;

	if (e->keepalive_only && task->type != TASK_KEEPALIVE)
		return true;

	free(task);

	return false;
}

void fastd_task_delete_peer(fastd_context_t *ctx, fastd_peer_t *peer) {
	delete_task_extra_t extra = {peer, false, false};
	fastd_queue_filter(ctx, &ctx->task_queue, delete_task, &extra);
}

void fastd_task_delete_peer_handshakes(fastd_context_t *ctx, fastd_peer_t *peer) {
	delete_task_extra_t extra = {peer, true, false};
	fastd_queue_filter(ctx, &ctx->task_queue, delete_task, &extra);
}

void fastd_task_delete_peer_keepalives(fastd_context_t *ctx, fastd_peer_t *peer) {
	delete_task_extra_t extra = {peer, false, true};
	fastd_queue_filter(ctx, &ctx->task_queue, delete_task, &extra);
}
