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


#ifndef _FASTD_HANDSHAKE_H_
#define _FASTD_HANDSHAKE_H_

#include "fastd.h"
#include "packet.h"


typedef enum _fastd_handshake_record_type {
	RECORD_HANDSHAKE_TYPE = 0,
	RECORD_REPLY_CODE,
	RECORD_ERROR_DETAIL,
	RECORD_FLAGS,
	RECORD_MODE,
	RECORD_PROTOCOL_NAME,
	RECORD_MAX,
} fastd_handshake_record_type;

typedef enum _fastd_reply_code {
	REPLY_SUCCESS = 0,
	REPLY_MANDATORY_MISSING,
	REPLY_UNACCEPTABLE_VALUE,
	REPLY_MAX,
} fastd_reply_code;


typedef struct _fastd_handshake_record {
	size_t length;
	void *data;
} fastd_handshake_record;

struct _fastd_handshake {
	uint8_t req_id;
	fastd_handshake_record records[RECORD_MAX];
};


fastd_buffer fastd_handshake_new_init(fastd_context *ctx, fastd_peer *peer, size_t tail_space);
fastd_buffer fastd_handshake_new_reply(fastd_context *ctx, fastd_peer *peer, const fastd_handshake *handshake, size_t tail_space);

void fastd_handshake_handle(fastd_context *ctx, fastd_peer *peer, fastd_buffer buffer);


#endif /* _FASTD_HANDSHAKE_H_ */
