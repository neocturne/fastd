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

/*
  types.h
  
  Basic enums and typedefs for common types
*/


#ifndef _FASTD_TYPES_H_
#define _FASTD_TYPES_H_

typedef enum _fastd_mode {
	MODE_TAP,
	MODE_TUN,
} fastd_mode;


typedef struct _fastd_buffer fastd_buffer;

typedef union _fastd_peer_address fastd_peer_address;
typedef struct _fastd_peer_config fastd_peer_config;
typedef struct _fastd_eth_addr fastd_eth_addr;
typedef struct _fastd_peer fastd_peer;
typedef struct _fastd_peer_eth_addr fastd_peer_eth_addr;

typedef struct _fastd_log_file fastd_log_file;
typedef struct _fastd_log_fd fastd_log_fd;

typedef struct _fastd_config fastd_config;
typedef struct _fastd_context fastd_context;

typedef struct _fastd_protocol fastd_protocol;
typedef struct _fastd_method fastd_method;

typedef struct _fastd_handshake fastd_handshake;

typedef struct _fastd_string_stack fastd_string_stack;

typedef struct _fastd_resolve_return fastd_resolve_return;


/* May be defined by the protocol/method however it likes */
typedef struct _fastd_protocol_config fastd_protocol_config;
typedef struct _fastd_protocol_state fastd_protocol_state;
typedef struct _fastd_protocol_peer_config fastd_protocol_peer_config;
typedef struct _fastd_protocol_peer_state fastd_protocol_peer_state;
typedef struct _fastd_method_session_state fastd_method_session_state;

#endif /* _FASTD_TYPES_H_ */
