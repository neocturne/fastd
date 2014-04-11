/*
  Copyright (c) 2012-2014, Matthias Schiffer <mschiffer@universe-factory.net>
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


#pragma once

#include "compat.h"

#include <stdbool.h>
#include <stddef.h>


#define UNUSED __attribute__((unused))


typedef struct fastd_tristate {
	bool set : 1;
	bool state : 1;
} fastd_tristate_t;

static const fastd_tristate_t fastd_tristate_true = {true, true};
static const fastd_tristate_t fastd_tristate_false = {true, false};
static const fastd_tristate_t fastd_tristate_undef = {false, false};


#define PACKET_TYPE_LEN 1


typedef enum fastd_packet_type {
	PACKET_UNKNOWN = 0,
	PACKET_HANDSHAKE,
	PACKET_DATA,
} fastd_packet_type_t;

typedef enum fastd_mode {
	MODE_TAP,
	MODE_TUN,
} fastd_mode_t;

typedef enum fastd_drop_caps {
	DROP_CAPS_OFF,
	DROP_CAPS_ON,
	DROP_CAPS_EARLY,
} fastd_drop_caps_t;

typedef enum fastd_peer_state {
	STATE_INIT = 0,
	STATE_RESOLVING,
	STATE_HANDSHAKE,
	STATE_ESTABLISHED,
} fastd_peer_state_t;

typedef enum fastd_loglevel {
	LL_UNSPEC = 0,
	LL_FATAL,
	LL_ERROR,
	LL_WARN,
	LL_INFO,
	LL_VERBOSE,
	LL_DEBUG,
	LL_DEBUG2,
} fastd_loglevel_t;

typedef enum fastd_async_type {
	ASYNC_TYPE_RESOLVE_RETURN,
} fastd_async_type_t;


typedef struct fastd_buffer fastd_buffer_t;

typedef union fastd_peer_address fastd_peer_address_t;
typedef struct fastd_bind_address fastd_bind_address_t;
typedef struct fastd_socket fastd_socket_t;
typedef struct fastd_peer_group_config fastd_peer_group_config_t;
typedef struct fastd_peer_group fastd_peer_group_t;
typedef struct fastd_peer_config fastd_peer_config_t;
typedef struct fastd_eth_addr fastd_eth_addr_t;
typedef struct fastd_peer fastd_peer_t;
typedef struct fastd_peer_eth_addr fastd_peer_eth_addr_t;
typedef struct fastd_remote_config fastd_remote_config_t;
typedef struct fastd_remote fastd_remote_t;
typedef struct fastd_stats fastd_stats_t;
typedef struct fastd_handshake_timeout fastd_handshake_timeout_t;

typedef struct fastd_log_file fastd_log_file_t;
typedef struct fastd_log_fd fastd_log_fd_t;

typedef struct fastd_config fastd_config_t;
typedef struct fastd_context fastd_context_t;

typedef struct fastd_protocol fastd_protocol_t;
typedef struct fastd_method_info fastd_method_info_t;
typedef struct fastd_method_provider fastd_method_provider_t;

typedef struct fastd_cipher_info fastd_cipher_info_t;
typedef struct fastd_cipher fastd_cipher_t;

typedef struct fastd_mac_info fastd_mac_info_t;
typedef struct fastd_mac fastd_mac_t;

typedef struct fastd_handshake fastd_handshake_t;

typedef struct fastd_lex fastd_lex_t;
typedef struct fastd_string_stack fastd_string_stack_t;

typedef struct fastd_shell_command fastd_shell_command_t;

typedef struct fastd_async_resolve_return fastd_async_resolve_return_t;


typedef union fastd_block128 {
	uint8_t b[16];
	uint64_t qw[2];
} __attribute__((aligned(16))) fastd_block128_t;


/* May be defined by the protocol/method/crypto implementations however they like */
typedef struct fastd_protocol_config fastd_protocol_config_t;
typedef struct fastd_protocol_state fastd_protocol_state_t;
typedef struct fastd_protocol_peer_config fastd_protocol_peer_config_t;
typedef struct fastd_protocol_peer_state fastd_protocol_peer_state_t;

typedef struct fastd_method fastd_method_t;
typedef struct fastd_method_session_state fastd_method_session_state_t;

typedef struct fastd_cipher_state fastd_cipher_state_t;
typedef struct fastd_mac_state fastd_mac_state_t;
