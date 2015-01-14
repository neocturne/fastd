/*
  Copyright (c) 2012-2015, Matthias Schiffer <mschiffer@universe-factory.net>
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

/**
  \file

  Basic enums and typedefs for common types
*/


#pragma once

#include "compat.h"

#include <stdbool.h>
#include <stddef.h>


/** Annotation for unused function parameters */
#define UNUSED __attribute__((unused))


/** A tri-state with the values \em true, \em false and \em undefined */
typedef struct fastd_tristate {
	bool set : 1;		/**< Specifies if the tri-state is set (\em true or \em false) or not (\em undefined) */
	bool state : 1;		/**< Specifies if the tri-state is \em true or \em false */
} fastd_tristate_t;

/** A fastd_tristate_t instance representing the value \em true */
static const fastd_tristate_t fastd_tristate_true = {true, true};
/** A fastd_tristate_t instance representing the value \em false */
static const fastd_tristate_t fastd_tristate_false = {true, false};
/** A fastd_tristate_t instance representing the value \em undefined */
static const fastd_tristate_t fastd_tristate_undef = {false, false};


/** The defined packet types */
typedef enum fastd_packet_type {
	PACKET_HANDSHAKE = 1,	/**< Packet type \em handshake (used to negotiate a session) */
	PACKET_DATA = 2,	/**< Packet type \em data (used for payload data) */
} fastd_packet_type_t;

/** The supported modes of operation */
typedef enum fastd_mode {
	MODE_TAP,		/**< TAP (Layer 2/Ethernet mode) */
	MODE_TUN,		/**< TUN (Layer 3/IP mode) */
} fastd_mode_t;

/** Specifies when \em fastd drops its capabilities (if supported) */
typedef enum fastd_drop_caps {
	DROP_CAPS_OFF,		/**< The capabilities aren't dropped at all */
	DROP_CAPS_ON,		/**< The capabilities are dropped after executing the on-up command */
	DROP_CAPS_EARLY,	/**< The capabilities are dropped before executing the on-up command */
} fastd_drop_caps_t;


/** A timestamp used as a timeout */
typedef int64_t fastd_timeout_t;


typedef struct fastd_buffer fastd_buffer_t;

typedef union fastd_peer_address fastd_peer_address_t;
typedef struct fastd_bind_address fastd_bind_address_t;
typedef struct fastd_socket fastd_socket_t;
typedef struct fastd_peer_group fastd_peer_group_t;
typedef struct fastd_eth_addr fastd_eth_addr_t;
typedef struct fastd_peer fastd_peer_t;
typedef struct fastd_peer_eth_addr fastd_peer_eth_addr_t;
typedef struct fastd_remote fastd_remote_t;
typedef struct fastd_stats fastd_stats_t;
typedef struct fastd_handshake_timeout fastd_handshake_timeout_t;

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
typedef struct fastd_handshake_buffer fastd_handshake_buffer_t;

typedef struct fastd_lex fastd_lex_t;
typedef struct fastd_parser_state fastd_parser_state_t;
typedef struct fastd_string_stack fastd_string_stack_t;

typedef struct fastd_shell_command fastd_shell_command_t;
typedef struct fastd_shell_env fastd_shell_env_t;


/** A 128-bit aligned block of data, primarily used by the cryptographic functions */
typedef union fastd_block128 {
	uint8_t b[16];		/**< Byte-wise access to the data */
	uint32_t dw[4];		/**< Doubleword-wise access to the data */
	uint64_t qw[2];		/**< Quadword-wise access to the data */
} __attribute__((aligned(16))) fastd_block128_t;


/* May be defined by the protocol/method/crypto implementations however they like */
typedef struct fastd_protocol_config fastd_protocol_config_t;
typedef struct fastd_protocol_state fastd_protocol_state_t;
typedef struct fastd_protocol_key fastd_protocol_key_t;
typedef struct fastd_protocol_peer_state fastd_protocol_peer_state_t;

typedef struct fastd_method fastd_method_t;
typedef struct fastd_method_session_state fastd_method_session_state_t;

typedef struct fastd_cipher_state fastd_cipher_state_t;
typedef struct fastd_mac_state fastd_mac_state_t;
