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

#include <config.h>


typedef enum fastd_mode {
	MODE_TAP,
	MODE_TUN,
} fastd_mode_t;

typedef enum fastd_drop_caps {
	DROP_CAPS_OFF,
	DROP_CAPS_ON,
	DROP_CAPS_EARLY,
} fastd_drop_caps_t;

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

typedef struct fastd_log_file fastd_log_file_t;
typedef struct fastd_log_fd fastd_log_fd_t;

typedef struct fastd_config fastd_config_t;
typedef struct fastd_context fastd_context_t;

typedef struct fastd_protocol fastd_protocol_t;
typedef struct fastd_method fastd_method_t;

typedef struct fastd_handshake fastd_handshake_t;

typedef struct fastd_string_stack fastd_string_stack_t;

typedef struct fastd_resolve_return fastd_resolve_return_t;

#ifdef USE_CRYPTO_AES128CTR
typedef struct fastd_crypto_aes128ctr fastd_crypto_aes128ctr_t;
#endif
#ifdef USE_CRYPTO_GHASH
typedef struct fastd_crypto_ghash fastd_crypto_ghash_t;
#endif


/* May be defined by the protocol/method/crypto implementations however they like */
typedef struct fastd_protocol_config fastd_protocol_config_t;
typedef struct fastd_protocol_state fastd_protocol_state_t;
typedef struct fastd_protocol_peer_config fastd_protocol_peer_config_t;
typedef struct fastd_protocol_peer_state fastd_protocol_peer_state_t;

typedef struct fastd_method_session_state fastd_method_session_state_t;

#ifdef USE_CRYPTO_AES128CTR
typedef struct fastd_crypto_aes128ctr_context fastd_crypto_aes128ctr_context_t;
typedef struct fastd_crypto_aes128ctr_state fastd_crypto_aes128ctr_state_t;
#endif

#ifdef USE_CRYPTO_GHASH
typedef struct fastd_crypto_ghash_context fastd_crypto_ghash_context_t;
typedef struct fastd_crypto_ghash_state fastd_crypto_ghash_state_t;
#endif

#endif /* _FASTD_TYPES_H_ */
