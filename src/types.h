// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2021, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
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
	bool set : 1;   /**< Specifies if the tri-state is set (\em true or \em false) or not (\em undefined) */
	bool state : 1; /**< Specifies if the tri-state is \em true or \em false */
} fastd_tristate_t;

/** A fastd_tristate_t instance representing the value \em true */
#define FASTD_TRISTATE_TRUE ((fastd_tristate_t){ true, true })
/** A fastd_tristate_t instance representing the value \em false */
#define FASTD_TRISTATE_FALSE ((fastd_tristate_t){ true, false })
/** A fastd_tristate_t instance representing the value \em undefined */
#define FASTD_TRISTATE_UNDEF ((fastd_tristate_t){ false, false })

/** The L2TP "T" (control) flag */
#define PACKET_L2TP_T 0x80

/** L2TP-compatible packet type \em control (all packets that don't use PACKET_DATA in L2TP-compatible sessions) */
#define PACKET_CONTROL 0xC8
/** L2TP-compatible packet type \em data (used for payload data) */
#define PACKET_DATA 0x00
/** Packet type \em handshake (used to negotiate a session) */
#define PACKET_HANDSHAKE 0x01
/** Pre-v22 packet type \em data (used for payload data) */
#define PACKET_DATA_COMPAT 0x02


#define PACKET_L2TP_VER_MASK 0x0F /**< Mask of L2TP version number in flags_ver field */
#define PACKET_L2TP_VERSION 3     /**< L2TP version used by fastd */

/** The (L2TP) control packet header */
typedef struct fastd_control_packet {
	uint8_t packet_type; /**< Packet type / flags */
	uint8_t flags_ver;   /**< More flags / L2TP version */
	uint16_t length;     /**< Control packet length */
	uint32_t conn_id;    /**< Control connection ID */
	uint16_t ns;         /**< Send sequence number */
	uint16_t nr;         /**< Receive sequence number */
} fastd_control_packet_t;


/** The supported modes of operation */
typedef enum fastd_mode {
	MODE_TAP,      /**< TAP (Layer 2/Ethernet mode) */
	MODE_MULTITAP, /**< TAP (Layer 2/Ethernet mode, one interface per peer) */
	MODE_TUN,      /**< TUN (Layer 3/IP mode) */
} fastd_mode_t;

/** Specifies when \em fastd drops its capabilities (if supported) */
typedef enum fastd_drop_caps {
	DROP_CAPS_OFF,   /**< The capabilities aren't dropped at all */
	DROP_CAPS_ON,    /**< The capabilities are dropped after executing the on-up command */
	DROP_CAPS_EARLY, /**< The capabilities are dropped before executing the on-up command */
	DROP_CAPS_FORCE, /**< The capabilities are dropped before executing the on-up command; CAP_NET_ADMIN is dropped
			    even when TUN/TAP interfaces need to be opened */
} fastd_drop_caps_t;

/** Types of file descriptors to poll on */
typedef enum fastd_poll_type {
	POLL_TYPE_UNSPEC = 0, /**< Unspecified file descriptor type */
	POLL_TYPE_ASYNC,      /**< The async action socket */
	POLL_TYPE_STATUS,     /**< The status socket */
	POLL_TYPE_IFACE,      /**< A TUN/TAP interface */
	POLL_TYPE_SOCKET,     /**< A network socket */
} fastd_poll_type_t;

/** Task types */
typedef enum fastd_task_type {
	TASK_TYPE_UNSPEC = 0,  /**< Unspecified task type */
	TASK_TYPE_MAINTENANCE, /**< Scheduled maintenance */
	TASK_TYPE_PEER,        /**< Peer maintenance (handshake, reset, keepalive) */
} fastd_task_type_t;


/** A timestamp used as a timeout */
typedef int64_t fastd_timeout_t;

/** Invalid timestamp */
#define FASTD_TIMEOUT_INV INT64_MAX


/** Session flags */
#define FASTD_SESSION_INITIATOR 0x01 /**< We initiated this session */


typedef struct fastd_buffer fastd_buffer_t;
typedef struct fastd_buffer_view fastd_buffer_view_t;
typedef struct fastd_poll_fd fastd_poll_fd_t;
typedef struct fastd_pqueue fastd_pqueue_t;
typedef struct fastd_task fastd_task_t;

typedef union fastd_peer_address fastd_peer_address_t;
typedef struct fastd_bind_address fastd_bind_address_t;
typedef struct fastd_iface fastd_iface_t;
typedef struct fastd_socket fastd_socket_t;
typedef struct fastd_peer_group fastd_peer_group_t;
typedef struct fastd_eth_addr fastd_eth_addr_t;
typedef struct fastd_eth_header fastd_eth_header_t;
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

typedef struct fastd_lex fastd_lex_t;
typedef struct fastd_parser_state fastd_parser_state_t;
typedef struct fastd_string_stack fastd_string_stack_t;

typedef struct fastd_shell_command fastd_shell_command_t;
typedef struct fastd_shell_env fastd_shell_env_t;


/** A 128-bit aligned block of data, primarily used by the cryptographic functions */
typedef union fastd_block128 {
	uint8_t b[16];  /**< Byte-wise access to the data */
	uint32_t dw[4]; /**< Doubleword-wise access to the data */
	uint64_t qw[2]; /**< Quadword-wise access to the data */
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
