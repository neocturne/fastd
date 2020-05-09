// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
*/

/**
   \file

   Configuration management
*/


#pragma once

#include "fastd.h"


/** State of the config parser */
struct fastd_parser_state {
	fastd_peer_group_t *peer_group; /**< The current peer group */
	fastd_peer_t *peer;             /**< The peer currently being loaded */

	const char *const filename; /**< The filename of the currently parsed file */
	const int depth;            /**< The include depth */
};


void fastd_config_protocol(const char *name);
void fastd_config_method(fastd_peer_group_t *group, const char *name);
bool fastd_config_ifname(fastd_peer_t *peer, const char *ifname);
void fastd_config_cipher(const char *name, const char *impl);
void fastd_config_mac(const char *name, const char *impl);
void fastd_config_bind_address(const fastd_peer_address_t *address, const char *bindtodev, unsigned flags);
void fastd_config_release(void);
void fastd_config_handle_options(int argc, char *const argv[]);
void fastd_config_verify(void);

bool fastd_config_read(const char *filename, fastd_peer_group_t *peer_group, fastd_peer_t *peer, int depth);
void fastd_config_peer_group_push(fastd_parser_state_t *state, const char *name);
void fastd_config_peer_group_pop(fastd_parser_state_t *state);
void fastd_config_add_peer_dir(fastd_peer_group_t *group, const char *dir);

void fastd_configure(int argc, char *const argv[]);
void fastd_configure_peers(void);
void fastd_config_check(void);
void fastd_config_load_peer_dirs(bool dirs_only);
bool fastd_config_single_iface(void);
bool fastd_config_persistent_ifaces(void);
