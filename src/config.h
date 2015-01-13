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

/**
   \file

   Configuration management
*/


#pragma once

#include "fastd.h"


/** State of the config parser */
struct fastd_parser_state {
	fastd_peer_group_t *peer_group;	/**< The current peer group */
	fastd_peer_t *peer;	/**< The peer currently being loaded */

	const char *const filename;	/**< The filename of the currently parsed file */
	const int depth;		/**< The include depth */
};


void fastd_config_protocol(const char *name);
void fastd_config_method(fastd_peer_group_t *group, const char *name);
void fastd_config_cipher(const char *name, const char *impl);
void fastd_config_mac(const char *name, const char *impl);
void fastd_config_bind_address(const fastd_peer_address_t *address, const char *bindtodev, bool default_v4, bool default_v6);
void fastd_config_release(void);
void fastd_config_handle_options(int argc, char *const argv[]);
void fastd_config_verify(void);

bool fastd_config_read(const char *filename, fastd_peer_group_t *peer_group, fastd_peer_t *peer, int depth);
void fastd_config_peer_group_push(fastd_parser_state_t *state, const char *name);
void fastd_config_peer_group_pop(fastd_parser_state_t *state);
void fastd_config_add_peer_dir(fastd_peer_group_t *group, const char *dir);

void fastd_configure(int argc, char *const argv[]);
void fastd_config_check(void);
void fastd_config_load_peer_dirs(void);

