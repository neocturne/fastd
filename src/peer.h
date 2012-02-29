/*
  Copyright (c) 2012, Matthias Schiffer <mschiffer@universe-factory.net>
  Partly based on QuickTun Copyright (c) 2010, Ivo Smits <Ivo@UCIS.nl>.
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


#ifndef _FASTD_PEER_H_
#define _FASTD_PEER_H_

#include "fastd.h"


const fastd_eth_addr* fastd_get_source_address(const fastd_context *ctx, fastd_buffer buffer);
const fastd_eth_addr* fastd_get_dest_address(const fastd_context *ctx, fastd_buffer buffer);

fastd_peer* fastd_peer_init(fastd_context *ctx, fastd_peer_config *conf);
void fastd_peer_free(fastd_context *ctx, fastd_peer *peer);

static inline int fastd_eth_addr_is_unicast(const fastd_eth_addr *addr) {
	return ((addr->data[0] & 1) == 0);
}

void fastd_peer_add_eth_addr(fastd_context *ctx, fastd_peer *peer, const fastd_eth_addr *addr);
fastd_peer* fastd_peer_find_by_eth_addr(fastd_context *ctx, const fastd_eth_addr *addr);

#endif /* _FASTD_PEER_H_ */
