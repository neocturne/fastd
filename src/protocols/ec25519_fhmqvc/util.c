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

   ec25519-fhmqvc protocol: utilify functions
*/


#include "ec25519_fhmqvc.h"


/** Prints a private or public key on stdout with an optional descriptive text */
static inline void print_hexdump(const char *desc, const unsigned char d[32]) {
	char buf[65];
	hexdump(buf, d);

	printf("%s%s\n", desc, buf);
}

/** Generates a new keypair */
void fastd_protocol_ec25519_fhmqvc_generate_key(void) {
	ecc_int256_t secret_key;
	ecc_int256_t public_key;

	if (!conf.machine_readable)
		pr_info("Reading 32 bytes from /dev/random...");

	fastd_random_bytes(secret_key.p, SECRETKEYBYTES, true);
	ecc_25519_gf_sanitize_secret(&secret_key, &secret_key);

	ecc_25519_work_t work;
	ecc_25519_scalarmult_base(&work, &secret_key);
	ecc_25519_store_packed(&public_key, &work);

	if (conf.machine_readable) {
		print_hexdump("", secret_key.p);
	}
	else {
		print_hexdump("Secret: ", secret_key.p);
		print_hexdump("Public: ", public_key.p);
	}
}

/** Prints the public key corresponding to the configured private key */
void fastd_protocol_ec25519_fhmqvc_show_key(void) {
	if (conf.machine_readable)
		print_hexdump("", conf.protocol_config->key.public.u8);
	else
		print_hexdump("Public: ", conf.protocol_config->key.public.u8);
}

/** Adds protocol- and peer-specific environment variables to an environment */
void fastd_protocol_ec25519_fhmqvc_set_shell_env(fastd_shell_env_t *env, const fastd_peer_t *peer) {
	char buf[65];

	hexdump(buf, conf.protocol_config->key.public.u8);
	fastd_shell_env_set(env, "LOCAL_KEY", buf);

	if (peer) {
		hexdump(buf, peer->key->key.u8);
		fastd_shell_env_set(env, "PEER_KEY", buf);
	}
	else {
		fastd_shell_env_set(env, "PEER_KEY", NULL);
	}
}

/**
   Generates a protocol-specific string representation of a peer

   This will only be used for peers without names (e.g. dynamic peers) and
   creates a string containing the first 16 hexadecimal digits of the peer's
   public key.
*/
bool fastd_protocol_ec25519_fhmqvc_describe_peer(const fastd_peer_t *peer, char *buf, size_t len) {
	if (!peer->key)
		return false;

	char dumpbuf[65];
	hexdump(dumpbuf, peer->key->key.u8);
	snprintf(buf, len, "%s", dumpbuf);

	return true;
}
