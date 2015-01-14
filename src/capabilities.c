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

   Handling of POSIX capabilities
*/


#include "fastd.h"

#ifdef WITH_CAPABILITIES

#include <sys/capability.h>


/** Tries to acquire a capability */
static void try_cap(cap_value_t cap) {
	char *name = cap_to_name(cap);
	if (!name)
		return;

	cap_t caps = cap_get_proc();
	if (!caps)
		goto end_free;

	cap_flag_value_t val;
	if (cap_get_flag(caps, cap, CAP_EFFECTIVE, &val) < 0) {
		pr_debug_errno("cap_get_flag");
		goto end_free;
	}

	if (val == CAP_SET)
		goto end_free;

	pr_verbose("Trying to acquire %s", name);

	if (cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, CAP_SET) < 0) {
		pr_debug_errno("cap_set_flags");
		goto end_free;
	}

	if (cap_set_proc(caps) < 0) {
		pr_debug_errno("cap_set_proc");
		goto end_free;
	}

	pr_verbose("acquired capability %s", name);

 end_free:
	cap_free(caps);
	cap_free(name);
}

/** Tries to acquire the capabilities needed to perform initialization without root privileges */
void fastd_cap_init(void) {
	/* interface creation */
	try_cap(CAP_NET_ADMIN);

	/* privileged binds */
	try_cap(CAP_NET_BIND_SERVICE);

	/* for device binds */
	try_cap(CAP_NET_RAW);
}

/** Drops all capabilities */
void fastd_cap_drop(void) {
	cap_t caps = cap_init();

	if (cap_set_proc(caps) < 0) {
		pr_debug_errno("cap_set_proc");
	}
	else {
		pr_verbose("dropped capabilities");
	}

	cap_free(caps);

}


#else /* WITH_CAPABILITIES */

void fastd_cap_init(void) {
}

void fastd_cap_drop(void) {
}

#endif /* WITH_CAPABILITIES */


