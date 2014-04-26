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


#include "verify.h"


#ifdef WITH_VERIFY

#include "async.h"
#include "shell.h"

#include <pthread.h>


static bool do_verify(const fastd_shell_env_t *env) {
	int ret;
	if (!fastd_shell_command_exec_sync(&conf.on_verify, env, &ret))
		return false;

	if (WIFSIGNALED(ret)) {
		pr_error("verify command exited with signal %i", WTERMSIG(ret));
		return false;
	}
	else if (WEXITSTATUS(ret)) {
		pr_debug("verify command exited with status %i", WEXITSTATUS(ret));
		return false;
	}

	return true;
}

typedef struct verify_arg {
	fastd_shell_env_t *env;
	size_t ret_len;
	fastd_async_verify_return_t ret;
} verify_arg_t;

static void * do_verify_thread(void *p) {
	verify_arg_t *arg = p;

	arg->ret.ok = do_verify(arg->env);
	fastd_shell_env_free(arg->env);

	fastd_async_enqueue(ASYNC_TYPE_VERIFY_RETURN, &arg->ret, arg->ret_len);

	free(arg);

	return NULL;
}

fastd_tristate_t fastd_verify_peer(fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr, const fastd_peer_address_t *remote_addr, const fastd_method_info_t *method, const void *data, size_t data_len) {
	if (!fastd_shell_command_isset(&conf.on_verify))
		exit_bug("tried to verify peer without on-verify command");

	fastd_peer_set_verifying(peer);

	fastd_shell_env_t *env = fastd_shell_env_alloc();
	fastd_peer_set_shell_env(env, peer, local_addr, remote_addr);

	if (conf.on_verify.sync) {
		bool ret = do_verify(env);
		fastd_shell_env_free(env);
		fastd_peer_set_verified(peer, ret);
		return (fastd_tristate_t){.set = true, .state = ret};
	}
	else {
		verify_arg_t *arg = calloc(1, sizeof(verify_arg_t) + data_len);

		arg->env = env;
		arg->ret_len = sizeof(fastd_async_verify_return_t) + data_len;

		arg->ret.peer_id = peer->id;
		arg->ret.method = method;
		arg->ret.sock = sock;
		arg->ret.local_addr = *local_addr;
		arg->ret.remote_addr = *remote_addr;
		memcpy(arg->ret.protocol_data, data, data_len);

		pthread_t thread;
		if ((errno = pthread_create(&thread, NULL, do_verify_thread, arg)) != 0) {
			pr_error_errno("unable to create verify thread");

			fastd_shell_env_free(env);
			free(arg);

			return (fastd_tristate_t){.set = true, .state = false};
		}

		pthread_detach(thread);
		return (fastd_tristate_t){.set = false};
	}
}

#endif /* WITH_VERIFY */
