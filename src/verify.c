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

   Handling of on-verify commands to add peers not configured statically ("dynamic peers")
*/


#include "verify.h"


#ifdef WITH_DYNAMIC_PEERS

#include "async.h"
#include "shell.h"

#include <sys/wait.h>


/**
   Calls the on-verify command and returns the result

   do_verify() may be called from secondary threads as all information about the peer
   to verify is encoded in the supplied environment
*/
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

/** The argument given to asynchronous verifier threads */
typedef struct verify_arg {
	fastd_shell_env_t *env;			/**< Enviroment containing information about the peer to verify */
	size_t ret_len;				/**< Length of the \e ret field (as it contains a flexible member) */
	fastd_async_verify_return_t ret;	/**< Information to return to the main thread after the verification */
} verify_arg_t;

/** Verifier thread main function */
static void * do_verify_thread(void *p) {
	verify_arg_t *arg = p;

	arg->ret.ok = do_verify(arg->env);
	fastd_shell_env_free(arg->env);

	fastd_async_enqueue(ASYNC_TYPE_VERIFY_RETURN, &arg->ret, arg->ret_len);

	free(arg);

	fastd_sem_post(&ctx.verify_limit);

	return NULL;
}

/**
   Verifies a peer

   \return A tristate. If on-verify is a synchronous command, it will be \e true or \e false, but if the command is asynchronous (which is the default),
   \e undef will be returned and the result is sent via the asyncronous notification mechanism.
*/
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
		return ret ? fastd_tristate_true : fastd_tristate_false;
	}
	else {
		if (!fastd_sem_trywait(&ctx.verify_limit)) {
			pr_debug("maximum number of verification processes reached");
			return fastd_tristate_false;
		}

		verify_arg_t *arg = fastd_alloc0(sizeof(verify_arg_t) + data_len);

		arg->env = env;
		arg->ret_len = sizeof(fastd_async_verify_return_t) + data_len;

		arg->ret.peer_id = peer->id;
		arg->ret.method = method;
		arg->ret.sock = sock;
		arg->ret.local_addr = *local_addr;
		arg->ret.remote_addr = *remote_addr;
		memcpy(arg->ret.protocol_data, data, data_len);

		pthread_t thread;
		if ((errno = pthread_create(&thread, &ctx.detached_thread, do_verify_thread, arg)) != 0) {
			pr_error_errno("unable to create verify thread");

			fastd_sem_post(&ctx.verify_limit);

			fastd_shell_env_free(env);
			free(arg);

			return fastd_tristate_false;
		}

		return fastd_tristate_undef;
	}
}

#endif /* WITH_DYNAMIC_PEERS */
