// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
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
	if (!fastd_shell_command_isset(&conf.on_verify))
		exit_bug("tried to verify peer without on-verify command");

	if (!fastd_shell_command_exec_sync(&conf.on_verify, env, &ret))
		return false;

	if (WIFSIGNALED(ret)) {
		pr_error("verify command exited with signal %i", WTERMSIG(ret));
		return false;
	} else if (WEXITSTATUS(ret)) {
		pr_debug("verify command exited with status %i", WEXITSTATUS(ret));
		return false;
	}

	return true;
}

/** The argument given to asynchronous verifier threads */
typedef struct verify_arg {
	fastd_shell_env_t *env;          /**< Enviroment containing information about the peer to verify */
	size_t ret_len;                  /**< Length of the \e ret field (as it contains a flexible member) */
	fastd_async_verify_return_t ret; /**< Information to return to the main thread after the verification */
} verify_arg_t;

/** Verifier thread main function */
static void *do_verify_thread(void *p) {
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

   \return A tristate. If on-verify is a synchronous command, it will be \e true or \e false, but if the command is
   asynchronous (which is the default), \e undef will be returned and the result is sent via the asyncronous
   notification mechanism.
*/
fastd_tristate_t fastd_verify_peer(
	fastd_peer_t *peer, fastd_socket_t *sock, const fastd_peer_address_t *local_addr,
	const fastd_peer_address_t *remote_addr, const void *data, size_t data_len) {
	if (!fastd_shell_command_isset(&conf.on_verify))
		exit_bug("tried to verify peer without on-verify command");

	fastd_peer_set_verifying(peer);

	fastd_shell_env_t *env = fastd_shell_env_alloc();
	fastd_peer_set_shell_env(env, peer, local_addr, remote_addr);

	if (conf.on_verify.sync) {
		bool ret = do_verify(env);
		fastd_shell_env_free(env);
		fastd_peer_set_verified(peer, ret);
		return ret ? FASTD_TRISTATE_TRUE : FASTD_TRISTATE_FALSE;
	} else {
		if (!fastd_sem_trywait(&ctx.verify_limit)) {
			pr_debug("maximum number of verification processes reached");
			return FASTD_TRISTATE_FALSE;
		}

		verify_arg_t *arg = fastd_alloc0(sizeof(verify_arg_t) + data_len);

		arg->env = env;
		arg->ret_len = sizeof(fastd_async_verify_return_t) + data_len;

		arg->ret.peer_id = peer->id;
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

			return FASTD_TRISTATE_FALSE;
		}

		return FASTD_TRISTATE_UNDEF;
	}
}

#endif /* WITH_DYNAMIC_PEERS */
