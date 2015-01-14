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

   Execution of shell commands and management of environment variables
*/


#include "shell.h"
#include "fastd.h"

#include <net/if.h>
#include <signal.h>
#include <sys/wait.h>


/** An environment variable */
typedef struct shell_env_entry {
	const char *key;			/**< The name of the enviroment variable */
	char *value;				/**< The value of the environment variable */
} shell_env_entry_t;


/** A shell environment */
struct fastd_shell_env {
	VECTOR(shell_env_entry_t) entries;	/**< Vector of the entries of the environment */
};


/** Allocated a new shell environment */
fastd_shell_env_t * fastd_shell_env_alloc(void) {
	return fastd_new0(fastd_shell_env_t);
}

/** Sets a variable in a shell environment */
void fastd_shell_env_set(fastd_shell_env_t *env, const char *key, const char *value) {
	shell_env_entry_t entry = {.key = key, .value = fastd_strdup(value)};
	VECTOR_ADD(env->entries, entry);
}

/** Frees a variable in a shell environment */
void fastd_shell_env_free(fastd_shell_env_t *env) {
	size_t i;
	for (i = 0; i < VECTOR_LEN(env->entries); i++) {
		shell_env_entry_t *entry = &VECTOR_INDEX(env->entries, i);
		free(entry->value);
	}

	VECTOR_FREE(env->entries);
	free(env);
}

/** Applies a shell environment to the current process */
static void shell_command_setenv(pid_t pid, const fastd_shell_env_t *env) {
	char buf[20];

	unsetenv("NOTIFY_SOCKET");

	snprintf(buf, sizeof(buf), "%u", (unsigned)pid);
	setenv("FASTD_PID", buf, 1);

	if (ctx.ifname) {
		setenv("INTERFACE", ctx.ifname, 1);
	}
	else if (conf.ifname) {
		char ifname[IF_NAMESIZE];

		strncpy(ifname, conf.ifname, sizeof(ifname)-1);
		ifname[sizeof(ifname)-1] = 0;

		setenv("INTERFACE", ifname, 1);
	}
	else {
		unsetenv("INTERFACE");
	}

	snprintf(buf, sizeof(buf), "%u", conf.mtu);
	setenv("INTERFACE_MTU", buf, 1);

	if (!env)
		return;

	size_t i;
	for (i = 0; i < VECTOR_LEN(env->entries); i++) {
		shell_env_entry_t *entry = &VECTOR_INDEX(env->entries, i);

		if (entry->value)
			setenv(entry->key, entry->value, 1);
		else
			unsetenv(entry->key);
	}
}

/** Tries to fork and execute the given command with some environment */
static bool shell_command_do_exec(const fastd_shell_command_t *command, const fastd_shell_env_t *env, pid_t *pid) {
	pid_t parent = getpid();

	*pid = fork();
	if (*pid < 0) {
		pr_error_errno("shell_command_do_exec: fork");
		return false;
	}
	else if (*pid > 0) {
		return true;
	}

	/* child process */

	fastd_close_all_fds();

	if (chdir(command->dir))
		_exit(126);

	shell_command_setenv(parent, env);

	/* unblock signals */
	sigset_t set;
	sigemptyset(&set);
	pthread_sigmask(SIG_SETMASK, &set, NULL);

	execl("/bin/sh", "sh", "-c", command->command, (char *)NULL);
	_exit(127);
}

/**
   Executes a shell command synchronously, regardless of the value of the \e sync field

   May be called from secondary threads.
*/
bool fastd_shell_command_exec_sync(const fastd_shell_command_t *command, const fastd_shell_env_t *env, int *ret) {
	if (!fastd_shell_command_isset(command))
		return true;

	pid_t pid;
	if (!shell_command_do_exec(command, env, &pid))
		return false;

	int status;
	pid_t err = waitpid(pid, &status, 0);

	if (err <= 0) {
		pr_error_errno("fastd_shell_command_exec_sync: waitpid");
		return false;
	}

	if (ret) {
		*ret = status;
	}
	else {
		if (WIFSIGNALED(status))
			pr_warn("command exited with signal %i", WTERMSIG(status));
		else if (WEXITSTATUS(status))
			pr_warn("command exited with status %i", WEXITSTATUS(status));
	}

	return true;
}

/**
   Executes a shell command asynchronously

   The new process's pid is added to \e ctx.async_pids so it can be reaped later
   on SIGCHLD.
*/
static void shell_command_exec_async(const fastd_shell_command_t *command, const fastd_shell_env_t *env) {
	pid_t pid;
	if (shell_command_do_exec(command, env, &pid))
		VECTOR_ADD(ctx.async_pids, pid);
}

/** Executes a shell command */
void fastd_shell_command_exec(const fastd_shell_command_t *command, const fastd_shell_env_t *env) {
	if (!fastd_shell_command_isset(command))
		return;

	if (command->sync)
		fastd_shell_command_exec_sync(command, env, NULL);
	else
		shell_command_exec_async(command, env);
}
