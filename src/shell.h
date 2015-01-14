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


#pragma once

#include "alloc.h"

#include <stdlib.h>
#include <string.h>


/** A shell command */
struct fastd_shell_command {
	char *command;		/**< The command as given to \em /bin/sh */
	char *dir;		/**< The working directory for the command */
	bool sync;		/**< If false, the command will be executed in the background by default */
};


/** Frees the resources used by a shell command */
static inline void fastd_shell_command_unset(fastd_shell_command_t *command) {
	free(command->command);
	command->command = NULL;

	free(command->dir);
	command->dir = NULL;
}

/** Sets a shell command */
static inline void fastd_shell_command_set(fastd_shell_command_t *command, const char *val, bool sync) {
	fastd_shell_command_unset(command);

	command->command = fastd_strdup(val);
	command->dir = get_current_dir_name();
	command->sync = sync;
}

/** Checks if a shell command is set */
static inline bool fastd_shell_command_isset(const fastd_shell_command_t *command) {
	return command->command;
}

fastd_shell_env_t * fastd_shell_env_alloc(void);
void fastd_shell_env_set(fastd_shell_env_t *env, const char *key, const char *value);
void fastd_shell_env_free(fastd_shell_env_t *env);

bool fastd_shell_command_exec_sync(const fastd_shell_command_t *command, const fastd_shell_env_t *env, int *ret);
void fastd_shell_command_exec(const fastd_shell_command_t *command, const fastd_shell_env_t *env);
