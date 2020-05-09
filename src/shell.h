// SPDX-License-Identifier: BSD-2-Clause
/*
  Copyright (c) 2012-2016, Matthias Schiffer <mschiffer@universe-factory.net>
  All rights reserved.
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
	char *command; /**< The command as given to \em /bin/sh */
	char *dir;     /**< The working directory for the command */
	bool sync;     /**< If false, the command will be executed in the background by default */
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

fastd_shell_env_t *fastd_shell_env_alloc(void);
void fastd_shell_env_set(fastd_shell_env_t *env, const char *key, const char *value);
void fastd_shell_env_set_iface(fastd_shell_env_t *env, const fastd_iface_t *iface);
void fastd_shell_env_free(fastd_shell_env_t *env);

bool fastd_shell_command_exec_sync(const fastd_shell_command_t *command, const fastd_shell_env_t *env, int *ret);
void fastd_shell_command_exec(const fastd_shell_command_t *command, const fastd_shell_env_t *env);
