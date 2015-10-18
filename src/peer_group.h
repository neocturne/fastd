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

   Peer groups
*/


#pragma once

#include "fastd.h"


/**
   A group of peers

   Peer groups may be nested and form a tree
*/
struct fastd_peer_group {
	fastd_peer_group_t *next;			/**< The next sibling in the group tree */
	fastd_peer_group_t *parent;			/**< The group's parent group */
	fastd_peer_group_t *children;			/**< The group's first child */

	char *name;					/**< The group's name; NULL for the root group */
	fastd_string_stack_t *peer_dirs;		/**< List of peer directories which belong to this group */

	int max_connections;				/**< The maximum number of connections to allow in this group; -1 for no limit */
	fastd_string_stack_t *methods;			/**< The list of configured method names */

	fastd_shell_command_t on_up;			/**< The command to execute after the initialization of the tunnel interface */
	fastd_shell_command_t on_down;			/**< The command to execute before the destruction of the tunnel interface */
	fastd_shell_command_t on_connect;		/**< The command to execute before a handshake is sent to establish a new connection */
	fastd_shell_command_t on_establish;		/**< The command to execute when a new connection has been established */
	fastd_shell_command_t on_disestablish;		/**< The command to execute when a connection has been disestablished */
};


/**
   Looks up an attribute in the peer group tree

   Returns a pointer to the attribute, going up the group tree to the first group
   where the attribute is not NULL if such a group exists.

   @param group		the peer group
   @param attr		the name of the member

   \hideinitializer
 */
#define fastd_peer_group_lookup(group, attr) ({				\
			const fastd_peer_group_t *_grp = (group);	\
									\
			while (_grp->parent && !_grp->attr)		\
				_grp = _grp->parent;			\
									\
			&_grp->attr;					\
		})

/**
   Looks up an attribute in the peer group tree, for a given peer

   Returns a pointer to the attribute, going up the group tree to the first group
   where the attribute is not NULL if such a group exists. Uses the default group
   if no peer is given.

   @param peer		the peer
   @param attr		the name of the member

   \hideinitializer
 */
#define fastd_peer_group_lookup_peer(peer, attr) ({			\
			const fastd_peer_t *_peer = (peer);		\
			_peer ? fastd_peer_group_lookup(_peer->group, attr) : &conf.peer_group->attr; \
		})

/**
   Looks up an shell command attribute in the peer group tree, for a given peer

   Returns a pointer to the attribute, going up the group tree to the first group
   where the attribute is not NULL if such a group exists. Uses the default group
   if no peer is given.

   @param peer		the peer
   @param attr		the name of the shell command member

   \hideinitializer
 */
#define fastd_peer_group_lookup_peer_shell_command(peer, attr) container_of(fastd_peer_group_lookup_peer(peer, attr.command), fastd_shell_command_t, command)
