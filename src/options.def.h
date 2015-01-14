OPTION(usage, "--help" OR "-h", "Shows this help text");
OPTION(version, "--version" OR "-v", "Shows the fastd version");
OPTION(option_daemon, "--daemon" OR "-d", "Runs fastd in the background");
OPTION_ARG(option_pid_file, "--pid-file", "<filename>", "Writes fastd's PID to the specified file");
#ifdef WITH_STATUS_SOCKET
OPTION_ARG(option_status_socket, "--status-socket", "<socket>", "Configure a socket to get fastd's status");
#endif
SEPARATOR;

OPTION_ARG(option_config, "--config" OR "-c", "<filename>", "Loads a config file");
OPTION_ARG(option_config_peer, "--config-peer", "<filename>", "Loads a config file for a single peer");
OPTION_ARG(option_config_peer_dir, "--config-peer-dir", "<dir>", "Loads all files from a directory as peer configs");
SEPARATOR;

#ifdef WITH_CMDLINE_USER
OPTION_ARG(option_user, "--user", "<user>", "Sets the user to run fastd as");
OPTION_ARG(option_group, "--group", "<group>", "Sets the group to run fastd as");
SEPARATOR;
#endif

#ifdef WITH_CMDLINE_LOGGING
OPTION_ARG(option_log_level, "--log-level", "error|warn|info|verbose|debug|debug2", "Sets the stderr log level; default is info, if no alternative log destination is configured");
OPTION_ARG(option_syslog_level, "--syslog-level", "error|warn|info|verbose|debug|debug2", "Sets the log level for syslog output; default is not to use syslog");
OPTION_ARG(option_syslog_ident, "--syslog-ident", "<ident>", "Sets the syslog identification; default is 'fastd'");
OPTION(option_hide_ip_addresses, "--hide-ip-addresses", "Hides IP addresses in log output");
OPTION(option_hide_mac_addresses, "--hide-mac-addresses", "Hides MAC addresses in log output");
SEPARATOR;
#endif

#ifdef WITH_CMDLINE_OPERATION
OPTION_ARG(option_mode, "--mode" OR "-m", "tap|tun", "Sets the mode of the interface");
OPTION_ARG(option_interface, "--interface" OR "-i", "<name>", "Sets the name of the TUN/TAP interface to use");
OPTION_ARG(option_mtu, "--mtu" OR "-M", "<mtu>", "Sets the MTU; must be at least 576");
OPTION_ARG(option_bind, "--bind" OR "-b", "<address>[:<port>]", "Sets the bind address");
OPTION_ARG(option_protocol, "--protocol" OR "-p", "<protocol>", "Sets the protocol");
OPTION_ARG(option_method, "--method", "<method>", "Sets the encryption method");
OPTION(option_forward, "--forward", "Enables forwarding of packets between peers; read the documentation before use!");
SEPARATOR;
#endif

#ifdef __ANDROID__
OPTION(option_android_integration, "--android-integration", "Enable integration with Android GUI");
SEPARATOR;
#endif

#ifdef WITH_CMDLINE_COMMANDS
OPTION_ARG(option_on_pre_up, "--on-pre-up", "<command>", "Sets a shell command to execute before interface creation");
OPTION_ARG(option_on_up, "--on-up", "<command>", "Sets a shell command to execute after interface creation");
OPTION_ARG(option_on_down, "--on-down", "<command>", "Sets a shell command to execute before interface destruction");
OPTION_ARG(option_on_post_down, "--on-post-down", "<command>", "Sets a shell command to execute after interface destruction");
OPTION_ARG(option_on_connect, "--on-connect", "<command>", "Sets a shell command to execute when a handshake is sent to establish a new connection");
OPTION_ARG(option_on_establish, "--on-establish", "<command>", "Sets a shell command to execute when a new connection is established");
OPTION_ARG(option_on_disestablish, "--on-disestablish", "<command>", "Sets a shell command to execute when a connection is lost");
#ifdef WITH_DYNAMIC_PEERS
OPTION_ARG(option_on_verify, "--on-verify", "<command>", "Sets a shell command to execute to check a connection attempt by an unknown peer");
#endif
SEPARATOR;
#endif

OPTION(option_verify_config, "--verify-config", "Checks the configuration and exits");
OPTION(option_generate_key, "--generate-key", "Generates a new keypair");
OPTION(option_show_key, "--show-key", "Shows the public key corresponding to the configured secret");
OPTION(option_machine_readable, "--machine-readable", "Suppresses output of explaining text in the --show-key and --generate-key commands");
