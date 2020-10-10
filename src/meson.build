cc = meson.get_compiler('c')

default_args = [ '-D_GNU_SOURCE' ]

if host_machine.system() == 'darwin'
	default_args += '__APPLE_USE_RFC_3542'
endif

if cc.has_argument('-Wno-format-truncation')
	default_args += '-Wno-format-truncation'
endif
if cc.has_argument('-Wno-stringop-truncation')
	default_args += '-Wno-stringop-truncation'
endif

add_project_arguments(default_args, language : 'c')


bison = find_program('bison')

config_y = custom_target(
	'config.yy.[ch]',
	output : ['config.yy.c', 'config.yy.h'],
	input : 'config.y',
	command : [bison, '@INPUT@', '--defines=@OUTPUT1@', '--output=@OUTPUT0@'],
)

version_h = vcs_tag(
	output : 'version.h',
	input : 'version.h.in',
	command : [
		'git',
		'--work-tree=' + meson.source_root(),
		'--git-dir=' + meson.source_root() / '.git',
		'describe',
		'--dirty=+',
	],
)

src = [
	config_y,
	version_h,
	'android.c',
	'async.c',
	'buffer.c',
	'capabilities.c',
	'config.c',
	'fastd.c',
	'handshake.c',
	'hkdf_sha256.c',
	'iface.c',
	'lex.c',
	'log.c',
	'options.c',
	'peer.c',
	'peer_hashtable.c',
	'polling.c',
	'pqueue.c',
	'random.c',
	'receive.c',
	'resolve.c',
	'send.c',
	'sha256.c',
	'shell.c',
	'socket.c',
	'status.c',
	'task.c',
	'time.c',
	'vector.c',
	'verify.c',
]
libs = []

srcdir = include_directories('.')

need_libcrypto = false
need_libsodium_nacl = false

subdir('crypto')
subdir('methods')
subdir('protocols')


is_android = host_machine.system() == 'android'
is_darwin = host_machine.system() == 'darwin'
is_openbsd = host_machine.system() == 'openbsd'
is_linux = host_machine.system() == 'linux'

conf_data = configuration_data()

deps = []

deps += dependency('threads')
deps += dependency('libuecc', version : '>=6')

with_capabilities = get_option('capabilities').enabled() or (get_option('capabilities').auto() and is_linux)
if with_capabilities
	deps += dependency('libcap')
endif

with_status_socket = not get_option('status_socket').disabled()
if with_status_socket
	deps += dependency('json-c')
endif

with_systemd = get_option('systemd').enabled() or (get_option('systemd').auto() and is_linux)

with_cmdline_user = get_option('cmdline_user').enabled() or (get_option('cmdline_user').auto() and not is_android)
if with_cmdline_user and is_android
	error('cmdline_user is not available on Android')
endif

if need_libcrypto
	deps += dependency('libcrypto')
endif

if need_libsodium_nacl
	if get_option('use_nacl')
		deps += cc.find_library('nacl')
	else
		deps += dependency('libsodium')
		conf_data.set('HAVE_LIBSODIUM', true)
	endif
endif

conf_data.set(
	'HAVE_AI_ADDRCONFIG',
	cc.has_header_symbol(
		'netdb.h',
		'AI_ADDRCONFIG',
		prefix : '#include <sys/types.h>\n#include <sys/socket.h>',
		args : default_args,
	),
)

conf_data.set(
	'HAVE_GET_CURRENT_DIR_NAME',
	cc.has_function(
		'get_current_dir_name',
		prefix : '#include <unistd.h>',
		args : default_args,
	),
)

have_endian_h = false
have_sys_endian_h = false
have_linux_endian = false

if not is_darwin
	have_endian_h = cc.has_header('endian.h')

	if not have_endian_h
		have_sys_endian_h = cc.has_header('sys/endian.h')
	endif

	if have_endian_h
		have_linux_endian = cc.has_header_symbol(
			'endian.h',
			'be32toh',
			args : default_args,
		)
	elif have_sys_endian_h
		have_linux_endian = cc.has_header_symbol(
			'sys/endian.h',
			'be32toh',
			prefix : '#include <sys/types.h>',
			args : default_args,
		)
	else
		error('Required header <endian.h> or <sys/endian.h> not found')
	endif
endif

conf_data.set('HAVE_ENDIAN_H', have_endian_h)
conf_data.set('HAVE_SYS_ENDIAN_H', have_sys_endian_h)
conf_data.set('HAVE_LINUX_ENDIAN', have_linux_endian)

conf_data.set('HAVE_SETRESUID',
	cc.has_function(
		'setresuid',
		prefix : '#include <unistd.h>',
		args : default_args,
	),
)
conf_data.set('HAVE_SETRESGID',
	cc.has_function(
		'setresgid',
		prefix : '#include <unistd.h>',
		args : default_args,
	),
)

conf_data.set('USE_BINDTODEVICE', is_android or is_linux)
conf_data.set('USE_EPOLL', is_android or is_linux)
conf_data.set('USE_SELECT', is_darwin)
conf_data.set('USE_FREEBIND', is_android or is_linux)
conf_data.set('USE_PMTU', is_android or is_linux)
conf_data.set('USE_PKTINFO', is_android or is_linux)
conf_data.set('USE_PACKET_MARK', is_linux)

conf_data.set('USE_USER', not is_android)
conf_data.set('USE_MULTIAF_BIND', not is_openbsd)

conf_data.set('WITH_CAPABILITIES', with_capabilities)
conf_data.set('WITH_CMDLINE_USER', with_cmdline_user)
conf_data.set('WITH_CMDLINE_LOGGING', not get_option('cmdline_logging').disabled())
conf_data.set('WITH_CMDLINE_OPERATION', not get_option('cmdline_operation').disabled())
conf_data.set('WITH_CMDLINE_COMMANDS', not get_option('cmdline_commands').disabled())
conf_data.set('WITH_DYNAMIC_PEERS', not get_option('dynamic_peers').disabled())
conf_data.set('WITH_STATUS_SOCKET', with_status_socket)
conf_data.set('WITH_SYSTEMD', with_systemd)

configure_file(
	input : 'build.h.in',
	output : 'build.h',
	configuration : conf_data,
)

libfastd = static_library(
	'libfastd',
	sources : src,
	link_with : libs,
	dependencies : deps,
)

executable(
	'fastd', 'main.c',
	link_with : libfastd,
	install : true,
)
